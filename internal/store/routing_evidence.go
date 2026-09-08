package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
)

var ErrCandidateEvidenceChanged = errors.New("candidate routing evidence changed")

type CandidateEvidenceChangedError struct {
	CandidateID string
}

func (err CandidateEvidenceChangedError) Error() string {
	if err.CandidateID == "" {
		return ErrCandidateEvidenceChanged.Error()
	}
	return fmt.Sprintf("%s: %s", ErrCandidateEvidenceChanged, err.CandidateID)
}

func (CandidateEvidenceChangedError) Unwrap() error   { return ErrCandidateEvidenceChanged }
func (CandidateEvidenceChangedError) Temporary() bool { return true }

type CandidateRoutingEvidence struct {
	Candidate               Candidate
	Payload                 string
	SourceEnabled           bool
	Health                  CandidateHealth
	HasHealth               bool
	ActiveResultSequence    int64
	ActiveAppliedSequence   int64
	FailureGeneration       int64
	ActiveFailureGeneration int64
	Probe                   CandidateProbeState
	HasProbe                bool
	FailureDomain           FailureDomainState
	HasFailureDomain        bool
	QoE                     qoe.State
	HasQoE                  bool
	Digest                  string
}

type RoutingEvidenceSnapshot struct {
	Candidates     []CandidateRoutingEvidence
	InventoryEpoch int64
}

type candidateEvidenceDigest struct {
	Inventory               candidateInventoryEvidence
	SourceEnabled           bool
	PayloadSHA256           string
	Health                  candidateHealthDecisionEvidence
	HasHealth               bool
	FailureGeneration       int64
	ActiveFailureGeneration int64
	Probe                   CandidateProbeState
	HasProbe                bool
	FailureDomain           FailureDomainState
	HasFailureDomain        bool
	QoE                     qoe.State
	HasQoE                  bool
}

type candidateHealthDecisionEvidence struct {
	Score             float64
	TCPQualified      bool
	UDPQualified      bool
	Available         bool
	LatencyMS         float64
	ThroughputMbps    float64
	ActiveSuccess     bool
	ActiveCurrent     bool
	ActiveHardFailure bool
}

type candidateInventoryEvidence struct {
	ID            string
	SourceID      string
	Kind          sources.Kind
	Fingerprint   string
	RouteKey      string
	FailureDomain string
	Enabled       bool
	Lifecycle     string
}

func (evidence CandidateRoutingEvidence) semanticDigest() (string, error) {
	payloadDigest := sha256.Sum256([]byte(evidence.Payload))
	encoded, err := json.Marshal(candidateEvidenceDigest{
		Inventory: candidateInventoryEvidence{
			ID:            evidence.Candidate.ID,
			SourceID:      evidence.Candidate.SourceID,
			Kind:          evidence.Candidate.Kind,
			Fingerprint:   evidence.Candidate.Fingerprint,
			RouteKey:      evidence.Candidate.RouteKey,
			FailureDomain: evidence.Candidate.FailureDomain,
			Enabled:       evidence.Candidate.Enabled,
			Lifecycle:     evidence.Candidate.Lifecycle,
		},
		SourceEnabled: evidence.SourceEnabled,
		PayloadSHA256: hex.EncodeToString(payloadDigest[:]),
		Health: candidateHealthDecisionEvidence{
			Score:             evidence.Health.Score,
			TCPQualified:      evidence.Health.TCPQualified,
			UDPQualified:      evidence.Health.UDPQualified,
			Available:         evidence.Health.Available,
			LatencyMS:         evidence.Health.LatencyMS,
			ThroughputMbps:    evidence.Health.ThroughputMbps,
			ActiveSuccess:     evidence.Health.ActiveSuccess,
			ActiveCurrent:     evidence.Health.ActiveCurrent,
			ActiveHardFailure: evidence.Health.ActiveHardFailure,
		},
		HasHealth:               evidence.HasHealth,
		FailureGeneration:       evidence.FailureGeneration,
		ActiveFailureGeneration: evidence.ActiveFailureGeneration,
		Probe:                   evidence.Probe,
		HasProbe:                evidence.HasProbe,
		FailureDomain:           evidence.FailureDomain,
		HasFailureDomain:        evidence.HasFailureDomain,
		QoE:                     evidence.QoE,
		HasQoE:                  evidence.HasQoE,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (store *Store) LoadRoutingEvidenceSnapshot(
	ctx context.Context,
	referencedIDs []string,
) (RoutingEvidenceSnapshot, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RoutingEvidenceSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	snapshot := RoutingEvidenceSnapshot{}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&snapshot.InventoryEpoch); err != nil {
		return RoutingEvidenceSnapshot{}, err
	}
	candidates, err := store.listRoutingEvidenceCandidatesTx(ctx, tx, referencedIDs)
	if err != nil {
		return RoutingEvidenceSnapshot{}, err
	}
	for _, evidence := range candidates {
		if err := loadCandidateRoutingEvidenceStateTx(ctx, tx, &evidence); err != nil {
			return RoutingEvidenceSnapshot{}, err
		}
		evidence.Digest, err = evidence.semanticDigest()
		if err != nil {
			return RoutingEvidenceSnapshot{}, err
		}
		snapshot.Candidates = append(snapshot.Candidates, evidence)
	}
	if err := tx.Commit(); err != nil {
		return RoutingEvidenceSnapshot{}, err
	}
	return snapshot, nil
}

func (store *Store) listRoutingEvidenceCandidatesTx(
	ctx context.Context,
	tx *sql.Tx,
	referencedIDs []string,
) ([]CandidateRoutingEvidence, error) {
	var hasProbeState bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM candidate_probe_state
		  WHERE candidate_id<>'' AND observation_placeholder=0
		)
	`).Scan(&hasProbeState); err != nil {
		return nil, err
	}
	arguments := make([]any, 0, len(referencedIDs)*2)
	lifecyclePredicate := `c.lifecycle='active'`
	routingPredicate := `1=1`
	if len(referencedIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(referencedIDs)), ",")
		lifecyclePredicate = `(c.lifecycle='active' OR (c.lifecycle='draining' AND c.id IN (` +
			placeholders + `)))`
		for _, candidateID := range referencedIDs {
			arguments = append(arguments, candidateID)
		}
		if hasProbeState {
			routingPredicate = `(c.id IN (` + placeholders + `) OR EXISTS (
			  SELECT 1 FROM candidate_probe_state p
			  WHERE p.candidate_id=c.id
			    AND p.observation_placeholder=0
			    AND (p.in_working_pool=1 OR p.draining=1)
			))`
			for _, candidateID := range referencedIDs {
				arguments = append(arguments, candidateID)
			}
		}
	} else if hasProbeState {
		routingPredicate = `EXISTS (
		  SELECT 1 FROM candidate_probe_state p
		  WHERE p.candidate_id=c.id
		    AND p.observation_placeholder=0
		    AND (p.in_working_pool=1 OR p.draining=1)
		)`
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.source_id, c.kind, c.label, c.fingerprint,
		       c.route_key, c.failure_domain, c.enabled, c.source_position,
		       c.lifecycle, c.retired_at, c.drain_after,
		       c.created_at, c.updated_at, c.encrypted_payload, s.enabled
		FROM candidates c
		JOIN sources s ON s.id=c.source_id
		WHERE c.enabled=1 AND s.enabled=1 AND `+lifecyclePredicate+`
		  AND `+routingPredicate+`
		ORDER BY s.created_at, s.id, c.source_position, c.id
	`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CandidateRoutingEvidence, 0)
	seenFingerprints := make(map[string]bool)
	for rows.Next() {
		evidence, encrypted, err := scanCandidateRoutingEvidenceBase(rows)
		if err != nil {
			return nil, err
		}
		if seenFingerprints[evidence.Candidate.Fingerprint] {
			continue
		}
		seenFingerprints[evidence.Candidate.Fingerprint] = true
		plain, err := store.box.Open(evidence.Candidate.ID, encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt candidate: %w", err)
		}
		evidence.Payload = string(plain)
		result = append(result, evidence)
	}
	return result, rows.Err()
}

func (store *Store) loadCandidateRoutingEvidenceTx(
	ctx context.Context,
	tx *sql.Tx,
	candidateID string,
) (CandidateRoutingEvidence, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT c.id, c.source_id, c.kind, c.label, c.fingerprint,
		       c.route_key, c.failure_domain, c.enabled, c.source_position,
		       c.lifecycle, c.retired_at, c.drain_after,
		       c.created_at, c.updated_at, c.encrypted_payload, s.enabled
		FROM candidates c
		JOIN sources s ON s.id=c.source_id
		WHERE c.id=?
	`, candidateID)
	evidence, encrypted, err := scanCandidateRoutingEvidenceBase(row)
	if err != nil {
		return CandidateRoutingEvidence{}, err
	}
	plain, err := store.box.Open(evidence.Candidate.ID, encrypted)
	if err != nil {
		return CandidateRoutingEvidence{}, fmt.Errorf("decrypt candidate: %w", err)
	}
	evidence.Payload = string(plain)
	if err := loadCandidateRoutingEvidenceStateTx(ctx, tx, &evidence); err != nil {
		return CandidateRoutingEvidence{}, err
	}
	evidence.Digest, err = evidence.semanticDigest()
	return evidence, err
}

func scanCandidateRoutingEvidenceBase(row rowScanner) (
	CandidateRoutingEvidence,
	[]byte,
	error,
) {
	var evidence CandidateRoutingEvidence
	var encrypted []byte
	err := row.Scan(
		&evidence.Candidate.ID, &evidence.Candidate.SourceID,
		&evidence.Candidate.Kind, &evidence.Candidate.Label,
		&evidence.Candidate.Fingerprint, &evidence.Candidate.RouteKey,
		&evidence.Candidate.FailureDomain, &evidence.Candidate.Enabled,
		&evidence.Candidate.SourcePosition, &evidence.Candidate.Lifecycle,
		&evidence.Candidate.RetiredAt, &evidence.Candidate.DrainAfter,
		&evidence.Candidate.CreatedAt, &evidence.Candidate.UpdatedAt,
		&encrypted, &evidence.SourceEnabled,
	)
	return evidence, encrypted, err
}

func loadCandidateRoutingEvidenceStateTx(
	ctx context.Context,
	tx *sql.Tx,
	evidence *CandidateRoutingEvidence,
) error {
	var updated int64
	var activeObserved sql.NullInt64
	err := tx.QueryRowContext(ctx, `
		SELECT candidate_id, score, tcp_qualified, udp_qualified, available,
		       latency_ms, throughput_mbps, updated_at,
		       active_observed_at, active_success,
		       active_result_seq, active_applied_seq,
		       failure_generation, active_failure_generation,
		       active_hard_failure
		FROM candidate_health
		WHERE candidate_id=? AND observation_placeholder=0
	`, evidence.Candidate.ID).Scan(
		&evidence.Health.CandidateID, &evidence.Health.Score,
		&evidence.Health.TCPQualified, &evidence.Health.UDPQualified,
		&evidence.Health.Available, &evidence.Health.LatencyMS,
		&evidence.Health.ThroughputMbps, &updated, &activeObserved,
		&evidence.Health.ActiveSuccess, &evidence.ActiveResultSequence,
		&evidence.ActiveAppliedSequence, &evidence.FailureGeneration,
		&evidence.ActiveFailureGeneration, &evidence.Health.ActiveHardFailure,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		evidence.HasHealth = true
		evidence.Health.UpdatedAt = timeFromUnix(updated)
		if activeObserved.Valid {
			evidence.Health.ActiveObservedAt = time.UnixMilli(activeObserved.Int64)
		}
		evidence.Health.ActiveCurrent = activeObserved.Valid &&
			evidence.ActiveAppliedSequence > 0 &&
			evidence.FailureGeneration == evidence.ActiveFailureGeneration
	}
	probe, err := scanCandidateProbeState(tx.QueryRowContext(
		ctx, candidateStateSelect+`
		WHERE candidate_probe_state.candidate_id=?
		  AND candidate_probe_state.observation_placeholder=0`,
		evidence.Candidate.ID,
	))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		evidence.Probe, evidence.HasProbe = probe, true
	}
	if evidence.Candidate.FailureDomain != "" {
		domain, exists, err := loadFailureDomainState(
			ctx, tx, evidence.Candidate.FailureDomain,
		)
		if err != nil {
			return err
		}
		if exists {
			evidence.FailureDomain, evidence.HasFailureDomain = domain, true
		}
	}
	state, err := scanCandidateQoEState(tx.QueryRowContext(
		ctx, candidateQoEStateSelect+` WHERE candidate_id=?`,
		evidence.Candidate.ID,
	))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		evidence.QoE, evidence.HasQoE = state, true
	}
	return nil
}

func timeFromUnix(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}
