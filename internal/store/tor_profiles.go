package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/only-hydrat/hydrat/internal/sources"
)

type TorProfileCandidate struct {
	Candidate         Candidate
	Payload           string
	ConservativeScore float64
	Assigned          bool
	Draining          bool
	Referenced        bool
	Qualified         bool
	SourceEnabled     bool
	Mandatory         bool
}

type TorProfileSetRequest struct {
	Active                  []Candidate
	Draining                []Candidate
	ForceCandidateIDs       []string
	ExcludeCandidateID      string
	ExcludeCandidateIDs     []string
	UsePersistedWorkingPool bool
}

type TorProfileSetSnapshot struct {
	Candidates            []TorProfileCandidate
	MandatoryCandidateIDs []string
	DesiredGeneration     int64
	AppliedGeneration     int64
	InventoryEpoch        int64
	SemanticDigest        string
}


func (store *Store) LoadTorProfileSetSnapshot(
	ctx context.Context,
	request TorProfileSetRequest,
) (TorProfileSetSnapshot, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var snapshot TorProfileSetSnapshot
	var desiredPlan, appliedPlan []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&snapshot.DesiredGeneration,
		&snapshot.AppliedGeneration,
		&desiredPlan,
		&appliedPlan,
	); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&snapshot.InventoryEpoch); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	references, err := loadCandidateRetirementReferencesTx(
		ctx,
		tx,
		snapshot.DesiredGeneration,
		desiredPlan,
		snapshot.AppliedGeneration,
		appliedPlan,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	snapshot.Candidates, err = loadTorProfileSetSnapshotTx(
		ctx, tx, request, references, store.box,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	snapshot.SemanticDigest, err = torProfileSemanticDigest(
		snapshot.Candidates,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	return snapshot, nil
}

func (store *Store) LoadTorCompensationSnapshot(
	ctx context.Context,
	targetCandidateIDs []string,
) (TorProfileSetSnapshot, error) {
	if len(targetCandidateIDs) == 0 || len(targetCandidateIDs) > 64 {
		return TorProfileSetSnapshot{},
			errors.New("Tor compensation target batch is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var snapshot TorProfileSetSnapshot
	var desiredPlan, appliedPlan []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&snapshot.DesiredGeneration,
		&snapshot.AppliedGeneration,
		&desiredPlan,
		&appliedPlan,
	); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&snapshot.InventoryEpoch); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	references, err := loadCandidateRetirementReferencesTx(
		ctx,
		tx,
		snapshot.DesiredGeneration,
		desiredPlan,
		snapshot.AppliedGeneration,
		appliedPlan,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	seen := make(map[string]bool, len(targetCandidateIDs))
	for _, candidateID := range targetCandidateIDs {
		if candidateID == "" || seen[candidateID] {
			continue
		}
		seen[candidateID] = true
		var kind sources.Kind
		var lifecycle string
		err := tx.QueryRowContext(ctx, `
			SELECT kind, lifecycle FROM candidates WHERE id=?
		`, candidateID).Scan(&kind, &lifecycle)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return TorProfileSetSnapshot{}, err
		}
		if kind == sources.KindTorBridge &&
			(lifecycle == CandidateLifecycleActive ||
				references[candidateID]) {
			snapshot.MandatoryCandidateIDs = append(
				snapshot.MandatoryCandidateIDs, candidateID,
			)
		}
	}
	sort.Strings(snapshot.MandatoryCandidateIDs)
	snapshot.Candidates, err = loadTorProfileSetSnapshotTx(
		ctx,
		tx,
		TorProfileSetRequest{
			ForceCandidateIDs:       snapshot.MandatoryCandidateIDs,
			UsePersistedWorkingPool: true,
		},
		references,
		store.box,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	snapshot.SemanticDigest, err = torProfileSemanticDigest(
		snapshot.Candidates,
	)
	if err != nil {
		return TorProfileSetSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return TorProfileSetSnapshot{}, err
	}
	return snapshot, nil
}

type retirementRowScanner interface {
	Scan(...any) error
}


func loadTorProfileSetSnapshotTx(
	ctx context.Context,
	tx *sql.Tx,
	request TorProfileSetRequest,
	references map[string]bool,
	box interface {
		Open(string, []byte) ([]byte, error)
	},
) ([]TorProfileCandidate, error) {
	requestedActive := candidateIdentityByID(request.Active)
	requestedDraining := candidateIdentityByID(request.Draining)
	forced := make(map[string]bool, len(request.ForceCandidateIDs))
	for _, candidateID := range request.ForceCandidateIDs {
		if candidateID != "" {
			forced[candidateID] = true
		}
	}
	excluded := make(map[string]bool, len(request.ExcludeCandidateIDs)+1)
	if request.ExcludeCandidateID != "" {
		excluded[request.ExcludeCandidateID] = true
	}
	for _, candidateID := range request.ExcludeCandidateIDs {
		if candidateID != "" {
			excluded[candidateID] = true
		}
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.source_id, c.kind, c.label, c.fingerprint,
		       c.route_key, c.failure_domain, c.enabled, c.source_position,
		       c.lifecycle, c.retired_at, c.drain_after,
		       c.created_at, c.updated_at, c.encrypted_payload,
		       s.enabled,
		       COALESCE(p.status, ''),
		       COALESCE(p.full_success_streak, 0),
		       COALESCE(p.conservative_score, 0),
		       COALESCE(p.in_working_pool, 0),
		       COALESCE(p.draining, 0),
		       EXISTS(
		         SELECT 1 FROM assignments a
		         WHERE a.tcp_outbound=c.id OR a.udp_outbound=c.id
		       )
		FROM candidates c
		JOIN sources s ON s.id=c.source_id
		LEFT JOIN candidate_probe_state p
		  ON p.fingerprint=c.fingerprint
		 AND p.candidate_id=c.id
		 AND p.source_id=c.source_id
		 AND p.observation_placeholder=0
		WHERE c.kind=?
		ORDER BY c.id
	`, string(sources.KindTorBridge))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TorProfileCandidate, 0)
	for rows.Next() {
		var candidate Candidate
		var encrypted []byte
		var (
			sourceEnabled     bool
			status            CandidateStatus
			fullSuccessStreak int
			conservativeScore float64
			inWorkingPool     bool
			stateDraining     bool
			assigned          bool
		)
		if err := rows.Scan(
			&candidate.ID, &candidate.SourceID, &candidate.Kind,
			&candidate.Label, &candidate.Fingerprint, &candidate.RouteKey,
			&candidate.FailureDomain, &candidate.Enabled,
			&candidate.SourcePosition, &candidate.Lifecycle,
			&candidate.RetiredAt, &candidate.DrainAfter,
			&candidate.CreatedAt, &candidate.UpdatedAt, &encrypted,
			&sourceEnabled, &status, &fullSuccessStreak,
			&conservativeScore, &inWorkingPool, &stateDraining,
			&assigned,
		); err != nil {
			return nil, err
		}
		if excluded[candidate.ID] {
			continue
		}
		activeRequested := candidateIdentityMatches(
			requestedActive[candidate.ID], candidate,
		)
		drainingRequested := candidateIdentityMatches(
			requestedDraining[candidate.ID], candidate,
		)
		persistedPool := request.UsePersistedWorkingPool &&
			(inWorkingPool || stateDraining)
		qualified := fullSuccessStreak >= 2 &&
			(status == CandidateQualified || status == CandidateDraining)
		referenced := references[candidate.ID]
		continuity := referenced &&
			(candidate.Lifecycle == CandidateLifecycleDraining ||
				!candidate.Enabled || !sourceEnabled)
		if !forced[candidate.ID] &&
			!((activeRequested || drainingRequested || persistedPool) &&
				qualified) &&
			!continuity {
			continue
		}
		payload, err := box.Open(candidate.ID, encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt Tor retirement candidate: %w", err)
		}
		result = append(result, TorProfileCandidate{
			Candidate:         candidate,
			Payload:           string(payload),
			ConservativeScore: conservativeScore,
			Assigned:          assigned,
			Draining: drainingRequested || stateDraining ||
				candidate.Lifecycle == CandidateLifecycleDraining ||
				!candidate.Enabled || !sourceEnabled,
			Referenced:    referenced,
			Qualified:     qualified,
			SourceEnabled: sourceEnabled,
			Mandatory:     forced[candidate.ID],
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func candidateIdentityByID(candidates []Candidate) map[string]Candidate {
	result := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID != "" {
			result[candidate.ID] = candidate
		}
	}
	return result
}

func candidateIdentityMatches(expected, current Candidate) bool {
	return expected.ID != "" &&
		expected.ID == current.ID &&
		expected.SourceID == current.SourceID &&
		expected.Fingerprint == current.Fingerprint
}

func torProfileSemanticDigest(
	items []TorProfileCandidate,
) (string, error) {
	type semanticCandidate struct {
		ID                string
		SourceID          string
		Fingerprint       string
		Lifecycle         string
		Enabled           bool
		SourceEnabled     bool
		ConservativeScore float64
		Assigned          bool
		Draining          bool
		Referenced        bool
		Qualified         bool
	}
	semantic := make([]semanticCandidate, 0, len(items))
	for _, item := range items {
		semantic = append(semantic, semanticCandidate{
			ID:                item.Candidate.ID,
			SourceID:          item.Candidate.SourceID,
			Fingerprint:       item.Candidate.Fingerprint,
			Lifecycle:         item.Candidate.Lifecycle,
			Enabled:           item.Candidate.Enabled,
			SourceEnabled:     item.SourceEnabled,
			ConservativeScore: item.ConservativeScore,
			Assigned:          item.Assigned,
			Draining:          item.Draining,
			Referenced:        item.Referenced,
			Qualified:         item.Qualified,
		})
	}
	sort.Slice(semantic, func(left, right int) bool {
		return semantic[left].ID < semantic[right].ID
	})
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return "", fmt.Errorf("encode Tor profile semantics: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

