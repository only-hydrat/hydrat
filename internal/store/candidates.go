package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

func (store *Store) ReplaceCandidates(
	ctx context.Context,
	sourceID string,
	inputs []CandidateInput,
	retirementGrace ...time.Duration,
) error {
	if len(inputs) == 0 {
		return errors.New("refusing to replace candidates with an empty refresh")
	}
	grace := 15 * time.Minute
	if len(retirementGrace) > 0 && retirementGrace[0] > 0 {
		grace = retirementGrace[0]
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var pendingDelete bool
	if err := tx.QueryRowContext(ctx, `
		SELECT pending_delete FROM sources WHERE id=?
	`, sourceID).Scan(&pendingDelete); err != nil {
		return err
	}
	if pendingDelete {
		return errors.New("source is pending deletion")
	}
	now := time.Now().Unix()
	candidateIDs := make([]string, 0, len(inputs))
	seenCandidateIDs := make(map[string]struct{}, len(inputs))
	for sourcePosition, input := range inputs {
		if input.Fingerprint == "" || input.Payload == "" {
			return errors.New("candidate fingerprint and payload are required")
		}
		digest := sha256.Sum256([]byte(sourceID + ":" + input.Fingerprint))
		id := "cand_" + hex.EncodeToString(digest[:8])
		if _, duplicate := seenCandidateIDs[id]; duplicate {
			return errors.New("duplicate candidate fingerprint")
		}
		seenCandidateIDs[id] = struct{}{}
		candidateIDs = append(candidateIDs, id)
		encrypted, err := store.box.Seal(id, []byte(input.Payload))
		if err != nil {
			return fmt.Errorf("encrypt candidate: %w", err)
		}
		routeKey := input.RouteKey
		failureDomain := input.FailureDomain
		if input.Kind != sources.KindVLESS {
			routeKey = ""
			failureDomain = ""
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO candidates(
              id, source_id, kind, label, fingerprint, route_key, failure_domain,
			  encrypted_payload, enabled, source_position, lifecycle,
			  retired_at, drain_after, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'active', NULL, NULL, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
			  kind=excluded.kind, label=excluded.label,
			  fingerprint=excluded.fingerprint,
			  route_key=excluded.route_key,
			  failure_domain=excluded.failure_domain,
			  encrypted_payload=excluded.encrypted_payload, enabled=1,
			  source_position=excluded.source_position,
			  lifecycle='active', retired_at=NULL, drain_after=NULL,
			  updated_at=excluded.updated_at
		`, id, sourceID, string(input.Kind), input.Label, input.Fingerprint,
			routeKey, failureDomain, encrypted, sourcePosition, now, now); err != nil {
			return fmt.Errorf("insert candidate: %w", err)
		}
	}
	drainArguments := make([]any, 0, len(candidateIDs)+3)
	drainArguments = append(
		drainArguments,
		now+int64(grace/time.Second),
		now,
		sourceID,
	)
	for _, candidateID := range candidateIDs {
		drainArguments = append(drainArguments, candidateID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(candidateIDs)), ",")
	if _, err := tx.ExecContext(ctx, `
		UPDATE candidates
		SET lifecycle='draining',
		    drain_after=COALESCE(drain_after, ?),
		    retired_at=NULL,
		    updated_at=?
		WHERE source_id=? AND id NOT IN (`+placeholders+`)
		  AND lifecycle='active'
	`, drainArguments...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE sources SET candidate_count = ?, last_refresh_at = ?, last_refresh_error = '', updated_at = ? WHERE id = ?
    `, len(inputs), now, now, sourceID); err != nil {
		return err
	}
	if err := incrementInventoryEpochTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func incrementInventoryEpochTx(ctx context.Context, tx sqlExecutor) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE inventory_state SET epoch=epoch+1 WHERE singleton=1
	`)
	if err != nil {
		return err
	}
	return requireAffected(result, "inventory state")
}

func (store *Store) InventoryEpoch(ctx context.Context) (int64, error) {
	var epoch int64
	err := store.db.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&epoch)
	return epoch, err
}

func (store *Store) RecordRefreshFailure(ctx context.Context, sourceID, message string) error {
	result, err := store.db.ExecContext(ctx, `
        UPDATE sources SET last_refresh_at = ?, last_refresh_error = ?, updated_at = ? WHERE id = ?
    `, time.Now().Unix(), message, time.Now().Unix(), sourceID)
	if err != nil {
		return err
	}
	return requireAffected(result, "source")
}

func (store *Store) ListCandidates(ctx context.Context, sourceID string) ([]Candidate, error) {
	return listCandidates(ctx, store.db, sourceID, nil)
}

func (store *Store) ListRoutableCandidates(
	ctx context.Context,
	referencedIDs []string,
) ([]Candidate, error) {
	return listCandidates(ctx, store.db, "", referencedIDs)
}

type candidateRowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (store *Store) ListRoutableCandidatesSnapshot(
	ctx context.Context,
	referencedIDs []string,
) ([]Candidate, int64, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var epoch int64
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&epoch); err != nil {
		return nil, 0, err
	}
	candidates, err := listCandidates(ctx, tx, "", referencedIDs)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return candidates, epoch, nil
}

func listCandidates(
	ctx context.Context,
	queryer candidateRowsQueryer,
	sourceID string,
	referencedIDs []string,
) ([]Candidate, error) {
	arguments := []any{sourceID, sourceID}
	lifecyclePredicate := `c.lifecycle='active'`
	if len(referencedIDs) > 0 {
		placeholders := strings.TrimSuffix(
			strings.Repeat("?,", len(referencedIDs)),
			",",
		)
		lifecyclePredicate = `(c.lifecycle='active' OR (
			c.lifecycle='draining' AND c.id IN (` + placeholders + `)
		))`
		for _, candidateID := range referencedIDs {
			arguments = append(arguments, candidateID)
		}
	}
	rows, err := queryer.QueryContext(ctx, `
		SELECT c.id, c.source_id, c.kind, c.label, c.fingerprint,
		       c.route_key, c.failure_domain, c.enabled, c.source_position,
		       c.lifecycle, c.retired_at, c.drain_after,
		       c.created_at, c.updated_at
		FROM candidates c
		JOIN sources s ON s.id = c.source_id
		WHERE c.enabled = 1 AND s.enabled = 1
		  AND (? = '' OR c.source_id = ?)
		  AND `+lifecyclePredicate+`
		ORDER BY s.created_at, s.id, c.source_position, c.id
    `, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Candidate, 0)
	seenFingerprints := make(map[string]bool)
	for rows.Next() {
		var candidate Candidate
		if err := rows.Scan(&candidate.ID, &candidate.SourceID, &candidate.Kind, &candidate.Label,
			&candidate.Fingerprint, &candidate.RouteKey, &candidate.FailureDomain,
			&candidate.Enabled, &candidate.SourcePosition,
			&candidate.Lifecycle, &candidate.RetiredAt, &candidate.DrainAfter,
			&candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
			return nil, err
		}
		if sourceID == "" &&
			candidate.Lifecycle == CandidateLifecycleActive &&
			seenFingerprints[candidate.Fingerprint] {
			continue
		}
		if candidate.Lifecycle == CandidateLifecycleActive {
			seenFingerprints[candidate.Fingerprint] = true
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

func (store *Store) CandidatePayload(ctx context.Context, id string) (string, error) {
	var encrypted []byte
	if err := store.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM candidates WHERE id = ?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	plaintext, err := store.box.Open(id, encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt candidate: %w", err)
	}
	return string(plaintext), nil
}

type CandidateSummary struct {
	ID    string       `json:"id"`
	Kind  sources.Kind `json:"kind"`
	Label string       `json:"label"`
}

func (store *Store) CandidateSummaries(ctx context.Context, ids []string) (map[string]CandidateSummary, error) {
	if len(ids) == 0 {
		return map[string]CandidateSummary{}, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	arguments := make([]any, len(ids))
	for i, id := range ids {
		arguments[i] = id
	}
	rows, err := store.db.QueryContext(ctx, "SELECT id, kind, label FROM candidates WHERE id IN ("+placeholders+")", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]CandidateSummary, len(ids))
	for rows.Next() {
		var s CandidateSummary
		if err := rows.Scan(&s.ID, &s.Kind, &s.Label); err != nil {
			return nil, err
		}
		result[s.ID] = s
	}
	return result, rows.Err()
}

func (store *Store) ActiveCandidatePayloadsSnapshot(
	ctx context.Context,
	candidates []Candidate,
) ([]CandidatePayloadSnapshot, int64, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var epoch int64
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&epoch); err != nil {
		return nil, 0, err
	}
	result := make([]CandidatePayloadSnapshot, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID == "" ||
			candidate.SourceID == "" ||
			candidate.Fingerprint == "" {
			return nil, 0, errors.New("candidate identity is incomplete")
		}
		var encrypted []byte
		err := tx.QueryRowContext(ctx, `
			SELECT c.encrypted_payload
			FROM candidates c
			JOIN sources s ON s.id=c.source_id
			WHERE c.id=? AND c.source_id=? AND c.fingerprint=?
			  AND c.enabled=1 AND s.enabled=1 AND c.lifecycle='active'
		`, candidate.ID, candidate.SourceID, candidate.Fingerprint).Scan(
			&encrypted,
		)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		plaintext, err := store.box.Open(candidate.ID, encrypted)
		if err != nil {
			return nil, 0, fmt.Errorf("decrypt candidate: %w", err)
		}
		result = append(result, CandidatePayloadSnapshot{
			Candidate: candidate,
			Payload:   string(plaintext),
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return result, epoch, nil
}

func requireAffected(result sql.Result, resource string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s not found", resource)
	}
	return nil
}

