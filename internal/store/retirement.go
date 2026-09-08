package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/sources"
)

type CandidateRetirementSnapshot struct {
	Candidate         Candidate
	DesiredGeneration int64
	AppliedGeneration int64
	InventoryEpoch    int64
	Referenced        bool
	TorCandidates     []TorProfileCandidate
	TorSemanticDigest string
}

type CandidateRetirementBatchSnapshot struct {
	Candidates        []Candidate
	DesiredGeneration int64
	AppliedGeneration int64
	InventoryEpoch    int64
	TorCandidates     []TorProfileCandidate
	TorSemanticDigest string
}

type CandidateRetirementResult struct {
	Changed   bool
	Lifecycle string
}

type CandidateRetirementBatchResult struct {
	Changed int
}

func (store *Store) CandidateForRetirement(
	ctx context.Context,
	candidateID string,
) (Candidate, error) {
	candidate, err := scanCandidateForRetirement(store.db.QueryRowContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates WHERE id=?
	`, candidateID))
	if errors.Is(err, sql.ErrNoRows) {
		return Candidate{}, ErrCandidateNotFound
	}
	return candidate, err
}

func (store *Store) ListCandidatesDueRetirement(
	ctx context.Context,
	now time.Time,
	retiredRetention time.Duration,
) ([]Candidate, error) {
	if now.IsZero() {
		return nil, errors.New("candidate retirement time is required")
	}
	if retiredRetention <= 0 {
		return nil, errors.New("retired candidate retention must be positive")
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates
		WHERE (lifecycle='draining' AND drain_after IS NOT NULL AND drain_after<=?)
		   OR (lifecycle='retired' AND retired_at IS NOT NULL AND retired_at<=?)
		ORDER BY id
	`, now.Unix(), now.Add(-retiredRetention).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Candidate, 0)
	for rows.Next() {
		candidate, err := scanCandidateForRetirement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

func (store *Store) ListCandidatesDueRetirementPage(
	ctx context.Context,
	now time.Time,
	retiredRetention time.Duration,
	afterID string,
	limit int,
) ([]Candidate, error) {
	if now.IsZero() {
		return nil, errors.New("candidate retirement time is required")
	}
	if retiredRetention <= 0 {
		return nil, errors.New("retired candidate retention must be positive")
	}
	if limit <= 0 || limit > 64 {
		return nil, errors.New("candidate retirement page limit is invalid")
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates
		WHERE id>?
		  AND (
		    (lifecycle='draining' AND drain_after IS NOT NULL AND drain_after<=?)
		    OR
		    (lifecycle='retired' AND retired_at IS NOT NULL AND retired_at<=?)
		  )
		ORDER BY id
		LIMIT ?
	`, afterID, now.Unix(), now.Add(-retiredRetention).Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Candidate, 0, limit)
	for rows.Next() {
		candidate, err := scanCandidateForRetirement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

func (store *Store) LoadCandidateRetirementBatchSnapshot(
	ctx context.Context,
	candidateIDs []string,
	now time.Time,
	retiredRetention time.Duration,
) (CandidateRetirementBatchSnapshot, error) {
	if len(candidateIDs) == 0 || len(candidateIDs) > 64 {
		return CandidateRetirementBatchSnapshot{},
			errors.New("candidate retirement batch size is invalid")
	}
	if now.IsZero() || retiredRetention <= 0 {
		return CandidateRetirementBatchSnapshot{},
			errors.New("candidate retirement batch time is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var snapshot CandidateRetirementBatchSnapshot
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
		return CandidateRetirementBatchSnapshot{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&snapshot.InventoryEpoch); err != nil {
		return CandidateRetirementBatchSnapshot{}, err
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
		return CandidateRetirementBatchSnapshot{}, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(candidateIDs)), ",")
	arguments := make([]any, len(candidateIDs))
	for index, candidateID := range candidateIDs {
		arguments[index] = candidateID
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates
		WHERE id IN (`+placeholders+`)
		ORDER BY id
	`, arguments...)
	if err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	for rows.Next() {
		candidate, scanErr := scanCandidateForRetirement(rows)
		if scanErr != nil {
			_ = rows.Close()
			return CandidateRetirementBatchSnapshot{}, scanErr
		}
		if !references[candidate.ID] &&
			candidateRetirementDue(candidate, now, retiredRetention) {
			snapshot.Candidates = append(snapshot.Candidates, candidate)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return CandidateRetirementBatchSnapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	excludedIDs := make([]string, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if candidate.Kind == sources.KindTorBridge {
			excludedIDs = append(excludedIDs, candidate.ID)
		}
	}
	snapshot.TorCandidates, err = loadTorProfileSetSnapshotTx(
		ctx,
		tx,
		TorProfileSetRequest{
			ExcludeCandidateIDs:     excludedIDs,
			UsePersistedWorkingPool: true,
		},
		references,
		store.box,
	)
	if err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	snapshot.TorSemanticDigest, err = torProfileSemanticDigest(
		snapshot.TorCandidates,
	)
	if err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateRetirementBatchSnapshot{}, err
	}
	return snapshot, nil
}

func (store *Store) LoadCandidateRetirementSnapshot(
	ctx context.Context,
	candidateID string,
) (CandidateRetirementSnapshot, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateRetirementSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	candidate, err := scanCandidateForRetirement(tx.QueryRowContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates WHERE id=?
	`, candidateID))
	if errors.Is(err, sql.ErrNoRows) {
		return CandidateRetirementSnapshot{}, ErrCandidateNotFound
	}
	if err != nil {
		return CandidateRetirementSnapshot{}, err
	}
	var snapshot CandidateRetirementSnapshot
	snapshot.Candidate = candidate
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
		return CandidateRetirementSnapshot{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&snapshot.InventoryEpoch); err != nil {
		return CandidateRetirementSnapshot{}, err
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
		return CandidateRetirementSnapshot{}, err
	}
	snapshot.Referenced = references[candidateID]
	torSnapshot, err := loadTorProfileSetSnapshotTx(
		ctx,
		tx,
		TorProfileSetRequest{
			ExcludeCandidateID:      candidateID,
			UsePersistedWorkingPool: true,
		},
		references,
		store.box,
	)
	if err != nil {
		return CandidateRetirementSnapshot{}, err
	}
	snapshot.TorCandidates = torSnapshot
	snapshot.TorSemanticDigest, err = torProfileSemanticDigest(torSnapshot)
	if err != nil {
		return CandidateRetirementSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateRetirementSnapshot{}, err
	}
	return snapshot, nil
}

func (store *Store) AdvanceCandidateRetirement(
	ctx context.Context,
	candidateID string,
	expectedGeneration int64,
	expectedInventoryEpoch int64,
	expectedTorSemanticDigest string,
	now time.Time,
	retiredRetention time.Duration,
) (CandidateRetirementResult, error) {
	if candidateID == "" {
		return CandidateRetirementResult{}, errors.New("candidate ID is required")
	}
	if expectedGeneration < 0 {
		return CandidateRetirementResult{}, errors.New("candidate retirement generation is invalid")
	}
	if now.IsZero() {
		return CandidateRetirementResult{}, errors.New("candidate retirement time is required")
	}
	if retiredRetention <= 0 {
		return CandidateRetirementResult{}, errors.New("retired candidate retention must be positive")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateRetirementResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var desiredGeneration, appliedGeneration, inventoryEpoch int64
	var desiredPlan, appliedPlan []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredGeneration, &appliedGeneration, &desiredPlan, &appliedPlan,
	); err != nil {
		return CandidateRetirementResult{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&inventoryEpoch); err != nil {
		return CandidateRetirementResult{}, err
	}
	if desiredGeneration != expectedGeneration ||
		appliedGeneration != expectedGeneration ||
		inventoryEpoch != expectedInventoryEpoch {
		return CandidateRetirementResult{}, tx.Commit()
	}
	references, err := loadCandidateRetirementReferencesTx(
		ctx,
		tx,
		desiredGeneration,
		desiredPlan,
		appliedGeneration,
		appliedPlan,
	)
	if err != nil {
		return CandidateRetirementResult{}, err
	}
	candidate, err := scanCandidateForRetirement(tx.QueryRowContext(ctx, `
		SELECT id, source_id, kind, label, fingerprint, route_key,
		       failure_domain, enabled, source_position, lifecycle,
		       retired_at, drain_after, created_at, updated_at
		FROM candidates WHERE id=?
	`, candidateID))
	if errors.Is(err, sql.ErrNoRows) {
		return CandidateRetirementResult{}, tx.Commit()
	}
	if err != nil {
		return CandidateRetirementResult{}, err
	}
	if references[candidateID] {
		return CandidateRetirementResult{Lifecycle: candidate.Lifecycle}, tx.Commit()
	}
	currentTor, err := loadTorProfileSetSnapshotTx(
		ctx,
		tx,
		TorProfileSetRequest{
			ExcludeCandidateID:      candidateID,
			UsePersistedWorkingPool: true,
		},
		references,
		store.box,
	)
	if err != nil {
		return CandidateRetirementResult{}, err
	}
	currentTorDigest, err := torProfileSemanticDigest(currentTor)
	if err != nil {
		return CandidateRetirementResult{}, err
	}
	if expectedTorSemanticDigest == "" ||
		currentTorDigest != expectedTorSemanticDigest {
		return CandidateRetirementResult{Lifecycle: candidate.Lifecycle}, tx.Commit()
	}

	result := CandidateRetirementResult{Lifecycle: candidate.Lifecycle}
	switch candidate.Lifecycle {
	case CandidateLifecycleDraining:
		if candidate.DrainAfter == nil || *candidate.DrainAfter > now.Unix() {
			return result, tx.Commit()
		}
		updated, err := tx.ExecContext(ctx, `
			UPDATE candidates
			SET lifecycle='retired', retired_at=?, updated_at=?
			WHERE id=? AND lifecycle='draining' AND drain_after<=?
		`, now.Unix(), now.Unix(), candidateID, now.Unix())
		if err != nil {
			return CandidateRetirementResult{}, err
		}
		if err := requireAffected(updated, "draining candidate"); err != nil {
			return CandidateRetirementResult{}, err
		}
		result.Changed = true
		result.Lifecycle = CandidateLifecycleRetired
	case CandidateLifecycleRetired:
		if candidate.RetiredAt == nil ||
			*candidate.RetiredAt > now.Add(-retiredRetention).Unix() {
			return result, tx.Commit()
		}
		if err := deleteCandidateRetirementStateTx(
			ctx, tx, candidate,
		); err != nil {
			return CandidateRetirementResult{}, err
		}
		result.Changed = true
		result.Lifecycle = ""
	default:
		return result, tx.Commit()
	}
	if err := incrementInventoryEpochTx(ctx, tx); err != nil {
		return CandidateRetirementResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateRetirementResult{}, err
	}
	return result, nil
}

func (store *Store) AdvanceCandidateRetirementBatch(
	ctx context.Context,
	expectedCandidates []Candidate,
	expectedGeneration int64,
	expectedInventoryEpoch int64,
	expectedTorSemanticDigest string,
	now time.Time,
	retiredRetention time.Duration,
) (CandidateRetirementBatchResult, error) {
	if len(expectedCandidates) == 0 || len(expectedCandidates) > 64 {
		return CandidateRetirementBatchResult{},
			errors.New("candidate retirement batch size is invalid")
	}
	if expectedGeneration < 0 {
		return CandidateRetirementBatchResult{},
			errors.New("candidate retirement generation is invalid")
	}
	if now.IsZero() {
		return CandidateRetirementBatchResult{},
			errors.New("candidate retirement time is required")
	}
	if retiredRetention <= 0 {
		return CandidateRetirementBatchResult{},
			errors.New("retired candidate retention must be positive")
	}
	expectedByID := make(map[string]Candidate, len(expectedCandidates))
	for _, candidate := range expectedCandidates {
		if candidate.ID == "" || expectedByID[candidate.ID].ID != "" {
			return CandidateRetirementBatchResult{},
				errors.New("candidate retirement batch identity is invalid")
		}
		expectedByID[candidate.ID] = candidate
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var desiredGeneration, appliedGeneration, inventoryEpoch int64
	var desiredPlan, appliedPlan []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredGeneration, &appliedGeneration, &desiredPlan, &appliedPlan,
	); err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT epoch FROM inventory_state WHERE singleton=1
	`).Scan(&inventoryEpoch); err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	if desiredGeneration != expectedGeneration ||
		appliedGeneration != expectedGeneration ||
		inventoryEpoch != expectedInventoryEpoch {
		return CandidateRetirementBatchResult{}, tx.Commit()
	}
	references, err := loadCandidateRetirementReferencesTx(
		ctx,
		tx,
		desiredGeneration,
		desiredPlan,
		appliedGeneration,
		appliedPlan,
	)
	if err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	current := make([]Candidate, 0, len(expectedCandidates))
	torIDs := make([]string, 0, len(expectedCandidates))
	for _, expected := range expectedCandidates {
		candidate, err := scanCandidateForRetirement(tx.QueryRowContext(ctx, `
			SELECT id, source_id, kind, label, fingerprint, route_key,
			       failure_domain, enabled, source_position, lifecycle,
			       retired_at, drain_after, created_at, updated_at
			FROM candidates WHERE id=?
		`, expected.ID))
		if errors.Is(err, sql.ErrNoRows) {
			return CandidateRetirementBatchResult{}, tx.Commit()
		}
		if err != nil {
			return CandidateRetirementBatchResult{}, err
		}
		if !candidateRetirementIdentityMatches(expected, candidate) ||
			references[candidate.ID] ||
			!candidateRetirementDue(candidate, now, retiredRetention) {
			return CandidateRetirementBatchResult{}, tx.Commit()
		}
		current = append(current, candidate)
		if candidate.Kind == sources.KindTorBridge {
			torIDs = append(torIDs, candidate.ID)
		}
	}
	currentTor, err := loadTorProfileSetSnapshotTx(
		ctx,
		tx,
		TorProfileSetRequest{
			ExcludeCandidateIDs:     torIDs,
			UsePersistedWorkingPool: true,
		},
		references,
		store.box,
	)
	if err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	currentTorDigest, err := torProfileSemanticDigest(currentTor)
	if err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	if expectedTorSemanticDigest == "" ||
		currentTorDigest != expectedTorSemanticDigest {
		return CandidateRetirementBatchResult{}, tx.Commit()
	}
	for _, candidate := range current {
		switch candidate.Lifecycle {
		case CandidateLifecycleDraining:
			updated, err := tx.ExecContext(ctx, `
				UPDATE candidates
				SET lifecycle='retired', retired_at=?, updated_at=?
				WHERE id=? AND lifecycle='draining' AND drain_after<=?
			`, now.Unix(), now.Unix(), candidate.ID, now.Unix())
			if err != nil {
				return CandidateRetirementBatchResult{}, err
			}
			if err := requireAffected(updated, "draining candidate"); err != nil {
				return CandidateRetirementBatchResult{}, err
			}
		case CandidateLifecycleRetired:
			if err := deleteCandidateRetirementStateTx(
				ctx, tx, candidate,
			); err != nil {
				return CandidateRetirementBatchResult{}, err
			}
		default:
			return CandidateRetirementBatchResult{}, tx.Commit()
		}
	}
	if err := incrementInventoryEpochTx(ctx, tx); err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateRetirementBatchResult{}, err
	}
	return CandidateRetirementBatchResult{Changed: len(current)}, nil
}

func candidateRetirementIdentityMatches(expected, current Candidate) bool {
	return expected.ID != "" &&
		expected.ID == current.ID &&
		expected.SourceID == current.SourceID &&
		expected.Fingerprint == current.Fingerprint &&
		expected.Lifecycle == current.Lifecycle
}

func candidateRetirementDue(
	candidate Candidate,
	now time.Time,
	retiredRetention time.Duration,
) bool {
	switch candidate.Lifecycle {
	case CandidateLifecycleDraining:
		return candidate.DrainAfter != nil &&
			*candidate.DrainAfter <= now.Unix()
	case CandidateLifecycleRetired:
		return candidate.RetiredAt != nil &&
			*candidate.RetiredAt <= now.Add(-retiredRetention).Unix()
	default:
		return false
	}
}

func scanCandidateForRetirement(scanner retirementRowScanner) (Candidate, error) {
	var candidate Candidate
	err := scanner.Scan(
		&candidate.ID, &candidate.SourceID, &candidate.Kind, &candidate.Label,
		&candidate.Fingerprint, &candidate.RouteKey, &candidate.FailureDomain,
		&candidate.Enabled, &candidate.SourcePosition, &candidate.Lifecycle,
		&candidate.RetiredAt, &candidate.DrainAfter,
		&candidate.CreatedAt, &candidate.UpdatedAt,
	)
	return candidate, err
}

func loadCandidateRetirementReferencesTx(
	ctx context.Context,
	tx *sql.Tx,
	desiredGeneration int64,
	desiredPlan []byte,
	appliedGeneration int64,
	appliedPlan []byte,
) (map[string]bool, error) {
	references, err := persistedPlanCandidateReferences(
		desiredPlan, desiredGeneration,
	)
	if err != nil {
		return nil, fmt.Errorf("validate persisted desired plan: %w", err)
	}
	appliedReferences, err := persistedPlanCandidateReferences(
		appliedPlan, appliedGeneration,
	)
	if err != nil {
		return nil, fmt.Errorf("validate persisted applied plan: %w", err)
	}
	for candidateID := range appliedReferences {
		references[candidateID] = true
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT tcp_outbound FROM assignments WHERE tcp_outbound<>''
		UNION
		SELECT udp_outbound FROM assignments WHERE udp_outbound<>''
		UNION
		SELECT tcp_primary_candidate_id
		FROM route_reserve_mappings WHERE tcp_primary_candidate_id<>''
		UNION
		SELECT tcp_reserve_candidate_id
		FROM route_reserve_mappings WHERE tcp_reserve_candidate_id<>''
		UNION
		SELECT udp_primary_candidate_id
		FROM route_reserve_mappings WHERE udp_primary_candidate_id<>''
		UNION
		SELECT udp_reserve_candidate_id
		FROM route_reserve_mappings WHERE udp_reserve_candidate_id<>''
		UNION
		SELECT candidate_id
		FROM candidate_probe_state
		WHERE candidate_id<>'' AND (in_working_pool=1 OR draining=1)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var candidateID string
		if err := rows.Scan(&candidateID); err != nil {
			return nil, err
		}
		references[normalizePersistedCandidateID(candidateID)] = true
	}
	return references, rows.Err()
}

func persistedPlanCandidateReferences(
	encoded []byte,
	expectedGeneration int64,
) (map[string]bool, error) {
	references := make(map[string]bool)
	if expectedGeneration == 0 && len(bytes.TrimSpace(encoded)) == 0 {
		return references, nil
	}
	type persistedPlan struct {
		Generation     *int64                   `json:"generation"`
		Outbounds      *[]dataplane.Outbound    `json:"outbounds"`
		Clients        *[]dataplane.ClientRoute `json:"clients"`
		DirectSuffixes *[]string                `json:"direct_suffixes"`
		DirectDomains  *[]string                `json:"direct_domains,omitempty"`
		FailClosed     *bool                    `json:"fail_closed"`
	}
	var persisted persistedPlan
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return nil, errors.New("invalid persisted plan")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, errors.New("invalid persisted plan")
	}
	if persisted.Generation == nil ||
		persisted.Outbounds == nil ||
		persisted.Clients == nil ||
		persisted.DirectSuffixes == nil ||
		persisted.FailClosed == nil {
		return nil, errors.New("incomplete persisted plan")
	}
	plan := dataplane.DesiredPlan{
		Generation:     *persisted.Generation,
		Outbounds:      *persisted.Outbounds,
		Clients:        *persisted.Clients,
		DirectSuffixes: *persisted.DirectSuffixes,
		FailClosed:     *persisted.FailClosed,
	}
	if persisted.DirectDomains != nil {
		plan.DirectDomains = *persisted.DirectDomains
	}
	if plan.Generation != expectedGeneration {
		return nil, errors.New("persisted plan generation mismatch")
	}
	if err := plan.Validate(); err != nil {
		return nil, errors.New("invalid persisted plan")
	}
	outboundCandidates := make(map[string]string, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		if outbound.Protocol != dataplane.ProtocolVLESS &&
			outbound.Protocol != dataplane.ProtocolTor {
			continue
		}
		candidateID := normalizePersistedCandidateID(outbound.ID)
		if candidateID == "" {
			continue
		}
		outboundCandidates[outbound.ID] = candidateID
		references[candidateID] = true
	}
	for _, client := range plan.Clients {
		for _, outboundID := range []string{
			client.TCPOutbound,
			client.UDPOutbound,
			client.TCPReserveOutbound,
			client.UDPReserveOutbound,
		} {
			if candidateID := outboundCandidates[outboundID]; candidateID != "" {
				references[candidateID] = true
			}
		}
	}
	return references, nil
}

func canonicalizeLegacyPlanStateTx(
	ctx context.Context,
	tx *sql.Tx,
) error {
	var (
		desiredGeneration int64
		appliedGeneration int64
		desiredPlan       []byte
		appliedPlan       []byte
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredGeneration,
		&appliedGeneration,
		&desiredPlan,
		&appliedPlan,
	); err != nil {
		return err
	}
	canonicalDesired, rewriteDesired := canonicalLegacyPlan(
		desiredPlan, desiredGeneration,
	)
	canonicalApplied, rewriteApplied := canonicalLegacyPlan(
		appliedPlan, appliedGeneration,
	)
	if !rewriteDesired && !rewriteApplied {
		return nil
	}
	if rewriteDesired {
		if _, err := tx.ExecContext(ctx, `
			UPDATE plan_state SET desired_plan=? WHERE singleton=1
		`, canonicalDesired); err != nil {
			return err
		}
	}
	if rewriteApplied {
		if _, err := tx.ExecContext(ctx, `
			UPDATE plan_state SET applied_plan=? WHERE singleton=1
		`, canonicalApplied); err != nil {
			return err
		}
	}
	return nil
}

func canonicalLegacyPlan(
	encoded []byte,
	expectedGeneration int64,
) ([]byte, bool) {
	if expectedGeneration <= 0 || len(bytes.TrimSpace(encoded)) == 0 {
		return nil, false
	}
	type legacyPlan struct {
		Generation     *int64          `json:"generation"`
		Outbounds      json.RawMessage `json:"outbounds"`
		Clients        json.RawMessage `json:"clients"`
		DirectSuffixes *[]string       `json:"direct_suffixes"`
		DirectDomains  *[]string       `json:"direct_domains,omitempty"`
		FailClosed     *bool           `json:"fail_closed"`
	}
	var persisted legacyPlan
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil ||
		ensureJSONEOF(decoder) != nil ||
		persisted.Generation == nil ||
		len(persisted.Outbounds) == 0 ||
		len(persisted.Clients) == 0 ||
		persisted.DirectSuffixes == nil ||
		persisted.FailClosed == nil ||
		*persisted.Generation != expectedGeneration {
		return nil, false
	}
	outboundsNull := bytes.Equal(
		bytes.TrimSpace(persisted.Outbounds), []byte("null"),
	)
	clientsNull := bytes.Equal(
		bytes.TrimSpace(persisted.Clients), []byte("null"),
	)
	if !outboundsNull && !clientsNull {
		return nil, false
	}
	outbounds := make([]dataplane.Outbound, 0)
	if !outboundsNull {
		if !decodeStrictJSON(persisted.Outbounds, &outbounds) ||
			outbounds == nil {
			return nil, false
		}
	}
	clients := make([]dataplane.ClientRoute, 0)
	if !clientsNull {
		if !decodeStrictJSON(persisted.Clients, &clients) ||
			clients == nil {
			return nil, false
		}
	}
	plan := dataplane.DesiredPlan{
		Generation:     *persisted.Generation,
		Outbounds:      outbounds,
		Clients:        clients,
		DirectSuffixes: *persisted.DirectSuffixes,
		FailClosed:     *persisted.FailClosed,
	}
	if persisted.DirectDomains != nil {
		plan.DirectDomains = *persisted.DirectDomains
	}
	if err := plan.Validate(); err != nil {
		return nil, false
	}
	canonical, err := json.Marshal(plan)
	if err != nil {
		return nil, false
	}
	return canonical, true
}

func decodeStrictJSON(encoded []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && ensureJSONEOF(decoder) == nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("trailing persisted plan data")
}

func normalizePersistedCandidateID(outboundID string) string {
	if marker := strings.Index(outboundID, "-profile-"); marker > 0 {
		return outboundID[:marker]
	}
	return outboundID
}

func deleteCandidateRetirementStateTx(
	ctx context.Context,
	tx *sql.Tx,
	candidate Candidate,
) error {
	for _, deletion := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM candidate_health WHERE candidate_id=?`, []any{candidate.ID}},
		{`DELETE FROM probe_samples WHERE candidate_id=?`, []any{candidate.ID}},
		{`DELETE FROM exclusions WHERE candidate_id=?`, []any{candidate.ID}},
		{`DELETE FROM failure_domain_evidence WHERE candidate_id=?`, []any{candidate.ID}},
		{`DELETE FROM candidate_probe_state WHERE candidate_id=?`, []any{candidate.ID}},
		{
			`UPDATE failure_domain_state
			 SET canary_candidate='', updated_at=unixepoch()
			 WHERE canary_candidate=?`,
			[]any{candidate.ID},
		},
	} {
		if _, err := tx.ExecContext(ctx, deletion.query, deletion.args...); err != nil {
			return err
		}
	}
	deleted, err := tx.ExecContext(ctx, `
		DELETE FROM candidates WHERE id=? AND lifecycle='retired'
	`, candidate.ID)
	if err != nil {
		return err
	}
	if err := requireAffected(deleted, "retired candidate"); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		DELETE FROM sources
		WHERE id=? AND pending_delete=1
		  AND NOT EXISTS (
		    SELECT 1 FROM candidates WHERE source_id=?
		  )
	`, candidate.SourceID, candidate.SourceID)
	return err
}
