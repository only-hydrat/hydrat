package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

type CandidateStatus string

const (
	CandidateUnknown   CandidateStatus = "unknown"
	CandidatePreflight CandidateStatus = "preflight"
	CandidateProbing   CandidateStatus = "probing"
	CandidateQualified CandidateStatus = "qualified"
	CandidateBanned    CandidateStatus = "banned"
	CandidateDraining  CandidateStatus = "draining"
)

const defaultCandidateResetWindow = 5 * time.Hour

// ErrCandidateNoLongerCurrent marks probe work whose candidate identity was
// removed or disabled before the result could be recorded.
var ErrCandidateNoLongerCurrent = errors.New("candidate is no longer current")

type CandidateProbeState struct {
	Fingerprint       string          `json:"fingerprint"`
	CandidateID       string          `json:"candidate_id"`
	SourceID          string          `json:"source_id"`
	Status            CandidateStatus `json:"status"`
	FailureStreak     int             `json:"failure_streak"`
	FullSuccessStreak int             `json:"full_success_streak"`
	WindowStartedAt   time.Time       `json:"window_started_at,omitempty"`
	BannedUntil       time.Time       `json:"banned_until,omitempty"`
	LastFastProbeAt   time.Time       `json:"last_fast_probe_at,omitempty"`
	LastFullProbeAt   time.Time       `json:"last_full_probe_at,omitempty"`
	LastSuccessAt     time.Time       `json:"last_success_at,omitempty"`
	LastFailureAt     time.Time       `json:"last_failure_at,omitempty"`
	LastErrorCode     string          `json:"last_error_code,omitempty"`
	LastErrorMessage  string          `json:"last_error_message,omitempty"`
	LastScore         float64         `json:"last_score"`
	ConservativeScore float64         `json:"conservative_score"`
	InWorkingPool     bool            `json:"in_working_pool"`
	Draining          bool            `json:"draining"`
	Stale             bool            `json:"stale"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type ProbeTransition struct {
	Fingerprint           string
	CandidateID           string
	SourceID              string
	Full                  bool
	Success               bool
	InfrastructureFailure bool
	ErrorCode             string
	SafeErrorMessage      string
	Score                 float64
	At                    time.Time
	ResetWindow           time.Duration
}

type WorkingPoolMembership struct {
	Active   []Candidate
	Draining []Candidate
}

func (store *Store) CandidateProbeState(ctx context.Context, fingerprint string) (CandidateProbeState, error) {
	if fingerprint == "" {
		return CandidateProbeState{}, errors.New("candidate fingerprint is required")
	}
	state, err := scanCandidateProbeState(store.db.QueryRowContext(ctx, candidateStateSelect+` WHERE fingerprint = ?`, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return CandidateProbeState{}, fmt.Errorf("candidate probe state not found: %s", fingerprint)
	}
	return state, err
}

func (store *Store) ListCandidateProbeStates(ctx context.Context) ([]CandidateProbeState, error) {
	rows, err := store.db.QueryContext(ctx, candidateStateSelect+`
		WHERE candidate_probe_state.observation_placeholder = 0
		ORDER BY candidate_probe_state.fingerprint
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make([]CandidateProbeState, 0)
	for rows.Next() {
		state, err := scanCandidateProbeState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (store *Store) RecordCandidateProbe(ctx context.Context, transition ProbeTransition) (CandidateProbeState, error) {
	return store.recordCandidateProbe(ctx, transition, nil, nil)
}

func (store *Store) RecordCandidateProbeResult(
	ctx context.Context,
	transition ProbeTransition,
	health *CandidateHealth,
	sample *ProbeSample,
) (CandidateProbeState, error) {
	return store.recordCandidateProbe(ctx, transition, health, sample)
}

// RecordCandidateHealthResult persists health and an optional sample only while
// the exact candidate/source/fingerprint identity is still enabled. It does
// not mutate probe state.
func (store *Store) RecordCandidateHealthResult(
	ctx context.Context,
	candidate Candidate,
	health *CandidateHealth,
	sample *ProbeSample,
) error {
	if health == nil && sample == nil {
		return errors.New("candidate health result is empty")
	}
	if candidate.ID == "" || candidate.SourceID == "" || candidate.Fingerprint == "" {
		return errors.New("candidate identity is incomplete")
	}
	if health != nil && health.CandidateID != candidate.ID {
		return errors.New("candidate health identity does not match candidate")
	}
	if sample != nil && sample.CandidateID != candidate.ID {
		return errors.New("probe sample identity does not match candidate")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := candidateCurrentTx(ctx, tx, candidate)
	if err != nil {
		return err
	}
	if !current {
		return ErrCandidateNoLongerCurrent
	}
	if health != nil {
		if err := saveCandidateHealthTx(ctx, tx, *health); err != nil {
			return err
		}
	}
	if sample != nil {
		if err := appendProbeSampleTx(ctx, tx, *sample); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) recordCandidateProbe(
	ctx context.Context,
	transition ProbeTransition,
	health *CandidateHealth,
	sample *ProbeSample,
) (CandidateProbeState, error) {
	if err := normalizeProbeTransition(&transition); err != nil {
		return CandidateProbeState{}, err
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateProbeState{}, err
	}
	defer func() { _ = tx.Rollback() }()
	state, err := recordCandidateProbeTx(
		ctx, tx, transition, health, sample, false,
	)
	if err != nil {
		return CandidateProbeState{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateProbeState{}, err
	}
	return state, nil
}

func normalizeProbeTransition(transition *ProbeTransition) error {
	if transition.Fingerprint == "" {
		return errors.New("candidate fingerprint is required")
	}
	if transition.At.IsZero() {
		transition.At = time.Now()
	}
	if transition.ResetWindow <= 0 {
		transition.ResetWindow = defaultCandidateResetWindow
	}
	transition.ErrorCode = boundedSafeText(transition.ErrorCode, 64)
	transition.SafeErrorMessage = boundedSafeText(transition.SafeErrorMessage, 256)
	return nil
}

func recordCandidateProbeTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	transition ProbeTransition,
	health *CandidateHealth,
	sample *ProbeSample,
	allowDraining bool,
) (CandidateProbeState, error) {
	if transition.CandidateID != "" || transition.SourceID != "" {
		if transition.CandidateID == "" || transition.SourceID == "" {
			return CandidateProbeState{}, errors.New("candidate identity is incomplete")
		}
		candidate := Candidate{
			ID: transition.CandidateID, SourceID: transition.SourceID,
			Fingerprint: transition.Fingerprint,
		}
		current, err := candidateCurrentTx(ctx, tx, candidate)
		if allowDraining {
			current, err = candidateRoutableTx(ctx, tx, candidate)
		}
		if err != nil {
			return CandidateProbeState{}, err
		}
		if !current {
			return CandidateProbeState{}, ErrCandidateNoLongerCurrent
		}
	}
	state, err := scanCandidateProbeState(tx.QueryRowContext(ctx, candidateStateSelect+` WHERE fingerprint = ?`, transition.Fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		state = CandidateProbeState{
			Fingerprint: transition.Fingerprint,
			CandidateID: transition.CandidateID,
			SourceID:    transition.SourceID,
			Status:      CandidateUnknown,
			Stale:       true,
		}
	} else if err != nil {
		return CandidateProbeState{}, err
	}
	if transition.CandidateID != "" {
		state.CandidateID = transition.CandidateID
	}
	if transition.SourceID != "" {
		state.SourceID = transition.SourceID
	}
	resetCandidateWindow(&state, transition.At, transition.ResetWindow)
	if state.WindowStartedAt.IsZero() {
		state.WindowStartedAt = transition.At
	}

	switch {
	case transition.InfrastructureFailure:
		state.LastErrorCode = transition.ErrorCode
		state.LastErrorMessage = transition.SafeErrorMessage
	case !transition.Success:
		if transition.Full {
			state.LastFullProbeAt = transition.At
		} else {
			state.LastFastProbeAt = transition.At
		}
		state.FailureStreak++
		state.FullSuccessStreak = 0
		state.LastFailureAt = transition.At
		state.LastErrorCode = transition.ErrorCode
		state.LastErrorMessage = transition.SafeErrorMessage
		state.Stale = true
		if state.FailureStreak >= 3 {
			state.Status = CandidateBanned
			state.BannedUntil = state.WindowStartedAt.Add(transition.ResetWindow)
		} else {
			state.Status = CandidateUnknown
		}
	case transition.Full:
		previousScore := state.LastScore
		previousSuccesses := state.FullSuccessStreak
		state.FailureStreak = 0
		state.FullSuccessStreak++
		state.LastFullProbeAt = transition.At
		state.LastSuccessAt = transition.At
		state.LastErrorCode = ""
		state.LastErrorMessage = ""
		state.LastScore = transition.Score
		state.Stale = false
		if previousSuccesses > 0 {
			state.ConservativeScore = minFloat(previousScore, transition.Score)
		}
		if state.FullSuccessStreak >= 2 {
			state.Status = CandidateQualified
		} else {
			state.Status = CandidatePreflight
		}
	default:
		state.FailureStreak = 0
		state.LastFastProbeAt = transition.At
		state.LastSuccessAt = transition.At
		state.LastErrorCode = ""
		state.LastErrorMessage = ""
		state.Status = CandidatePreflight
	}
	state.UpdatedAt = transition.At

	if err := upsertCandidateProbeState(ctx, tx, state); err != nil {
		return CandidateProbeState{}, err
	}
	if health != nil {
		if health.CandidateID != transition.CandidateID {
			return CandidateProbeState{}, errors.New("candidate health identity does not match probe transition")
		}
		if err := saveCandidateHealthTx(ctx, tx, *health); err != nil {
			return CandidateProbeState{}, err
		}
	}
	if sample != nil {
		if sample.CandidateID != transition.CandidateID {
			return CandidateProbeState{}, errors.New("probe sample identity does not match probe transition")
		}
		if err := appendProbeSampleTx(ctx, tx, *sample); err != nil {
			return CandidateProbeState{}, err
		}
	}
	return state, nil
}

func (store *Store) ReplaceWorkingPool(ctx context.Context, active, draining []string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
        UPDATE candidate_probe_state
        SET in_working_pool = 0, draining = 0,
            status = CASE WHEN status = 'draining' THEN 'qualified' ELSE status END,
            updated_at = unixepoch()
    `); err != nil {
		return err
	}
	for _, fingerprint := range active {
		if _, err := tx.ExecContext(ctx, `
            UPDATE candidate_probe_state
            SET in_working_pool = 1, draining = 0, updated_at = unixepoch()
            WHERE fingerprint = ?
        `, fingerprint); err != nil {
			return err
		}
	}
	for _, fingerprint := range draining {
		if _, err := tx.ExecContext(ctx, `
            UPDATE candidate_probe_state
            SET in_working_pool = 0, draining = 1, status = 'draining', updated_at = unixepoch()
            WHERE fingerprint = ?
        `, fingerprint); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) ClearWorkingPoolByKind(
	ctx context.Context,
	kind sources.Kind,
) error {
	if kind == "" {
		return errors.New("candidate kind is required")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE candidate_probe_state
		SET in_working_pool=0,
		    draining=0,
		    status=CASE
		      WHEN status='draining' THEN 'qualified'
		      ELSE status
		    END,
		    updated_at=unixepoch()
		WHERE candidate_id IN (
		  SELECT id FROM candidates WHERE kind=?
		)
	`, string(kind)); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceWorkingPoolCurrent replaces membership and returns only requested
// identities that still exactly match an enabled candidate and enabled source
// in the same transaction. Active candidates must also remain qualified at
// the selection time supplied by the caller.
func (store *Store) ReplaceWorkingPoolCurrent(
	ctx context.Context,
	active, draining []Candidate,
	now time.Time,
) (WorkingPoolMembership, error) {
	return store.replaceWorkingPoolCurrent(
		ctx, active, draining, now, nil,
	)
}

func (store *Store) ReplaceWorkingPoolCurrentAtEpoch(
	ctx context.Context,
	active, draining []Candidate,
	now time.Time,
	expectedEpoch int64,
) (WorkingPoolMembership, error) {
	return store.replaceWorkingPoolCurrent(
		ctx, active, draining, now, &expectedEpoch,
	)
}

func (store *Store) replaceWorkingPoolCurrent(
	ctx context.Context,
	active, draining []Candidate,
	now time.Time,
	expectedEpoch *int64,
) (WorkingPoolMembership, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return WorkingPoolMembership{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if expectedEpoch != nil {
		var epoch int64
		if err := tx.QueryRowContext(ctx, `
			SELECT epoch FROM inventory_state WHERE singleton=1
		`).Scan(&epoch); err != nil {
			return WorkingPoolMembership{}, err
		}
		if epoch != *expectedEpoch {
			return WorkingPoolMembership{}, ErrCandidateInventoryChanged
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE candidate_probe_state
		SET in_working_pool = 0, draining = 0,
		    status = CASE WHEN status = 'draining' THEN 'qualified' ELSE status END,
		    updated_at = unixepoch()
	`); err != nil {
		return WorkingPoolMembership{}, err
	}
	applied := WorkingPoolMembership{
		Active:   make([]Candidate, 0, len(active)),
		Draining: make([]Candidate, 0, len(draining)),
	}
	for _, candidate := range active {
		current, err := candidateCurrentTx(ctx, tx, candidate)
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		if !current {
			continue
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE candidate_probe_state
			SET in_working_pool = 1, draining = 0, updated_at = unixepoch()
			WHERE fingerprint = ? AND candidate_id = ? AND source_id = ?
			  AND status = 'qualified'
			  AND full_success_streak >= 2
			  AND (banned_until IS NULL OR banned_until <= ?)
		`, candidate.Fingerprint, candidate.ID, candidate.SourceID, now.Unix())
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		if affected == 1 {
			applied.Active = append(applied.Active, candidate)
		}
	}
	for _, candidate := range draining {
		current, err := candidateCurrentTx(ctx, tx, candidate)
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		if !current {
			continue
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE candidate_probe_state
			SET in_working_pool = 0, draining = 1, status = 'draining',
			    updated_at = unixepoch()
			WHERE fingerprint = ? AND candidate_id = ? AND source_id = ?
		`, candidate.Fingerprint, candidate.ID, candidate.SourceID)
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return WorkingPoolMembership{}, err
		}
		if affected == 1 {
			applied.Draining = append(applied.Draining, candidate)
		}
	}
	if err := tx.Commit(); err != nil {
		return WorkingPoolMembership{}, err
	}
	return applied, nil
}

func candidateCurrentTx(ctx context.Context, tx sqlQueryExecutor, candidate Candidate) (bool, error) {
	return candidateIdentityCurrentTx(
		ctx, tx, candidate, CandidateLifecycleActive,
	)
}

func candidateRoutableTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
) (bool, error) {
	return candidateIdentityCurrentTx(
		ctx,
		tx,
		candidate,
		CandidateLifecycleActive,
		CandidateLifecycleDraining,
	)
}

func candidateReferencedRoutableTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
) (bool, error) {
	if candidate.ID == "" ||
		candidate.SourceID == "" ||
		candidate.Fingerprint == "" {
		return false, errors.New("candidate identity is incomplete")
	}
	var current int
	err := tx.QueryRowContext(ctx, `
		SELECT 1
		FROM candidates c
		JOIN sources s ON s.id=c.source_id
		WHERE c.id=? AND c.source_id=? AND c.fingerprint=?
		  AND c.enabled=1 AND s.enabled=1
		  AND (
		    c.lifecycle='active'
		    OR (
		      c.lifecycle='draining'
		      AND EXISTS (
		        SELECT 1 FROM assignments a
		        WHERE a.tcp_outbound=c.id OR a.udp_outbound=c.id
		      )
		    )
		  )
	`, candidate.ID, candidate.SourceID, candidate.Fingerprint).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func candidateIdentityCurrentTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
	lifecycles ...string,
) (bool, error) {
	if candidate.ID == "" || candidate.SourceID == "" || candidate.Fingerprint == "" {
		return false, errors.New("candidate identity is incomplete")
	}
	if len(lifecycles) == 0 {
		return false, errors.New("candidate lifecycle is required")
	}
	arguments := []any{candidate.ID, candidate.SourceID, candidate.Fingerprint}
	for _, lifecycle := range lifecycles {
		arguments = append(arguments, lifecycle)
	}
	placeholders := strings.TrimSuffix(
		strings.Repeat("?,", len(lifecycles)),
		",",
	)
	var current int
	err := tx.QueryRowContext(ctx, `
		SELECT 1
		FROM candidates c
		JOIN sources s ON s.id = c.source_id
		WHERE c.id = ? AND c.source_id = ? AND c.fingerprint = ?
		  AND c.enabled = 1 AND s.enabled = 1
		  AND c.lifecycle IN (`+placeholders+`)
	`, arguments...).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

const candidateStateSelect = `
    SELECT candidate_probe_state.fingerprint, candidate_probe_state.candidate_id,
           candidate_probe_state.source_id, candidate_probe_state.status,
           candidate_probe_state.failure_streak,
           candidate_probe_state.full_success_streak,
           candidate_probe_state.window_started_at,
           candidate_probe_state.banned_until,
           candidate_probe_state.last_fast_probe_at,
           candidate_probe_state.last_full_probe_at,
           candidate_probe_state.last_success_at,
           candidate_probe_state.last_failure_at,
           candidate_probe_state.last_error_code,
           candidate_probe_state.last_error_message,
           candidate_probe_state.last_score,
           candidate_probe_state.conservative_score,
           candidate_probe_state.in_working_pool,
           candidate_probe_state.draining, candidate_probe_state.stale,
           candidate_probe_state.updated_at
    FROM candidate_probe_state`

type rowScanner interface {
	Scan(...any) error
}

func scanCandidateProbeState(row rowScanner) (CandidateProbeState, error) {
	var state CandidateProbeState
	var window, banned, fast, full, success, failure sql.NullInt64
	var updated int64
	err := row.Scan(
		&state.Fingerprint, &state.CandidateID, &state.SourceID, &state.Status,
		&state.FailureStreak, &state.FullSuccessStreak, &window, &banned, &fast,
		&full, &success, &failure, &state.LastErrorCode,
		&state.LastErrorMessage, &state.LastScore, &state.ConservativeScore,
		&state.InWorkingPool, &state.Draining, &state.Stale, &updated,
	)
	if err != nil {
		return CandidateProbeState{}, err
	}
	state.WindowStartedAt = nullableTime(window)
	state.BannedUntil = nullableTime(banned)
	state.LastFastProbeAt = nullableTime(fast)
	state.LastFullProbeAt = nullableTime(full)
	state.LastSuccessAt = nullableTime(success)
	state.LastFailureAt = nullableTime(failure)
	state.UpdatedAt = time.Unix(updated, 0)
	return state, nil
}

func upsertCandidateProbeState(ctx context.Context, tx sqlExecutor, state CandidateProbeState) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO candidate_probe_state(
          fingerprint, candidate_id, source_id, status, failure_streak,
          full_success_streak, window_started_at, banned_until,
          last_fast_probe_at, last_full_probe_at, last_success_at,
          last_failure_at, last_error_code, last_error_message, last_score,
          conservative_score, in_working_pool, draining, stale, updated_at,
          observation_placeholder
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(fingerprint) DO UPDATE SET
          candidate_id=excluded.candidate_id, source_id=excluded.source_id,
          status=excluded.status, failure_streak=excluded.failure_streak,
          full_success_streak=excluded.full_success_streak,
          window_started_at=excluded.window_started_at,
          banned_until=excluded.banned_until,
          last_fast_probe_at=excluded.last_fast_probe_at,
          last_full_probe_at=excluded.last_full_probe_at,
          last_success_at=excluded.last_success_at,
          last_failure_at=excluded.last_failure_at,
          last_error_code=excluded.last_error_code,
          last_error_message=excluded.last_error_message,
          last_score=excluded.last_score,
          conservative_score=excluded.conservative_score,
          in_working_pool=excluded.in_working_pool, draining=excluded.draining,
          stale=excluded.stale, updated_at=excluded.updated_at,
          observation_placeholder=0
    `, state.Fingerprint, state.CandidateID, state.SourceID, state.Status,
		state.FailureStreak, state.FullSuccessStreak, unixOrNil(state.WindowStartedAt),
		unixOrNil(state.BannedUntil), unixOrNil(state.LastFastProbeAt),
		unixOrNil(state.LastFullProbeAt), unixOrNil(state.LastSuccessAt),
		unixOrNil(state.LastFailureAt), state.LastErrorCode,
		state.LastErrorMessage, state.LastScore, state.ConservativeScore,
		state.InWorkingPool, state.Draining, state.Stale, state.UpdatedAt.Unix())
	return err
}

func resetCandidateWindow(state *CandidateProbeState, now time.Time, window time.Duration) {
	if state.WindowStartedAt.IsZero() || now.Before(state.WindowStartedAt.Add(window)) {
		return
	}
	state.FailureStreak = 0
	state.FullSuccessStreak = 0
	state.BannedUntil = time.Time{}
	state.Status = CandidateUnknown
	state.Stale = true
	state.WindowStartedAt = now
}

func nullableTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0)
}

func unixOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.Unix()
}

func boundedSafeText(value string, limit int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value))
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func minFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
