package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

const (
	failureDomainWindow       = 5 * time.Minute
	failureDomainOpenDuration = 10 * time.Minute
)

var errFailureDomainIdentifierRequired = errors.New("failure domain identifiers are required")

var ErrFailureDomainNotOpen = errors.New("failure domain circuit is not open")

type FailureDomainState struct {
	Domain          string
	FailureCount    int
	WindowStartedAt time.Time
	OpenUntil       time.Time
	CanaryCandidate string
	UpdatedAt       time.Time
}

// RecordActiveVLESSHardFailure atomically fences the exact current candidate,
// records correlated-domain evidence, and marks its probe and health state
// unavailable. No mutation is committed when the candidate is stale or any
// later write fails.
func (store *Store) RecordActiveVLESSHardFailure(
	ctx context.Context,
	candidate Candidate,
	health CandidateHealth,
	now time.Time,
) (FailureDomainState, error) {
	if health.CandidateID != candidate.ID {
		return FailureDomainState{}, errors.New(
			"candidate health identity does not match candidate",
		)
	}
	reservation, err := store.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		return FailureDomainState{}, err
	}
	state, _, err := store.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, reservation, now,
	)
	return state, err
}

// CommitActiveVLESSHardFailureObservation atomically rejects an older active
// result before mutating health, probe state, or correlated-domain evidence.
func (store *Store) CommitActiveVLESSHardFailureObservation(
	ctx context.Context,
	candidate Candidate,
	reservation ObservationReservation,
	now time.Time,
) (FailureDomainState, ObservationCommitResult, error) {
	if candidate.Kind != sources.KindVLESS || candidate.FailureDomain == "" {
		return FailureDomainState{}, ObservationCommitResult{}, errors.New(
			"active VLESS failure requires a failure domain",
		)
	}
	if err := validateObservationReservation(candidate, reservation); err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if reservation.Stage != ObservationActive {
		return FailureDomainState{}, ObservationCommitResult{}, errors.New(
			"active VLESS failure requires active observation reservation",
		)
	}
	if now.IsZero() {
		return FailureDomainState{}, ObservationCommitResult{}, errors.New(
			"active VLESS failure observation time is required",
		)
	}
	eventAt := failureDomainEventTime(now)
	transition := ProbeTransition{
		Fingerprint:      candidate.Fingerprint,
		CandidateID:      candidate.ID,
		SourceID:         candidate.SourceID,
		Success:          false,
		ErrorCode:        "active_hard_failure",
		SafeErrorMessage: "primary and confirmation liveness checks failed",
		At:               eventAt,
	}
	if err := normalizeProbeTransition(&transition); err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}

	tx, err := store.beginFailureDomainTx(ctx)
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, fmt.Errorf(
			"begin atomic active VLESS failure: %w", err,
		)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := candidateReferencedRoutableTx(ctx, tx, candidate)
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if !current {
		return FailureDomainState{}, ObservationCommitResult{},
			ErrCandidateNoLongerCurrent
	}
	accepted, err := observationReservationCurrentTx(
		ctx, tx, candidate, reservation,
	)
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if !accepted {
		return FailureDomainState{}, ObservationCommitResult{Accepted: false}, nil
	}
	domainState, accepted, err := recordFailureDomainFailureTx(
		ctx, tx, candidate.FailureDomain, candidate.ID, eventAt,
	)
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if !accepted {
		return domainState, ObservationCommitResult{Accepted: false}, nil
	}
	if _, err := recordCandidateProbeTx(
		ctx, tx, transition, nil, nil, true,
	); err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE candidate_health
		SET available=0, updated_at=?, active_observed_at=?, active_success=0,
		    active_hard_failure=1,
		    failure_generation=failure_generation+1,
		    active_failure_generation=failure_generation+1,
		    observation_placeholder=0
		WHERE candidate_id=? AND active_result_seq>=?
		  AND active_applied_seq<?
	`, eventAt.Unix(), eventAt.UnixMilli(), candidate.ID, reservation.Sequence,
		reservation.Sequence)
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if affected != 1 {
		return FailureDomainState{}, ObservationCommitResult{},
			errors.New("active observation health row is missing")
	}
	if err := applyObservationReservationTx(
		ctx, tx, candidate, reservation,
	); err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return FailureDomainState{}, ObservationCommitResult{}, fmt.Errorf(
			"commit atomic active VLESS failure: %w", err,
		)
	}
	return domainState, ObservationCommitResult{Accepted: true}, nil
}

func (store *Store) RecordFailureDomainFailure(
	ctx context.Context,
	domain string,
	candidateID string,
	now time.Time,
) (FailureDomainState, error) {
	if domain == "" || candidateID == "" {
		return FailureDomainState{}, errFailureDomainIdentifierRequired
	}
	tx, err := store.beginFailureDomainTx(ctx)
	if err != nil {
		return FailureDomainState{}, fmt.Errorf("begin failure domain update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	state, _, err := recordFailureDomainFailureTx(
		ctx, tx, domain, candidateID, now,
	)
	if err != nil {
		return FailureDomainState{}, err
	}
	if err := tx.Commit(); err != nil {
		return FailureDomainState{}, fmt.Errorf("commit failure domain update: %w", err)
	}
	return state, nil
}

func recordFailureDomainFailureTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	domain string,
	candidateID string,
	now time.Time,
) (FailureDomainState, bool, error) {
	state, exists, err := loadFailureDomainState(ctx, tx, domain)
	if err != nil {
		return FailureDomainState{}, false, err
	}
	eventAt := failureDomainEventTime(now)
	if exists && eventAt.Before(state.UpdatedAt) {
		return state, false, nil
	}
	if exists && state.OpenUntil.After(eventAt) {
		if candidateID != state.CanaryCandidate {
			return state, true, nil
		}
		state.OpenUntil = eventAt.Add(failureDomainOpenDuration)
		state.UpdatedAt = eventAt
		if _, err := tx.ExecContext(ctx, `
			UPDATE failure_domain_state
			SET open_until=?, updated_at=?
			WHERE domain=?
		`, state.OpenUntil.Unix(), state.UpdatedAt.Unix(), domain); err != nil {
			return FailureDomainState{}, false, fmt.Errorf("extend failure domain circuit: %w", err)
		}
		return state, true, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO failure_domain_state(
		  domain, failure_count, window_started_at, open_until,
		  canary_candidate, updated_at
		)
		VALUES (?, 0, 0, 0, '', ?)
		ON CONFLICT(domain) DO NOTHING
	`, domain, eventAt.Unix()); err != nil {
		return FailureDomainState{}, false, fmt.Errorf("initialize failure domain state: %w", err)
	}
	if exists && !state.OpenUntil.IsZero() {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM failure_domain_evidence WHERE domain=?`,
			domain,
		); err != nil {
			return FailureDomainState{}, false, fmt.Errorf("reset expired failure domain evidence: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM failure_domain_evidence
		WHERE domain=? AND last_failed_at < ?
	`, domain, eventAt.Add(-failureDomainWindow).Unix()); err != nil {
		return FailureDomainState{}, false, fmt.Errorf("prune failure domain evidence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO failure_domain_evidence(domain, candidate_id, last_failed_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain, candidate_id) DO UPDATE SET
		  last_failed_at=MAX(last_failed_at, excluded.last_failed_at)
	`, domain, candidateID, eventAt.Unix()); err != nil {
		return FailureDomainState{}, false, fmt.Errorf("record failure domain evidence: %w", err)
	}

	var (
		failureCount int
		windowStart  int64
		canary       string
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*), min(last_failed_at), min(candidate_id)
		FROM failure_domain_evidence
		WHERE domain=?
	`, domain).Scan(&failureCount, &windowStart, &canary); err != nil {
		return FailureDomainState{}, false, fmt.Errorf("summarize failure domain evidence: %w", err)
	}
	state = FailureDomainState{
		Domain:          domain,
		FailureCount:    failureCount,
		WindowStartedAt: failureDomainTime(windowStart),
		UpdatedAt:       eventAt,
	}
	if failureCount >= 3 {
		state.OpenUntil = eventAt.Add(failureDomainOpenDuration)
		state.CanaryCandidate = canary
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE failure_domain_state
		SET failure_count=?, window_started_at=?, open_until=?,
		    canary_candidate=?, updated_at=?
		WHERE domain=?
	`, state.FailureCount, unixSeconds(state.WindowStartedAt),
		unixSeconds(state.OpenUntil), state.CanaryCandidate,
		state.UpdatedAt.Unix(), domain,
	); err != nil {
		return FailureDomainState{}, false, fmt.Errorf("persist failure domain state: %w", err)
	}
	return state, true, nil
}

func (store *Store) RecordFailureDomainSuccess(
	ctx context.Context,
	domain string,
	now time.Time,
) error {
	_, err := store.ResetFailureDomainOnSuccess(ctx, domain, now)
	return err
}

// ResetFailureDomainOnSuccess clears older failure evidence and reports
// whether the success changed an open or accumulating circuit state. It still
// advances the persisted event time for an already-clear state so delayed
// failures cannot overwrite a newer success.
func (store *Store) ResetFailureDomainOnSuccess(
	ctx context.Context,
	domain string,
	now time.Time,
) (bool, error) {
	if domain == "" {
		return false, errFailureDomainIdentifierRequired
	}
	tx, err := store.beginFailureDomainTx(ctx)
	if err != nil {
		return false, fmt.Errorf("begin failure domain reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	state, exists, err := loadFailureDomainState(ctx, tx, domain)
	if err != nil {
		return false, err
	}
	if !exists {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit absent failure domain reset: %w", err)
		}
		return false, nil
	}
	eventAt := failureDomainEventTime(now)
	// Failures win timestamp ties. A success only closes evidence strictly
	// older than its persisted-second observation time.
	if !eventAt.After(state.UpdatedAt) {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit stale failure domain reset: %w", err)
		}
		return false, nil
	}
	changed := state.FailureCount != 0 || !state.WindowStartedAt.IsZero() ||
		!state.OpenUntil.IsZero() || state.CanaryCandidate != ""
	if _, err := tx.ExecContext(ctx, `
		UPDATE failure_domain_state
		SET failure_count=0, window_started_at=0, open_until=0,
		    canary_candidate='', updated_at=?
		WHERE domain=?
	`, eventAt.Unix(), domain); err != nil {
		return false, fmt.Errorf("reset failure domain state: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM failure_domain_evidence WHERE domain=?`,
		domain,
	); err != nil {
		return false, fmt.Errorf("clear failure domain evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit failure domain reset: %w", err)
	}
	return changed, nil
}

func (store *Store) ElectFailureDomainCanary(
	ctx context.Context,
	domain string,
	candidateIDs []string,
	now time.Time,
) (FailureDomainState, error) {
	if domain == "" || len(candidateIDs) == 0 {
		return FailureDomainState{}, errFailureDomainIdentifierRequired
	}
	selected := candidateIDs[0]
	for _, candidateID := range candidateIDs {
		if candidateID == "" {
			return FailureDomainState{}, errFailureDomainIdentifierRequired
		}
		if candidateID < selected {
			selected = candidateID
		}
	}

	tx, err := store.beginFailureDomainTx(ctx)
	if err != nil {
		return FailureDomainState{}, fmt.Errorf("begin failure domain canary election: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	state, exists, err := loadFailureDomainState(ctx, tx, domain)
	if err != nil {
		return FailureDomainState{}, err
	}
	eventAt := failureDomainEventTime(now)
	if !exists || !state.OpenUntil.After(eventAt) {
		return FailureDomainState{}, ErrFailureDomainNotOpen
	}
	state.CanaryCandidate = selected
	if _, err := tx.ExecContext(ctx, `
		UPDATE failure_domain_state
		SET canary_candidate=?
		WHERE domain=?
	`, state.CanaryCandidate, domain); err != nil {
		return FailureDomainState{}, fmt.Errorf("persist failure domain canary: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return FailureDomainState{}, fmt.Errorf("commit failure domain canary election: %w", err)
	}
	return state, nil
}

func (store *Store) ListFailureDomainStates(ctx context.Context) ([]FailureDomainState, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT domain, failure_count, window_started_at, open_until,
		       canary_candidate, updated_at
		FROM failure_domain_state
		ORDER BY domain
	`)
	if err != nil {
		return nil, fmt.Errorf("list failure domain states: %w", err)
	}
	defer rows.Close()
	states := make([]FailureDomainState, 0)
	for rows.Next() {
		state, err := scanFailureDomainState(rows)
		if err != nil {
			return nil, fmt.Errorf("scan failure domain state: %w", err)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list failure domain states: %w", err)
	}
	return states, nil
}

type failureDomainScanner interface {
	Scan(...any) error
}

func loadFailureDomainState(
	ctx context.Context,
	tx sqlQueryExecutor,
	domain string,
) (FailureDomainState, bool, error) {
	state, err := scanFailureDomainState(tx.QueryRowContext(ctx, `
		SELECT domain, failure_count, window_started_at, open_until,
		       canary_candidate, updated_at
		FROM failure_domain_state
		WHERE domain=?
	`, domain))
	if errors.Is(err, sql.ErrNoRows) {
		return FailureDomainState{}, false, nil
	}
	if err != nil {
		return FailureDomainState{}, false, fmt.Errorf("load failure domain state: %w", err)
	}
	return state, true, nil
}

type failureDomainTx struct {
	ctx  context.Context
	conn *sql.Conn
	done bool
}

func (store *Store) beginFailureDomainTx(ctx context.Context) (*failureDomainTx, error) {
	conn, err := store.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &failureDomainTx{ctx: ctx, conn: conn}, nil
}

func (tx *failureDomainTx) ExecContext(
	ctx context.Context,
	query string,
	args ...any,
) (sql.Result, error) {
	return tx.conn.ExecContext(ctx, query, args...)
}

func (tx *failureDomainTx) QueryRowContext(
	ctx context.Context,
	query string,
	args ...any,
) *sql.Row {
	return tx.conn.QueryRowContext(ctx, query, args...)
}

func (tx *failureDomainTx) Commit() error {
	if tx.done {
		return sql.ErrTxDone
	}
	if _, err := tx.conn.ExecContext(tx.ctx, `COMMIT`); err != nil {
		return err
	}
	tx.done = true
	return tx.conn.Close()
}

func (tx *failureDomainTx) Rollback() error {
	if tx.done {
		return sql.ErrTxDone
	}
	tx.done = true
	_, err := tx.conn.ExecContext(context.Background(), `ROLLBACK`)
	closeErr := tx.conn.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func scanFailureDomainState(row failureDomainScanner) (FailureDomainState, error) {
	var (
		state       FailureDomainState
		windowStart int64
		openUntil   int64
		updatedAt   int64
	)
	if err := row.Scan(
		&state.Domain,
		&state.FailureCount,
		&windowStart,
		&openUntil,
		&state.CanaryCandidate,
		&updatedAt,
	); err != nil {
		return FailureDomainState{}, err
	}
	state.WindowStartedAt = failureDomainTime(windowStart)
	state.OpenUntil = failureDomainTime(openUntil)
	state.UpdatedAt = failureDomainTime(updatedAt)
	return state, nil
}

func failureDomainTime(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

func failureDomainEventTime(value time.Time) time.Time {
	return time.Unix(value.Unix(), 0)
}

func unixSeconds(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}
