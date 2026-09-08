package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

const candidateQoEStateSelect = `
    SELECT candidate_id, status, baseline_ttfb_ms,
           baseline_throughput_mbps, baseline_samples, current_ttfb_ms,
	       current_throughput_mbps, window_valid, window_bad,
	       window_started_at, window_max_gap_ms, median_effective_ms, last_valid_at, last_reason, degraded_at,
           recovered_at, updated_at
    FROM candidate_qoe_state`

const candidateQoESampleSelect = `
    SELECT success, bad, reason, ttfb_ms, transfer_ms, bytes,
           throughput_mbps, effective_ms, created_at
    FROM candidate_qoe_samples`

func (store *Store) RecordCandidateQoE(
	ctx context.Context,
	candidate Candidate,
	observation qoe.Observation,
	policy qoe.Policy,
) (qoe.State, qoe.Transition, error) {
	if policy.WindowSize < 1 || policy.WindowSize > qoe.MaxWindowSize {
		return qoe.State{}, qoe.Transition{}, fmt.Errorf(
			"qoe.window_size must be between 1 and %d", qoe.MaxWindowSize,
		)
	}
	if policy.AvailabilityWindow < 1 || policy.AvailabilityWindow > qoe.MaxWindowSize {
		return qoe.State{}, qoe.Transition{}, fmt.Errorf(
			"qoe.availability_window must be between 1 and %d", qoe.MaxWindowSize,
		)
	}
	if policy.AvailabilityFailures < 1 ||
		policy.AvailabilityFailures > policy.AvailabilityWindow {
		return qoe.State{}, qoe.Transition{}, errors.New(
			"qoe.availability_failures must be positive and not exceed qoe.availability_window",
		)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	defer func() { _ = tx.Rollback() }()

	currentCandidate, err := candidateReferencedRoutableTx(ctx, tx, candidate)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if !currentCandidate {
		return qoe.State{}, qoe.Transition{}, ErrCandidateNoLongerCurrent
	}

	state, err := loadCandidateQoEStateTx(ctx, tx, candidate.ID)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	historyWindow := max(policy.WindowSize, policy.AvailabilityWindow)
	recent, err := loadCandidateQoESamplesTx(
		ctx, tx, candidate.ID, false, historyWindow,
	)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	learningSuccesses, err := loadCandidateQoESamplesTx(
		ctx, tx, candidate.ID, true, policy.WindowSize,
	)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}

	decision := qoe.Apply(policy, state, recent, learningSuccesses, observation)
	decision.State.CandidateID = candidate.ID
	decision.State.LastReason = boundedSafeText(decision.State.LastReason, 64)
	if decision.Sample != nil {
		decision.Sample.Reason = boundedSafeText(decision.Sample.Reason, 64)
		if err := appendCandidateQoESampleTx(ctx, tx, candidate.ID, *decision.Sample); err != nil {
			return qoe.State{}, qoe.Transition{}, err
		}
	}
	if err := upsertCandidateQoEStateTx(ctx, tx, decision.State); err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if event := candidateQoETransitionEvent(decision.State, decision.Transition); event != nil {
		if err := appendCandidateQoEEventTx(ctx, tx, *event); err != nil {
			return qoe.State{}, qoe.Transition{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	return decision.State, decision.Transition, nil
}

func candidateQoETransitionEvent(state qoe.State, transition qoe.Transition) *Event {
	if !transition.Changed() {
		return nil
	}
	kind := ""
	switch {
	case transition.To == qoe.StatusDegraded:
		kind = "candidate_qoe_degraded"
	case transition.From == qoe.StatusDegraded:
		kind = "candidate_qoe_recovered"
	default:
		return nil
	}
	return &Event{
		Kind: kind, CandidateID: state.CandidateID, CreatedAt: state.UpdatedAt,
		Message: fmt.Sprintf(
			"reason=%s ttfb_ms=%.0f throughput_mbps=%.3f window_bad=%d window_valid=%d",
			state.LastReason, float64(state.CurrentTTFB)/float64(time.Millisecond),
			state.CurrentThroughputMbps, state.WindowBad, state.WindowValid,
		),
	}
}

func appendCandidateQoEEventTx(ctx context.Context, tx *sql.Tx, event Event) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO events(kind, client_id, candidate_id, message, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, event.Kind, event.ClientID, event.CandidateID, event.Message, event.CreatedAt.Unix())
	return err
}

func (store *Store) ListCandidateQoEStates(ctx context.Context) ([]qoe.State, error) {
	rows, err := store.db.QueryContext(ctx, candidateQoEStateSelect+` ORDER BY candidate_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := make([]qoe.State, 0)
	for rows.Next() {
		state, err := scanCandidateQoEState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (store *Store) ListCandidateQoESamples(
	ctx context.Context,
	candidateID string,
	limit int,
) ([]qoe.Sample, error) {
	if limit <= 0 {
		return []qoe.Sample{}, nil
	}
	rows, err := store.db.QueryContext(ctx, candidateQoESampleSelect+`
        WHERE candidate_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?`, candidateID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := make([]qoe.Sample, 0)
	for rows.Next() {
		sample, err := scanCandidateQoESample(rows)
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

func (store *Store) PruneCandidateQoESamples(
	ctx context.Context,
	olderThan time.Time,
	batch int,
) (int64, error) {
	if batch <= 0 {
		return 0, nil
	}
	result, err := store.db.ExecContext(ctx, `
        DELETE FROM candidate_qoe_samples
        WHERE id IN (
          SELECT id
          FROM candidate_qoe_samples
          WHERE created_at < ?
          ORDER BY created_at, id
          LIMIT ?
        )
    `, olderThan.Unix(), batch)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func loadCandidateQoEStateTx(
	ctx context.Context,
	tx *sql.Tx,
	candidateID string,
) (qoe.State, error) {
	state, err := scanCandidateQoEState(tx.QueryRowContext(
		ctx, candidateQoEStateSelect+` WHERE candidate_id = ?`, candidateID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return qoe.State{CandidateID: candidateID, Status: qoe.StatusLearning}, nil
	}
	return state, err
}

func loadCandidateQoESamplesTx(
	ctx context.Context,
	tx *sql.Tx,
	candidateID string,
	successesOnly bool,
	limit int,
) ([]qoe.Sample, error) {
	if limit <= 0 {
		return []qoe.Sample{}, nil
	}
	filter := ""
	if successesOnly {
		filter = " AND success = 1"
	}
	rows, err := tx.QueryContext(ctx, candidateQoESampleSelect+`
        WHERE candidate_id = ?`+filter+`
        ORDER BY created_at DESC, id DESC
        LIMIT ?`, candidateID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	newestFirst := make([]qoe.Sample, 0)
	for rows.Next() {
		sample, err := scanCandidateQoESample(rows)
		if err != nil {
			return nil, err
		}
		newestFirst = append(newestFirst, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	chronological := make([]qoe.Sample, len(newestFirst))
	for index := range newestFirst {
		chronological[len(newestFirst)-1-index] = newestFirst[index]
	}
	return chronological, nil
}

func appendCandidateQoESampleTx(
	ctx context.Context,
	tx *sql.Tx,
	candidateID string,
	sample qoe.Sample,
) error {
	_, err := tx.ExecContext(ctx, `
        INSERT INTO candidate_qoe_samples(
          candidate_id, success, bad, reason, ttfb_ms, transfer_ms, bytes,
          throughput_mbps, effective_ms, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, candidateID, sample.Success, sample.Bad, sample.Reason,
		milliseconds(sample.TTFB), milliseconds(sample.TransferDuration), sample.Bytes,
		sample.ThroughputMbps, milliseconds(sample.EffectiveTime), sample.At.Unix())
	return err
}

func upsertCandidateQoEStateTx(ctx context.Context, tx *sql.Tx, state qoe.State) error {
	_, err := tx.ExecContext(ctx, `
        INSERT INTO candidate_qoe_state(
          candidate_id, status, baseline_ttfb_ms, baseline_throughput_mbps,
          baseline_samples, current_ttfb_ms, current_throughput_mbps,
		  window_valid, window_bad, window_started_at, window_max_gap_ms,
		  median_effective_ms, last_valid_at,
		  last_reason, degraded_at, recovered_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(candidate_id) DO UPDATE SET
          status=excluded.status,
          baseline_ttfb_ms=excluded.baseline_ttfb_ms,
          baseline_throughput_mbps=excluded.baseline_throughput_mbps,
          baseline_samples=excluded.baseline_samples,
          current_ttfb_ms=excluded.current_ttfb_ms,
          current_throughput_mbps=excluded.current_throughput_mbps,
		  window_valid=excluded.window_valid,
		  window_bad=excluded.window_bad,
		  window_started_at=excluded.window_started_at,
		  window_max_gap_ms=excluded.window_max_gap_ms,
          median_effective_ms=excluded.median_effective_ms,
          last_valid_at=excluded.last_valid_at,
          last_reason=excluded.last_reason,
          degraded_at=excluded.degraded_at,
          recovered_at=excluded.recovered_at,
          updated_at=excluded.updated_at
    `, state.CandidateID, state.Status, milliseconds(state.BaselineTTFB),
		state.BaselineThroughputMbps, state.BaselineSamples,
		milliseconds(state.CurrentTTFB), state.CurrentThroughputMbps,
		state.WindowValid, state.WindowBad, unixOrNil(state.WindowStartedAt),
		milliseconds(state.WindowMaxGap),
		milliseconds(state.MedianEffectiveTime),
		unixOrNil(state.LastValidAt), state.LastReason, unixOrNil(state.DegradedAt),
		unixOrNil(state.RecoveredAt), state.UpdatedAt.Unix())
	return err
}

func scanCandidateQoEState(row rowScanner) (qoe.State, error) {
	var state qoe.State
	var baselineTTFBMS, currentTTFBMS, windowMaxGapMS, medianEffectiveMS float64
	var windowStartedAt, lastValidAt, degradedAt, recoveredAt sql.NullInt64
	var updatedAt int64
	err := row.Scan(
		&state.CandidateID, &state.Status, &baselineTTFBMS,
		&state.BaselineThroughputMbps, &state.BaselineSamples, &currentTTFBMS,
		&state.CurrentThroughputMbps, &state.WindowValid, &state.WindowBad,
		&windowStartedAt, &windowMaxGapMS, &medianEffectiveMS, &lastValidAt, &state.LastReason, &degradedAt,
		&recoveredAt, &updatedAt,
	)
	if err != nil {
		return qoe.State{}, err
	}
	state.BaselineTTFB = durationFromMilliseconds(baselineTTFBMS)
	state.CurrentTTFB = durationFromMilliseconds(currentTTFBMS)
	state.MedianEffectiveTime = durationFromMilliseconds(medianEffectiveMS)
	state.WindowStartedAt = nullableTime(windowStartedAt)
	state.WindowMaxGap = durationFromMilliseconds(windowMaxGapMS)
	state.LastValidAt = nullableTime(lastValidAt)
	state.DegradedAt = nullableTime(degradedAt)
	state.RecoveredAt = nullableTime(recoveredAt)
	state.UpdatedAt = time.Unix(updatedAt, 0)
	return state, nil
}

func scanCandidateQoESample(row rowScanner) (qoe.Sample, error) {
	var sample qoe.Sample
	var ttfbMS, transferMS, effectiveMS float64
	var createdAt int64
	err := row.Scan(
		&sample.Success, &sample.Bad, &sample.Reason, &ttfbMS, &transferMS,
		&sample.Bytes, &sample.ThroughputMbps, &effectiveMS, &createdAt,
	)
	if err != nil {
		return qoe.Sample{}, err
	}
	sample.Valid = true
	sample.TTFB = durationFromMilliseconds(ttfbMS)
	sample.TransferDuration = durationFromMilliseconds(transferMS)
	sample.EffectiveTime = durationFromMilliseconds(effectiveMS)
	sample.At = time.Unix(createdAt, 0)
	return sample, nil
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func durationFromMilliseconds(value float64) time.Duration {
	return time.Duration(value * float64(time.Millisecond))
}
