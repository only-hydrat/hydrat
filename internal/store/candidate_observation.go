package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type ObservationStage string

const (
	ObservationFast   ObservationStage = "fast"
	ObservationFull   ObservationStage = "full"
	ObservationActive ObservationStage = "active"
)

type ObservationReservation struct {
	CandidateID       string
	Stage             ObservationStage
	Sequence          int64
	FailureGeneration int64
}

type ObservationRequest struct {
	Candidate Candidate
	Stage     ObservationStage
}

type ObservationCommitResult struct {
	Accepted            bool
	BecameProofEligible bool
}

type ActiveObservationOutcome struct {
	Available           bool
	ProofSuccess        bool
	RetainPreviousProof bool
	ProofFreshAfter     time.Time
}

func (store *Store) ReserveCandidateObservation(
	ctx context.Context,
	candidate Candidate,
	stage ObservationStage,
) (ObservationReservation, error) {
	reservations, err := store.ReserveCandidateObservations(
		ctx,
		[]ObservationRequest{{Candidate: candidate, Stage: stage}},
	)
	if err != nil {
		return ObservationReservation{}, err
	}
	return reservations[0], nil
}

// ReserveCandidateObservations validates every current candidate identity
// before advancing any stage clock, then commits the complete batch atomically.
func (store *Store) ReserveCandidateObservations(
	ctx context.Context,
	requests []ObservationRequest,
) ([]ObservationReservation, error) {
	type candidateIdentity struct {
		sourceID    string
		fingerprint string
	}
	identities := make(map[string]candidateIdentity, len(requests))
	stages := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		if !validObservationStage(request.Stage) {
			return nil, errors.New("candidate observation stage is invalid")
		}
		if request.Candidate.ID == "" ||
			request.Candidate.SourceID == "" ||
			request.Candidate.Fingerprint == "" {
			return nil, errors.New("candidate identity is incomplete")
		}
		identity := candidateIdentity{
			sourceID:    request.Candidate.SourceID,
			fingerprint: request.Candidate.Fingerprint,
		}
		if existing, found := identities[request.Candidate.ID]; found &&
			existing != identity {
			return nil, errors.New(
				"candidate observation batch has inconsistent identity",
			)
		}
		identities[request.Candidate.ID] = identity
		key := request.Candidate.ID + "\x00" + string(request.Stage)
		if _, duplicate := stages[key]; duplicate {
			return nil, errors.New(
				"candidate observation batch has duplicate stage",
			)
		}
		stages[key] = struct{}{}
	}
	if len(requests) == 0 {
		return []ObservationReservation{}, nil
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, request := range requests {
		var current bool
		var err error
		if request.Stage == ObservationActive {
			current, err = candidateReferencedRoutableTx(
				ctx, tx, request.Candidate,
			)
		} else {
			current, err = candidateCurrentTx(ctx, tx, request.Candidate)
		}
		if err != nil {
			return nil, err
		}
		if !current {
			return nil, ErrCandidateNoLongerCurrent
		}
	}

	reservations := make([]ObservationReservation, 0, len(requests))
	for _, request := range requests {
		reservation, err := reserveCandidateObservationTx(
			ctx, tx, request.Candidate, request.Stage,
		)
		if err != nil {
			return nil, err
		}
		reservations = append(reservations, reservation)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reservations, nil
}

func reserveCandidateObservationTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
	stage ObservationStage,
) (ObservationReservation, error) {
	reservation := ObservationReservation{
		CandidateID: candidate.ID,
		Stage:       stage,
	}
	var err error
	switch stage {
	case ObservationFast:
		err = tx.QueryRowContext(ctx, `
			INSERT INTO candidate_probe_state(
			  fingerprint, candidate_id, source_id, updated_at, fast_result_seq,
			  observation_placeholder
			)
			VALUES (?, ?, ?, unixepoch(), 1, 1)
			ON CONFLICT(fingerprint) DO UPDATE SET
			  candidate_id=excluded.candidate_id,
			  source_id=excluded.source_id,
			  fast_result_seq=candidate_probe_state.fast_result_seq+1
			RETURNING fast_result_seq
		`, candidate.Fingerprint, candidate.ID, candidate.SourceID).Scan(
			&reservation.Sequence,
		)
	case ObservationFull:
		err = tx.QueryRowContext(ctx, `
			INSERT INTO candidate_health(
			  candidate_id, score, tcp_qualified, udp_qualified, available,
			  latency_ms, throughput_mbps, updated_at, full_result_seq,
			  observation_placeholder
			)
			VALUES (?, 0, 0, 0, 0, 0, 0, unixepoch(), 1, 1)
			ON CONFLICT(candidate_id) DO UPDATE SET
			  full_result_seq=candidate_health.full_result_seq+1
			RETURNING full_result_seq, failure_generation
		`, candidate.ID).Scan(
			&reservation.Sequence,
			&reservation.FailureGeneration,
		)
	case ObservationActive:
		err = tx.QueryRowContext(ctx, `
			INSERT INTO candidate_health(
			  candidate_id, score, tcp_qualified, udp_qualified, available,
			  latency_ms, throughput_mbps, updated_at, active_result_seq,
			  observation_placeholder
			)
			VALUES (?, 0, 0, 0, 0, 0, 0, unixepoch(), 1, 1)
			ON CONFLICT(candidate_id) DO UPDATE SET
			  active_result_seq=candidate_health.active_result_seq+1
			RETURNING active_result_seq, failure_generation
		`, candidate.ID).Scan(
			&reservation.Sequence,
			&reservation.FailureGeneration,
		)
	}
	if err != nil {
		return ObservationReservation{}, err
	}
	return reservation, nil
}

func (store *Store) CommitCandidateProbeObservation(
	ctx context.Context,
	candidate Candidate,
	reservation ObservationReservation,
	transition ProbeTransition,
	health *CandidateHealth,
	sample *ProbeSample,
) (CandidateProbeState, ObservationCommitResult, error) {
	if err := validateObservationReservation(candidate, reservation); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if reservation.Stage != ObservationFast && reservation.Stage != ObservationFull {
		return CandidateProbeState{}, ObservationCommitResult{},
			errors.New("candidate probe observation requires fast or full reservation")
	}
	if (reservation.Stage == ObservationFull) != transition.Full {
		return CandidateProbeState{}, ObservationCommitResult{},
			errors.New("candidate probe transition stage does not match reservation")
	}
	if err := validateProbeObservationPayload(
		candidate, transition, health, sample,
	); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if err := normalizeProbeTransition(&transition); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := candidateCurrentTx(ctx, tx, candidate)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if !current {
		return CandidateProbeState{}, ObservationCommitResult{},
			ErrCandidateNoLongerCurrent
	}
	accepted, err := observationReservationCurrentTx(
		ctx, tx, candidate, reservation,
	)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if !accepted {
		return CandidateProbeState{}, ObservationCommitResult{Accepted: false}, nil
	}
	state, err := recordCandidateProbeTx(
		ctx, tx, transition, health, sample, false,
	)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if reservation.Stage == ObservationFull &&
		!transition.Success &&
		!transition.InfrastructureFailure &&
		!(transition.ErrorCode == "score_too_low" && state.Status == CandidateQualified) {
		result, err := tx.ExecContext(ctx, `
			UPDATE candidate_health
			SET failure_generation=failure_generation+1
			WHERE candidate_id=? AND full_result_seq>=?
			  AND full_applied_seq<? AND failure_generation=?
		`, candidate.ID, reservation.Sequence, reservation.Sequence,
			reservation.FailureGeneration)
		if err != nil {
			return CandidateProbeState{}, ObservationCommitResult{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return CandidateProbeState{}, ObservationCommitResult{}, err
		}
		if affected != 1 {
			return CandidateProbeState{}, ObservationCommitResult{},
				errors.New("full observation fence changed during commit")
		}
	}
	if err := applyObservationReservationTx(
		ctx, tx, candidate, reservation,
	); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	return state, ObservationCommitResult{Accepted: true}, nil
}

func (store *Store) CommitCandidateActiveObservation(
	ctx context.Context,
	candidate Candidate,
	reservation ObservationReservation,
	available bool,
	at time.Time,
) (ObservationCommitResult, error) {
	return store.CommitCandidateActiveOutcome(
		ctx, candidate, reservation, ActiveObservationOutcome{
			Available: available, ProofSuccess: available,
		}, at,
	)
}

func (store *Store) CommitCandidateActiveOutcome(
	ctx context.Context,
	candidate Candidate,
	reservation ObservationReservation,
	outcome ActiveObservationOutcome,
	at time.Time,
) (ObservationCommitResult, error) {
	if err := validateObservationReservation(candidate, reservation); err != nil {
		return ObservationCommitResult{}, err
	}
	if reservation.Stage != ObservationActive {
		return ObservationCommitResult{},
			errors.New("candidate active observation requires active reservation")
	}
	if at.IsZero() {
		at = time.Now()
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ObservationCommitResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := candidateReferencedRoutableTx(ctx, tx, candidate)
	if err != nil {
		return ObservationCommitResult{}, err
	}
	if !current {
		return ObservationCommitResult{}, ErrCandidateNoLongerCurrent
	}
	accepted, err := observationReservationCurrentTx(
		ctx, tx, candidate, reservation,
	)
	if err != nil {
		return ObservationCommitResult{}, err
	}
	if !accepted {
		return ObservationCommitResult{Accepted: false}, nil
	}
	generationCurrent, err := activeSuccessGenerationCurrentTx(
		ctx, tx, candidate.ID, reservation.FailureGeneration,
	)
	if err != nil {
		return ObservationCommitResult{}, err
	}
	if !generationCurrent {
		return ObservationCommitResult{Accepted: false}, nil
	}
	var (
		previousSuccess       bool
		previousObservedAt    sql.NullInt64
		previousGenerationOK  bool
		previousProofAccepted bool
		activeResultSequence  int64
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT active_success, active_observed_at,
		       active_failure_generation=failure_generation,
		       active_applied_seq>0, active_result_seq
		FROM candidate_health WHERE candidate_id=?
	`, candidate.ID).Scan(
		&previousSuccess, &previousObservedAt,
		&previousGenerationOK, &previousProofAccepted, &activeResultSequence,
	); err != nil {
		return ObservationCommitResult{}, err
	}
	previousProofFresh := previousSuccess && previousObservedAt.Valid &&
		previousGenerationOK && previousProofAccepted &&
		(outcome.ProofFreshAfter.IsZero() ||
			!time.UnixMilli(previousObservedAt.Int64).Before(outcome.ProofFreshAfter))
	retainPreviousProof := outcome.RetainPreviousProof && previousProofFresh
	if reservation.Sequence < activeResultSequence &&
		!outcome.ProofSuccess && previousProofFresh {
		return ObservationCommitResult{Accepted: false}, nil
	}
	becameProofEligible := outcome.ProofSuccess && !previousProofFresh
	result, err := tx.ExecContext(ctx, `
		UPDATE candidate_health
		SET available=?, updated_at=?,
		    active_observed_at=CASE WHEN ? THEN active_observed_at ELSE ? END,
		    active_success=CASE WHEN ? THEN active_success ELSE ? END,
		    active_failure_generation=failure_generation,
		    active_hard_failure=CASE
		      WHEN ? THEN 0
		      ELSE active_hard_failure
		    END,
		    observation_placeholder=0
		WHERE candidate_id=? AND active_result_seq>=?
		  AND active_applied_seq<?
	`, outcome.Available, at.Unix(),
		retainPreviousProof, at.UnixMilli(),
		retainPreviousProof, outcome.ProofSuccess,
		outcome.Available, candidate.ID, reservation.Sequence,
		reservation.Sequence)
	if err != nil {
		return ObservationCommitResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ObservationCommitResult{}, err
	}
	if affected != 1 {
		return ObservationCommitResult{},
			errors.New("active observation health row is missing")
	}
	if err := applyObservationReservationTx(
		ctx, tx, candidate, reservation,
	); err != nil {
		return ObservationCommitResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ObservationCommitResult{}, err
	}
	return ObservationCommitResult{
		Accepted: true, BecameProofEligible: becameProofEligible,
	}, nil
}

func (store *Store) CommitCandidateActiveHardFailureObservation(
	ctx context.Context,
	candidate Candidate,
	reservation ObservationReservation,
	at time.Time,
) (CandidateProbeState, ObservationCommitResult, error) {
	if err := validateObservationReservation(candidate, reservation); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if reservation.Stage != ObservationActive {
		return CandidateProbeState{}, ObservationCommitResult{},
			errors.New("candidate active failure requires active reservation")
	}
	if at.IsZero() {
		return CandidateProbeState{}, ObservationCommitResult{},
			errors.New("active failure observation time is required")
	}
	transition := ProbeTransition{
		Fingerprint:      candidate.Fingerprint,
		CandidateID:      candidate.ID,
		SourceID:         candidate.SourceID,
		Success:          false,
		ErrorCode:        "active_hard_failure",
		SafeErrorMessage: "primary and confirmation liveness checks failed",
		At:               at,
	}
	if err := normalizeProbeTransition(&transition); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := candidateReferencedRoutableTx(ctx, tx, candidate)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if !current {
		return CandidateProbeState{}, ObservationCommitResult{},
			ErrCandidateNoLongerCurrent
	}
	accepted, err := observationReservationCurrentTx(
		ctx, tx, candidate, reservation,
	)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if !accepted {
		return CandidateProbeState{}, ObservationCommitResult{Accepted: false}, nil
	}
	state, err := recordCandidateProbeTx(
		ctx, tx, transition, nil, nil, true,
	)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
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
	`, at.Unix(), at.UnixMilli(), candidate.ID, reservation.Sequence, reservation.Sequence)
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if affected != 1 {
		return CandidateProbeState{}, ObservationCommitResult{},
			errors.New("active observation health row is missing")
	}
	if err := applyObservationReservationTx(
		ctx, tx, candidate, reservation,
	); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CandidateProbeState{}, ObservationCommitResult{}, err
	}
	return state, ObservationCommitResult{Accepted: true}, nil
}

func validateProbeObservationPayload(
	candidate Candidate,
	transition ProbeTransition,
	health *CandidateHealth,
	sample *ProbeSample,
) error {
	if transition.CandidateID != candidate.ID ||
		transition.SourceID != candidate.SourceID ||
		transition.Fingerprint != candidate.Fingerprint {
		return errors.New(
			"candidate probe transition identity does not match reservation",
		)
	}
	if health != nil && health.CandidateID != candidate.ID {
		return errors.New(
			"candidate health identity does not match reservation",
		)
	}
	if sample != nil && sample.CandidateID != candidate.ID {
		return errors.New(
			"probe sample identity does not match reservation",
		)
	}
	return nil
}

func activeSuccessGenerationCurrentTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidateID string,
	failureGeneration int64,
) (bool, error) {
	var current int64
	err := tx.QueryRowContext(ctx, `
		SELECT failure_generation
		FROM candidate_health
		WHERE candidate_id=?
	`, candidateID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return current == failureGeneration, nil
}

func applyObservationReservationTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
	reservation ObservationReservation,
) error {
	var (
		result sql.Result
		err    error
	)
	switch reservation.Stage {
	case ObservationFast:
		result, err = tx.ExecContext(ctx, `
			UPDATE candidate_probe_state
			SET fast_applied_seq=?
			WHERE fingerprint=? AND candidate_id=? AND source_id=?
			  AND fast_result_seq>=? AND fast_applied_seq<?
		`, reservation.Sequence, candidate.Fingerprint, candidate.ID,
			candidate.SourceID, reservation.Sequence, reservation.Sequence)
	case ObservationFull:
		result, err = tx.ExecContext(ctx, `
			UPDATE candidate_health
			SET full_applied_seq=?
			WHERE candidate_id=? AND full_result_seq>=?
			  AND full_applied_seq<?
		`, reservation.Sequence, candidate.ID, reservation.Sequence,
			reservation.Sequence)
	case ObservationActive:
		result, err = tx.ExecContext(ctx, `
			UPDATE candidate_health
			SET active_applied_seq=?
			WHERE candidate_id=? AND active_result_seq>=?
			  AND active_applied_seq<?
		`, reservation.Sequence, candidate.ID, reservation.Sequence,
			reservation.Sequence)
	default:
		return errors.New("candidate observation stage is invalid")
	}
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("candidate observation applied fence changed during commit")
	}
	return nil
}

func observationReservationCurrentTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	candidate Candidate,
	reservation ObservationReservation,
) (bool, error) {
	var (
		allocated  int64
		applied    int64
		generation int64
	)
	switch reservation.Stage {
	case ObservationFast:
		err := tx.QueryRowContext(ctx, `
			SELECT fast_result_seq, fast_applied_seq
			FROM candidate_probe_state
			WHERE fingerprint=? AND candidate_id=? AND source_id=?
		`, candidate.Fingerprint, candidate.ID, candidate.SourceID).Scan(
			&allocated, &applied,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return reservation.Sequence <= allocated &&
			reservation.Sequence > applied, nil
	case ObservationFull:
		err := tx.QueryRowContext(ctx, `
			SELECT full_result_seq, full_applied_seq, failure_generation
			FROM candidate_health
			WHERE candidate_id=?
		`, candidate.ID).Scan(&allocated, &applied, &generation)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return reservation.Sequence <= allocated &&
			reservation.Sequence > applied &&
			generation == reservation.FailureGeneration, nil
	case ObservationActive:
		err := tx.QueryRowContext(ctx, `
			SELECT active_result_seq, active_applied_seq
			FROM candidate_health
			WHERE candidate_id=?
		`, candidate.ID).Scan(&allocated, &applied)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return reservation.Sequence <= allocated &&
			reservation.Sequence > applied, nil
	default:
		return false, errors.New("candidate observation stage is invalid")
	}
}

func validateObservationReservation(
	candidate Candidate,
	reservation ObservationReservation,
) error {
	if candidate.ID == "" || reservation.CandidateID != candidate.ID {
		return errors.New("candidate observation reservation identity does not match candidate")
	}
	if !validObservationStage(reservation.Stage) || reservation.Sequence <= 0 {
		return errors.New("candidate observation reservation is invalid")
	}
	return nil
}

func validObservationStage(stage ObservationStage) bool {
	switch stage {
	case ObservationFast, ObservationFull, ObservationActive:
		return true
	default:
		return false
	}
}
