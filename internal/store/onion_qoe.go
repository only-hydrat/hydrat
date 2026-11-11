package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
)

// Onion uses the same QoE state machine and bounded evidence window as ordinary
// traffic, but never writes ordinary health or throughput evidence.
type OnionQoEState struct {
	Instance string
	State    qoe.State
	Samples  []qoe.Sample
}

func (store *Store) migrateOnionQoE(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS candidate_onion_qoe (
 candidate_id TEXT PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
 evidence BLOB NOT NULL CHECK(length(evidence)<=65536)
 )`)
	return err
}
func (store *Store) RecordOnionQoE(ctx context.Context, candidate Candidate, instance string, observation qoe.Observation, generation int64) (qoe.State, qoe.Transition, error) {
	if candidate.Kind != sources.KindTorBridge || instance == "" || len(instance) > 128 || observation.At.IsZero() {
		return qoe.State{}, qoe.Transition{}, errors.New("invalid onion observation")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	defer tx.Rollback()
	current, err := candidateReferencedRoutableTx(ctx, tx, candidate)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if !current {
		return qoe.State{}, qoe.Transition{}, ErrCandidateNoLongerCurrent
	}
	var nowGeneration int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT failure_generation FROM candidate_health WHERE candidate_id=?),0)`, candidate.ID).Scan(&nowGeneration); err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if generation != nowGeneration {
		return qoe.State{}, qoe.Transition{}, ErrQoEObservationSuperseded
	}
	var encoded []byte
	var evidence OnionQoEState
	err = tx.QueryRowContext(ctx, `SELECT evidence FROM candidate_onion_qoe WHERE candidate_id=?`, candidate.ID).Scan(&encoded)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return qoe.State{}, qoe.Transition{}, err
	}
	if len(encoded) > 0 {
		if err = json.Unmarshal(encoded, &evidence); err != nil {
			return qoe.State{}, qoe.Transition{}, err
		}
	}
	if observation.Infrastructure {
		return evidence.State, qoe.Transition{}, nil
	}
	if observation.At.Before(evidence.State.UpdatedAt) {
		return qoe.State{}, qoe.Transition{}, ErrQoEObservationSuperseded
	}
	if evidence.Instance != instance {
		evidence = OnionQoEState{Instance: instance}
	}
	var recent, successes []qoe.Sample
	for _, s := range evidence.Samples {
		if !s.At.Before(observation.At.Add(-qoe.EvidenceMaxAge)) && !s.At.After(observation.At) {
			recent = append(recent, s)
			if s.Success {
				successes = append(successes, s)
			}
		}
	}
	decision := qoe.Apply(qoe.OnionPolicy(), evidence.State, recent, successes, observation)
	decision.State.CandidateID = candidate.ID
	evidence.State = decision.State
	if decision.Sample != nil {
		recent = append(recent, *decision.Sample)
	}
	evidence.Samples = recent[max(0, len(recent)-qoe.MaxWindowSize):]
	encoded, err = json.Marshal(evidence)
	if err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO candidate_onion_qoe(candidate_id,evidence) VALUES(?,?) ON CONFLICT(candidate_id) DO UPDATE SET evidence=excluded.evidence`, candidate.ID, encoded); err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	if event := candidateQoETransitionEvent(decision.State, decision.Transition); event != nil {
		event.Kind = "onion_" + event.Kind
		if err = appendCandidateQoEEventTx(ctx, tx, *event); err != nil {
			return qoe.State{}, qoe.Transition{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return qoe.State{}, qoe.Transition{}, err
	}
	return decision.State, decision.Transition, nil
}
func (store *Store) ListOnionQoEStates(ctx context.Context) ([]OnionQoEState, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT evidence FROM candidate_onion_qoe ORDER BY candidate_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OnionQoEState
	for rows.Next() {
		var raw []byte
		var s OnionQoEState
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		s.Samples = nil
		result = append(result, s)
	}
	return result, rows.Err()
}
