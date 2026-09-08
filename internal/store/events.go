package store

import (
	"context"
	"fmt"
	"time"
)

type Event struct {
	ID          int64     `json:"id"`
	Kind        string    `json:"kind"`
	ClientID    string    `json:"client_id,omitempty"`
	CandidateID string    `json:"candidate_id,omitempty"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"created_at"`
}

type DiagnosticPruneResult struct {
	Events       int
	ProbeSamples int
}

type ExclusionRecord struct {
	ClientID    string    `json:"client_id"`
	CandidateID string    `json:"candidate_id"`
	Reason      string    `json:"reason"`
	Until       time.Time `json:"until"`
}


func (store *Store) AppendEvent(ctx context.Context, event Event) error {
	_, err := store.db.ExecContext(ctx, `
        INSERT INTO events(kind, client_id, candidate_id, message, created_at) VALUES (?, ?, ?, ?, ?)
    `, event.Kind, event.ClientID, event.CandidateID, event.Message, event.CreatedAt.Unix())
	return err
}

func (store *Store) ListEvents(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := store.db.QueryContext(ctx, `
        SELECT id, kind, client_id, candidate_id, message, created_at FROM events ORDER BY id DESC LIMIT ?
    `, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Event, 0)
	for rows.Next() {
		var event Event
		var created int64
		if err := rows.Scan(&event.ID, &event.Kind, &event.ClientID, &event.CandidateID, &event.Message, &created); err != nil {
			return nil, err
		}
		event.CreatedAt = time.Unix(created, 0)
		result = append(result, event)
	}
	return result, rows.Err()
}

func (store *Store) PruneDiagnostics(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (DiagnosticPruneResult, error) {
	if cutoff.IsZero() {
		return DiagnosticPruneResult{}, fmt.Errorf(
			"diagnostic retention cutoff is required",
		)
	}
	if batchSize <= 0 {
		return DiagnosticPruneResult{}, fmt.Errorf(
			"diagnostic retention batch size must be positive",
		)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DiagnosticPruneResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	prune := func(table string) (int, error) {
		result, err := tx.ExecContext(ctx, `
			DELETE FROM `+table+`
			WHERE id IN (
				SELECT id FROM `+table+`
				WHERE created_at <= ?
				ORDER BY created_at, id
				LIMIT ?
			)
		`, cutoff.Unix(), batchSize)
		if err != nil {
			return 0, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		return int(deleted), nil
	}
	events, err := prune("events")
	if err != nil {
		return DiagnosticPruneResult{}, fmt.Errorf(
			"prune diagnostic events: %w", err,
		)
	}
	samples, err := prune("probe_samples")
	if err != nil {
		return DiagnosticPruneResult{}, fmt.Errorf(
			"prune diagnostic probe samples: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return DiagnosticPruneResult{}, fmt.Errorf(
			"commit diagnostic retention: %w", err,
		)
	}
	return DiagnosticPruneResult{
		Events: events, ProbeSamples: samples,
	}, nil
}

func (store *Store) SetExclusion(ctx context.Context, clientID, candidateID, reason string, until time.Time) error {
	_, err := store.db.ExecContext(ctx, `
        INSERT INTO exclusions(client_id, candidate_id, until_at, reason) VALUES (?, ?, ?, ?)
        ON CONFLICT(client_id, candidate_id) DO UPDATE SET until_at=excluded.until_at, reason=excluded.reason
    `, clientID, candidateID, until.Unix(), reason)
	return err
}

func (store *Store) ListExclusions(ctx context.Context, now time.Time) ([]ExclusionRecord, error) {
	if _, err := store.db.ExecContext(ctx, `DELETE FROM exclusions WHERE until_at <= ?`, now.Unix()); err != nil {
		return nil, err
	}
	rows, err := store.db.QueryContext(ctx, `
        SELECT client_id, candidate_id, reason, until_at
        FROM exclusions ORDER BY client_id, candidate_id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ExclusionRecord, 0)
	for rows.Next() {
		var record ExclusionRecord
		var until int64
		if err := rows.Scan(&record.ClientID, &record.CandidateID, &record.Reason, &until); err != nil {
			return nil, err
		}
		record.Until = time.Unix(until, 0)
		result = append(result, record)
	}
	return result, rows.Err()
}
