package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

func (store *Store) ImportSources(ctx context.Context, items []sources.PreviewItem) (ImportResult, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result := ImportResult{}
	now := time.Now().Unix()
	for _, item := range items {
		if item.Error != "" || item.Duplicate || item.Fingerprint == "" || item.Payload == "" {
			result.Skipped++
			continue
		}
		id := "src_" + item.Fingerprint
		encrypted, err := store.box.Seal(id, []byte(item.Payload))
		if err != nil {
			return ImportResult{}, fmt.Errorf("encrypt source %s: %w", item.Fingerprint, err)
		}
		label := item.Display
		if label == "" {
			label = string(item.Kind)
		}
		restored, err := tx.ExecContext(ctx, `
			UPDATE sources
			SET kind=?, label=?, encrypted_payload=?, enabled=1,
			    pending_delete=0, candidate_count=0, last_refresh_error='', updated_at=?
			WHERE fingerprint=? AND pending_delete=1
		`, string(item.Kind), label, encrypted, now, item.Fingerprint)
		if err != nil {
			return ImportResult{}, fmt.Errorf("restore source: %w", err)
		}
		if rows, err := restored.RowsAffected(); err != nil {
			return ImportResult{}, err
		} else if rows == 1 {
			result.Restored++
			continue
		}
		queryResult, err := tx.ExecContext(ctx, `
            INSERT INTO sources(id, kind, label, fingerprint, encrypted_payload, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(fingerprint) DO NOTHING
        `, id, string(item.Kind), label, item.Fingerprint, encrypted, now, now)
		if err != nil {
			return ImportResult{}, fmt.Errorf("insert source: %w", err)
		}
		rows, err := queryResult.RowsAffected()
		if err != nil {
			return ImportResult{}, err
		}
		if rows == 1 {
			result.Imported++
		} else {
			result.Skipped++
		}
	}
	if result.Restored > 0 {
		if err := incrementInventoryEpochTx(ctx, tx); err != nil {
			return ImportResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

func (store *Store) ListSources(ctx context.Context) ([]Source, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, kind, label, fingerprint, enabled, pending_delete,
		       created_at, updated_at,
		       last_refresh_at, last_refresh_error, candidate_count
        FROM sources
        ORDER BY created_at, id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Source, 0)
	for rows.Next() {
		var source Source
		if err := rows.Scan(
			&source.ID,
			&source.Kind,
			&source.Label,
			&source.Fingerprint,
			&source.Enabled,
			&source.PendingDelete,
			&source.CreatedAt,
			&source.UpdatedAt,
			&source.LastRefreshAt,
			&source.LastRefreshError,
			&source.CandidateCount,
		); err != nil {
			return nil, err
		}
		result = append(result, source)
	}
	return result, rows.Err()
}

func (store *Store) UpdateSource(ctx context.Context, id, label string, enabled bool) error {
	if label == "" {
		return errors.New("source label must not be empty")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
        UPDATE sources SET label = ?, enabled = ?, updated_at = ?
		WHERE id = ? AND pending_delete = 0
    `, label, enabled, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if err := requireAffected(result, "source"); err != nil {
		return err
	}
	if err := incrementInventoryEpochTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) DeleteSource(
	ctx context.Context,
	id string,
	retirementGrace ...time.Duration,
) error {
	grace := 15 * time.Minute
	if len(retirementGrace) > 0 && retirementGrace[0] > 0 {
		grace = retirementGrace[0]
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var candidateCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM candidates WHERE source_id=?
	`, id).Scan(&candidateCount); err != nil {
		return err
	}
	var result sql.Result
	if candidateCount == 0 {
		result, err = tx.ExecContext(ctx, `DELETE FROM sources WHERE id = ?`, id)
	} else {
		now := time.Now().Unix()
		result, err = tx.ExecContext(ctx, `
			UPDATE sources
			SET enabled=0, pending_delete=1, updated_at=?
			WHERE id=?
		`, now, id)
		if err == nil {
			_, err = tx.ExecContext(ctx, `
				UPDATE candidates
				SET lifecycle='draining',
				    drain_after=COALESCE(drain_after, ?),
				    retired_at=NULL,
				    updated_at=?
				WHERE source_id=? AND lifecycle='active'
			`, now+int64(grace/time.Second), now, id)
		}
	}
	if err != nil {
		return err
	}
	if err := requireAffected(result, "source"); err != nil {
		return err
	}
	if err := incrementInventoryEpochTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) SourcePayload(ctx context.Context, id string) (string, error) {
	var encrypted []byte
	if err := store.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM sources WHERE id = ?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	plaintext, err := store.box.Open(id, encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt source: %w", err)
	}
	return string(plaintext), nil
}
