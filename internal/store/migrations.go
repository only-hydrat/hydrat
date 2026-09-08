package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func (store *Store) initialize(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            encrypted_payload BLOB NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            pending_delete INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            last_refresh_at INTEGER,
            last_refresh_error TEXT NOT NULL DEFAULT '',
            candidate_count INTEGER NOT NULL DEFAULT 0
        )`,
		`CREATE TABLE IF NOT EXISTS candidates (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            route_key TEXT NOT NULL DEFAULT '',
            failure_domain TEXT NOT NULL DEFAULT '',
            encrypted_payload BLOB NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            source_position INTEGER NOT NULL DEFAULT 0,
            lifecycle TEXT NOT NULL DEFAULT 'active',
            retired_at INTEGER,
            drain_after INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(source_id, fingerprint)
        )`,
		`CREATE INDEX IF NOT EXISTS candidates_source_idx ON candidates(source_id)`,
		`CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            encrypted_config BLOB NOT NULL,
            paused INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            last_traffic_at INTEGER,
			activity_seen INTEGER NOT NULL DEFAULT 0,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            tx_bytes INTEGER NOT NULL DEFAULT 0
        )`,
		`CREATE TABLE IF NOT EXISTS assignments (
            client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
            tcp_outbound TEXT NOT NULL,
            udp_outbound TEXT NOT NULL,
            tcp_since INTEGER NOT NULL,
            udp_since INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS candidate_health (
            candidate_id TEXT PRIMARY KEY,
            score REAL NOT NULL,
            tcp_qualified INTEGER NOT NULL,
            udp_qualified INTEGER NOT NULL,
            available INTEGER NOT NULL,
            latency_ms REAL NOT NULL DEFAULT 0,
            throughput_mbps REAL NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS candidate_probe_state (
            fingerprint TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL DEFAULT '',
            source_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'unknown',
            failure_streak INTEGER NOT NULL DEFAULT 0,
            full_success_streak INTEGER NOT NULL DEFAULT 0,
            window_started_at INTEGER,
            banned_until INTEGER,
            last_fast_probe_at INTEGER,
            last_full_probe_at INTEGER,
            last_success_at INTEGER,
            last_failure_at INTEGER,
            last_error_code TEXT NOT NULL DEFAULT '',
            last_error_message TEXT NOT NULL DEFAULT '',
            last_score REAL NOT NULL DEFAULT 0,
            conservative_score REAL NOT NULL DEFAULT 0,
            in_working_pool INTEGER NOT NULL DEFAULT 0,
            draining INTEGER NOT NULL DEFAULT 0,
            stale INTEGER NOT NULL DEFAULT 1,
            updated_at INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS candidate_probe_state_status_idx
            ON candidate_probe_state(status)`,
		`CREATE INDEX IF NOT EXISTS candidate_probe_state_banned_idx
            ON candidate_probe_state(banned_until)`,
		`CREATE INDEX IF NOT EXISTS candidate_probe_state_pool_idx
            ON candidate_probe_state(in_working_pool, draining)`,
		`CREATE INDEX IF NOT EXISTS candidate_probe_state_probe_time_idx
            ON candidate_probe_state(last_full_probe_at, last_fast_probe_at)`,
		`CREATE INDEX IF NOT EXISTS candidate_probe_state_candidate_idx
		    ON candidate_probe_state(candidate_id)`,
		`CREATE TABLE IF NOT EXISTS probe_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id TEXT NOT NULL,
            success INTEGER NOT NULL,
            latency_ms REAL NOT NULL,
            throughput_mbps REAL NOT NULL,
            packet_drop_ratio REAL NOT NULL,
            created_at INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS probe_samples_candidate_time_idx ON probe_samples(candidate_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS exclusions (
            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            candidate_id TEXT NOT NULL,
            until_at INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY(client_id, candidate_id)
        )`,
		`CREATE TABLE IF NOT EXISTS plan_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            desired_generation INTEGER NOT NULL DEFAULT 0,
            applied_generation INTEGER NOT NULL DEFAULT 0,
            desired_plan BLOB,
			desired_reason TEXT NOT NULL DEFAULT '',
            applied_plan BLOB,
			desired_assignments_generation INTEGER NOT NULL DEFAULT 0,
			desired_assignments BLOB,
			invalidated_generation INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )`,
		`INSERT OR IGNORE INTO plan_state(singleton, updated_at) VALUES (1, unixepoch())`,
		`CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            client_id TEXT NOT NULL DEFAULT '',
            candidate_id TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )`,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, unixepoch())`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize store: %w", err)
		}
	}
	if err := store.migrateCandidateProbeState(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateSourcePosition(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateQoE(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateIdentity(ctx); err != nil {
		return err
	}
	if err := store.migrateFailureDomains(ctx); err != nil {
		return err
	}
	if err := store.migrateDiagnosticRetention(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateObservationOrdering(ctx); err != nil {
		return err
	}
	if err := store.migrateObservationPlaceholders(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateLifecycle(ctx); err != nil {
		return err
	}
	if err := store.migrateRouteReserveMappings(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateActiveEvidence(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateActiveHardFailure(ctx); err != nil {
		return err
	}
	if err := store.migrateDesiredPlanReason(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateActiveObservedAtMilliseconds(ctx); err != nil {
		return err
	}
	if err := store.migrateCandidateProbeLookupIndex(ctx); err != nil {
		return err
	}
	return store.migrateCandidateQoEWindowStartedAt(ctx)
}

func (store *Store) migrateCandidateQoEWindowStartedAt(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate QoE window migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM pragma_table_info('candidate_qoe_state')
		WHERE name='window_started_at'
	`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect candidate_qoe_state.window_started_at: %w", err)
	}
	if exists == 0 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE candidate_qoe_state ADD COLUMN window_started_at INTEGER
		`); err != nil {
			return fmt.Errorf("add candidate QoE window start: %w", err)
		}
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM pragma_table_info('candidate_qoe_state')
		WHERE name='window_max_gap_ms'
	`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect candidate_qoe_state.window_max_gap_ms: %w", err)
	}
	if exists == 0 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE candidate_qoe_state
			ADD COLUMN window_max_gap_ms REAL NOT NULL DEFAULT 0
		`); err != nil {
			return fmt.Errorf("add candidate QoE window maximum gap: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (17, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 17: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate QoE window migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateProbeLookupIndex(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate probe lookup index migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var applied int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=16
	`).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version 16: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT name FROM pragma_index_info('candidate_probe_state_candidate_idx')
		ORDER BY seqno
	`)
	if err != nil {
		return fmt.Errorf("inspect candidate probe lookup index: %w", err)
	}
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan candidate probe lookup index: %w", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read candidate probe lookup index: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close candidate probe lookup index rows: %w", err)
	}
	if len(columns) != 1 || columns[0] != "candidate_id" {
		if _, err := tx.ExecContext(ctx,
			`DROP INDEX IF EXISTS candidate_probe_state_candidate_idx`,
		); err != nil {
			return fmt.Errorf("drop candidate probe lookup index: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			CREATE INDEX candidate_probe_state_candidate_idx
			ON candidate_probe_state(candidate_id)
		`); err != nil {
			return fmt.Errorf("create candidate probe lookup index: %w", err)
		}
	}
	if err := validateCandidateProbeLookupIndex(ctx, tx); err != nil {
		return err
	}
	if applied == 0 {
		for _, cleanup := range []struct {
			name  string
			query string
		}{
			{
				name: "candidate probe state",
				query: `DELETE FROM candidate_probe_state
					WHERE candidate_id<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=candidate_probe_state.candidate_id
					)`,
			},
			{
				name: "candidate health",
				query: `DELETE FROM candidate_health
					WHERE candidate_id<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=candidate_health.candidate_id
					)`,
			},
			{
				name: "probe samples",
				query: `DELETE FROM probe_samples
					WHERE candidate_id<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=probe_samples.candidate_id
					)`,
			},
			{
				name: "candidate exclusions",
				query: `DELETE FROM exclusions
					WHERE candidate_id<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=exclusions.candidate_id
					)`,
			},
			{
				name: "failure domain evidence",
				query: `DELETE FROM failure_domain_evidence
					WHERE candidate_id<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=failure_domain_evidence.candidate_id
					)`,
			},
			{
				name: "failure domain canaries",
				query: `UPDATE failure_domain_state
					SET canary_candidate='', updated_at=unixepoch()
					WHERE canary_candidate<>'' AND NOT EXISTS (
					  SELECT 1 FROM candidates
					  WHERE candidates.id=failure_domain_state.canary_candidate
					)`,
			},
		} {
			if _, err := tx.ExecContext(ctx, cleanup.query); err != nil {
				return fmt.Errorf("clean orphan %s: %w", cleanup.name, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (16, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 16: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate probe lookup index migration: %w", err)
	}
	return nil
}

func validateCandidateProbeLookupIndex(
	ctx context.Context,
	executor sqlRowsQueryExecutor,
) error {
	rows, err := executor.QueryContext(ctx, `
		SELECT name FROM pragma_index_info('candidate_probe_state_candidate_idx')
		ORDER BY seqno
	`)
	if err != nil {
		return fmt.Errorf("validate candidate probe lookup index: %w", err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return fmt.Errorf("validate candidate probe lookup index: %w", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("validate candidate probe lookup index: %w", err)
	}
	if len(columns) != 1 || columns[0] != "candidate_id" {
		return fmt.Errorf(
			"candidate probe lookup index columns=%v, want [candidate_id]",
			columns,
		)
	}
	return nil
}

func (store *Store) migrateCandidateActiveObservedAtMilliseconds(
	ctx context.Context,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin active observation precision migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateCandidateActiveEvidenceSchema(ctx, tx); err != nil {
		return err
	}
	var applied int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=15
	`).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version 15: %w", err)
	}
	if applied == 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE candidate_health
			SET active_observed_at=CASE
			      WHEN active_observed_at>=1
			       AND active_observed_at<?
			        THEN active_observed_at*1000
			      WHEN active_observed_at>=?
			       AND active_observed_at<=?
			        THEN active_observed_at
			      ELSE NULL
			    END,
			    active_success=CASE
			      WHEN active_observed_at>=1
			       AND active_observed_at<=?
			        THEN active_success
			      ELSE 0
			    END
			WHERE active_observed_at IS NOT NULL
		`, minActiveObservedAtMilliseconds,
			minActiveObservedAtMilliseconds,
			maxActiveObservedAtMilliseconds,
			maxActiveObservedAtMilliseconds,
		); err != nil {
			return fmt.Errorf("convert active observation timestamps: %w", err)
		}
	}
	if err := validateCandidateActiveObservedAtMilliseconds(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (15, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 15: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit active observation precision migration: %w", err)
	}
	return nil
}

func (store *Store) migrateDesiredPlanReason(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin desired plan reason migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM pragma_table_info('plan_state')
		WHERE name='desired_reason'
	`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect plan_state.desired_reason: %w", err)
	}
	if exists == 0 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE plan_state ADD COLUMN desired_reason
			TEXT NOT NULL DEFAULT ''
		`); err != nil {
			return fmt.Errorf("add plan_state.desired_reason: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE plan_state SET desired_reason='legacy'
		WHERE desired_generation>0 AND desired_reason=''
	`); err != nil {
		return fmt.Errorf("backfill desired plan reason: %w", err)
	}
	if err := validateDesiredPlanReasonSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (14, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 14: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit desired plan reason migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateProbeState(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate state migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 2`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT OR IGNORE INTO candidate_probe_state(
          fingerprint, candidate_id, source_id, status, last_full_probe_at,
          last_success_at, last_score, conservative_score, stale, updated_at
        )
        SELECT c.fingerprint, c.id, c.source_id, 'unknown', h.updated_at,
               CASE WHEN h.available = 1 THEN h.updated_at ELSE NULL END,
               h.score, h.score, 1, unixepoch()
        FROM candidate_health h
        JOIN candidates c ON c.id = h.candidate_id
    `); err != nil {
		return fmt.Errorf("migrate candidate health: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (2, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 2: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate state migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateSourcePosition(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate source position migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 3`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}

	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(candidates)`)
	if err != nil {
		return fmt.Errorf("inspect candidates schema: %w", err)
	}
	hasSourcePosition := false
	for rows.Next() {
		var (
			cid          int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(
			&cid,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan candidates schema: %w", err)
		}
		if name == "source_position" {
			hasSourcePosition = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect candidates schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close candidates schema rows: %w", err)
	}

	if !hasSourcePosition {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE candidates
			ADD COLUMN source_position INTEGER NOT NULL DEFAULT 0
		`); err != nil {
			return fmt.Errorf("add candidate source position: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE candidates
			SET source_position = (
			  SELECT COUNT(*)
			  FROM candidates AS previous
			  WHERE previous.source_id = candidates.source_id
			    AND (
			      previous.created_at < candidates.created_at
			      OR (
			        previous.created_at = candidates.created_at
			        AND previous.id < candidates.id
			      )
			    )
			)
		`); err != nil {
			return fmt.Errorf("backfill candidate source position: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS candidates_source_position_idx
		ON candidates(source_id, source_position, id)
	`); err != nil {
		return fmt.Errorf("index candidate source position: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (3, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 3: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate source position migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateQoE(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate QoE migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	statements := []string{
		`CREATE TABLE IF NOT EXISTS candidate_qoe_state (
          candidate_id TEXT PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
          status TEXT NOT NULL,
          baseline_ttfb_ms REAL NOT NULL DEFAULT 0,
          baseline_throughput_mbps REAL NOT NULL DEFAULT 0,
          baseline_samples INTEGER NOT NULL DEFAULT 0,
          current_ttfb_ms REAL NOT NULL DEFAULT 0,
          current_throughput_mbps REAL NOT NULL DEFAULT 0,
          window_valid INTEGER NOT NULL DEFAULT 0,
          window_bad INTEGER NOT NULL DEFAULT 0,
          median_effective_ms REAL NOT NULL DEFAULT 0,
          last_valid_at INTEGER,
          last_reason TEXT NOT NULL DEFAULT '',
          degraded_at INTEGER,
          recovered_at INTEGER,
          updated_at INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS candidate_qoe_samples (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
          success INTEGER NOT NULL,
          bad INTEGER NOT NULL,
          reason TEXT NOT NULL DEFAULT '',
          ttfb_ms REAL NOT NULL DEFAULT 0,
          transfer_ms REAL NOT NULL DEFAULT 0,
          bytes INTEGER NOT NULL DEFAULT 0,
          throughput_mbps REAL NOT NULL DEFAULT 0,
          effective_ms REAL NOT NULL,
          created_at INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS candidate_qoe_samples_candidate_time_idx
          ON candidate_qoe_samples(candidate_id, created_at DESC, id DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create candidate QoE schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (4, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 4: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate QoE migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateIdentity(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate identity migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 5`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}

	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(candidates)`)
	if err != nil {
		return fmt.Errorf("inspect candidates schema: %w", err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid          int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(
			&cid,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan candidates schema: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect candidates schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close candidates schema rows: %w", err)
	}

	for _, column := range []string{"route_key", "failure_domain"} {
		if columns[column] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE candidates
			ADD COLUMN `+column+` TEXT NOT NULL DEFAULT ''
		`); err != nil {
			return fmt.Errorf("add candidate %s: %w", column, err)
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS candidates_route_key_idx
			ON candidates(route_key)`,
		`CREATE INDEX IF NOT EXISTS candidates_failure_domain_idx
			ON candidates(failure_domain)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("index candidate identity: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (5, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 5: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate identity migration: %w", err)
	}
	return nil
}

func (store *Store) migrateFailureDomains(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin failure domain migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 6`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS failure_domain_state (
		  domain TEXT PRIMARY KEY,
		  failure_count INTEGER NOT NULL DEFAULT 0,
		  window_started_at INTEGER NOT NULL DEFAULT 0,
		  open_until INTEGER NOT NULL DEFAULT 0,
		  canary_candidate TEXT NOT NULL DEFAULT '',
		  updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS failure_domain_evidence (
		  domain TEXT NOT NULL REFERENCES failure_domain_state(domain) ON DELETE CASCADE,
		  candidate_id TEXT NOT NULL,
		  last_failed_at INTEGER NOT NULL,
		  PRIMARY KEY(domain, candidate_id)
		)`,
		`CREATE INDEX IF NOT EXISTS failure_domain_evidence_time_idx
		  ON failure_domain_evidence(domain, last_failed_at, candidate_id)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create failure domain schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (6, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 6: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failure domain migration: %w", err)
	}
	return nil
}

func (store *Store) migrateDiagnosticRetention(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin diagnostic retention migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 7`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS events_created_at_idx
		  ON events(created_at)`,
		`CREATE INDEX IF NOT EXISTS probe_samples_created_at_idx
		  ON probe_samples(created_at)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create diagnostic retention indexes: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (7, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 7: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit diagnostic retention migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateObservationOrdering(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate observation ordering migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 8`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if applied != 0 {
		return tx.Commit()
	}

	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{
			table:      "candidate_probe_state",
			name:       "fast_result_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "full_result_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "active_result_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "failure_generation",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
	}
	for _, column := range columns {
		var exists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*)
			FROM pragma_table_info(?)
			WHERE name = ?
		`, column.table, column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect %s schema: %w", column.table, err)
		}
		if exists != 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`ALTER TABLE `+column.table+` ADD COLUMN `+column.name+` `+column.definition,
		); err != nil {
			return fmt.Errorf("add %s.%s: %w", column.table, column.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (8, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 8: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate observation ordering migration: %w", err)
	}
	return nil
}

func (store *Store) migrateObservationPlaceholders(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin observation placeholder migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{
			table:      "candidate_probe_state",
			name:       "observation_placeholder",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_probe_state",
			name:       "fast_applied_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "observation_placeholder",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "full_applied_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
		{
			table:      "candidate_health",
			name:       "active_applied_seq",
			definition: "INTEGER NOT NULL DEFAULT 0",
		},
	}
	for _, column := range columns {
		var exists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*)
			FROM pragma_table_info(?)
			WHERE name = ?
		`, column.table, column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect %s.%s: %w",
				column.table, column.name, err)
		}
		if exists == 0 {
			if _, err := tx.ExecContext(ctx,
				`ALTER TABLE `+column.table+` ADD COLUMN `+
					column.name+` `+column.definition,
			); err != nil {
				return fmt.Errorf("add %s.%s: %w",
					column.table, column.name, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		 VALUES (9, unixepoch())`,
	); err != nil {
		return fmt.Errorf("record schema version 9: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit observation placeholder migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateLifecycle(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate lifecycle migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	columns := []struct {
		name       string
		definition string
	}{
		{name: "lifecycle", definition: "TEXT NOT NULL DEFAULT 'active'"},
		{name: "retired_at", definition: "INTEGER"},
		{name: "drain_after", definition: "INTEGER"},
	}
	for _, column := range columns {
		var exists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*)
			FROM pragma_table_info('candidates')
			WHERE name=?
		`, column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect candidates.%s: %w", column.name, err)
		}
		if exists != 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`ALTER TABLE candidates ADD COLUMN `+
				column.name+` `+column.definition,
		); err != nil {
			return fmt.Errorf("add candidates.%s: %w", column.name, err)
		}
	}
	var pendingDeleteExists int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM pragma_table_info('sources')
		WHERE name='pending_delete'
	`).Scan(&pendingDeleteExists); err != nil {
		return fmt.Errorf("inspect sources.pending_delete: %w", err)
	}
	if pendingDeleteExists == 0 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE sources
			ADD COLUMN pending_delete INTEGER NOT NULL DEFAULT 0
		`); err != nil {
			return fmt.Errorf("add sources.pending_delete: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS inventory_state (
		  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
		  epoch INTEGER NOT NULL DEFAULT 0
		)
	`); err != nil {
		return fmt.Errorf("create inventory state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO inventory_state(singleton, epoch) VALUES (1, 0)
	`); err != nil {
		return fmt.Errorf("initialize inventory state: %w", err)
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS candidates_lifecycle_deadline_idx
		 ON candidates(lifecycle, drain_after, retired_at, id)`,
		`CREATE INDEX IF NOT EXISTS sources_pending_delete_idx
		 ON sources(pending_delete, id)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create retirement lifecycle index: %w", err)
		}
	}
	if err := canonicalizeLegacyPlanStateTx(ctx, tx); err != nil {
		return fmt.Errorf("canonicalize legacy plan state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (10, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 10: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate lifecycle migration: %w", err)
	}
	return nil
}

func (store *Store) migrateRouteReserveMappings(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route reserve migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "desired_assignments_generation", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "desired_assignments", definition: "BLOB"},
		{name: "invalidated_generation", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		var exists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM pragma_table_info('plan_state') WHERE name=?
		`, column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect plan assignment snapshot schema: %w", err)
		}
		if exists == 0 {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE plan_state ADD COLUMN `+
				column.name+` `+column.definition); err != nil {
				return fmt.Errorf("repair plan assignment snapshot schema: %w", err)
			}
		}
	}
	if err := validatePlanAssignmentSnapshotSchema(ctx, tx); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, strings.Replace(
		routeReserveTableDDL, "CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1,
	)); err != nil {
		return fmt.Errorf("create route reserve mappings: %w", err)
	}
	missingColumns, err := missingRouteReserveColumns(ctx, tx)
	if err != nil {
		return err
	}
	if len(missingColumns) != 0 {
		var rows int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM route_reserve_mappings
		`).Scan(&rows); err != nil {
			return fmt.Errorf("inspect partial route reserve rows: %w", err)
		}
		if rows != 0 {
			return errors.New("incompatible route reserve schema: missing columns with persisted rows")
		}
		if _, err := tx.ExecContext(ctx, `DROP TABLE route_reserve_mappings`); err != nil {
			return fmt.Errorf("drop partial route reserve schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, routeReserveTableDDL); err != nil {
			return fmt.Errorf("repair route reserve schema: %w", err)
		}
	}
	if err := validateRouteReserveTable(ctx, tx); err != nil {
		return err
	}
	validIndex, err := routeReserveIndexValid(ctx, tx)
	if err != nil {
		return err
	}
	if !validIndex {
		if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS route_reserve_generation_idx`); err != nil {
			return fmt.Errorf("repair route reserve index: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			CREATE INDEX route_reserve_generation_idx
			ON route_reserve_mappings(stage, generation, client_id)
		`); err != nil {
			return fmt.Errorf("index route reserve mappings: %w", err)
		}
	}
	if err := validateRouteReserveIndex(ctx, tx); err != nil {
		return err
	}
	if _, err := rebaseUnsafeDesiredPlanTx(ctx, tx, true); err != nil {
		return fmt.Errorf("rebase unsafe desired plan: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (11, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 11: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route reserve migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateActiveEvidence(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate active evidence migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "active_observed_at", definition: "INTEGER"},
		{name: "active_success", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "active_failure_generation", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		var exists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM pragma_table_info('candidate_health') WHERE name=?
		`, column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect candidate_health.%s: %w", column.name, err)
		}
		if exists == 0 {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE candidate_health ADD COLUMN `+
				column.name+` `+column.definition); err != nil {
				return fmt.Errorf("add candidate_health.%s: %w", column.name, err)
			}
		}
	}
	if err := validateCandidateActiveEvidenceSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (12, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 12: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate active evidence migration: %w", err)
	}
	return nil
}

func (store *Store) migrateCandidateActiveHardFailure(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin candidate active hard failure migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM pragma_table_info('candidate_health')
		WHERE name='active_hard_failure'
	`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect candidate_health.active_hard_failure: %w", err)
	}
	if exists == 0 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE candidate_health ADD COLUMN active_hard_failure
			INTEGER NOT NULL DEFAULT 0
		`); err != nil {
			return fmt.Errorf("add candidate_health.active_hard_failure: %w", err)
		}
		// V12 did not store an explicit hard bit. Its accepted route-level
		// hard failure is exactly the current negative active outcome that also
		// made the route unavailable. Partial endpoint degradation remained
		// available and must not be upgraded to a hard failure.
		if _, err := tx.ExecContext(ctx, `
			UPDATE candidate_health
			SET active_hard_failure=1
			WHERE active_observed_at IS NOT NULL
			  AND active_success=0 AND available=0
			  AND active_failure_generation=failure_generation
		`); err != nil {
			return fmt.Errorf("backfill candidate active hard failure: %w", err)
		}
	}
	if err := validateCandidateActiveHardFailureSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO schema_migrations(version, applied_at)
		VALUES (13, unixepoch())
	`); err != nil {
		return fmt.Errorf("record schema version 13: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit candidate active hard failure migration: %w", err)
	}
	return nil
}

func rebaseUnsafeDesiredPlanTx(
	ctx context.Context,
	tx *sql.Tx,
	rebaseInvalidPlan bool,
) (bool, error) {
	var (
		desiredGeneration            int64
		appliedGeneration            int64
		invalidatedGeneration        int64
		desiredPlan                  []byte
		desiredAssignmentsGeneration int64
		desiredAssignments           []byte
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, invalidated_generation,
		       desired_plan,
		       desired_assignments_generation, desired_assignments
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredGeneration, &appliedGeneration, &invalidatedGeneration,
		&desiredPlan,
		&desiredAssignmentsGeneration, &desiredAssignments,
	); err != nil {
		return false, err
	}
	if desiredGeneration <= appliedGeneration {
		return false, nil
	}
	var assignments []AssignmentRecord
	hasExactSnapshot := desiredAssignmentsGeneration == desiredGeneration &&
		!bytes.Equal(bytes.TrimSpace(desiredAssignments), []byte("null")) &&
		decodeStrictJSON(desiredAssignments, &assignments) && assignments != nil
	if hasExactSnapshot {
		hasExactSnapshot = validatePersistedAssignmentSnapshot(
			ctx, tx, desiredPlan, assignments,
		) == nil
	}
	if hasExactSnapshot {
		return false, nil
	}
	if !rebaseInvalidPlan {
		var plan dataplane.DesiredPlan
		if !decodeStrictJSON(desiredPlan, &plan) ||
			plan.Generation != desiredGeneration || plan.Validate() != nil {
			return false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE plan_state
		SET desired_generation=applied_generation,
		    desired_plan=applied_plan,
		    invalidated_generation=max(invalidated_generation, desired_generation),
		    desired_assignments_generation=0,
		    desired_assignments=NULL,
		    updated_at=unixepoch()
		WHERE singleton=1
	`); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM route_reserve_mappings WHERE stage='desired'
	`); err != nil {
		return false, err
	}
	return true, nil
}

type schemaQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type routeReserveColumn struct {
	columnType string
	notNull    int
	primaryKey int
}

var expectedRouteReserveColumns = map[string]routeReserveColumn{
	"stage":                    {columnType: "TEXT", notNull: 1, primaryKey: 1},
	"client_id":                {columnType: "TEXT", notNull: 1, primaryKey: 2},
	"generation":               {columnType: "INTEGER", notNull: 1},
	"tcp_primary_candidate_id": {columnType: "TEXT", notNull: 1},
	"tcp_reserve_candidate_id": {columnType: "TEXT", notNull: 1},
	"udp_primary_candidate_id": {columnType: "TEXT", notNull: 1},
	"udp_reserve_candidate_id": {columnType: "TEXT", notNull: 1},
}

func missingRouteReserveColumns(
	ctx context.Context,
	querier schemaQuerier,
) ([]string, error) {
	rows, err := querier.QueryContext(ctx, `PRAGMA table_info(route_reserve_mappings)`)
	if err != nil {
		return nil, fmt.Errorf("inspect route reserve columns: %w", err)
	}
	defer rows.Close()
	present := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("scan route reserve columns: %w", err)
		}
		present[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect route reserve columns: %w", err)
	}
	missing := make([]string, 0)
	for name := range expectedRouteReserveColumns {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func validatePlanAssignmentSnapshotSchema(
	ctx context.Context,
	querier schemaQuerier,
) error {
	rows, err := querier.QueryContext(ctx, `PRAGMA table_info(plan_state)`)
	if err != nil {
		return fmt.Errorf("inspect plan assignment snapshot schema: %w", err)
	}
	defer rows.Close()
	foundGeneration := false
	foundSnapshot := false
	foundInvalidatedGeneration := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("inspect plan assignment snapshot schema: %w", err)
		}
		switch name {
		case "desired_assignments_generation":
			foundGeneration = strings.EqualFold(columnType, "INTEGER") && notNull == 1
		case "desired_assignments":
			foundSnapshot = strings.EqualFold(columnType, "BLOB") && notNull == 0
		case "invalidated_generation":
			foundInvalidatedGeneration = strings.EqualFold(columnType, "INTEGER") && notNull == 1
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect plan assignment snapshot schema: %w", err)
	}
	if !foundGeneration || !foundSnapshot || !foundInvalidatedGeneration {
		return errors.New("incompatible route reserve schema: invalid desired assignment snapshot columns")
	}
	return nil
}

func validateRouteReserveTable(ctx context.Context, querier schemaQuerier) error {
	rows, err := querier.QueryContext(ctx, `PRAGMA table_info(route_reserve_mappings)`)
	if err != nil {
		return fmt.Errorf("inspect route reserve schema: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("inspect route reserve schema: %w", err)
		}
		expected, exists := expectedRouteReserveColumns[name]
		if !exists || !strings.EqualFold(columnType, expected.columnType) ||
			notNull != expected.notNull || primaryKey != expected.primaryKey {
			return errors.New("incompatible route reserve schema: invalid column definition")
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect route reserve schema: %w", err)
	}
	if len(seen) != len(expectedRouteReserveColumns) {
		return errors.New("incompatible route reserve schema: incomplete columns")
	}

	var tableSQL string
	if err := querier.QueryRowContext(ctx, `
		SELECT sql FROM sqlite_master
		WHERE type='table' AND name='route_reserve_mappings'
	`).Scan(&tableSQL); err != nil {
		return errors.New("incompatible route reserve schema: missing table SQL")
	}
	normalized := normalizeSchemaSQL(tableSQL)
	if !strings.Contains(normalized, "check(stagein('desired','applied'))") ||
		!strings.Contains(normalized, "check(generation>0)") {
		return errors.New("incompatible route reserve schema: invalid CHECK constraint")
	}

	foreignKeys, err := querier.QueryContext(ctx, `PRAGMA foreign_key_list(route_reserve_mappings)`)
	if err != nil {
		return fmt.Errorf("inspect route reserve foreign keys: %w", err)
	}
	defer foreignKeys.Close()
	count := 0
	for foreignKeys.Next() {
		var id, sequence int
		var table, from, to, onUpdate, onDelete, match string
		if err := foreignKeys.Scan(
			&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match,
		); err != nil {
			return fmt.Errorf("inspect route reserve foreign keys: %w", err)
		}
		count++
		if table != "clients" || from != "client_id" || to != "id" ||
			onDelete != "CASCADE" {
			return errors.New("incompatible route reserve schema: invalid foreign key")
		}
	}
	if err := foreignKeys.Err(); err != nil {
		return fmt.Errorf("inspect route reserve foreign keys: %w", err)
	}
	if count != 1 {
		return errors.New("incompatible route reserve schema: invalid foreign key count")
	}
	return nil
}

func validateRouteReserveIndex(ctx context.Context, querier schemaQuerier) error {
	valid, err := routeReserveIndexValid(ctx, querier)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("incompatible route reserve schema: invalid generation index")
	}
	return nil
}

func routeReserveIndexValid(ctx context.Context, querier schemaQuerier) (bool, error) {
	indexRows, err := querier.QueryContext(ctx, `PRAGMA index_list(route_reserve_mappings)`)
	if err != nil {
		return false, fmt.Errorf("inspect route reserve index list: %w", err)
	}
	found := false
	for indexRows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := indexRows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			_ = indexRows.Close()
			return false, fmt.Errorf("inspect route reserve index list: %w", err)
		}
		if name == "route_reserve_generation_idx" {
			found = unique == 0 && partial == 0
		}
	}
	if err := indexRows.Err(); err != nil {
		_ = indexRows.Close()
		return false, fmt.Errorf("inspect route reserve index list: %w", err)
	}
	if err := indexRows.Close(); err != nil {
		return false, fmt.Errorf("close route reserve index list: %w", err)
	}
	if !found {
		return false, nil
	}
	rows, err := querier.QueryContext(ctx, `PRAGMA index_info(route_reserve_generation_idx)`)
	if err != nil {
		return false, fmt.Errorf("inspect route reserve index: %w", err)
	}
	defer rows.Close()
	columns := make([]string, 0, 3)
	for rows.Next() {
		var sequence, cid int
		var name string
		if err := rows.Scan(&sequence, &cid, &name); err != nil {
			return false, fmt.Errorf("inspect route reserve index: %w", err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("inspect route reserve index: %w", err)
	}
	return strings.Join(columns, ",") == "stage,generation,client_id", nil
}

func normalizeSchemaSQL(value string) string {
	return strings.Map(func(character rune) rune {
		switch character {
		case ' ', '\t', '\n', '\r', '"', '`', '[', ']':
			return -1
		default:
			return character
		}
	}, strings.ToLower(value))
}
