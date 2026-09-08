package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestCandidateProbeCandidateIndexMigrationV16RepairsProductionLookup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO failure_domain_state(
			domain, canary_candidate, updated_at
		) VALUES ('orphan-domain', 'orphan-candidate', unixepoch());
		INSERT INTO failure_domain_evidence(
			domain, candidate_id, last_failed_at
		) VALUES ('orphan-domain', 'orphan-candidate', unixepoch());
		INSERT INTO candidate_health(
			candidate_id, score, tcp_qualified, udp_qualified, available, updated_at
		) VALUES ('orphan-candidate', 1, 0, 0, 0, unixepoch());
		INSERT INTO candidate_probe_state(
			fingerprint, candidate_id, source_id, status, updated_at
		) VALUES ('orphan-fingerprint', 'orphan-candidate', 'removed-source', 'unknown', unixepoch());
		INSERT INTO probe_samples(
			candidate_id, success, latency_ms, throughput_mbps,
			packet_drop_ratio, created_at
		) VALUES ('orphan-candidate', 0, 0, 0, 1, unixepoch());
		DROP INDEX IF EXISTS candidate_probe_state_candidate_idx;
		DELETE FROM schema_migrations WHERE version=16;
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var migration int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=16
	`).Scan(&migration); err != nil || migration != 1 {
		t.Fatalf("v16 migration=%d err=%v", migration, err)
	}
	rows, err := database.db.QueryContext(ctx, `
		SELECT name FROM pragma_index_info('candidate_probe_state_candidate_idx')
		ORDER BY seqno
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(columns, ",") != "candidate_id" {
		t.Fatalf("candidate probe lookup index columns=%v", columns)
	}
	for _, table := range []string{
		"candidate_health", "candidate_probe_state", "probe_samples",
		"failure_domain_evidence",
	} {
		var count int
		if err := database.db.QueryRowContext(ctx,
			`SELECT count(*) FROM `+table+` WHERE candidate_id='orphan-candidate'`,
		).Scan(&count); err != nil {
			t.Fatalf("inspect %s orphan cleanup: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("v16 retained %d orphan rows in %s", count, table)
		}
	}
	var canary string
	if err := database.db.QueryRowContext(ctx, `
		SELECT canary_candidate FROM failure_domain_state
		WHERE domain='orphan-domain'
	`).Scan(&canary); err != nil {
		t.Fatal(err)
	}
	if canary != "" {
		t.Fatalf("v16 retained orphan canary candidate %q", canary)
	}
}

func TestCandidateObservationOrderingMigrationAddsZeroClocksAndReplaysSafely(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("https://observation.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "legacy candidate",
		Fingerprint: "legacy-observation-fingerprint",
		Payload:     "vless://legacy@example.net:443",
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, sourceRows[0].ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	probeAt := time.Unix(1_800_000_123, 0)
	if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
		Fingerprint: candidate.Fingerprint,
		CandidateID: candidate.ID,
		SourceID:    candidate.SourceID,
		Full:        true,
		Success:     true,
		Score:       87,
		At:          probeAt,
	}); err != nil {
		t.Fatal(err)
	}
	healthAt := probeAt.Add(17 * time.Second)
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID:  candidate.ID,
		Score:        87,
		TCPQualified: true,
		UDPQualified: true,
		Available:    true,
		UpdatedAt:    healthAt,
	}); err != nil {
		t.Fatal(err)
	}
	downgradeCandidateObservationSchemaToV7(t, database)
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	for reopen := 0; reopen < 2; reopen++ {
		database, err = Open(path, box)
		if err != nil {
			t.Fatalf("reopen %d: %v", reopen+1, err)
		}
		if reopen == 0 {
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()

	for table, columns := range map[string][]string{
		"candidate_probe_state": {
			"fast_result_seq",
			"fast_applied_seq",
			"observation_placeholder",
		},
		"candidate_health": {
			"full_result_seq",
			"active_result_seq",
			"full_applied_seq",
			"active_applied_seq",
			"failure_generation",
			"observation_placeholder",
		},
	} {
		for _, column := range columns {
			var (
				notNull      int
				defaultValue sql.NullString
			)
			if err := database.db.QueryRowContext(ctx, `
				SELECT "notnull", dflt_value
				FROM pragma_table_info(?)
				WHERE name = ?
			`, table, column).Scan(&notNull, &defaultValue); err != nil {
				t.Fatalf("inspect %s.%s: %v", table, column, err)
			}
			if notNull != 1 || !defaultValue.Valid || defaultValue.String != "0" {
				t.Fatalf("%s.%s notnull=%d default=%+v", table, column, notNull, defaultValue)
			}
		}
	}

	var (
		fastResultSeq, fullResultSeq, activeResultSeq    int64
		fastAppliedSeq, fullAppliedSeq, activeAppliedSeq int64
		failureGeneration                                int64
		lastFullProbeAt, probeUpdatedAt, healthUpdatedAt int64
	)
	if err := database.db.QueryRowContext(ctx, `
		SELECT p.fast_result_seq, h.full_result_seq, h.active_result_seq,
		       p.fast_applied_seq, h.full_applied_seq, h.active_applied_seq,
		       h.failure_generation, p.last_full_probe_at, p.updated_at,
		       h.updated_at
		FROM candidate_probe_state p
		JOIN candidate_health h ON h.candidate_id = p.candidate_id
		WHERE p.fingerprint = ?
	`, candidate.Fingerprint).Scan(
		&fastResultSeq, &fullResultSeq, &activeResultSeq,
		&fastAppliedSeq, &fullAppliedSeq, &activeAppliedSeq,
		&failureGeneration,
		&lastFullProbeAt, &probeUpdatedAt, &healthUpdatedAt,
	); err != nil {
		t.Fatal(err)
	}
	if fastResultSeq != 0 || fullResultSeq != 0 || activeResultSeq != 0 ||
		fastAppliedSeq != 0 || fullAppliedSeq != 0 || activeAppliedSeq != 0 ||
		failureGeneration != 0 {
		t.Fatalf("observation defaults=%d,%d,%d,%d,%d,%d,%d",
			fastResultSeq, fullResultSeq, activeResultSeq,
			fastAppliedSeq, fullAppliedSeq, activeAppliedSeq,
			failureGeneration)
	}
	if lastFullProbeAt != probeAt.Unix() || probeUpdatedAt != probeAt.Unix() ||
		healthUpdatedAt != healthAt.Unix() {
		t.Fatalf("timestamps last_full=%d probe_updated=%d health_updated=%d",
			lastFullProbeAt, probeUpdatedAt, healthUpdatedAt)
	}

	var migrationCount int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 8`,
	).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration version 8 count=%d", migrationCount)
	}
}

func downgradeCandidateObservationSchemaToV7(t *testing.T, database *Store) {
	t.Helper()
	ctx := context.Background()
	for table, columns := range map[string][]string{
		"candidate_probe_state": {
			"fast_result_seq",
			"fast_applied_seq",
			"observation_placeholder",
		},
		"candidate_health": {
			"full_result_seq",
			"active_result_seq",
			"full_applied_seq",
			"active_applied_seq",
			"failure_generation",
			"observation_placeholder",
			"active_observed_at",
			"active_success",
			"active_failure_generation",
			"active_hard_failure",
		},
		"plan_state": {
			"desired_reason",
		},
	} {
		for _, column := range columns {
			var count int
			if err := database.db.QueryRowContext(ctx, `
				SELECT count(*)
				FROM pragma_table_info(?)
				WHERE name = ?
			`, table, column).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				continue
			}
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE `+table+` DROP COLUMN `+column,
			); err != nil {
				t.Fatalf("drop %s.%s: %v", table, column, err)
			}
		}
	}
	if _, err := database.db.ExecContext(ctx, `DROP TABLE route_reserve_mappings`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version > 7`,
	); err != nil {
		t.Fatal(err)
	}
	var latestVersion int
	if err := database.db.QueryRowContext(ctx,
		`SELECT max(version) FROM schema_migrations`,
	).Scan(&latestVersion); err != nil {
		t.Fatal(err)
	}
	if latestVersion != 7 {
		t.Fatalf("fixture schema version=%d, want 7", latestVersion)
	}
}

func TestRecordCandidateProbeRejectsCandidateRemovedByRefresh(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "removed", Fingerprint: "removed", Payload: "vless://removed@example.net:443"},
		{Kind: sources.KindVLESS, Label: "current", Fingerprint: "current", Payload: "vless://current@example.net:443"},
	})
	removed := candidates["removed"]
	at := time.Unix(1_800_000_000, 0)
	before, err := database.RecordCandidateProbe(ctx, ProbeTransition{
		Fingerprint: removed.Fingerprint, CandidateID: removed.ID, SourceID: removed.SourceID,
		Success: true, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(ctx, removed.SourceID, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "current", Fingerprint: "current", Payload: "vless://current@example.net:443"},
	}); err != nil {
		t.Fatal(err)
	}

	health := CandidateHealth{
		CandidateID: removed.ID, Score: 99, TCPQualified: true,
		Available: true, UpdatedAt: at.Add(time.Minute),
	}
	sample := ProbeSample{
		CandidateID: removed.ID, Success: true, LatencyMS: 10,
		ThroughputMbps: 20, CreatedAt: at.Add(time.Minute),
	}
	_, err = database.RecordCandidateProbeResult(ctx, ProbeTransition{
		Fingerprint: removed.Fingerprint, CandidateID: removed.ID, SourceID: removed.SourceID,
		Full: true, Success: true, Score: 99, At: at.Add(time.Minute),
	}, &health, &sample)
	if !errors.Is(err, ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	after, err := database.CandidateProbeState(ctx, removed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if after.FullSuccessStreak != before.FullSuccessStreak ||
		after.Status != before.Status ||
		!after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("removed candidate state changed: before=%+v after=%+v", before, after)
	}
	var healthCount, sampleCount int
	if err := database.db.QueryRowContext(
		ctx, `SELECT count(*) FROM candidate_health WHERE candidate_id = ?`, removed.ID,
	).Scan(&healthCount); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(
		ctx, `SELECT count(*) FROM probe_samples WHERE candidate_id = ?`, removed.ID,
	).Scan(&sampleCount); err != nil {
		t.Fatal(err)
	}
	if healthCount != 0 || sampleCount != 0 {
		t.Fatalf("stale result wrote health=%d samples=%d", healthCount, sampleCount)
	}
}

func TestRecordCandidateHealthResultRejectsCandidateRemovedByRefresh(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "removed", Fingerprint: "removed",
			Payload: "vless://removed@example.net:443",
		},
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443",
		},
	})
	removed := candidates["removed"]
	if err := database.ReplaceCandidates(ctx, removed.SourceID, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443",
		},
	}); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_800_000_000, 0)
	health := CandidateHealth{
		CandidateID: removed.ID, Score: 99, TCPQualified: true,
		Available: true, UpdatedAt: at,
	}
	sample := ProbeSample{CandidateID: removed.ID, Success: true, CreatedAt: at}
	err := database.RecordCandidateHealthResult(ctx, removed, &health, &sample)
	if !errors.Is(err, ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	var healthCount, sampleCount int
	if err := database.db.QueryRowContext(
		ctx, `SELECT count(*) FROM candidate_health WHERE candidate_id = ?`, removed.ID,
	).Scan(&healthCount); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(
		ctx, `SELECT count(*) FROM probe_samples WHERE candidate_id = ?`, removed.ID,
	).Scan(&sampleCount); err != nil {
		t.Fatal(err)
	}
	if healthCount != 0 || sampleCount != 0 {
		t.Fatalf("stale health result wrote health=%d samples=%d", healthCount, sampleCount)
	}
}

func TestReplaceWorkingPoolCurrentAppliesOnlyExactCurrentInventory(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "removed", Fingerprint: "removed",
			Payload: "vless://removed@example.net:443",
		},
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	for _, candidate := range []Candidate{candidates["removed"], candidates["current"]} {
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 90, At: now.Add(time.Duration(attempt) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	removed := candidates["removed"]
	current := candidates["current"]
	if err := database.ReplaceCandidates(ctx, removed.SourceID, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443",
		},
	}); err != nil {
		t.Fatal(err)
	}
	applied, err := database.ReplaceWorkingPoolCurrent(
		ctx,
		[]Candidate{removed, current},
		nil,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Active) != 1 || applied.Active[0].ID != current.ID {
		t.Fatalf("applied active=%+v, want only current candidate", applied.Active)
	}
	removedState, err := database.CandidateProbeState(ctx, removed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	currentState, err := database.CandidateProbeState(ctx, current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if removedState.InWorkingPool || removedState.Draining || !currentState.InWorkingPool {
		t.Fatalf("removed=%+v current=%+v", removedState, currentState)
	}
}

func TestClearWorkingPoolByKindPreservesVLESSMembership(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "vless", Fingerprint: "vless",
			Payload: "vless://vless@example.net:443",
		},
		{
			Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
				Fingerprint: candidate.Fingerprint,
				CandidateID: candidate.ID,
				SourceID:    candidate.SourceID,
				Full:        true,
				Success:     true,
				Score:       90,
				At: now.Add(
					time.Duration(attempt) * time.Second,
				),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := database.ReplaceWorkingPool(
		ctx, []string{"vless", "tor"}, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.ClearWorkingPoolByKind(
		ctx, sources.KindTorBridge,
	); err != nil {
		t.Fatal(err)
	}
	vlessState, err := database.CandidateProbeState(ctx, "vless")
	if err != nil {
		t.Fatal(err)
	}
	torState, err := database.CandidateProbeState(ctx, "tor")
	if err != nil {
		t.Fatal(err)
	}
	if !vlessState.InWorkingPool || vlessState.Draining {
		t.Fatalf("VLESS membership was cleared: %+v", vlessState)
	}
	if torState.InWorkingPool || torState.Draining {
		t.Fatalf("Tor membership survived targeted clear: %+v", torState)
	}
}

func candidateStateTestStore(
	t *testing.T,
	inputs []CandidateInput,
) (*Store, map[string]Candidate) {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(context.Background())
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(context.Background(), sourceRows[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(context.Background(), sourceRows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	candidates := make(map[string]Candidate, len(rows))
	for _, candidate := range rows {
		candidates[candidate.Fingerprint] = candidate
	}
	return database, candidates
}

func TestOpenMigratesCandidateProbeStateWithoutLosingV1Data(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("vless://user@example.net:443?security=tls")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	const fingerprint = "stable-fingerprint"
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind:        sources.KindVLESS,
		Label:       "candidate",
		Fingerprint: fingerprint,
		Payload:     "vless://user@example.net:443?security=tls",
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, sourceRows[0].ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "[Interface]\nPrivateKey = encrypted-secret\n"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates[0].ID, UDPOutbound: candidates[0].ID,
		TCPSince: now, UDPSince: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidates[0].ID, Score: 91, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `DROP TABLE candidate_probe_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	state, err := database.CandidateProbeState(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Stale || state.LastScore != 91 {
		t.Fatalf("state=%+v", state)
	}
	config, err := database.ClientConfig(ctx, "alice")
	if err != nil || config != "[Interface]\nPrivateKey = encrypted-secret\n" {
		t.Fatalf("config=%q err=%v", config, err)
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil || len(assignments) != 1 ||
		assignments[0].TCPOutbound != candidates[0].ID ||
		assignments[0].UDPOutbound != candidates[0].ID {
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
}

func TestOpenMigratesCandidateSourcePositionWithoutLosingOrder(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	sourceID := sourceRows[0].ID
	initial := []CandidateInput{
		{Kind: sources.KindTorBridge, Label: "z", Fingerprint: "z", Payload: validBridge(1)},
		{Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a", Payload: validBridge(2)},
		{Kind: sources.KindTorBridge, Label: "m", Fingerprint: "m", Payload: validBridge(3)},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, initial); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt != candidates[j].CreatedAt {
			return candidates[i].CreatedAt < candidates[j].CreatedAt
		}
		return candidates[i].ID < candidates[j].ID
	})
	fallbackOrder := make([]string, len(candidates))
	for index, candidate := range candidates {
		fallbackOrder[index] = candidate.Fingerprint
	}

	if _, err := database.db.ExecContext(ctx, `
		DROP INDEX IF EXISTS candidates_source_position_idx;
		ALTER TABLE candidates DROP COLUMN source_position;
		DELETE FROM schema_migrations WHERE version = 3;
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var migrationCount int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 3`,
	).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration version 3 count=%d", migrationCount)
	}
	requireCandidateOrder(t, database, sourceID, fallbackOrder)

	refreshed := []CandidateInput{
		{Kind: sources.KindTorBridge, Label: "m", Fingerprint: "m", Payload: validBridge(3)},
		{Kind: sources.KindTorBridge, Label: "z", Fingerprint: "z", Payload: validBridge(1)},
		{Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a", Payload: validBridge(2)},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, refreshed); err != nil {
		t.Fatal(err)
	}
	requireCandidateOrder(t, database, sourceID, []string{"m", "z", "a"})
}
