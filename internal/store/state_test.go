package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestParseTorPlanHandlerAcceptsVersionedProfileIdentity(t *testing.T) {
	candidateID, clientID, ok := parseTorPlanHandler(
		"cand_tor-profile-7-a1b2c3d4e5f6-client-alice",
	)
	if !ok || candidateID != "cand_tor" || clientID != "alice" {
		t.Fatalf("candidate=%q client=%q ok=%v", candidateID, clientID, ok)
	}
}

func TestVisionUDP443HandlerPreservesCandidateBindingsAndBackup(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443?flow=xtls-rprx-vision"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key"}, "secret"); err != nil {
		t.Fatal(err)
	}
	primary := candidates["primary"].ID
	reserve := candidates["reserve"].ID
	versioned := primary + "-vision-udp443-v1"
	plan := vlessReservePlanBytes(t, 1, "alice", versioned, versioned, reserve, reserve)
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = database.SaveDesiredPlanSnapshotForCandidatesAndReserves(ctx, 1, plan, epoch,
		[]CandidatePlanExpectation{{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]}},
		[]RouteReserveMapping{{ClientID: "alice", TCPPrimaryCandidateID: primary, UDPPrimaryCandidateID: primary, TCPReserveCandidateID: reserve, UDPReserveCandidateID: reserve}},
		[]AssignmentRecord{{ClientID: "alice", TCPOutbound: primary, UDPOutbound: primary}})
	if err != nil {
		t.Fatalf("save versioned plan: %v", err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, plan); err != nil {
		t.Fatalf("apply versioned plan: %v", err)
	}
	if got := normalizePersistedCandidateID(versioned); got != primary {
		t.Fatalf("retirement candidate=%q, want %q", got, primary)
	}
	backup := filepath.Join(t.TempDir(), "vision.db")
	if err := database.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backup, database.box); err != nil {
		t.Fatalf("versioned plan backup: %v", err)
	}
}

func TestMarkAppliedPlanAtomicallyRecordsTransportMigrationReason(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "old", Fingerprint: "old", Payload: "vless://old@example.net:443"},
		{Kind: sources.KindVLESS, Label: "new", Fingerprint: "new", Payload: "vless://new@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	apply := func(generation int64, candidate Candidate, reason string) {
		t.Helper()
		encoded := vlessReservePlanBytes(
			t, generation, "alice", candidate.ID, "", "", "",
		)
		if err := database.SaveDesiredPlanSnapshotForCandidatesAndReservesWithReason(
			ctx, generation, encoded, reason, epoch,
			[]CandidatePlanExpectation{{Candidate: candidate}}, nil,
			[]AssignmentRecord{{
				ClientID: "alice", TCPOutbound: candidate.ID,
				TCPSince: now, UDPSince: now, UpdatedAt: now,
			}},
		); err != nil {
			t.Fatal(err)
		}
		if err := database.MarkAppliedPlan(ctx, generation, encoded); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, candidates["old"], "startup_normalization")
	apply(2, candidates["new"], "hard_failure")
	events, err := database.ListEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "assignment.migrated" ||
		events[0].ClientID != "alice" || events[0].CandidateID != candidates["new"].ID {
		t.Fatalf("migration events=%+v", events)
	}
	var detail struct {
		Transport string `json:"transport"`
		From      string `json:"from"`
		To        string `json:"to"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(events[0].Message), &detail); err != nil {
		t.Fatalf("migration message=%q: %v", events[0].Message, err)
	}
	if detail.Transport != "tcp" || detail.From != candidates["old"].ID ||
		detail.To != candidates["new"].ID || detail.Reason != "hard_failure" {
		t.Fatalf("migration detail=%+v", detail)
	}
}

func TestAssignmentMigrationReasonDistinguishesQoEFailureFromQualityImprovement(t *testing.T) {
	if got := assignmentMigrationReason("qoe_degraded"); got != "qoe_degraded" {
		t.Fatalf("QoE migration reason=%q", got)
	}
	if got := assignmentMigrationReason("periodic"); got != "quality_30_percent" {
		t.Fatalf("periodic migration reason=%q", got)
	}
	if got := assignmentMigrationReason("pool_promotion"); got != "capacity" {
		t.Fatalf("pool-promotion migration reason=%q", got)
	}
}

func TestLoadPlanStateReturnsPersistedSemanticBytes(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	initial, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.DesiredGeneration != 0 || initial.AppliedGeneration != 0 ||
		len(initial.DesiredPlan) != 0 || len(initial.AppliedPlan) != 0 {
		t.Fatalf("initial plan state=%+v", initial)
	}

	desired := []byte("{\n  \"generation\": 4,\n  \"marker\": \"desired\"\n}\n")
	if err := database.SaveDesiredPlan(ctx, 4, desired); err != nil {
		t.Fatal(err)
	}
	pending, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.DesiredGeneration != 4 || pending.AppliedGeneration != 0 ||
		!bytes.Equal(pending.DesiredPlan, desired) || len(pending.AppliedPlan) != 0 {
		t.Fatalf("pending plan state=%+v", pending)
	}

	pending.DesiredPlan[0] = 'x'
	reloaded, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded.DesiredPlan, desired) {
		t.Fatalf("loaded desired bytes alias caller memory: %q", reloaded.DesiredPlan)
	}

	if err := database.MarkAppliedPlan(ctx, 4, desired); err != nil {
		t.Fatal(err)
	}
	applied, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied.DesiredGeneration != 4 || applied.AppliedGeneration != 4 ||
		!bytes.Equal(applied.DesiredPlan, desired) || !bytes.Equal(applied.AppliedPlan, desired) {
		t.Fatalf("applied plan state=%+v", applied)
	}
}

func TestDesiredPlanReasonPersistsWithGeneration(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	plan := []byte(`{"generation":1}`)
	if err := database.SaveDesiredPlanWithReason(
		ctx, 1, plan, "hard_failure",
	); err != nil {
		t.Fatal(err)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 1 || state.DesiredReason != "hard_failure" {
		t.Fatalf("plan state=%+v", state)
	}
}

func TestPlanReasonMigrationV14BackfillsLegacyPendingFailClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(dataplane.DesiredPlan{
		Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 1, plan); err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.db.ExecContext(ctx, `
		ALTER TABLE plan_state DROP COLUMN desired_reason;
		DELETE FROM schema_migrations WHERE version=14;
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.migrateDesiredPlanReason(ctx); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := database.db.QueryRowContext(ctx, `
		SELECT desired_reason FROM plan_state WHERE singleton=1
	`).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "legacy" {
		t.Fatalf("migrated pending reason=%q", reason)
	}
}

func TestRouteReserveMigrationV11RepairsPartialMarkerAndPreservesSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "wireguard-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		DROP TABLE route_reserve_mappings;
		INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (11, unixepoch());
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
	var tableRows, migrationRows, indexRows int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_master
		WHERE type='table' AND name='route_reserve_mappings'
	`).Scan(&tableRows); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=11
	`).Scan(&migrationRows); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_master
		WHERE type='index' AND name='route_reserve_generation_idx'
	`).Scan(&indexRows); err != nil {
		t.Fatal(err)
	}
	if tableRows != 1 || migrationRows != 1 || indexRows != 1 {
		t.Fatalf("v11 table=%d marker=%d index=%d", tableRows, migrationRows, indexRows)
	}
	config, err := database.ClientConfig(ctx, "alice")
	if err != nil || config != "wireguard-secret" {
		t.Fatalf("encrypted client config=%q err=%v", config, err)
	}
}

func TestRouteReserveMigrationRebasesLegacyPendingPlanWithoutSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "wireguard-secret"); err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "old", Fingerprint: "old", Payload: "vless://old@example.net:443"},
		{Kind: sources.KindVLESS, Label: "new", Fingerprint: "new", Payload: "vless://new@example.net:443"},
	}); err != nil {
		t.Fatal(err)
	}
	candidateRows, err := database.ListCandidates(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	candidates := make(map[string]Candidate)
	for _, candidate := range candidateRows {
		candidates[candidate.Label] = candidate
	}
	oldPlan := vlessReservePlanBytes(t, 1, "alice", candidates["old"].ID, "", "", "")
	stalePlan := vlessReservePlanBytes(t, 2, "alice", candidates["new"].ID, "", "", "")
	if err := database.SetAssignment(ctx, AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates["old"].ID,
		TCPSince: time.Unix(1_900_000_000, 0), UDPSince: time.Unix(1_900_000_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 1, oldPlan); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, oldPlan); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates["new"].ID,
		TCPSince: time.Unix(1_900_000_100, 0), UDPSince: time.Unix(1_900_000_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 2, stalePlan); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		DELETE FROM schema_migrations WHERE version=11;
		DROP TABLE route_reserve_mappings;
		ALTER TABLE plan_state DROP COLUMN desired_assignments;
		ALTER TABLE plan_state DROP COLUMN desired_assignments_generation;
		ALTER TABLE plan_state DROP COLUMN invalidated_generation;
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
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 1 || state.AppliedGeneration != 1 ||
		!bytes.Equal(state.DesiredPlan, oldPlan) || !bytes.Equal(state.AppliedPlan, oldPlan) {
		t.Fatalf("unsafe legacy pending plan survived v11 migration: %+v", state)
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != candidates["new"].ID {
		t.Fatalf("migration lost the pending assignment input: %+v", assignments)
	}
	var snapshotGeneration int64
	var invalidatedGeneration int64
	var snapshot []byte
	if err := database.db.QueryRowContext(ctx, `
		SELECT desired_assignments_generation, desired_assignments,
		       invalidated_generation
		FROM plan_state WHERE singleton=1
	`).Scan(&snapshotGeneration, &snapshot, &invalidatedGeneration); err != nil {
		t.Fatal(err)
	}
	if snapshotGeneration != 0 || len(snapshot) != 0 || invalidatedGeneration != 2 {
		t.Fatalf(
			"migration snapshot generation=%d bytes=%q invalidated=%d",
			snapshotGeneration, snapshot, invalidatedGeneration,
		)
	}
	backupPath := filepath.Join(t.TempDir(), "rebased.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err != nil {
		t.Fatalf("rebased legacy state is not backup-safe: %v", err)
	}
}

func TestRouteReserveMigrationV11RepairsMissingColumnAndIndexAcrossReopen(t *testing.T) {
	tests := []struct {
		name    string
		corrupt string
	}{
		{
			name: "missing column",
			corrupt: `ALTER TABLE route_reserve_mappings
			          DROP COLUMN udp_reserve_candidate_id`,
		},
		{
			name:    "missing index",
			corrupt: `DROP INDEX route_reserve_generation_idx`,
		},
		{
			name:    "missing assignment snapshot column",
			corrupt: `ALTER TABLE plan_state DROP COLUMN desired_assignments`,
		},
		{
			name:    "missing invalidated generation column",
			corrupt: `ALTER TABLE plan_state DROP COLUMN invalidated_generation`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(test.corrupt); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			for reopen := 0; reopen < 2; reopen++ {
				database, err = Open(path, box)
				if err != nil {
					t.Fatalf("reopen %d: %v", reopen+1, err)
				}
				var columnRows, indexRows, assignmentColumns int
				if err := database.db.QueryRow(`
					SELECT count(*) FROM pragma_table_info('route_reserve_mappings')
					WHERE name='udp_reserve_candidate_id'
				`).Scan(&columnRows); err != nil {
					t.Fatal(err)
				}
				if err := database.db.QueryRow(`
					SELECT count(*) FROM pragma_index_list('route_reserve_mappings')
					WHERE name='route_reserve_generation_idx'
				`).Scan(&indexRows); err != nil {
					t.Fatal(err)
				}
				if err := database.db.QueryRow(`
					SELECT count(*) FROM pragma_table_info('plan_state')
					WHERE name IN (
					  'desired_assignments_generation', 'desired_assignments',
					  'invalidated_generation'
					)
				`).Scan(&assignmentColumns); err != nil {
					t.Fatal(err)
				}
				if columnRows != 1 || indexRows != 1 || assignmentColumns != 3 {
					t.Fatalf("reopen %d column=%d index=%d assignment_columns=%d",
						reopen+1, columnRows, indexRows, assignmentColumns)
				}
				if err := database.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRouteReserveMigrationV11RejectsWrongForeignKeyOrCheckBeforeUse(t *testing.T) {
	tests := []struct {
		name   string
		schema string
	}{
		{
			name: "wrong foreign key",
			schema: `CREATE TABLE route_reserve_mappings (
			  stage TEXT NOT NULL CHECK(stage IN ('desired', 'applied')),
			  client_id TEXT NOT NULL REFERENCES clients(id),
			  generation INTEGER NOT NULL CHECK(generation > 0),
			  tcp_primary_candidate_id TEXT NOT NULL DEFAULT '',
			  tcp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
			  udp_primary_candidate_id TEXT NOT NULL DEFAULT '',
			  udp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
			  PRIMARY KEY(stage, client_id)
			)`,
		},
		{
			name: "wrong check",
			schema: `CREATE TABLE route_reserve_mappings (
			  stage TEXT NOT NULL,
			  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
			  generation INTEGER NOT NULL CHECK(generation >= 0),
			  tcp_primary_candidate_id TEXT NOT NULL DEFAULT '',
			  tcp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
			  udp_primary_candidate_id TEXT NOT NULL DEFAULT '',
			  udp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
			  PRIMARY KEY(stage, client_id)
			)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`DROP TABLE route_reserve_mappings`); err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(test.schema); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path, box); err == nil {
				_ = reopened.Close()
				t.Fatal("incompatible v11 schema was accepted")
			} else if !strings.Contains(err.Error(), "incompatible route reserve schema") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRouteReserveSchemaIntentionallyUsesLifecycleFencingInsteadOfCandidateForeignKeys(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.db.Query(`PRAGMA foreign_key_list(route_reserve_mappings)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	foreignKeys := make(map[string]string)
	for rows.Next() {
		var id, sequence int
		var table, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatal(err)
		}
		foreignKeys[from] = table + "." + to + ":" + onDelete
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(foreignKeys, map[string]string{
		"client_id": "clients.id:CASCADE",
	}) {
		t.Fatalf("route reserve foreign keys=%v", foreignKeys)
	}
}

func TestValidateBackupConditionallyRequiresV11RouteReserveSchema(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	v11Backup := filepath.Join(t.TempDir(), "v11.db")
	if err := database.Backup(ctx, v11Backup); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(v11Backup, box); err != nil {
		t.Fatalf("valid v11 backup: %v", err)
	}

	if _, err := database.db.Exec(`
		DROP TABLE route_reserve_mappings;
		DELETE FROM schema_migrations WHERE version=11;
	`); err != nil {
		t.Fatal(err)
	}
	preV11Backup := filepath.Join(t.TempDir(), "v10.db")
	if err := database.Backup(ctx, preV11Backup); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(preV11Backup, box); err != nil {
		t.Fatalf("valid pre-v11 backup: %v", err)
	}
	migrated, err := Open(preV11Backup, box)
	if err != nil {
		t.Fatalf("migrate pre-v11 backup: %v", err)
	}
	if err := migrated.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := database.db.Exec(`
		INSERT INTO schema_migrations(version, applied_at) VALUES (11, unixepoch())
	`); err != nil {
		t.Fatal(err)
	}
	corruptBackup := filepath.Join(t.TempDir(), "corrupt-v11.db")
	if err := database.Backup(ctx, corruptBackup); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(corruptBackup, box); err == nil {
		t.Fatal("v11 backup without route reserve table was accepted")
	}
}

func TestRouteReserveDesiredAndAppliedStateIsAtomicAndGenerationBound(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
		{Kind: sources.KindVLESS, Label: "next", Fingerprint: "next", Payload: "vless://next@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "wireguard-secret"); err != nil {
		t.Fatal(err)
	}
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expectations := []CandidatePlanExpectation{
		{Candidate: candidates["primary"]},
		{Candidate: candidates["reserve"]},
		{Candidate: candidates["next"]},
	}
	first := RouteReserveMapping{
		ClientID:              "alice",
		TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["reserve"].ID,
		UDPPrimaryCandidateID: candidates["primary"].ID,
		UDPReserveCandidateID: candidates["reserve"].ID,
	}
	now := time.Unix(1_900_000_000, 0)
	assignment := AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates["primary"].ID,
		UDPOutbound: candidates["primary"].ID, TCPSince: now, UDPSince: now,
		UpdatedAt: now,
	}
	firstEncoded := vlessReservePlanBytes(
		t, 1, "alice", candidates["primary"].ID, candidates["primary"].ID,
		candidates["reserve"].ID, candidates["reserve"].ID,
	)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, firstEncoded, epoch, expectations,
		[]RouteReserveMapping{first}, []AssignmentRecord{assignment},
	); err != nil {
		t.Fatal(err)
	}
	var desiredGeneration int64
	if err := database.db.QueryRowContext(ctx, `
		SELECT generation FROM route_reserve_mappings
		WHERE stage='desired' AND client_id='alice'
	`).Scan(&desiredGeneration); err != nil {
		t.Fatal(err)
	}
	if desiredGeneration != 1 {
		t.Fatalf("desired reserve generation=%d want=1", desiredGeneration)
	}
	if reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	); err != nil || ok || reserve != "" {
		t.Fatalf("desired mapping leaked before apply reserve=%q ok=%v err=%v", reserve, ok, err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, firstEncoded); err != nil {
		t.Fatal(err)
	}
	generation, appliedMappings, err := database.ListAppliedReserveMappings(ctx)
	if err != nil || generation != 1 || len(appliedMappings) != 1 ||
		appliedMappings[0] != first {
		t.Fatalf("applied mapping snapshot generation=%d mappings=%+v err=%v",
			generation, appliedMappings, err)
	}
	for _, protocol := range []RouteTransport{RouteTransportTCP, RouteTransportUDP} {
		reserve, ok, err := database.AppliedReserveForFailure(
			ctx, "alice", protocol, candidates["primary"].ID,
		)
		if err != nil || !ok || reserve != candidates["reserve"].ID {
			t.Fatalf("%s reserve=%q ok=%v err=%v", protocol, reserve, ok, err)
		}
	}
	var databasePath string
	if err := database.db.QueryRowContext(ctx, `
		SELECT file FROM pragma_database_list WHERE name='main'
	`).Scan(&databasePath); err != nil {
		t.Fatal(err)
	}
	box := database.box
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(databasePath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	); err != nil || !ok || reserve != candidates["reserve"].ID {
		t.Fatalf("restart reserve=%q ok=%v err=%v", reserve, ok, err)
	}
	if reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["next"].ID,
	); err != nil || ok || reserve != "" {
		t.Fatalf("wrong-primary lookup reserve=%q ok=%v err=%v", reserve, ok, err)
	}

	second := RouteReserveMapping{
		ClientID:              "alice",
		TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["next"].ID,
		UDPPrimaryCandidateID: candidates["primary"].ID,
		UDPReserveCandidateID: candidates["next"].ID,
	}
	secondEncoded := vlessReservePlanBytes(
		t, 2, "alice", candidates["primary"].ID, candidates["primary"].ID,
		candidates["next"].ID, candidates["next"].ID,
	)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 2, secondEncoded, epoch, expectations,
		[]RouteReserveMapping{second}, []AssignmentRecord{assignment},
	); err != nil {
		t.Fatal(err)
	}
	reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	)
	if err != nil || !ok || reserve != candidates["reserve"].ID {
		t.Fatalf("future desired mapping replaced applied reserve=%q ok=%v err=%v", reserve, ok, err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, firstEncoded); err == nil {
		t.Fatal("stale concurrent apply was accepted")
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil || len(assignments) != 1 || assignments[0].TCPOutbound != candidates["primary"].ID {
		t.Fatalf("stale apply partially changed assignments=%+v err=%v", assignments, err)
	}
	reserve, ok, err = database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	)
	if err != nil || !ok || reserve != candidates["reserve"].ID {
		t.Fatalf("stale apply partially changed mapping reserve=%q ok=%v err=%v", reserve, ok, err)
	}
	if err := database.MarkAppliedPlan(ctx, 2, secondEncoded); err != nil {
		t.Fatal(err)
	}
	reserve, ok, err = database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	)
	if err != nil || !ok || reserve != candidates["next"].ID {
		t.Fatalf("applied generation 2 reserve=%q ok=%v err=%v", reserve, ok, err)
	}

	thirdEncoded := vlessReservePlanBytes(
		t, 3, "alice", candidates["primary"].ID, candidates["primary"].ID, "", "",
	)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 3, thirdEncoded, epoch, expectations, nil, []AssignmentRecord{assignment},
	); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 3, thirdEncoded); err != nil {
		t.Fatal(err)
	}
	if reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	); err != nil || ok || reserve != "" {
		t.Fatalf("empty mapping retained reserve=%q ok=%v err=%v", reserve, ok, err)
	}
}

func TestDesiredAssignmentSnapshotPromotesExactGenerationAcrossFailureAndRestart(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	for _, client := range []ClientRecord{
		{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key"},
		{ID: "paused", Name: "Paused", Address: "10.44.0.3/32", PublicKey: "paused-key", Paused: true},
	} {
		if err := database.PutClient(ctx, client, "secret-"+client.ID); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Unix(1_900_000_000, 0)
	for _, clientID := range []string{"alice", "paused"} {
		if err := database.SetAssignment(ctx, AssignmentRecord{
			ClientID: clientID, TCPOutbound: "old", UDPOutbound: "old",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour), UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{
			{ID: candidates["primary"].ID, Protocol: dataplane.ProtocolVLESS},
			{ID: candidates["reserve"].ID, Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: candidates["primary"].ID, BlockUDP: true,
			TCPReserveOutbound: candidates["reserve"].ID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	encoded, _ := json.Marshal(plan)
	epoch, _ := database.InventoryEpoch(ctx)
	expectations := []CandidatePlanExpectation{
		{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
	}
	mappings := []RouteReserveMapping{{
		ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["reserve"].ID,
	}}
	desiredAssignments := []AssignmentRecord{
		{ClientID: "alice", TCPOutbound: candidates["primary"].ID, TCPSince: now, UDPSince: now, UpdatedAt: now},
		{ClientID: "paused", TCPSince: now, UDPSince: now, UpdatedAt: now},
	}
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encoded, epoch, expectations, mappings,
		desiredAssignments[:1],
	); err == nil {
		t.Fatal("incomplete client assignment snapshot was accepted")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 0 {
		t.Fatalf("incomplete snapshot mutated desired state=%+v", state)
	}
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encoded, epoch, expectations, mappings, desiredAssignments,
	); err != nil {
		t.Fatal(err)
	}
	assignments, _ := database.ListAssignments(ctx)
	if len(assignments) != 2 || assignments[0].TCPOutbound != "old" || assignments[1].TCPOutbound != "old" {
		t.Fatalf("desired snapshot published before apply: %+v", assignments)
	}
	if _, err := database.db.ExecContext(ctx, `
		CREATE TRIGGER fail_snapshot_promotion BEFORE INSERT ON assignments
		BEGIN SELECT RAISE(ABORT, 'forced promotion failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, encoded); err == nil {
		t.Fatal("injected snapshot promotion failure was ignored")
	}
	state, _ = database.LoadPlanState(ctx)
	assignments, _ = database.ListAssignments(ctx)
	if state.AppliedGeneration != 0 || len(assignments) != 2 ||
		assignments[0].TCPOutbound != "old" || assignments[1].TCPOutbound != "old" {
		t.Fatalf("failed promotion partially mutated state=%+v assignments=%+v", state, assignments)
	}
	var appliedMappings int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings WHERE stage='applied'
	`).Scan(&appliedMappings); err != nil {
		t.Fatal(err)
	}
	if appliedMappings != 0 {
		t.Fatalf("failed promotion published %d mappings", appliedMappings)
	}
	if _, err := database.db.ExecContext(ctx, `DROP TRIGGER fail_snapshot_promotion`); err != nil {
		t.Fatal(err)
	}
	var databasePath string
	if err := database.db.QueryRowContext(ctx, `
		SELECT file FROM pragma_database_list WHERE name='main'
	`).Scan(&databasePath); err != nil {
		t.Fatal(err)
	}
	box := database.box
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(databasePath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.MarkAppliedPlan(ctx, 1, encoded); err != nil {
		t.Fatal(err)
	}
	assignments, err = database.ListAssignments(ctx)
	if err != nil || len(assignments) != 2 ||
		assignments[0].ClientID != "alice" || assignments[0].TCPOutbound != candidates["primary"].ID ||
		assignments[1].ClientID != "paused" || assignments[1].TCPOutbound != "" || assignments[1].UDPOutbound != "" {
		t.Fatalf("promoted assignments=%+v err=%v", assignments, err)
	}
	reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", RouteTransportTCP, candidates["primary"].ID,
	)
	if err != nil || !ok || reserve != candidates["reserve"].ID {
		t.Fatalf("promoted reserve=%q ok=%v err=%v", reserve, ok, err)
	}
}

func TestRouteReserveAppliedTransactionRollsBackAssignmentsPlanAndMapping(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	epoch, _ := database.InventoryEpoch(ctx)
	mapping := RouteReserveMapping{
		ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["reserve"].ID,
	}
	expectations := []CandidatePlanExpectation{
		{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
	}
	now := time.Unix(1_900_000_000, 0)
	encoded := vlessReservePlanBytes(
		t, 1, "alice", candidates["primary"].ID, "",
		candidates["reserve"].ID, "",
	)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encoded, epoch, expectations,
		[]RouteReserveMapping{mapping}, []AssignmentRecord{{
			ClientID: "alice", TCPOutbound: candidates["primary"].ID,
			TCPSince: now, UDPSince: now, UpdatedAt: now,
		}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		CREATE TRIGGER fail_assignment BEFORE INSERT ON assignments
		BEGIN SELECT RAISE(ABORT, 'forced assignment failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	err := database.MarkAppliedPlan(ctx, 1, encoded)
	if err == nil {
		t.Fatal("injected assignment failure was ignored")
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.AppliedGeneration != 0 || len(state.AppliedPlan) != 0 {
		t.Fatalf("failed transaction advanced applied plan: %+v", state)
	}
	var appliedMappings, assignments int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings WHERE stage='applied'
	`).Scan(&appliedMappings); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM assignments`).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	if appliedMappings != 0 || assignments != 0 {
		t.Fatalf("failed transaction mapping=%d assignments=%d", appliedMappings, assignments)
	}
}

func TestRouteReserveValidationRejectsTagsDuplicatesAndMalformedPairs(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	epoch, _ := database.InventoryEpoch(ctx)
	expectations := []CandidatePlanExpectation{
		{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
	}
	valid := RouteReserveMapping{
		ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["reserve"].ID,
	}
	tests := []struct {
		name     string
		mappings []RouteReserveMapping
	}{
		{name: "duplicate client", mappings: []RouteReserveMapping{valid, valid}},
		{name: "handler tag instead of candidate", mappings: []RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID + "-profile-0-client-alice",
			TCPReserveCandidateID: candidates["reserve"].ID,
		}}},
		{name: "unknown candidate", mappings: []RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: "missing",
			TCPReserveCandidateID: candidates["reserve"].ID,
		}}},
		{name: "missing reserve half", mappings: []RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
		}}},
		{name: "same primary reserve", mappings: []RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["primary"].ID,
		}}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
				ctx, int64(index+1), []byte(fmt.Sprintf(`{"generation":%d}`, index+1)),
				epoch, expectations, test.mappings, []AssignmentRecord{{ClientID: "alice"}},
			)
			if err == nil {
				t.Fatal("invalid reserve mapping was accepted")
			}
			if strings.Contains(err.Error(), "vless://") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error exposed secret: %v", err)
			}
			state, loadErr := database.LoadPlanState(ctx)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if state.DesiredGeneration != 0 {
				t.Fatalf("invalid mapping partially saved desired plan: %+v", state)
			}
		})
	}
}

func TestSaveDesiredReservesStrictlyMatchesSerializedPlanHandlerBindings(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindTorBridge, Label: "tor-reserve", Fingerprint: "tor-reserve", Payload: "obfs4 203.0.113.2:443 cert=x iat-mode=0"},
		{Kind: sources.KindVLESS, Label: "udp-reserve", Fingerprint: "udp-reserve", Payload: "vless://udp-reserve@example.net:443"},
		{Kind: sources.KindVLESS, Label: "known-extra", Fingerprint: "known-extra", Payload: "vless://known-extra@example.net:443"},
	})
	for _, client := range []ClientRecord{
		{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key"},
		{ID: "bob", Name: "Bob", Address: "10.44.0.3/32", PublicKey: "bob-key", Paused: true},
	} {
		if err := database.PutClient(ctx, client, "secret-"+client.ID); err != nil {
			t.Fatal(err)
		}
	}
	epoch, _ := database.InventoryEpoch(ctx)
	expectations := make([]CandidatePlanExpectation, 0, len(candidates))
	for _, candidate := range candidates {
		expectations = append(expectations, CandidatePlanExpectation{Candidate: candidate})
	}
	basePlan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{
			{ID: candidates["primary"].ID, Protocol: dataplane.ProtocolVLESS},
			{ID: candidates["tor-reserve"].ID + "-profile-0-client-alice", Protocol: dataplane.ProtocolTor},
			{ID: candidates["udp-reserve"].ID, Protocol: dataplane.ProtocolVLESS},
			{ID: candidates["known-extra"].ID, Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: candidates["primary"].ID,
			UDPOutbound:        candidates["primary"].ID,
			TCPReserveOutbound: candidates["tor-reserve"].ID + "-profile-0-client-alice",
			UDPReserveOutbound: candidates["udp-reserve"].ID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	baseMapping := RouteReserveMapping{
		ClientID:              "alice",
		TCPPrimaryCandidateID: candidates["primary"].ID,
		TCPReserveCandidateID: candidates["tor-reserve"].ID,
		UDPPrimaryCandidateID: candidates["primary"].ID,
		UDPReserveCandidateID: candidates["udp-reserve"].ID,
	}
	assignments := []AssignmentRecord{
		{ClientID: "alice", TCPOutbound: candidates["primary"].ID, UDPOutbound: candidates["primary"].ID},
		{ClientID: "bob"},
	}
	encode := func(t *testing.T, plan dataplane.DesiredPlan) []byte {
		t.Helper()
		encoded, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encode(t, basePlan), epoch, expectations,
		[]RouteReserveMapping{baseMapping}, assignments,
	); err != nil {
		t.Fatalf("valid plan binding: %v", err)
	}

	tests := []struct {
		name       string
		plan       dataplane.DesiredPlan
		generation int64
		mappings   []RouteReserveMapping
	}{
		{name: "generation mismatch", plan: basePlan, generation: 3, mappings: []RouteReserveMapping{baseMapping}},
		{name: "missing mapping", plan: basePlan, generation: 2, mappings: nil},
		{name: "known but nonmaterialized candidate", plan: basePlan, generation: 2, mappings: []RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["known-extra"].ID,
			UDPPrimaryCandidateID: candidates["primary"].ID,
			UDPReserveCandidateID: candidates["udp-reserve"].ID,
		}}},
		{name: "wrong client", plan: basePlan, generation: 2, mappings: []RouteReserveMapping{{
			ClientID: "bob", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["tor-reserve"].ID,
			UDPPrimaryCandidateID: candidates["primary"].ID,
			UDPReserveCandidateID: candidates["udp-reserve"].ID,
		}}},
	}
	withoutReserves := basePlan
	withoutReserves.Generation = 2
	withoutReserves.Clients = append([]dataplane.ClientRoute(nil), basePlan.Clients...)
	withoutReserves.Clients[0].TCPReserveOutbound = ""
	withoutReserves.Clients[0].UDPReserveOutbound = ""
	tests = append(tests, struct {
		name       string
		plan       dataplane.DesiredPlan
		generation int64
		mappings   []RouteReserveMapping
	}{name: "extra mapping", plan: withoutReserves, generation: 2, mappings: []RouteReserveMapping{baseMapping}})
	wrongTorBinding := basePlan
	wrongTorBinding.Generation = 2
	wrongTorBinding.Outbounds = append([]dataplane.Outbound(nil), basePlan.Outbounds...)
	wrongTorBinding.Clients = append([]dataplane.ClientRoute(nil), basePlan.Clients...)
	wrongTorBinding.Outbounds[1].ID = candidates["tor-reserve"].ID + "-profile-0-client-bob"
	wrongTorBinding.Clients[0].TCPReserveOutbound = wrongTorBinding.Outbounds[1].ID
	tests = append(tests, struct {
		name       string
		plan       dataplane.DesiredPlan
		generation int64
		mappings   []RouteReserveMapping
	}{name: "Tor handler bound to other client", plan: wrongTorBinding, generation: 2, mappings: []RouteReserveMapping{baseMapping}})
	wrongVLESSTag := basePlan
	wrongVLESSTag.Generation = 2
	wrongVLESSTag.Outbounds = append([]dataplane.Outbound(nil), basePlan.Outbounds...)
	wrongVLESSTag.Clients = append([]dataplane.ClientRoute(nil), basePlan.Clients...)
	wrongVLESSTag.Outbounds[0].ID = "custom-vless-tag"
	wrongVLESSTag.Clients[0].TCPOutbound = "custom-vless-tag"
	wrongVLESSTag.Clients[0].UDPOutbound = "custom-vless-tag"
	tests = append(tests, struct {
		name       string
		plan       dataplane.DesiredPlan
		generation int64
		mappings   []RouteReserveMapping
	}{name: "VLESS tag is not candidate ID", plan: wrongVLESSTag, generation: 2, mappings: []RouteReserveMapping{baseMapping}})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := test.plan
			if test.name != "generation mismatch" {
				plan.Generation = test.generation
			}
			err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
				ctx, test.generation, encode(t, plan), epoch, expectations, test.mappings,
				assignments,
			)
			if err == nil {
				t.Fatal("invalid serialized plan/mapping binding was accepted")
			}
			state, loadErr := database.LoadPlanState(ctx)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if state.DesiredGeneration != 1 {
				t.Fatalf("invalid binding mutated desired generation=%d", state.DesiredGeneration)
			}
		})
	}

	if err := database.SaveDesiredPlanForCandidatesAndReserves(
		ctx, 2, []byte(`{"generation":2`), epoch, expectations, nil,
	); err == nil {
		t.Fatal("malformed serialized plan was accepted")
	}
}

func TestDesiredReserveBindingsAllowAsymmetricAndBlockedTransports(t *testing.T) {
	primary := Candidate{ID: "cand_primary", Kind: sources.KindVLESS}
	reserve := Candidate{ID: "cand_reserve", Kind: sources.KindVLESS}
	expectations := []CandidatePlanExpectation{
		{Candidate: primary}, {Candidate: reserve},
	}
	tests := []struct {
		name       string
		tcpPrimary string
		udpPrimary string
		tcpReserve string
		udpReserve string
		mapping    RouteReserveMapping
	}{
		{
			name:       "TCP reserve does not bind UDP primary",
			tcpPrimary: primary.ID, udpPrimary: primary.ID,
			tcpReserve: reserve.ID,
			mapping: RouteReserveMapping{
				ClientID: "alice", TCPPrimaryCandidateID: primary.ID,
				TCPReserveCandidateID: reserve.ID,
			},
		},
		{
			name:       "UDP reserve does not bind TCP primary",
			tcpPrimary: primary.ID, udpPrimary: primary.ID,
			udpReserve: reserve.ID,
			mapping: RouteReserveMapping{
				ClientID: "alice", UDPPrimaryCandidateID: primary.ID,
				UDPReserveCandidateID: reserve.ID,
			},
		},
		{
			name:       "TCP reserve with UDP blocked",
			tcpPrimary: primary.ID, tcpReserve: reserve.ID,
			mapping: RouteReserveMapping{
				ClientID: "alice", TCPPrimaryCandidateID: primary.ID,
				TCPReserveCandidateID: reserve.ID,
			},
		},
		{
			name:       "UDP reserve with TCP blocked",
			udpPrimary: primary.ID, udpReserve: reserve.ID,
			mapping: RouteReserveMapping{
				ClientID: "alice", UDPPrimaryCandidateID: primary.ID,
				UDPReserveCandidateID: reserve.ID,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := vlessReservePlanBytes(
				t, 1, "alice", test.tcpPrimary, test.udpPrimary,
				test.tcpReserve, test.udpReserve,
			)
			if _, err := validateDesiredPlanReserveBindings(
				encoded, 1, expectations, []RouteReserveMapping{test.mapping},
			); err != nil {
				t.Fatalf("valid asymmetric reserve binding: %v", err)
			}
		})
	}
}

func TestReserveMappingsRequireCompleteDesiredAssignmentSnapshot(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	epoch, _ := database.InventoryEpoch(ctx)
	encoded := vlessReservePlanBytes(
		t, 1, "alice", candidates["primary"].ID, "",
		candidates["reserve"].ID, "",
	)
	err := database.SaveDesiredPlanForCandidatesAndReserves(
		ctx, 1, encoded, epoch,
		[]CandidatePlanExpectation{
			{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
		},
		[]RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["reserve"].ID,
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "assignment snapshot") {
		t.Fatalf("mapping without complete snapshot error=%v", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.DesiredGeneration != 0 {
		t.Fatalf("rejected mapping mutated desired state=%+v", state)
	}
}

func TestMarkAppliedRejectsDesiredReserveMappingWithoutExactSnapshot(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	encoded := []byte(`{"generation":1}`)
	if _, err := database.db.ExecContext(ctx, `
		UPDATE plan_state
		SET desired_generation=1, desired_plan=?,
		    desired_assignments_generation=0, desired_assignments=NULL
		WHERE singleton=1;
		INSERT INTO route_reserve_mappings(
		  stage, client_id, generation,
		  tcp_primary_candidate_id, tcp_reserve_candidate_id,
		  udp_primary_candidate_id, udp_reserve_candidate_id
		) VALUES ('desired', 'alice', 1, 'primary', 'reserve', '', '');
	`, encoded); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, encoded); err == nil {
		t.Fatal("reserve mapping without exact assignment snapshot was promoted")
	}
	if _, err := database.db.ExecContext(ctx, `
		UPDATE plan_state
		SET desired_assignments_generation=1, desired_assignments='[]'
		WHERE singleton=1
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, encoded); err == nil {
		t.Fatal("reserve mapping with incomplete assignment snapshot was promoted")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var appliedMappings int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings WHERE stage='applied'
	`).Scan(&appliedMappings); err != nil {
		t.Fatal(err)
	}
	if state.AppliedGeneration != 0 || appliedMappings != 0 {
		t.Fatalf("rejected promotion mutated state=%+v mappings=%d", state, appliedMappings)
	}
}

func TestRouteReserveRowsCascadeOnClientDeletion(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	})
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	epoch, _ := database.InventoryEpoch(ctx)
	encoded := vlessReservePlanBytes(
		t, 1, "alice", candidates["primary"].ID, "",
		candidates["reserve"].ID, "",
	)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encoded, epoch,
		[]CandidatePlanExpectation{{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]}},
		[]RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["reserve"].ID,
		}}, []AssignmentRecord{{
			ClientID: "alice", TCPOutbound: candidates["primary"].ID,
		}},
	); err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteClient(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM route_reserve_mappings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("client deletion retained %d reserve rows", rows)
	}
}

func TestPersistedPlanValidatorUnderstandsDNSReservesAndRejectsCorruption(t *testing.T) {
	plan := dataplane.DesiredPlan{
		Generation: 4,
		Outbounds: []dataplane.Outbound{
			{ID: "cand_primary", Protocol: dataplane.ProtocolVLESS},
			{ID: "cand_reserve", Protocol: dataplane.ProtocolVLESS},
			{ID: "dns-alice", Protocol: dataplane.ProtocolDNS, Config: json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53},"proxySettings":{"tag":"cand_primary"}}`)},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "cand_primary", UDPOutbound: "cand_primary",
			DNSOutbound: "dns-alice", TCPReserveOutbound: "cand_reserve",
			UDPReserveOutbound: "cand_reserve",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	references, err := persistedPlanCandidateReferences(encoded, 4)
	if err != nil {
		t.Fatalf("valid DNS/reserve persisted plan: %v", err)
	}
	if !references["cand_primary"] || !references["cand_reserve"] || references["dns-alice"] {
		t.Fatalf("candidate references=%v", references)
	}
	plan.Clients[0].TCPReserveOutbound = "missing"
	corrupt, _ := json.Marshal(plan)
	if _, err := persistedPlanCandidateReferences(corrupt, 4); err == nil {
		t.Fatal("corrupt reserve reference passed strict persisted validation")
	}
}

func vlessReservePlanBytes(
	t *testing.T,
	generation int64,
	clientID string,
	tcpPrimary string,
	udpPrimary string,
	tcpReserve string,
	udpReserve string,
) []byte {
	t.Helper()
	ids := make(map[string]bool)
	outbounds := make([]dataplane.Outbound, 0, 4)
	for _, id := range []string{tcpPrimary, udpPrimary, tcpReserve, udpReserve} {
		if id == "" || ids[id] {
			continue
		}
		ids[id] = true
		outbounds = append(outbounds, dataplane.Outbound{
			ID: id, Protocol: dataplane.ProtocolVLESS,
		})
	}
	plan := dataplane.DesiredPlan{
		Generation: generation,
		Outbounds:  outbounds,
		Clients: []dataplane.ClientRoute{{
			ClientID:    clientID,
			TCPOutbound: tcpPrimary, UDPOutbound: udpPrimary,
			TCPReserveOutbound: tcpReserve, UDPReserveOutbound: udpReserve,
			BlockTCP: tcpPrimary == "", BlockUDP: udpPrimary == "",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPlanStateCASRejectsStaleConcurrentGenerations(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	generationTwo := []byte(`{"generation":2}`)
	if err := database.SaveDesiredPlan(ctx, 2, generationTwo); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 2, []byte(`{"generation":2,"other":true}`)); err == nil {
		t.Fatal("desired generation was reused")
	}
	if err := database.SaveDesiredPlan(ctx, 1, []byte(`{"generation":1}`)); err == nil {
		t.Fatal("stale desired generation was accepted")
	}
	if err := database.MarkAppliedPlan(ctx, 1, []byte(`{"generation":1}`)); err == nil {
		t.Fatal("non-current desired generation was marked applied")
	}
	if err := database.MarkAppliedPlan(ctx, 2, generationTwo); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 2, generationTwo); err == nil {
		t.Fatal("applied generation was marked twice")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 2 || state.AppliedGeneration != 2 ||
		!bytes.Equal(state.DesiredPlan, generationTwo) ||
		!bytes.Equal(state.AppliedPlan, generationTwo) {
		t.Fatalf("CAS rejection changed state=%+v", state)
	}
}

func TestSaveDesiredPlanForCandidatesRejectsStaleInventoryWithoutMutation(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "selected", Fingerprint: "selected",
			Payload: "vless://selected@example.net:443",
		},
		{
			Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
			Payload: "vless://replacement@example.net:443",
		},
	})
	selected := candidates["selected"]
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(
		ctx,
		selected.SourceID,
		[]CandidateInput{{
			Kind: sources.KindVLESS, Label: "replacement",
			Fingerprint: "replacement",
			Payload:     "vless://replacement@example.net:443",
		}},
	); err != nil {
		t.Fatal(err)
	}
	err = database.SaveDesiredPlanForCandidates(
		ctx,
		1,
		[]byte(`{"generation":1}`),
		epoch,
		[]CandidatePlanExpectation{{Candidate: selected}},
	)
	if !errors.Is(err, ErrCandidateInventoryChanged) {
		t.Fatalf("error=%v want ErrCandidateInventoryChanged", err)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 0 || len(state.DesiredPlan) != 0 {
		t.Fatalf("stale inventory partially persisted plan: %+v", state)
	}
}

func TestRoutingEvidenceSnapshotAllowsMonotonicActiveProofRefresh(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "selected", Fingerprint: "selected",
		Payload: "vless://selected@example.net:443", RouteKey: "route-a",
		FailureDomain: "domain-a",
	}})
	candidate := candidates["selected"]
	now := time.Unix(1_900_000_000, 0)
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidate.ID, Score: 90, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
		Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
		SourceID: candidate.SourceID, Full: true, Success: true,
		Score: 90, At: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(
		`UPDATE candidate_probe_state SET in_working_pool=1, stale=0 WHERE candidate_id=?`,
		candidate.ID,
	); err != nil {
		t.Fatal(err)
	}
	seed, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, seed, ActiveObservationOutcome{
			Available: true, ProofSuccess: true,
		}, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("seed active proof=%+v err=%v", commit, err)
	}

	snapshot, err := database.LoadRoutingEvidenceSnapshot(ctx, nil)
	if err != nil || len(snapshot.Candidates) != 1 {
		t.Fatalf("routing snapshot=%+v err=%v", snapshot, err)
	}
	refresh, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, refresh, ActiveObservationOutcome{
			Available: true, ProofSuccess: true,
		}, now.Add(2*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("refresh active proof=%+v err=%v", commit, err)
	}
	if err := database.SaveDesiredPlanForCandidates(
		ctx, 1,
		vlessReservePlanBytes(t, 1, "alice", candidate.ID, "", "", ""),
		snapshot.InventoryEpoch,
		[]CandidatePlanExpectation{{
			Candidate: candidate, EvidenceDigest: snapshot.Candidates[0].Digest,
		}},
	); err != nil {
		t.Fatalf("monotonic active proof refresh blocked publish: %v", err)
	}
}

func TestRoutingEvidenceSnapshotRejectsEveryReferencedDecisionInputAsTemporary(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*testing.T, *Store, Candidate)
	}{
		{name: "source enabled", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE sources SET enabled=0 WHERE id=?`, candidate.SourceID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "lifecycle", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidates SET lifecycle='draining' WHERE id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "route identity", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidates SET route_key='changed' WHERE id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "payload", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			encrypted, err := database.box.Seal(candidate.ID, []byte("vless://changed@example.net:443"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`UPDATE candidates SET encrypted_payload=? WHERE id=?`, encrypted, candidate.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "health qualification", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidate_health SET tcp_qualified=0 WHERE candidate_id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "active hard failure", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidate_health SET available=0, active_success=0, active_hard_failure=1 WHERE candidate_id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "probe pool", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidate_probe_state SET stale=1 WHERE candidate_id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "domain circuit", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE failure_domain_state SET open_until=open_until+60 WHERE domain=?`, candidate.FailureDomain)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "qoe", mutate: func(t *testing.T, database *Store, candidate Candidate) {
			_, err := database.db.Exec(`UPDATE candidate_qoe_state SET median_effective_ms=median_effective_ms+1 WHERE candidate_id=?`, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := candidateStateTestStore(t, []CandidateInput{{
				Kind: sources.KindVLESS, Label: "selected", Fingerprint: "selected",
				Payload: "vless://selected@example.net:443", RouteKey: "route-a",
				FailureDomain: "domain-a",
			}})
			candidate := candidates["selected"]
			now := time.Unix(1_900_000_000, 0)
			if err := database.SaveCandidateHealth(ctx, CandidateHealth{
				CandidateID: candidate.ID, Score: 90, TCPQualified: true,
				UDPQualified: true, Available: true, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 90, At: now,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`UPDATE candidate_probe_state SET in_working_pool=1, stale=0 WHERE candidate_id=?`, candidate.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`INSERT INTO failure_domain_state(domain, failure_count, window_started_at, open_until, canary_candidate, updated_at) VALUES (?, 1, ?, ?, '', ?)`, candidate.FailureDomain, now.Unix(), now.Add(time.Minute).Unix(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, _, err := database.RecordCandidateQoE(ctx, candidate, qoe.Observation{
				At: now, Success: true, TTFB: 100 * time.Millisecond,
				TransferDuration: 50 * time.Millisecond, Bytes: 65536,
				ThroughputMbps: 10,
			}, qoe.DefaultPolicy()); err != nil {
				t.Fatal(err)
			}

			snapshot, err := database.LoadRoutingEvidenceSnapshot(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var evidence CandidateRoutingEvidence
			for _, row := range snapshot.Candidates {
				if row.Candidate.ID == candidate.ID {
					evidence = row
				}
			}
			if evidence.Digest == "" {
				t.Fatalf("missing candidate evidence: %+v", snapshot)
			}
			test.mutate(t, database, candidate)
			err = database.SaveDesiredPlanForCandidates(
				ctx, 1, vlessReservePlanBytes(t, 1, "alice", candidate.ID, "", "", ""),
				snapshot.InventoryEpoch,
				[]CandidatePlanExpectation{{
					Candidate: candidate, AllowDraining: true,
					EvidenceDigest: evidence.Digest,
				}},
			)
			if !errors.Is(err, ErrCandidateEvidenceChanged) {
				t.Fatalf("error=%v want ErrCandidateEvidenceChanged", err)
			}
			var temporary interface{ Temporary() bool }
			if !errors.As(err, &temporary) || !temporary.Temporary() {
				t.Fatalf("evidence conflict is not temporary: %T %v", err, err)
			}
		})
	}
}

func TestRoutingEvidencePublishIgnoresUnreferencedInventoryMutation(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "selected", Fingerprint: "selected", Payload: "vless://selected@example.net:443"},
		{Kind: sources.KindVLESS, Label: "other", Fingerprint: "other", Payload: "vless://other@example.net:443"},
	})
	selected := candidates["selected"]
	snapshot, err := database.LoadRoutingEvidenceSnapshot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	for _, row := range snapshot.Candidates {
		if row.Candidate.ID == selected.ID {
			digest = row.Digest
		}
	}
	if digest == "" {
		t.Fatal("selected evidence missing")
	}
	if _, err := database.db.Exec(`UPDATE candidates SET route_key='unrelated' WHERE id=?`, candidates["other"].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE inventory_state SET epoch=epoch+1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlanForCandidates(
		ctx, 1, vlessReservePlanBytes(t, 1, "alice", selected.ID, "", "", ""),
		snapshot.InventoryEpoch,
		[]CandidatePlanExpectation{{Candidate: selected, EvidenceDigest: digest}},
	); err != nil {
		t.Fatalf("unreferenced evidence blocked publish: %v", err)
	}
}

func TestRoutingEvidenceSnapshotBoundsProbedInventoryToWorkingAndReferenced(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{Kind: sources.KindVLESS, Label: "working", Fingerprint: "working", Payload: "vless://working@example.net:443"},
		{Kind: sources.KindVLESS, Label: "idle", Fingerprint: "idle", Payload: "vless://idle@example.net:443"},
		{Kind: sources.KindVLESS, Label: "referenced", Fingerprint: "referenced", Payload: "vless://referenced@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, name := range []string{"working", "idle", "referenced"} {
		candidate := candidates[name]
		if err := database.SaveCandidateHealth(ctx, CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: true,
			Score: 90, At: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.db.Exec(`
		UPDATE candidate_probe_state
		SET in_working_pool=1, stale=0
		WHERE candidate_id=?
	`, candidates["working"].ID); err != nil {
		t.Fatal(err)
	}

	assertIDs := func(referenced []string, want ...string) {
		t.Helper()
		snapshot, err := database.LoadRoutingEvidenceSnapshot(ctx, referenced)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(snapshot.Candidates))
		for _, row := range snapshot.Candidates {
			got = append(got, row.Candidate.ID)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("snapshot candidates=%v want=%v", got, want)
		}
	}
	assertIDs(nil, candidates["working"].ID)
	assertIDs(
		[]string{candidates["referenced"].ID},
		candidates["working"].ID, candidates["referenced"].ID,
	)
}

func TestSaveDesiredPlanForCandidatesAllowsOnlyPreReferencedDrainingIdentity(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "selected", Fingerprint: "selected",
			Payload: "vless://selected@example.net:443",
		},
		{
			Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
			Payload: "vless://replacement@example.net:443",
		},
	})
	selected := candidates["selected"]
	if err := database.ReplaceCandidates(
		ctx,
		selected.SourceID,
		[]CandidateInput{{
			Kind: sources.KindVLESS, Label: "replacement",
			Fingerprint: "replacement",
			Payload:     "vless://replacement@example.net:443",
		}},
	); err != nil {
		t.Fatal(err)
	}
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expectation := CandidatePlanExpectation{Candidate: selected}
	encoded := vlessReservePlanBytes(t, 1, "alice", selected.ID, "", "", "")
	err = database.SaveDesiredPlanForCandidates(
		ctx, 1, encoded, epoch,
		[]CandidatePlanExpectation{expectation},
	)
	if !errors.Is(err, ErrCandidateInventoryChanged) {
		t.Fatalf("new selection accepted draining candidate: %v", err)
	}
	expectation.AllowDraining = true
	if err := database.SaveDesiredPlanForCandidates(
		ctx, 1, encoded, epoch,
		[]CandidatePlanExpectation{expectation},
	); err != nil {
		t.Fatalf("pre-referenced draining candidate rejected: %v", err)
	}
}

func TestClientAssignmentHealthAndEventState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	client := ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public"}
	if err := database.PutClient(ctx, client, "[Interface]\nPrivateKey = super-secret\n"); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordActivity(ctx, "alice", now.Add(-time.Second), 90, 190); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordActivity(ctx, "alice", now, 100, 200); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, AssignmentRecord{ClientID: "alice", TCPOutbound: "tor", UDPOutbound: "vless", TCPSince: now, UDPSince: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{CandidateID: "vless", Score: 92, TCPQualified: true, UDPQualified: true, Available: true, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendEvent(ctx, Event{Kind: "assignment.changed", ClientID: "alice", Message: "tcp=tor udp=vless", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	clients, err := database.ListClients(ctx)
	if err != nil || len(clients) != 1 || clients[0].LastTrafficAt == nil {
		t.Fatalf("clients=%+v err=%v", clients, err)
	}
	config, err := database.ClientConfig(ctx, "alice")
	if err != nil || !strings.Contains(config, "super-secret") {
		t.Fatalf("client config=%q err=%v", config, err)
	}
	assignments, _ := database.ListAssignments(ctx)
	if len(assignments) != 1 || assignments[0].TCPOutbound != "tor" || assignments[0].UDPOutbound != "vless" {
		t.Fatalf("assignments=%+v", assignments)
	}
	health, _ := database.ListCandidateHealth(ctx)
	if len(health) != 1 || !health[0].UDPQualified {
		t.Fatalf("health=%+v", health)
	}
	events, _ := database.ListEvents(ctx, 10)
	if len(events) != 1 || events[0].Kind != "assignment.changed" {
		t.Fatalf("events=%+v", events)
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "super-secret") {
		t.Fatal("client WireGuard config was stored as plaintext")
	}
}

func TestPruneDiagnosticsDeletesExactBoundaryInBoundedBatchesOnly(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "retained-candidate",
	)["retained-candidate"]
	cutoff := time.Unix(1_800_000_000, 0)

	if err := database.PutClient(ctx, ClientRecord{
		ID: "retained-client", Name: "Retained", Address: "10.44.0.2/32",
		PublicKey: "retained-key",
	}, "retained-config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, AssignmentRecord{
		ClientID: "retained-client", TCPOutbound: candidate.ID,
		UDPOutbound: candidate.ID, TCPSince: cutoff, UDPSince: cutoff,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(
		ctx, 1, []byte(`{"generation":1}`),
	); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(
		ctx, 1, []byte(`{"generation":1}`),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecordFailureDomainFailure(
		ctx, candidate.FailureDomain, candidate.ID, cutoff,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO candidate_qoe_state(candidate_id, status, updated_at)
		VALUES (?, 'healthy', ?)
	`, candidate.ID, cutoff.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO candidate_qoe_samples(
			candidate_id, success, bad, effective_ms, created_at
		) VALUES (?, 1, 0, 10, ?)
	`, candidate.ID, cutoff.Add(-30*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	for index, createdAt := range []time.Time{
		cutoff.Add(-2 * time.Second),
		cutoff.Add(-time.Second),
		cutoff,
		cutoff.Add(time.Second),
	} {
		if err := database.AppendEvent(ctx, Event{
			Kind: "diagnostic", Message: fmt.Sprintf("event-%d", index),
			CreatedAt: createdAt,
		}); err != nil {
			t.Fatal(err)
		}
		if err := database.AppendProbeSample(ctx, ProbeSample{
			CandidateID: candidate.ID, Success: true,
			CreatedAt: createdAt,
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := database.PruneDiagnostics(ctx, cutoff, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first != (DiagnosticPruneResult{Events: 2, ProbeSamples: 2}) {
		t.Fatalf("first prune=%+v", first)
	}
	second, err := database.PruneDiagnostics(ctx, cutoff, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second != (DiagnosticPruneResult{Events: 1, ProbeSamples: 1}) {
		t.Fatalf("second prune=%+v", second)
	}
	third, err := database.PruneDiagnostics(ctx, cutoff, 2)
	if err != nil {
		t.Fatal(err)
	}
	if third != (DiagnosticPruneResult{}) {
		t.Fatalf("third prune=%+v", third)
	}

	for table, want := range map[string]int{
		"events":                  1,
		"probe_samples":           1,
		"clients":                 1,
		"assignments":             1,
		"candidates":              1,
		"plan_state":              1,
		"candidate_qoe_state":     1,
		"candidate_qoe_samples":   1,
		"failure_domain_state":    1,
		"failure_domain_evidence": 1,
		"candidate_probe_state":   0,
		"candidate_health":        0,
	} {
		var count int
		if err := database.db.QueryRowContext(
			ctx, `SELECT count(*) FROM `+table,
		).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != want {
			t.Fatalf("%s count=%d want=%d", table, count, want)
		}
	}
	var (
		eventCreated int64
		probeCreated int64
	)
	if err := database.db.QueryRowContext(
		ctx, `SELECT created_at FROM events`,
	).Scan(&eventCreated); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(
		ctx, `SELECT created_at FROM probe_samples`,
	).Scan(&probeCreated); err != nil {
		t.Fatal(err)
	}
	if eventCreated != cutoff.Add(time.Second).Unix() ||
		probeCreated != cutoff.Add(time.Second).Unix() {
		t.Fatalf(
			"newer diagnostics changed: event=%d probe=%d",
			eventCreated, probeCreated,
		)
	}
}

func TestDiagnosticRetentionMigrationCreatesVersionSevenIndexesIdempotently(
	t *testing.T,
) {
	database := failureDomainTestStore(t)
	for _, index := range []string{
		"events_created_at_idx", "probe_samples_created_at_idx",
	} {
		var count int
		if err := database.db.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`,
			index,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("missing index %s", index)
		}
	}
	if err := database.migrateDiagnosticRetention(
		context.Background(),
	); err != nil {
		t.Fatalf("replay migration: %v", err)
	}
	var versions int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM schema_migrations WHERE version=7`,
	).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("version count=%d err=%v", versions, err)
	}
}

func TestListExclusionsReturnsOnlyUnexpiredPersistentEntries(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, ClientRecord{ID: "client", Name: "client", Address: "10.44.0.2/32", PublicKey: "key"}, "config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetExclusion(ctx, "client", "old", "manual", now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetExclusion(ctx, "client", "current", "manual", now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err := database.ListExclusions(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].CandidateID != "current" || !items[0].Until.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("exclusions=%+v", items)
	}
}
