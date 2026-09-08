package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestBackupProducesConsistentOpenableSQLiteSnapshot(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	directory := t.TempDir()
	database, err := Open(filepath.Join(directory, "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	backupPath := filepath.Join(directory, "backup.db")
	if err := database.Backup(context.Background(), backupPath); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err != nil {
		t.Fatalf("valid backup rejected: %v", err)
	}
	wrongBox, _ := secretbox.New(bytesOf(1, secretbox.KeySize))
	if err := ValidateBackup(backupPath, wrongBox); err == nil {
		t.Fatal("backup encrypted with another key was accepted")
	}
	_ = database.Close()
	backup, err := Open(backupPath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	listed, err := backup.ListSources(context.Background())
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
}

func TestValidateBackupRejectsEmptyFileWithoutModifyingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	if err := ValidateBackup(path, box); err == nil {
		t.Fatal("empty file was accepted as a backup")
	}
	info, _ := os.Stat(path)
	if info.Size() != 0 {
		t.Fatal("backup validation modified its input")
	}
}

func TestValidateBackupRequiresQoETables(t *testing.T) {
	for _, missing := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		t.Run(missing, func(t *testing.T) {
			database, _ := qoeCandidateStore(t)
			backupPath := filepath.Join(t.TempDir(), "backup.db")
			if err := database.Backup(context.Background(), backupPath); err != nil {
				t.Fatal(err)
			}
			backup, err := Open(backupPath, database.box)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := backup.db.Exec(`DROP TABLE ` + missing); err != nil {
				t.Fatal(err)
			}
			if err := backup.Close(); err != nil {
				t.Fatal(err)
			}
			err = ValidateBackup(backupPath, database.box)
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("ValidateBackup() error=%v, want missing %s", err, missing)
			}
		})
	}
}

func TestValidateBackupRejectsV12WithoutPhysicalActiveEvidenceSchema(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	backupPath := filepath.Join(t.TempDir(), "missing-active-evidence.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`ALTER TABLE candidate_health DROP COLUMN active_success`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("v12 backup without active_success was accepted")
	}
}

func TestValidateBackupRejectsV13WithoutPhysicalActiveHardFailureSchema(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	backupPath := filepath.Join(t.TempDir(), "missing-active-hard-failure.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`ALTER TABLE candidate_health DROP COLUMN active_hard_failure`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("v13 backup without active_hard_failure was accepted")
	}
}

func TestValidateBackupRejectsV14WithoutPhysicalDesiredReasonSchema(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	backupPath := filepath.Join(t.TempDir(), "missing-desired-reason.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`ALTER TABLE plan_state DROP COLUMN desired_reason`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("v14 backup without desired_reason was accepted")
	}
}

func TestValidateBackupRejectsV15WithLegacySecondActiveTimestamp(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	base := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidate.ID, Score: 90, TCPQualified: true,
		Available: true, UpdatedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		UPDATE candidate_health
		SET active_observed_at=?, active_success=1
		WHERE candidate_id=?
	`, base.Unix(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "legacy-active-time.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("v15 backup with second-precision active timestamp was accepted")
	}
}

func TestValidateBackupRejectsV16WithoutCandidateProbeLookupIndex(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "missing-probe-lookup-index.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP INDEX candidate_probe_state_candidate_idx`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("v16 backup without candidate probe lookup index was accepted")
	}
}

func TestValidateBackupRejectsForeignKeyViolations(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "orphan.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		PRAGMA foreign_keys=OFF;
		INSERT INTO route_reserve_mappings(
		  stage, client_id, generation,
		  tcp_primary_candidate_id, tcp_reserve_candidate_id,
		  udp_primary_candidate_id, udp_reserve_candidate_id
		) VALUES ('applied', 'missing-client', 1, 'primary', 'reserve', '', '');
	`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil ||
		!strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("orphan foreign key validation error=%v", err)
	}
}

func TestValidateBackupRejectsInconsistentV11PlanState(t *testing.T) {
	tests := []struct {
		name    string
		corrupt string
	}{
		{
			name:    "missing singleton",
			corrupt: `DELETE FROM plan_state`,
		},
		{
			name: "applied generation exceeds desired",
			corrupt: `UPDATE plan_state SET
				desired_generation=1, desired_plan=x'01',
				applied_generation=2, applied_plan=x'02'`,
		},
		{
			name: "pending desired has no exact snapshot",
			corrupt: `UPDATE plan_state SET
				desired_generation=2, desired_plan=x'02',
				applied_generation=1, applied_plan=x'01',
				desired_assignments_generation=0, desired_assignments=NULL`,
		},
		{
			name: "snapshot generation mismatch",
			corrupt: `UPDATE plan_state SET
				desired_generation=2, desired_plan=x'02',
				applied_generation=1, applied_plan=x'01',
				desired_assignments_generation=3, desired_assignments=x'5b5d'`,
		},
		{
			name: "exact snapshot is null",
			corrupt: `UPDATE plan_state SET
				desired_generation=2, desired_plan=x'02',
				applied_generation=1, applied_plan=x'01',
				desired_assignments_generation=2, desired_assignments=NULL`,
		},
		{
			name: "invalidated generation while plan is pending",
			corrupt: `UPDATE plan_state SET
				desired_generation=2, desired_plan=x'02',
				applied_generation=1, applied_plan=x'01',
				invalidated_generation=3,
				desired_assignments_generation=2, desired_assignments=x'5b5d'`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
			if err != nil {
				t.Fatal(err)
			}
			backupPath := filepath.Join(t.TempDir(), "inconsistent.db")
			if err := database.Backup(ctx, backupPath); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := sql.Open("sqlite", backupPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(test.corrupt); err != nil {
				t.Fatal(err)
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := ValidateBackup(backupPath, box); err == nil {
				t.Fatal("inconsistent v11 plan state was accepted")
			}
		})
	}
}

func TestValidateBackupRejectsRouteReserveGenerationMismatch(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "mapping-generation.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		UPDATE plan_state SET
		  desired_generation=2, desired_plan=x'02',
		  applied_generation=1, applied_plan=x'01',
		  desired_assignments_generation=2, desired_assignments=x'5b5d';
		INSERT INTO route_reserve_mappings(
		  stage, client_id, generation,
		  tcp_primary_candidate_id, tcp_reserve_candidate_id,
		  udp_primary_candidate_id, udp_reserve_candidate_id
		) VALUES ('desired', 'alice', 3, 'primary', 'reserve', '', '');
	`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("route reserve mapping with wrong desired generation was accepted")
	}
}

func TestValidateBackupAcceptsLegacyAppliedPlanWithoutSnapshot(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(dataplane.DesiredPlan{
		Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 1, legacy); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, legacy); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "legacy-applied.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err != nil {
		t.Fatalf("legacy applied plan was rejected: %v", err)
	}
}

func TestValidateBackupRejectsMalformedOrWrongGenerationAppliedPlan(t *testing.T) {
	tests := []struct {
		name        string
		appliedPlan []byte
	}{
		{name: "malformed applied plan", appliedPlan: []byte(`{"generation":1}`)},
		{name: "embedded generation mismatch", appliedPlan: mustBackupPlan(t, 2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
			if err != nil {
				t.Fatal(err)
			}
			valid := mustBackupPlan(t, 1)
			if err := database.SaveDesiredPlan(ctx, 1, valid); err != nil {
				t.Fatal(err)
			}
			if err := database.MarkAppliedPlan(ctx, 1, valid); err != nil {
				t.Fatal(err)
			}
			backupPath := filepath.Join(t.TempDir(), "corrupt-plan.db")
			if err := database.Backup(ctx, backupPath); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := sql.Open("sqlite", backupPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(`
				UPDATE plan_state SET applied_plan=? WHERE singleton=1
			`, test.appliedPlan); err != nil {
				t.Fatal(err)
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := ValidateBackup(backupPath, box); err == nil {
				t.Fatal("corrupt applied plan was accepted")
			}
		})
	}
}

func TestValidateBackupRejectsSemanticallyCorruptReserveMappings(t *testing.T) {
	tests := []struct {
		name    string
		corrupt string
	}{
		{
			name: "same generation bogus candidate",
			corrupt: `UPDATE route_reserve_mappings
			          SET tcp_reserve_candidate_id='bogus'
			          WHERE stage='applied'`,
		},
		{
			name: "mapping belongs to another client",
			corrupt: `UPDATE route_reserve_mappings
			          SET client_id='bob'
			          WHERE stage='applied'`,
		},
		{
			name:    "missing applied mapping",
			corrupt: `DELETE FROM route_reserve_mappings WHERE stage='applied'`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := candidateStateTestStore(t, []CandidateInput{
				{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
				{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
			})
			for _, client := range []ClientRecord{
				{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key"},
				{ID: "bob", Name: "Bob", Address: "10.44.0.3/32", PublicKey: "bob-key", Paused: true},
			} {
				if err := database.PutClient(ctx, client, "secret-"+client.ID); err != nil {
					t.Fatal(err)
				}
			}
			plan := vlessReservePlanBytes(
				t, 1, "alice", candidates["primary"].ID, "",
				candidates["reserve"].ID, "",
			)
			epoch, _ := database.InventoryEpoch(ctx)
			if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
				ctx, 1, plan, epoch,
				[]CandidatePlanExpectation{
					{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
				},
				[]RouteReserveMapping{{
					ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
					TCPReserveCandidateID: candidates["reserve"].ID,
				}},
				[]AssignmentRecord{
					{ClientID: "alice", TCPOutbound: candidates["primary"].ID},
					{ClientID: "bob"},
				},
			); err != nil {
				t.Fatal(err)
			}
			if err := database.MarkAppliedPlan(ctx, 1, plan); err != nil {
				t.Fatal(err)
			}
			backupPath := filepath.Join(t.TempDir(), "corrupt-mapping.db")
			if err := database.Backup(ctx, backupPath); err != nil {
				t.Fatal(err)
			}
			raw, err := sql.Open("sqlite", backupPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(test.corrupt); err != nil {
				t.Fatal(err)
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := ValidateBackup(backupPath, database.box); err == nil {
				t.Fatal("semantically corrupt reserve mapping was accepted")
			}
		})
	}
}

func TestValidateBackupRejectsPlanHandlerWithoutCandidateBinding(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key",
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{{
			ID: "cand_missing", Protocol: dataplane.ProtocolVLESS,
		}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "cand_missing", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 1, plan); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, plan); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "missing-handler-candidate.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backupPath, box); err == nil {
		t.Fatal("plan handler without a persisted candidate was accepted")
	}
}

func mustBackupPlan(t *testing.T, generation int64) []byte {
	t.Helper()
	encoded, err := json.Marshal(dataplane.DesiredPlan{
		Generation: generation, DirectSuffixes: []string{".ru"}, FailClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
