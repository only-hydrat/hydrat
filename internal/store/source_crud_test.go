package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestCandidateLifecycleMigrationAddsDefaultsAndReplaysWithoutReencrypting(t *testing.T) {
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
	preview := sources.PreviewInput("https://lifecycle.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "legacy", Fingerprint: "legacy-lifecycle",
		Payload: "vless://legacy-secret@example.net:443",
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, sourceRows[0].ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	var sourceCiphertext, ciphertext []byte
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM sources WHERE id=?`,
		sourceRows[0].ID,
	).Scan(&sourceCiphertext); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM candidates WHERE id=?`,
		candidates[0].ID,
	).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx,
		`DROP INDEX IF EXISTS candidates_lifecycle_deadline_idx`,
	); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"lifecycle", "retired_at", "drain_after"} {
		var count int
		if err := database.db.QueryRowContext(ctx, `
			SELECT count(*) FROM pragma_table_info('candidates') WHERE name=?
		`, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE candidates DROP COLUMN `+column,
			); err != nil {
				t.Fatalf("drop candidates.%s: %v", column, err)
			}
		}
	}
	if _, err := database.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version=10`,
	); err != nil {
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
		if reopen == 0 {
			if _, err := database.db.ExecContext(ctx,
				`DROP INDEX IF EXISTS candidates_lifecycle_deadline_idx`,
			); err != nil {
				t.Fatalf("drop partial v10 index: %v", err)
			}
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE candidates DROP COLUMN drain_after`,
			); err != nil {
				t.Fatalf("create partial v10 schema: %v", err)
			}
			if _, err := database.db.ExecContext(ctx,
				`DROP TABLE inventory_state`,
			); err != nil {
				t.Fatalf("drop partial v10 inventory state: %v", err)
			}
			if _, err := database.db.ExecContext(ctx,
				`DROP INDEX IF EXISTS sources_pending_delete_idx`,
			); err != nil {
				t.Fatalf("drop partial v10 source index: %v", err)
			}
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE sources DROP COLUMN pending_delete`,
			); err != nil {
				t.Fatalf("drop partial v10 source state: %v", err)
			}
			var migrationRows int
			if err := database.db.QueryRowContext(ctx,
				`SELECT count(*) FROM schema_migrations WHERE version=10`,
			).Scan(&migrationRows); err != nil {
				t.Fatal(err)
			}
			if migrationRows != 1 {
				t.Fatalf("partial schema lost v10 marker: %d", migrationRows)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()

	for column, wantDefault := range map[string]string{
		"lifecycle":   "'active'",
		"retired_at":  "",
		"drain_after": "",
	} {
		var (
			notNull      int
			defaultValue sql.NullString
		)
		if err := database.db.QueryRowContext(ctx, `
			SELECT "notnull", dflt_value
			FROM pragma_table_info('candidates')
			WHERE name=?
		`, column).Scan(&notNull, &defaultValue); err != nil {
			t.Fatalf("inspect candidates.%s: %v", column, err)
		}
		if column == "lifecycle" {
			if notNull != 1 || !defaultValue.Valid || defaultValue.String != wantDefault {
				t.Fatalf("%s notnull=%d default=%+v", column, notNull, defaultValue)
			}
		} else if notNull != 0 {
			t.Fatalf("%s notnull=%d, want nullable", column, notNull)
		}
	}
	var (
		sourcePendingDefault sql.NullString
		sourceAfterCipher    []byte
	)
	if err := database.db.QueryRowContext(ctx, `
		SELECT dflt_value
		FROM pragma_table_info('sources')
		WHERE name='pending_delete'
	`).Scan(&sourcePendingDefault); err != nil {
		t.Fatalf("inspect sources.pending_delete: %v", err)
	}
	if !sourcePendingDefault.Valid || sourcePendingDefault.String != "0" {
		t.Fatalf("pending_delete default=%+v", sourcePendingDefault)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT encrypted_payload FROM sources WHERE id=?
	`, sourceRows[0].ID).Scan(&sourceAfterCipher); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceCiphertext, sourceAfterCipher) {
		t.Fatal("source encrypted payload changed during lifecycle migration")
	}
	var (
		lifecycle     string
		retiredAt     sql.NullInt64
		drainAfter    sql.NullInt64
		afterCipher   []byte
		migrationRows int
	)
	if err := database.db.QueryRowContext(ctx, `
		SELECT lifecycle, retired_at, drain_after, encrypted_payload
		FROM candidates WHERE id=?
	`, candidates[0].ID).Scan(
		&lifecycle, &retiredAt, &drainAfter, &afterCipher,
	); err != nil {
		t.Fatal(err)
	}
	if lifecycle != CandidateLifecycleActive || retiredAt.Valid || drainAfter.Valid {
		t.Fatalf("migrated lifecycle=%q retired=%+v drain=%+v",
			lifecycle, retiredAt, drainAfter)
	}
	if !bytes.Equal(ciphertext, afterCipher) {
		t.Fatal("candidate encrypted payload changed during lifecycle migration")
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=10`,
	).Scan(&migrationRows); err != nil {
		t.Fatal(err)
	}
	if migrationRows != 1 {
		t.Fatalf("migration v10 rows=%d", migrationRows)
	}
}

func TestCandidateLifecycleMigrationCanonicalizesOnlyValidLegacyPlanArrays(
	t *testing.T,
) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(
		`{"generation":4,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true}`,
	)
	if err := database.SaveDesiredPlan(ctx, 4, legacy); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 4, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version=10`,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	assertCanonical := func(stage string) {
		t.Helper()
		state, err := database.LoadPlanState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state.DesiredGeneration != 4 || state.AppliedGeneration != 4 {
			t.Fatalf("%s generations changed: %+v", stage, state)
		}
		for kind, encoded := range map[string][]byte{
			"desired": state.DesiredPlan,
			"applied": state.AppliedPlan,
		} {
			if !bytes.Contains(encoded, []byte(`"outbounds":[]`)) ||
				!bytes.Contains(encoded, []byte(`"clients":[]`)) ||
				bytes.Contains(encoded, []byte(`:null`)) {
				t.Fatalf("%s %s plan not canonical: %s", stage, kind, encoded)
			}
		}
	}
	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonical("v9 upgrade")
	if _, err := database.db.ExecContext(ctx, `
		UPDATE plan_state
		SET desired_plan=?, applied_plan=?
		WHERE singleton=1
	`, legacy, legacy); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonical("partial v10 repair")
	first, err := database.LoadPlanState(ctx)
	if err != nil {
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
	second, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.DesiredPlan, second.DesiredPlan) ||
		!bytes.Equal(first.AppliedPlan, second.AppliedPlan) {
		t.Fatalf("canonical plan changed on replay: first=%+v second=%+v",
			first, second)
	}
}

func TestCandidateLifecycleMigrationLeavesInvalidPlanBytesUntouched(t *testing.T) {
	tests := []struct {
		name    string
		invalid []byte
	}{
		{name: "whole null", invalid: []byte(`null`)},
		{
			name: "top level unknown",
			invalid: []byte(
				`{"generation":1,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true,"unknown":"do-not-log"}`,
			),
		},
		{
			name: "nested unknown",
			invalid: []byte(
				`{"generation":1,"outbounds":[{"id":"cand_x","protocol":"vless","unknown":"do-not-log"}],"clients":null,"direct_suffixes":[".ru"],"fail_closed":true}`,
			),
		},
		{
			name: "incomplete",
			invalid: []byte(
				`{"generation":1,"outbounds":null,"clients":null,"fail_closed":true}`,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			if err := database.SaveDesiredPlan(ctx, 1, test.invalid); err != nil {
				t.Fatal(err)
			}
			if err := database.MarkAppliedPlan(ctx, 1, test.invalid); err != nil {
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
			if !bytes.Equal(state.DesiredPlan, test.invalid) ||
				!bytes.Equal(state.AppliedPlan, test.invalid) {
				t.Fatalf("invalid plan was rewritten: %+v", state)
			}
		})
	}
}

func TestReplaceCandidatesDrainsEveryMissingCandidateAndReactivatesStableID(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("https://lifecycle.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourcesRows, _ := database.ListSources(ctx)
	sourceID := sourcesRows[0].ID
	initial := []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "assigned", Fingerprint: "assigned",
			Payload: "vless://assigned-secret@example.net:443",
		},
		{
			Kind: sources.KindTorBridge, Label: "warm tor", Fingerprint: "warm-tor",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindVLESS, Label: "survivor", Fingerprint: "survivor",
			Payload: "vless://survivor@example.net:443",
		},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, initial, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	active, _ := database.ListCandidates(ctx, sourceID)
	byFingerprint := make(map[string]Candidate, len(active))
	for _, candidate := range active {
		byFingerprint[candidate.Fingerprint] = candidate
	}
	assigned := byFingerprint["assigned"]
	warmTor := byFingerprint["warm-tor"]
	if err := database.ReplaceCandidates(ctx, sourceID, initial[2:], 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	active, err = database.ListCandidates(ctx, sourceID)
	if err != nil || len(active) != 1 || active[0].Fingerprint != "survivor" {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	for _, candidate := range []Candidate{assigned, warmTor} {
		var lifecycle string
		var firstDrain int64
		if err := database.db.QueryRowContext(ctx, `
			SELECT lifecycle, drain_after FROM candidates WHERE id=?
		`, candidate.ID).Scan(&lifecycle, &firstDrain); err != nil {
			t.Fatal(err)
		}
		if lifecycle != CandidateLifecycleDraining ||
			firstDrain < time.Now().Add(14*time.Minute).Unix() {
			t.Fatalf("candidate=%s lifecycle=%q drain_after=%d",
				candidate.ID, lifecycle, firstDrain)
		}
		payload, err := database.CandidatePayload(ctx, candidate.ID)
		if err != nil || payload == "" {
			t.Fatalf("preserved payload=%q err=%v", payload, err)
		}
		if err := database.ReplaceCandidates(ctx, sourceID, initial[2:], time.Hour); err != nil {
			t.Fatal(err)
		}
		var repeatedDrain int64
		if err := database.db.QueryRowContext(ctx,
			`SELECT drain_after FROM candidates WHERE id=?`,
			candidate.ID,
		).Scan(&repeatedDrain); err != nil {
			t.Fatal(err)
		}
		if repeatedDrain != firstDrain {
			t.Fatalf("repeated refresh extended drain deadline %d -> %d",
				firstDrain, repeatedDrain)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	routable, err := database.ListRoutableCandidates(ctx, []string{assigned.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(routable) != 2 {
		t.Fatalf("routable active+referenced draining=%+v", routable)
	}
	for _, candidate := range routable {
		if candidate.ID == warmTor.ID {
			t.Fatal("unreferenced draining Tor candidate became routable")
		}
	}
	if _, err := database.db.ExecContext(ctx, `
		UPDATE candidates SET lifecycle='retired', retired_at=unixepoch()
		WHERE id=?
	`, assigned.ID); err != nil {
		t.Fatal(err)
	}
	routable, err = database.ListRoutableCandidates(
		ctx, []string{assigned.ID, warmTor.ID},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range routable {
		if candidate.ID == assigned.ID {
			t.Fatal("retired candidate was returned as routable")
		}
	}
	if err := database.ReplaceCandidates(ctx, sourceID, []CandidateInput{
		initial[0], initial[2],
	}, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	active, err = database.ListCandidates(ctx, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	reactivated := false
	for _, candidate := range active {
		if candidate.ID != assigned.ID {
			continue
		}
		reactivated = true
		if candidate.Lifecycle != CandidateLifecycleActive ||
			candidate.RetiredAt != nil || candidate.DrainAfter != nil {
			t.Fatalf("reactivated candidate=%+v", candidate)
		}
	}
	if !reactivated {
		t.Fatal("stable candidate ID did not reactivate")
	}
}

func TestDeleteSourceStagesCandidatesWithoutPayloadLossOrResurrection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("https://delete.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, _ := database.ListSources(ctx)
	sourceID := sourceRows[0].ID
	payload := "vless://delete-secret@example.net:443"
	if err := database.ReplaceCandidates(ctx, sourceID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "delete", Fingerprint: "delete",
		Payload: payload,
	}}, time.Second); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, "")
	candidateID := candidates[0].ID
	if err := database.DeleteSource(ctx, sourceID, time.Second); err != nil {
		t.Fatal(err)
	}
	sourcesAfter, err := database.ListSources(ctx)
	if err != nil || len(sourcesAfter) != 1 ||
		!sourcesAfter[0].PendingDelete || sourcesAfter[0].Enabled {
		t.Fatalf("pending source=%+v err=%v", sourcesAfter, err)
	}
	candidate, err := database.CandidateForRetirement(ctx, candidateID)
	if err != nil || candidate.Lifecycle != CandidateLifecycleDraining ||
		candidate.DrainAfter == nil {
		t.Fatalf("draining candidate=%+v err=%v", candidate, err)
	}
	stableDeadline := *candidate.DrainAfter
	if err := database.DeleteSource(ctx, sourceID, time.Hour); err != nil {
		t.Fatal(err)
	}
	candidate, err = database.CandidateForRetirement(ctx, candidateID)
	if err != nil || candidate.DrainAfter == nil ||
		*candidate.DrainAfter != stableDeadline {
		t.Fatalf("repeated delete extended deadline: %+v err=%v", candidate, err)
	}
	if got, err := database.CandidatePayload(ctx, candidateID); err != nil || got != payload {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	if err := database.UpdateSource(ctx, sourceID, "resurrect", true); err == nil {
		t.Fatal("pending source was re-enabled")
	}
	if err := database.ReplaceCandidates(ctx, sourceID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "new", Fingerprint: "new",
		Payload: "vless://new@example.net:443",
	}}); err == nil {
		t.Fatal("pending source accepted refresh")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedSources, _ := reopened.ListSources(ctx)
	if len(reopenedSources) != 1 || !reopenedSources[0].PendingDelete {
		t.Fatalf("pending source after reopen=%+v", reopenedSources)
	}
	if got, err := reopened.CandidatePayload(ctx, candidateID); err != nil || got != payload {
		t.Fatalf("reopened payload=%q err=%v", got, err)
	}
}

func TestDeleteSourceDeletesOnlyEmptySourceAndPreservesDisabledSource(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("https://empty-delete.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListSources(ctx)
	if err := database.DeleteSource(ctx, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if rows, _ := database.ListSources(ctx); len(rows) != 0 {
		t.Fatalf("empty source survived: %+v", rows)
	}

	preview = sources.PreviewInput("https://disabled-keep.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	rows, _ = database.ListSources(ctx)
	if err := database.UpdateSource(ctx, rows[0].ID, "disabled", false); err != nil {
		t.Fatal(err)
	}
	if rows, _ := database.ListSources(ctx); len(rows) != 1 ||
		rows[0].PendingDelete {
		t.Fatalf("merely disabled source changed deletion state: %+v", rows)
	}
}

func TestInventoryEpochAdvancesOnlyWithSuccessfulEligibilityPublication(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
			Payload: "vless://a@example.net:443",
		},
		{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443",
		},
	})
	before, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(
		ctx,
		candidates["a"].SourceID,
		[]CandidateInput{{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443",
		}},
	); err != nil {
		t.Fatal(err)
	}
	afterRefresh, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRefresh != before+1 {
		t.Fatalf("refresh epoch=%d want=%d", afterRefresh, before+1)
	}
	if err := database.ReplaceCandidates(
		ctx, candidates["a"].SourceID,
		[]CandidateInput{
			{
				Kind: sources.KindVLESS, Label: "duplicate", Fingerprint: "b",
				Payload: "vless://b@example.net:443",
			},
			{
				Kind: sources.KindVLESS, Label: "duplicate", Fingerprint: "b",
				Payload: "vless://b@example.net:443",
			},
		},
	); err == nil {
		t.Fatal("duplicate refresh unexpectedly succeeded")
	}
	afterFailure, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure != afterRefresh {
		t.Fatalf("failed refresh advanced epoch %d -> %d",
			afterRefresh, afterFailure)
	}
	if err := database.UpdateSource(
		ctx, candidates["a"].SourceID, "disabled", false,
	); err != nil {
		t.Fatal(err)
	}
	afterDisable, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterDisable != afterRefresh+1 {
		t.Fatalf("source disable epoch=%d want=%d",
			afterDisable, afterRefresh+1)
	}
}

func TestCandidateObservationMigrationPreservesLegacyEncryptedPayloads(t *testing.T) {
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
	preview := sources.PreviewInput("https://legacy.example/subscription?token=secret")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	const candidatePayload = "vless://secret-user@legacy.example:443?security=tls"
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind:        sources.KindVLESS,
		Label:       "legacy",
		Fingerprint: "legacy-encrypted-payload",
		Payload:     candidatePayload,
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, sourceRows[0].ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}

	var sourceCiphertext, candidateCiphertext []byte
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM sources WHERE id = ?`,
		sourceRows[0].ID,
	).Scan(&sourceCiphertext); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM candidates WHERE id = ?`,
		candidates[0].ID,
	).Scan(&candidateCiphertext); err != nil {
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

	var migratedSourceCiphertext, migratedCandidateCiphertext []byte
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM sources WHERE id = ?`,
		sourceRows[0].ID,
	).Scan(&migratedSourceCiphertext); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT encrypted_payload FROM candidates WHERE id = ?`,
		candidates[0].ID,
	).Scan(&migratedCandidateCiphertext); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(migratedSourceCiphertext, sourceCiphertext) {
		t.Fatal("source encrypted payload changed during migration")
	}
	if !bytes.Equal(migratedCandidateCiphertext, candidateCiphertext) {
		t.Fatal("candidate encrypted payload changed during migration")
	}
	payload, err := database.CandidatePayload(ctx, candidates[0].ID)
	if err != nil || payload != candidatePayload {
		t.Fatalf("candidate payload=%q err=%v", payload, err)
	}
}

func TestSourceCRUDAndLastKnownGoodCandidates(t *testing.T) {
	ctx := context.Background()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list sources: %+v, %v", listed, err)
	}
	sourceID := listed[0].ID

	if err := database.UpdateSource(ctx, sourceID, "Primary subscription", false); err != nil {
		t.Fatal(err)
	}
	listed, _ = database.ListSources(ctx)
	if listed[0].Label != "Primary subscription" || listed[0].Enabled {
		t.Fatalf("source not updated: %+v", listed[0])
	}

	candidates := []CandidateInput{
		{Kind: sources.KindVLESS, Label: "one", Fingerprint: "fp-one", Payload: "vless://secret-one@example.net:443"},
		{Kind: sources.KindVLESS, Label: "two", Fingerprint: "fp-two", Payload: "vless://secret-two@example.net:443"},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, candidates); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordRefreshFailure(ctx, sourceID, "upstream timeout"); err != nil {
		t.Fatal(err)
	}
	got, err := database.ListCandidates(ctx, sourceID)
	if err != nil || len(got) != 0 {
		t.Fatalf("disabled source remained eligible: %+v, %v", got, err)
	}
	if err := database.UpdateSource(ctx, sourceID, "Primary subscription", true); err != nil {
		t.Fatal(err)
	}
	got, err = database.ListCandidates(ctx, sourceID)
	if err != nil || len(got) != 2 {
		t.Fatalf("last-known-good candidates lost: %+v, %v", got, err)
	}
	payload, err := database.CandidatePayload(ctx, got[0].ID)
	if err != nil || payload == "" {
		t.Fatalf("candidate payload: %q, %v", payload, err)
	}

	if err := database.DeleteSource(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	listed, _ = database.ListSources(ctx)
	if len(listed) != 1 || !listed[0].PendingDelete ||
		listed[0].Enabled {
		t.Fatalf("source was not staged for deletion: %+v", listed)
	}
	got, _ = database.ListCandidates(ctx, sourceID)
	if len(got) != 0 {
		t.Fatalf("pending source candidates remained routable: %+v", got)
	}
}

func TestReplaceCandidatesRejectsEmptyRefresh(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	preview := sources.PreviewInput("vless://user@example.net:443?security=tls")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, listed[0].ID, nil); err == nil {
		t.Fatal("empty refresh must not replace last-known-good candidates")
	}
}

func TestCandidateIdentityMigrationPreservesExistingRowsWithEmptyDefaultsAndIndexes(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)`,
		`INSERT INTO schema_migrations(version, applied_at)
			VALUES (1, 1), (2, 1), (3, 1), (4, 1)`,
		`CREATE TABLE sources (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			label TEXT NOT NULL,
			fingerprint TEXT NOT NULL UNIQUE,
			encrypted_payload BLOB NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_refresh_at INTEGER,
			last_refresh_error TEXT NOT NULL DEFAULT '',
			candidate_count INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE candidates (
			id TEXT PRIMARY KEY,
			source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			label TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			encrypted_payload BLOB NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			source_position INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(source_id, fingerprint)
		)`,
		`INSERT INTO sources(
			id, kind, label, fingerprint, encrypted_payload, candidate_count,
			created_at, updated_at
		) VALUES ('source-legacy', 'vless_subscription', 'legacy', 'source-fp', X'00', 1, 1, 1)`,
		`INSERT INTO candidates(
			id, source_id, kind, label, fingerprint, encrypted_payload,
			source_position, created_at, updated_at
		) VALUES (
			'candidate-legacy', 'source-legacy', 'vless', 'legacy route',
			'candidate-fp', X'00', 0, 1, 1
		)`,
	} {
		if _, err := legacy.ExecContext(ctx, statement); err != nil {
			_ = legacy.Close()
			t.Fatalf("prepare legacy database: %v", err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(databasePath, box)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer database.Close()

	candidates, err := database.ListCandidates(ctx, "source-legacy")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("legacy candidates=%+v err=%v", candidates, err)
	}
	if candidates[0].RouteKey != "" || candidates[0].FailureDomain != "" {
		t.Fatalf("legacy identity defaults=%+v", candidates[0])
	}

	for _, column := range []string{"route_key", "failure_domain"} {
		var (
			notNull      int
			defaultValue sql.NullString
		)
		if err := database.db.QueryRowContext(ctx, `
			SELECT "notnull", dflt_value
			FROM pragma_table_info('candidates')
			WHERE name = ?
		`, column).Scan(&notNull, &defaultValue); err != nil {
			t.Fatalf("inspect %s: %v", column, err)
		}
		if notNull != 1 || !defaultValue.Valid || defaultValue.String != "''" {
			t.Fatalf("%s notnull=%d default=%+v", column, notNull, defaultValue)
		}
	}
	for _, index := range []string{"candidates_route_key_idx", "candidates_failure_domain_idx"} {
		var count int
		if err := database.db.QueryRowContext(ctx, `
			SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?
		`, index).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("index %q count=%d", index, count)
		}
	}
	var migrationCount int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 5`,
	).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration version 5 count=%d", migrationCount)
	}
}

func TestReplaceCandidatesPersistsAndUpdatesIdentityMappings(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	preview := sources.PreviewInput("https://identity.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	sourceID := listed[0].ID
	inputs := []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "vless", Fingerprint: "vless-fp",
			Payload: "vless://id@example.net:443", RouteKey: "route-v1-old",
			FailureDomain: "domain-v1-old",
		},
		{
			Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor-fp",
			Payload: validBridge(4), RouteKey: "must-not-persist",
			FailureDomain: "must-not-persist",
		},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, inputs); err != nil {
		t.Fatal(err)
	}
	got, err := database.ListCandidates(ctx, sourceID)
	if err != nil || len(got) != 2 {
		t.Fatalf("candidates=%+v err=%v", got, err)
	}
	if got[0].RouteKey != "route-v1-old" || got[0].FailureDomain != "domain-v1-old" {
		t.Fatalf("insert identity mapping=%+v", got[0])
	}
	if got[1].RouteKey != "" || got[1].FailureDomain != "" {
		t.Fatalf("Tor identity must remain empty: %+v", got[1])
	}

	inputs[0].RouteKey = "route-v1-new"
	inputs[0].FailureDomain = "domain-v1-new"
	if err := database.ReplaceCandidates(ctx, sourceID, inputs); err != nil {
		t.Fatal(err)
	}
	got, err = database.ListCandidates(ctx, sourceID)
	if err != nil || len(got) != 2 {
		t.Fatalf("updated candidates=%+v err=%v", got, err)
	}
	if got[0].RouteKey != "route-v1-new" || got[0].FailureDomain != "domain-v1-new" {
		t.Fatalf("update identity mapping=%+v", got[0])
	}
}

func TestSameCandidateAcrossSourcesDoesNotCollideOrDoubleCountGlobally(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, _ := Open(filepath.Join(t.TempDir(), "state.db"), box)
	defer database.Close()
	preview := sources.PreviewInput("https://one.example/sub\nhttps://two.example/sub")
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	input := []CandidateInput{{Kind: sources.KindVLESS, Label: "same", Fingerprint: "same-fp", Payload: "vless://id@example.net:443"}}
	for _, source := range listed {
		if err := database.ReplaceCandidates(ctx, source.ID, input); err != nil {
			t.Fatal(err)
		}
	}
	global, err := database.ListCandidates(ctx, "")
	if err != nil || len(global) != 1 {
		t.Fatalf("global candidates=%+v err=%v", global, err)
	}
}

func TestReplaceCandidatesPreservesSourceOrderAcrossRefreshAndBackup(t *testing.T) {
	ctx := context.Background()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "state.db")
	database, err := Open(databasePath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	sourceID := listed[0].ID

	initial := []CandidateInput{
		{Kind: sources.KindTorBridge, Label: "z", Fingerprint: "z", Payload: validBridge(1)},
		{Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a", Payload: validBridge(2)},
		{Kind: sources.KindTorBridge, Label: "m", Fingerprint: "m", Payload: validBridge(3)},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, initial); err != nil {
		t.Fatal(err)
	}
	requireCandidateOrder(t, database, sourceID, []string{"z", "a", "m"})

	if err := database.RecordRefreshFailure(ctx, sourceID, "upstream timeout"); err != nil {
		t.Fatal(err)
	}
	requireCandidateOrder(t, database, sourceID, []string{"z", "a", "m"})

	refreshed := []CandidateInput{
		{Kind: sources.KindTorBridge, Label: "m", Fingerprint: "m", Payload: validBridge(3)},
		{Kind: sources.KindTorBridge, Label: "z", Fingerprint: "z", Payload: validBridge(1)},
		{Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a", Payload: validBridge(2)},
	}
	if err := database.ReplaceCandidates(ctx, sourceID, refreshed); err != nil {
		t.Fatal(err)
	}
	requireCandidateOrder(t, database, sourceID, []string{"m", "z", "a"})

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backup, err := Open(backupPath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	requireCandidateOrder(t, backup, sourceID, []string{"m", "z", "a"})
}

func validBridge(octet int) string {
	return fmt.Sprintf(
		"Bridge 192.0.2.%d:443 0123456789ABCDEF0123456789ABCDEF01234567",
		octet,
	)
}

func requireCandidateOrder(t *testing.T, database *Store, sourceID string, fingerprints []string) {
	t.Helper()
	candidates, err := database.ListCandidates(context.Background(), sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != len(fingerprints) {
		t.Fatalf("candidates=%+v", candidates)
	}
	for position, fingerprint := range fingerprints {
		if candidates[position].Fingerprint != fingerprint ||
			candidates[position].SourcePosition != position {
			t.Fatalf("candidate[%d]=%+v, want fingerprint=%q position=%d",
				position, candidates[position], fingerprint, position)
		}
	}
}
