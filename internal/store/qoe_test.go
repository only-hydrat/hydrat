package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestQoEMigrationCreatesVersionFourTables(t *testing.T) {
	database, _ := qoeCandidateStore(t)
	for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		var count int
		if err := database.db.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("missing table %s", table)
		}
	}
	if err := database.migrateCandidateQoE(context.Background()); err != nil {
		t.Fatalf("replay migration: %v", err)
	}
	var version int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM schema_migrations WHERE version=4`,
	).Scan(&version); err != nil || version != 1 {
		t.Fatalf("version=%d err=%v", version, err)
	}
}

func TestRecordCandidateQoEPersistsSampleAndTransitionAtomically(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	policy := qoe.DefaultPolicy()
	for index := 0; index < 5; index++ {
		_, _, err := database.RecordCandidateQoE(context.Background(), candidate, qoe.Observation{
			At: time.Unix(1_800_000_000+int64(index), 0), Success: true,
			TTFB: 200 * time.Millisecond, TransferDuration: 30 * time.Millisecond,
			Bytes: 65536, ThroughputMbps: 20,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 || states[0].Status != qoe.StatusHealthy {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 5)
	if err != nil || len(samples) != 5 {
		t.Fatalf("samples=%d err=%v", len(samples), err)
	}
	if samples[0].At.Before(samples[len(samples)-1].At) {
		t.Fatalf("samples are not newest-first: %+v", samples)
	}
}

func TestRecordCandidateQoERespectsConfiguredSevenSampleWindow(t *testing.T) {
	policy := qoe.DefaultPolicy()
	policy.WindowSize = 7
	policy.BadSamples = 4
	policy.RecoveryGoodSamples = 6

	t.Run("baseline", func(t *testing.T) {
		database, candidate := qoeCandidateStore(t)
		var state qoe.State
		for index := 0; index < policy.WindowSize; index++ {
			var err error
			state, _, err = database.RecordCandidateQoE(
				context.Background(), candidate,
				healthyQoEObservation(1_800_000_000+int64(index)), policy,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
		if state.Status != qoe.StatusHealthy || state.BaselineSamples != policy.WindowSize ||
			state.WindowValid != policy.WindowSize {
			t.Fatalf("state=%+v, want healthy baseline and window of %d", state, policy.WindowSize)
		}
	})

	t.Run("classification", func(t *testing.T) {
		database, candidate := qoeCandidateStore(t)
		for index := 0; index < policy.WindowSize; index++ {
			if _, _, err := database.RecordCandidateQoE(
				context.Background(), candidate,
				healthyQoEObservation(1_800_000_000+int64(index)), policy,
			); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := database.db.Exec(`
			UPDATE candidate_qoe_state
			SET status = ?, baseline_ttfb_ms = ?, baseline_throughput_mbps = ?,
			    baseline_samples = ?
			WHERE candidate_id = ?
		`, qoe.StatusHealthy, 200, 20, policy.WindowSize, candidate.ID); err != nil {
			t.Fatal(err)
		}

		badResults := map[int]bool{0: true, 3: true, 4: true, 6: true}
		var state qoe.State
		var transition qoe.Transition
		for index := 0; index < policy.WindowSize; index++ {
			observation := healthyQoEObservation(1_800_000_100 + int64(index))
			if badResults[index] {
				observation.Success = false
				observation.ErrorCode = "probe_failed"
			}
			var err error
			state, transition, err = database.RecordCandidateQoE(
				context.Background(), candidate, observation, policy,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
		if state.Status != qoe.StatusDegraded || state.WindowValid != policy.WindowSize ||
			state.WindowBad != policy.BadSamples || transition.From != qoe.StatusHealthy ||
			transition.To != qoe.StatusDegraded {
			t.Fatalf("state=%+v transition=%+v, want degradation on %d bad results in window of %d",
				state, transition, policy.BadSamples, policy.WindowSize)
		}
	})
}

func TestRecordCandidateQoELoadsLongAvailabilityWindow(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	policy := qoe.DefaultPolicy()
	policy.WindowSize = 3
	policy.BadSamples = 2
	policy.RecoveryGoodSamples = 3
	policy.AvailabilityWindow = 6
	policy.AvailabilityFailures = 2
	observations := []qoe.Observation{
		{At: time.Unix(1_800_000_200, 0), ErrorCode: qoe.ReasonRouteTimeout},
		healthyQoEObservation(1_800_000_201),
		healthyQoEObservation(1_800_000_202),
		healthyQoEObservation(1_800_000_203),
		{At: time.Unix(1_800_000_204, 0), ErrorCode: qoe.ReasonRouteTLS},
		healthyQoEObservation(1_800_000_205),
	}
	var state qoe.State
	for _, observation := range observations {
		var err error
		state, _, err = database.RecordCandidateQoE(
			context.Background(), candidate, observation, policy,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	if state.Status != qoe.StatusDegraded || state.LastReason != qoe.ReasonRouteTLS {
		t.Fatalf("state=%+v", state)
	}
}

func TestRecordCandidateQoERejectsUnsupportedWindowSizeWithoutWrites(t *testing.T) {
	for _, windowSize := range []int{0, -1, 101} {
		t.Run(fmt.Sprintf("window_%d", windowSize), func(t *testing.T) {
			database, candidate := qoeCandidateStore(t)
			policy := qoe.DefaultPolicy()
			policy.WindowSize = windowSize

			_, _, err := database.RecordCandidateQoE(
				context.Background(), candidate,
				healthyQoEObservation(1_800_000_000), policy,
			)
			if err == nil {
				t.Fatal("unsupported window size was accepted")
			}
			for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
				var count int
				if err := database.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("rejected policy wrote %d rows to %s", count, table)
				}
			}
		})
	}
}

func TestRecordCandidateQoERollsBackSampleWhenStateWriteFails(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	if _, err := database.db.Exec(`
		CREATE TRIGGER reject_qoe_state
		BEFORE INSERT ON candidate_qoe_state
		BEGIN SELECT RAISE(ABORT, 'forced state write failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	_, _, err := database.RecordCandidateQoE(
		context.Background(), candidate, healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	)
	if err == nil {
		t.Fatal("forced state write failure was ignored")
	}
	for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		var count int
		if err := database.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("transaction left %d rows in %s", count, table)
		}
	}
}

func TestRecordCandidateQoEInfrastructureObservationProducesNoSample(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	before, _, err := database.RecordCandidateQoE(
		context.Background(), candidate, healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	after, transition, err := database.RecordCandidateQoE(context.Background(), candidate, qoe.Observation{
		At: time.Unix(1_800_000_100, 0), Infrastructure: true,
		ErrorCode: "qoe_endpoint_unavailable",
	}, qoe.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if after != before || transition.Changed() {
		t.Fatalf("infrastructure observation mutated state: before=%+v after=%+v transition=%+v",
			before, after, transition)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 10)
	if err != nil || len(samples) != 1 {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
}

func TestRecordCandidateQoERejectsCandidateFromDisabledSource(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	if err := database.ReplaceCandidates(context.Background(), candidate.SourceID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
		Payload: "vless://22222222-2222-2222-2222-222222222222@example.com:443?security=tls",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateSource(
		context.Background(), candidate.SourceID, "disabled source", false,
	); err != nil {
		t.Fatal(err)
	}
	_, _, err := database.RecordCandidateQoE(
		context.Background(), candidate, healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	)
	if !errors.Is(err, ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		var count int
		if err := database.db.QueryRow(
			`SELECT count(*) FROM `+table+` WHERE candidate_id = ?`, candidate.ID,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("stale result wrote %d rows to %s", count, table)
		}
	}
}

func TestCandidateQoERowsRemainUntilPendingSourceCandidatesAreCollected(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	if _, _, err := database.RecordCandidateQoE(
		context.Background(), candidate, healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	); err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteSource(context.Background(), candidate.SourceID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		var count int
		if err := database.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("staged source deletion prematurely cleared %s", table)
		}
	}
}

func TestCandidateQoECascadeSurvivesConnectionReplacement(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	if _, _, err := database.RecordCandidateQoE(
		context.Background(), candidate,
		healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	); err != nil {
		t.Fatal(err)
	}

	// Connection-local pragmas must still apply if database/sql replaces the
	// connection during a long-running controller process.
	database.db.SetMaxIdleConns(0)
	database.db.SetMaxIdleConns(1)
	var foreignKeys int
	if err := database.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys=%d after connection replacement, want 1", foreignKeys)
	}
	var busyTimeout int
	if err := database.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout=%d after connection replacement, want 5000", busyTimeout)
	}
	if _, err := database.db.Exec(
		`DELETE FROM candidates WHERE id=?`, candidate.ID,
	); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"candidate_qoe_state", "candidate_qoe_samples"} {
		var count int
		if err := database.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("connection replacement left %d rows in %s", count, table)
		}
	}
}

func TestReplaceCandidatesPreservesQoEForUnchangedCandidate(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	for index := 0; index < 5; index++ {
		if _, _, err := database.RecordCandidateQoE(
			context.Background(), candidate,
			healthyQoEObservation(1_800_000_000+int64(index)), qoe.DefaultPolicy(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.ReplaceCandidates(context.Background(), candidate.SourceID, []CandidateInput{{
		Kind: candidate.Kind, Label: "refreshed", Fingerprint: candidate.Fingerprint,
		Payload: "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#refreshed",
	}}); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 || states[0].CandidateID != candidate.ID ||
		states[0].Status != qoe.StatusHealthy || states[0].BaselineSamples != 5 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 10)
	if err != nil || len(samples) != 5 {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
}

func TestReplaceCandidatesRejectsDuplicateSurvivorsWithoutLosingQoE(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	if _, _, err := database.RecordCandidateQoE(
		context.Background(), candidate, healthyQoEObservation(1_800_000_000), qoe.DefaultPolicy(),
	); err != nil {
		t.Fatal(err)
	}
	duplicate := CandidateInput{
		Kind: candidate.Kind, Label: "duplicate", Fingerprint: candidate.Fingerprint,
		Payload: "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#duplicate",
	}
	if err := database.ReplaceCandidates(
		context.Background(), candidate.SourceID, []CandidateInput{duplicate, duplicate},
	); err == nil {
		t.Fatal("duplicate candidate refresh was accepted")
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 || states[0].CandidateID != candidate.ID {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 10)
	if err != nil || len(samples) != 1 {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
}

func TestCandidateQoEPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hydrat.db")
	box, err := secretbox.New(bytes.Repeat([]byte{0x42}, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	candidate := seedQoECandidate(t, database)
	for index := 0; index < 5; index++ {
		if _, _, err := database.RecordCandidateQoE(
			context.Background(), candidate,
			healthyQoEObservation(1_800_000_000+int64(index)), qoe.DefaultPolicy(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	states, err := reopened.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 || states[0].CandidateID != candidate.ID ||
		states[0].Status != qoe.StatusHealthy || states[0].BaselineSamples != 5 ||
		!states[0].WindowStartedAt.Equal(time.Unix(1_800_000_000, 0)) ||
		states[0].WindowMaxGap != time.Second {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	samples, err := reopened.ListCandidateQoESamples(context.Background(), candidate.ID, 5)
	if err != nil || len(samples) != 5 {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
}

func TestRecordCandidateQoEBoundsReasonBeforePersistence(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	_, _, err := database.RecordCandidateQoE(context.Background(), candidate, qoe.Observation{
		At: time.Unix(1_800_000_000, 0), ErrorCode: "qoe candidate/timeout\nсекрет-" +
			"abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
	}, qoe.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 1)
	if err != nil || len(samples) != 1 {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	for label, reason := range map[string]string{
		"sample": samples[0].Reason,
		"state":  states[0].LastReason,
	} {
		if len(reason) > 64 {
			t.Fatalf("%s reason length=%d reason=%q", label, len(reason), reason)
		}
		for _, character := range []byte(reason) {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '_' || character == '-' || character == '.') {
				t.Fatalf("unsafe %s reason byte %q in %q", label, character, reason)
			}
		}
	}
}

func TestPruneCandidateQoESamplesDeletesOldestInBoundedBatches(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	for index := 0; index < 6; index++ {
		if _, _, err := database.RecordCandidateQoE(
			context.Background(), candidate,
			healthyQoEObservation(1_800_000_000+int64(index)), qoe.DefaultPolicy(),
		); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Unix(1_800_000_005, 0)
	deleted, err := database.PruneCandidateQoESamples(context.Background(), cutoff, 2)
	if err != nil || deleted != 2 {
		t.Fatalf("first prune deleted=%d err=%v", deleted, err)
	}
	samples, err := database.ListCandidateQoESamples(context.Background(), candidate.ID, 10)
	if err != nil || len(samples) != 4 || !samples[len(samples)-1].At.Equal(time.Unix(1_800_000_002, 0)) {
		t.Fatalf("samples=%+v err=%v", samples, err)
	}
	deleted, err = database.PruneCandidateQoESamples(context.Background(), cutoff, 10)
	if err != nil || deleted != 3 {
		t.Fatalf("second prune deleted=%d err=%v", deleted, err)
	}
	deleted, err = database.PruneCandidateQoESamples(context.Background(), cutoff, 0)
	if err != nil || deleted != 0 {
		t.Fatalf("zero batch deleted=%d err=%v", deleted, err)
	}
	samples, err = database.ListCandidateQoESamples(context.Background(), candidate.ID, 10)
	if err != nil || len(samples) != 1 || !samples[0].At.Equal(time.Unix(1_800_000_005, 0)) {
		t.Fatalf("remaining samples=%+v err=%v", samples, err)
	}
}

func qoeCandidateStore(t *testing.T) (*Store, Candidate) {
	t.Helper()
	box, err := secretbox.New(bytes.Repeat([]byte{0x42}, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(filepath.Join(t.TempDir(), "hydrat.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, seedQoECandidate(t, database)
}

func seedQoECandidate(t *testing.T, database *Store) Candidate {
	t.Helper()
	const payload = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#qoe"
	preview := sources.PreviewInput(payload)
	if len(preview.Items) != 1 {
		t.Fatalf("preview items=%+v", preview.Items)
	}
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(context.Background())
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	item := preview.Items[0]
	if err := database.ReplaceCandidates(context.Background(), sourceRows[0].ID, []CandidateInput{{
		Kind: item.Kind, Label: item.Display, Fingerprint: item.Fingerprint, Payload: item.Payload,
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	return candidates[0]
}

func healthyQoEObservation(unix int64) qoe.Observation {
	return qoe.Observation{
		At: time.Unix(unix, 0), Success: true,
		TTFB: 200 * time.Millisecond, TransferDuration: 30 * time.Millisecond,
		Bytes: 65536, ThroughputMbps: 20,
	}
}
