package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestObservationBatchReservationIsAtomicAndStageIndependent(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
			Payload: "vless://a@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443?security=tls",
		},
	})
	a, b := candidates["a"], candidates["b"]
	if err := database.ReplaceCandidates(ctx, a.SourceID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
		Payload: "vless://a@example.net:443?security=tls",
	}}); err != nil {
		t.Fatal(err)
	}
	_, err := database.ReserveCandidateObservations(ctx, []ObservationRequest{
		{Candidate: a, Stage: ObservationFull},
		{Candidate: b, Stage: ObservationFull},
	})
	if !errors.Is(err, ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	var healthRows int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM candidate_health WHERE candidate_id=?`,
		a.ID,
	).Scan(&healthRows); err != nil {
		t.Fatal(err)
	}
	if healthRows != 0 {
		t.Fatalf("failed batch partially reserved current candidate health=%d", healthRows)
	}

	reservations, err := database.ReserveCandidateObservations(
		ctx,
		[]ObservationRequest{
			{Candidate: a, Stage: ObservationFast},
			{Candidate: a, Stage: ObservationFull},
			{Candidate: a, Stage: ObservationActive},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(reservations) != 3 {
		t.Fatalf("reservations=%+v", reservations)
	}
	for _, reservation := range reservations {
		if reservation.Sequence != 1 {
			t.Fatalf("independent first stage reservation=%+v", reservation)
		}
	}
}

func TestObservationBatchRejectsDuplicateIdentityStageWithoutClockMutation(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	_, err := database.ReserveCandidateObservations(ctx, []ObservationRequest{
		{Candidate: candidate, Stage: ObservationFast},
		{Candidate: candidate, Stage: ObservationFast},
	})
	if err == nil {
		t.Fatal("duplicate candidate stage batch was accepted")
	}
	var probeRows, healthRows int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM candidate_probe_state WHERE fingerprint=?`,
		candidate.Fingerprint,
	).Scan(&probeRows); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM candidate_health WHERE candidate_id=?`,
		candidate.ID,
	).Scan(&healthRows); err != nil {
		t.Fatal(err)
	}
	if probeRows != 0 || healthRows != 0 {
		t.Fatalf("duplicate batch advanced clocks probe=%d health=%d",
			probeRows, healthRows)
	}
}

func TestObservationActiveSuccessRejectsNewerFullFailureGeneration(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	activeSuccess, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	fullFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Second)
	_, fullCommit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		fullFailure,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: false,
			ErrorCode: "full_probe_failed", At: at,
		},
		&CandidateHealth{CandidateID: candidate.ID, UpdatedAt: at},
		nil,
	)
	if err != nil || !fullCommit.Accepted {
		t.Fatalf("full failure commit=%+v err=%v", fullCommit, err)
	}
	activeCommit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, activeSuccess, true, at.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if activeCommit.Accepted {
		t.Fatal("active success crossed a newer full hard failure generation")
	}
	health, generation := observationHealth(t, database, candidate.ID)
	if health.Available || generation != 1 {
		t.Fatalf("health=%+v generation=%d", health, generation)
	}
}

func TestCandidateHealthExposesFreshCurrentActiveObservationFence(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("initial health=%+v err=%v", rows, err)
	}
	if !rows[0].ActiveObservedAt.IsZero() || rows[0].ActiveSuccess || rows[0].ActiveCurrent {
		t.Fatalf("full-only health claimed active freshness: %+v", rows[0])
	}

	first, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	activeAt := base.Add(time.Minute)
	commit, err := database.CommitCandidateActiveObservation(ctx, candidate, first, true, activeAt)
	if err != nil || !commit.Accepted {
		t.Fatalf("active commit=%+v err=%v", commit, err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveObservedAt.Equal(activeAt) ||
		!rows[0].ActiveSuccess || !rows[0].ActiveCurrent {
		t.Fatalf("accepted active health=%+v err=%v", rows, err)
	}

	second, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveCurrent ||
		!rows[0].ActiveSuccess || !rows[0].ActiveObservedAt.Equal(activeAt) {
		t.Fatalf("in-flight active reservation revoked accepted proof: %+v err=%v", rows, err)
	}
	secondAt := activeAt.Add(time.Minute)
	commit, err = database.CommitCandidateActiveObservation(ctx, candidate, second, true, secondAt)
	if err != nil || !commit.Accepted {
		t.Fatalf("second active commit=%+v err=%v", commit, err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveObservedAt.Equal(secondAt) ||
		!rows[0].ActiveSuccess || !rows[0].ActiveCurrent {
		t.Fatalf("latest active health=%+v err=%v", rows, err)
	}

	third, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	failureAt := secondAt.Add(time.Minute)
	_, failureCommit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidate, third, failureAt,
	)
	if err != nil || !failureCommit.Accepted {
		t.Fatalf("active failure commit=%+v err=%v", failureCommit, err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveObservedAt.Equal(failureAt) ||
		rows[0].ActiveSuccess || !rows[0].ActiveCurrent || !rows[0].ActiveHardFailure {
		t.Fatalf("active failure health=%+v err=%v", rows, err)
	}
}

func TestCandidateActiveObservedAtV15MigratesSecondsAndFailsClosed(t *testing.T) {
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
	candidates := failureDomainVLESSCandidates(
		t, database, "legacy-seconds", "already-millis", "invalid",
	)
	base := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		saveObservationHealth(t, database, candidate.ID, base, 90)
	}
	values := map[string]int64{
		"legacy-seconds": base.Unix(),
		"already-millis": base.Add(750 * time.Millisecond).UnixMilli(),
		"invalid":        -1,
	}
	for name, value := range values {
		if _, err := database.db.ExecContext(ctx, `
			UPDATE candidate_health
			SET active_observed_at=?, active_success=1,
			    active_applied_seq=1,
			    active_failure_generation=failure_generation
			WHERE candidate_id=?
		`, value, candidates[name].ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version=15`,
	); err != nil {
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
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]CandidateHealth, len(rows))
	for _, row := range rows {
		byID[row.CandidateID] = row
	}
	legacy := byID[candidates["legacy-seconds"].ID]
	if !legacy.ActiveObservedAt.Equal(base) || !legacy.ActiveSuccess || !legacy.ActiveCurrent {
		t.Fatalf("legacy seconds migration=%+v", legacy)
	}
	millis := byID[candidates["already-millis"].ID]
	if !millis.ActiveObservedAt.Equal(base.Add(750*time.Millisecond)) ||
		!millis.ActiveSuccess || !millis.ActiveCurrent {
		t.Fatalf("existing milliseconds migration=%+v", millis)
	}
	invalid := byID[candidates["invalid"].ID]
	if !invalid.ActiveObservedAt.IsZero() || invalid.ActiveSuccess || invalid.ActiveCurrent {
		t.Fatalf("invalid timestamp did not fail closed=%+v", invalid)
	}
	var migration int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=15`,
	).Scan(&migration); err != nil || migration != 1 {
		t.Fatalf("v15 migration=%d err=%v", migration, err)
	}
}

func TestCandidateActiveReservationRejectsSupersededCompletionWithoutRevokingProof(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	seed, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	proofAt := base.Add(time.Minute)
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, seed, true, proofAt,
	); err != nil || !commit.Accepted {
		t.Fatalf("seed proof commit=%+v err=%v", commit, err)
	}
	older, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveCurrent ||
		!rows[0].ActiveSuccess || !rows[0].ActiveObservedAt.Equal(proofAt) {
		t.Fatalf("blocked reprobe revoked proof: health=%+v err=%v", rows, err)
	}
	stale, err := database.CommitCandidateActiveObservation(
		ctx, candidate, older, false, proofAt.Add(time.Minute),
	)
	if err != nil || stale.Accepted {
		t.Fatalf("superseded active completion=%+v err=%v", stale, err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].ActiveCurrent ||
		!rows[0].ActiveSuccess || !rows[0].ActiveObservedAt.Equal(proofAt) {
		t.Fatalf("stale completion revoked proof: health=%+v err=%v", rows, err)
	}
	latestAt := proofAt.Add(2 * time.Minute)
	latest, err := database.CommitCandidateActiveObservation(
		ctx, candidate, newer, true, latestAt,
	)
	if err != nil || !latest.Accepted {
		t.Fatalf("latest active completion=%+v err=%v", latest, err)
	}
}

func TestRoutingEvidenceSnapshotIgnoresOnlyActiveReservationOrderFence(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)
	seed, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, seed, true, base.Add(time.Minute),
	); err != nil || !commit.Accepted {
		t.Fatalf("seed proof commit=%+v err=%v", commit, err)
	}
	snapshot, err := database.LoadRoutingEvidenceSnapshot(ctx, []string{candidate.ID})
	if err != nil || len(snapshot.Candidates) != 1 {
		t.Fatalf("routing snapshot=%+v err=%v", snapshot, err)
	}
	if _, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.ValidateCandidatePlanSnapshot(
		ctx, snapshot.InventoryEpoch, []CandidatePlanExpectation{{
			Candidate: candidate, EvidenceDigest: snapshot.Candidates[0].Digest,
		}},
	); err != nil {
		t.Fatalf("active reservation order fence changed routing evidence: %v", err)
	}
}

func TestCandidateActiveOutcomeSeparatesAvailabilityFromFreshProofTransition(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	commit := func(at time.Time, outcome ActiveObservationOutcome) ObservationCommitResult {
		t.Helper()
		reservation, err := database.ReserveCandidateObservation(
			ctx, candidate, ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		result, err := database.CommitCandidateActiveOutcome(
			ctx, candidate, reservation, outcome, at,
		)
		if err != nil || !result.Accepted {
			t.Fatalf("active outcome commit=%+v err=%v", result, err)
		}
		return result
	}

	partialAt := base.Add(time.Minute)
	partial := commit(partialAt, ActiveObservationOutcome{
		Available: true, ProofSuccess: false,
		RetainPreviousProof: true, ProofFreshAfter: base,
	})
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].Available ||
		rows[0].ActiveSuccess || rows[0].ActiveHardFailure ||
		partial.BecameProofEligible {
		t.Fatalf("partial active outcome=%+v commit=%+v err=%v",
			rows, partial, err)
	}

	proofAt := partialAt.Add(time.Minute)
	proof := commit(proofAt, ActiveObservationOutcome{
		Available: true, ProofSuccess: true,
		ProofFreshAfter: base,
	})
	if !proof.BecameProofEligible {
		t.Fatalf("first proof transition=%+v", proof)
	}
	fresh := commit(proofAt.Add(time.Minute), ActiveObservationOutcome{
		Available: true, ProofSuccess: true,
		ProofFreshAfter: proofAt.Add(-time.Second),
	})
	if fresh.BecameProofEligible {
		t.Fatalf("fresh prior proof retriggered transition=%+v", fresh)
	}
	stale := commit(proofAt.Add(2*time.Minute), ActiveObservationOutcome{
		Available: true, ProofSuccess: true,
		ProofFreshAfter: proofAt.Add(time.Minute + time.Second),
	})
	if !stale.BecameProofEligible {
		t.Fatalf("stale prior proof did not transition=%+v", stale)
	}
}

func TestCandidateActiveOutcomeRetainsPreviousProofForDegradedObservation(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	seed, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	proofAt := base.Add(time.Second)
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, seed, ActiveObservationOutcome{
			Available: true, ProofSuccess: true,
			ProofFreshAfter: base,
		}, proofAt,
	); err != nil || !commit.Accepted {
		t.Fatalf("seed proof commit=%+v err=%v", commit, err)
	}

	older, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	degradedAt := proofAt.Add(time.Second)
	commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, degraded, ActiveObservationOutcome{
			Available: true, ProofSuccess: false,
			RetainPreviousProof: true,
			ProofFreshAfter:     proofAt.Add(-time.Second),
		}, degradedAt,
	)
	if err != nil || !commit.Accepted || commit.BecameProofEligible {
		t.Fatalf("degraded proof commit=%+v err=%v", commit, err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].Available ||
		!rows[0].ActiveSuccess || !rows[0].ActiveCurrent ||
		!rows[0].ActiveObservedAt.Equal(proofAt) {
		t.Fatalf("retained proof health=%+v err=%v", rows, err)
	}
	var resultSequence, appliedSequence int64
	if err := database.db.QueryRowContext(ctx, `
		SELECT active_result_seq, active_applied_seq
		FROM candidate_health WHERE candidate_id=?
	`, candidate.ID).Scan(&resultSequence, &appliedSequence); err != nil {
		t.Fatal(err)
	}
	if resultSequence != degraded.Sequence || appliedSequence != degraded.Sequence {
		t.Fatalf("active sequences result=%d applied=%d want=%d",
			resultSequence, appliedSequence, degraded.Sequence)
	}

	stale, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, older, ActiveObservationOutcome{
			Available: true, ProofSuccess: false,
			RetainPreviousProof: true,
			ProofFreshAfter:     proofAt.Add(-time.Second),
		}, degradedAt.Add(time.Second),
	)
	if err != nil || stale.Accepted {
		t.Fatalf("older degraded completion=%+v err=%v", stale, err)
	}
}

func TestCandidateActiveHardFailurePersistsAcrossRepeatedDownUntilAvailableRecovery(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_900_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	failure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidate, failure, base.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}

	repeatedDown, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, repeatedDown,
		ActiveObservationOutcome{Available: false, ProofSuccess: false},
		base.Add(2*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("repeated down commit=%+v err=%v", commit, err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || rows[0].Available ||
		!rows[0].ActiveHardFailure {
		t.Fatalf("repeated down cleared hard failure: health=%+v err=%v", rows, err)
	}

	recovery, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, recovery,
		ActiveObservationOutcome{Available: true, ProofSuccess: true},
		base.Add(3*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("recovery commit=%+v err=%v", commit, err)
	}
	rows, err = database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].Available ||
		rows[0].ActiveHardFailure {
		t.Fatalf("available recovery retained hard failure: health=%+v err=%v", rows, err)
	}
}

func TestCandidateActiveHardFailureMigrationIsFailClosedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	path := filepath.Join(t.TempDir(), "active-hard-failure.db")
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO candidate_health(
		  candidate_id, score, tcp_qualified, udp_qualified, available, updated_at,
		  active_observed_at, active_success, active_failure_generation
		) VALUES ('legacy-partial', 88, 1, 1, 1, 1900000000, 1900000000, 0, 0);
		INSERT INTO candidate_health(
		  candidate_id, score, tcp_qualified, udp_qualified, available, updated_at,
		  active_observed_at, active_success, active_failure_generation,
		  active_result_seq, active_applied_seq
		) VALUES ('legacy-hard', 88, 1, 1, 0, 1900000000, 1900000000, 0, 0, 1, 1);
		ALTER TABLE candidate_health DROP COLUMN active_hard_failure;
		DELETE FROM schema_migrations WHERE version IN (13, 15);
	`); err != nil {
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
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("migrated active outcomes=%+v err=%v", rows, err)
	}
	hardByID := make(map[string]bool, len(rows))
	currentByID := make(map[string]bool, len(rows))
	for _, row := range rows {
		hardByID[row.CandidateID] = row.ActiveHardFailure
		currentByID[row.CandidateID] = row.ActiveCurrent
	}
	if hardByID["legacy-partial"] || !hardByID["legacy-hard"] ||
		!currentByID["legacy-hard"] {
		t.Fatalf("migrated hard semantics=%v current=%v", hardByID, currentByID)
	}
	var migrations int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=13
	`).Scan(&migrations); err != nil || migrations != 1 {
		t.Fatalf("v13 migrations=%d err=%v", migrations, err)
	}
}

func TestCandidateActiveEvidenceMigrationIsFailClosedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	path := filepath.Join(t.TempDir(), "active-evidence.db")
	database, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO candidate_health(
		  candidate_id, score, tcp_qualified, udp_qualified, available, updated_at
		) VALUES ('legacy', 88, 1, 1, 1, 1900000000);
		ALTER TABLE candidate_health DROP COLUMN active_observed_at;
		ALTER TABLE candidate_health DROP COLUMN active_success;
		ALTER TABLE candidate_health DROP COLUMN active_failure_generation;
		DELETE FROM schema_migrations WHERE version=12;
	`); err != nil {
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
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()

	for column, wantDefault := range map[string]string{
		"active_observed_at":        "",
		"active_success":            "0",
		"active_failure_generation": "0",
	} {
		var notNull int
		var defaultValue sql.NullString
		if err := database.db.QueryRowContext(ctx, `
			SELECT "notnull", dflt_value
			FROM pragma_table_info('candidate_health')
			WHERE name=?
		`, column).Scan(&notNull, &defaultValue); err != nil {
			t.Fatalf("inspect %s: %v", column, err)
		}
		if wantDefault == "" {
			if notNull != 0 || defaultValue.Valid {
				t.Fatalf("%s notnull=%d default=%+v", column, notNull, defaultValue)
			}
		} else if notNull != 1 || !defaultValue.Valid || defaultValue.String != wantDefault {
			t.Fatalf("%s notnull=%d default=%+v", column, notNull, defaultValue)
		}
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || rows[0].CandidateID != "legacy" ||
		!rows[0].ActiveObservedAt.IsZero() || rows[0].ActiveSuccess || rows[0].ActiveCurrent {
		t.Fatalf("migrated legacy health=%+v err=%v", rows, err)
	}
	var migrations int
	if err := database.db.QueryRowContext(ctx, `
		SELECT count(*) FROM schema_migrations WHERE version=12
	`).Scan(&migrations); err != nil || migrations != 1 {
		t.Fatalf("v12 migrations=%d err=%v", migrations, err)
	}
}

func TestObservationActiveHardFailureRemainsFailClosedAcrossFullFailureGeneration(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	activeFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	fullFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Second)
	_, fullCommit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		fullFailure,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: false,
			ErrorCode: "full_probe_failed", At: at,
		},
		&CandidateHealth{CandidateID: candidate.ID, UpdatedAt: at},
		nil,
	)
	if err != nil || !fullCommit.Accepted {
		t.Fatalf("full failure commit=%+v err=%v", fullCommit, err)
	}
	_, activeCommit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, activeFailure, at.Add(time.Second),
	)
	if err != nil || !activeCommit.Accepted {
		t.Fatalf("active failure commit=%+v err=%v", activeCommit, err)
	}
	health, generation := observationHealth(t, database, candidate.ID)
	if health.Available || generation != 2 {
		t.Fatalf("health=%+v generation=%d", health, generation)
	}
}

func TestObservationReservationReplayIsRejectedForEveryStage(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	fast, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFast)
	if err != nil {
		t.Fatal(err)
	}
	fastTransition := ProbeTransition{
		Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
		SourceID: candidate.SourceID, Success: true, At: base.Add(time.Second),
	}
	if _, commit, err := database.CommitCandidateProbeObservation(
		ctx, candidate, fast, fastTransition, nil, nil,
	); err != nil || !commit.Accepted {
		t.Fatalf("first fast commit=%+v err=%v", commit, err)
	}
	beforeFast, err := database.CandidateProbeState(ctx, candidate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, replay, err := database.CommitCandidateProbeObservation(
		ctx, candidate, fast, fastTransition, nil, nil,
	); err != nil || replay.Accepted {
		t.Fatalf("fast replay=%+v err=%v", replay, err)
	}
	afterFast, _ := database.CandidateProbeState(ctx, candidate.Fingerprint)
	if afterFast != beforeFast {
		t.Fatalf("fast replay mutated state before=%+v after=%+v",
			beforeFast, afterFast)
	}

	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	fullAt := base.Add(2 * time.Second)
	fullTransition := ProbeTransition{
		Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
		SourceID: candidate.SourceID, Full: true, Success: true,
		Score: 95, At: fullAt,
	}
	fullHealth := CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		Available: true, UpdatedAt: fullAt,
	}
	fullSample := ProbeSample{
		CandidateID: candidate.ID, Success: true, CreatedAt: fullAt,
	}
	if _, commit, err := database.CommitCandidateProbeObservation(
		ctx, candidate, full, fullTransition, &fullHealth, &fullSample,
	); err != nil || !commit.Accepted {
		t.Fatalf("first full commit=%+v err=%v", commit, err)
	}
	beforeFull := observationMutationCounts(t, database, candidate)
	beforeFullHealth, _ := observationHealth(t, database, candidate.ID)
	replayHealth := fullHealth
	replayHealth.Score = 1
	if _, replay, err := database.CommitCandidateProbeObservation(
		ctx, candidate, full, fullTransition, &replayHealth, &fullSample,
	); err != nil || replay.Accepted {
		t.Fatalf("full replay=%+v err=%v", replay, err)
	}
	afterFull := observationMutationCounts(t, database, candidate)
	afterFullHealth, _ := observationHealth(t, database, candidate.ID)
	if afterFull != beforeFull || afterFullHealth != beforeFullHealth {
		t.Fatalf("full replay mutated artifacts before=%+v/%+v after=%+v/%+v",
			beforeFull, beforeFullHealth, afterFull, afterFullHealth)
	}

	active, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, active, false, base.Add(3*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("first active commit=%+v err=%v", commit, err)
	}
	beforeActive, _ := observationHealth(t, database, candidate.ID)
	if replay, err := database.CommitCandidateActiveObservation(
		ctx, candidate, active, true, base.Add(4*time.Second),
	); err != nil || replay.Accepted {
		t.Fatalf("active replay=%+v err=%v", replay, err)
	}
	afterActive, _ := observationHealth(t, database, candidate.ID)
	if afterActive != beforeActive {
		t.Fatalf("active replay mutated health before=%+v after=%+v",
			beforeActive, afterActive)
	}
}

func TestObservationOverlappingReservationsAcceptOrderedCompletionsAndRejectReplay(
	t *testing.T,
) {
	for _, stage := range []ObservationStage{
		ObservationFast,
		ObservationFull,
		ObservationActive,
	} {
		t.Run(string(stage), func(t *testing.T) {
			ctx := context.Background()
			database, candidates := observationTestStore(t)
			candidate := candidates["candidate"]
			base := time.Unix(1_800_000_000, 0)
			saveObservationHealth(t, database, candidate.ID, base, 91)

			first, err := database.ReserveCandidateObservation(
				ctx, candidate, stage,
			)
			if err != nil {
				t.Fatal(err)
			}
			second, err := database.ReserveCandidateObservation(
				ctx, candidate, stage,
			)
			if err != nil {
				t.Fatal(err)
			}
			if second.Sequence != first.Sequence+1 {
				t.Fatalf("sequences first=%d second=%d",
					first.Sequence, second.Sequence)
			}

			firstCommit, err := commitOverlappingObservation(
				ctx, database, candidate, first, base.Add(time.Second),
			)
			if err != nil || !firstCommit.Accepted {
				t.Fatalf("first commit=%+v err=%v", firstCommit, err)
			}
			secondCommit, err := commitOverlappingObservation(
				ctx, database, candidate, second, base.Add(2*time.Second),
			)
			if err != nil || !secondCommit.Accepted {
				t.Fatalf("second commit=%+v err=%v", secondCommit, err)
			}
			replay, err := commitOverlappingObservation(
				ctx, database, candidate, first, base.Add(3*time.Second),
			)
			if err != nil {
				t.Fatal(err)
			}
			if replay.Accepted {
				t.Fatal("older reservation replay accepted after newer result")
			}
		})
	}
}

func TestObservationContinuousActiveOverlappingLatencyPreservesFreshProof(
	t *testing.T,
) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	inFlight, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	for tick := 1; tick <= 8; tick++ {
		next, err := database.ReserveCandidateObservation(
			ctx, candidate, ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := database.CommitCandidateActiveObservation(
			ctx,
			candidate,
			inFlight,
			tick%2 == 0,
			base.Add(time.Duration(tick)*250*time.Millisecond),
		)
		expectAccepted := tick < 3 || tick%2 == 0
		if err != nil || commit.Accepted != expectAccepted {
			t.Fatalf("tick %d sequence %d commit=%+v err=%v",
				tick, inFlight.Sequence, commit, err)
		}
		inFlight = next
	}
	commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, inFlight, true, base.Add(3*time.Second),
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("final sequence %d commit=%+v err=%v",
			inFlight.Sequence, commit, err)
	}
}

func TestObservationActiveCompletionReorderingNewestResultWins(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)
	older, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, newer, false, base.Add(2*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("newer commit=%+v err=%v", commit, err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, older, true, base.Add(3*time.Second),
	); err != nil || commit.Accepted {
		t.Fatalf("older completion after newer=%+v err=%v", commit, err)
	}
	health, _ := observationHealth(t, database, candidate.ID)
	if health.Available || !health.UpdatedAt.Equal(base.Add(2*time.Second)) {
		t.Fatalf("newest accepted result was overwritten: %+v", health)
	}
}

func commitOverlappingObservation(
	ctx context.Context,
	database *Store,
	candidate Candidate,
	reservation ObservationReservation,
	at time.Time,
) (ObservationCommitResult, error) {
	switch reservation.Stage {
	case ObservationFast, ObservationFull:
		transition := ProbeTransition{
			Fingerprint: candidate.Fingerprint,
			CandidateID: candidate.ID,
			SourceID:    candidate.SourceID,
			Full:        reservation.Stage == ObservationFull,
			Success:     true,
			Score:       90 + float64(reservation.Sequence),
			At:          at,
		}
		var health *CandidateHealth
		if reservation.Stage == ObservationFull {
			health = &CandidateHealth{
				CandidateID: candidate.ID,
				Score:       transition.Score,
				Available:   true,
				UpdatedAt:   at,
			}
		}
		_, commit, err := database.CommitCandidateProbeObservation(
			ctx, candidate, reservation, transition, health, nil,
		)
		return commit, err
	case ObservationActive:
		_, commit, err := database.CommitCandidateActiveHardFailureObservation(
			ctx, candidate, reservation, at,
		)
		return commit, err
	default:
		return ObservationCommitResult{}, errors.New("unexpected observation stage")
	}
}

func TestObservationHardFailureReservationReplayIsOneShot(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)
	active, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, active, base.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("first hard failure=%+v err=%v", commit, err)
	}
	before := observationMutationCounts(t, database, candidate)
	beforeHealth, _ := observationHealth(t, database, candidate.ID)
	if _, replay, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, active, base.Add(2*time.Second),
	); err != nil || replay.Accepted {
		t.Fatalf("hard failure replay=%+v err=%v", replay, err)
	}
	after := observationMutationCounts(t, database, candidate)
	afterHealth, _ := observationHealth(t, database, candidate.ID)
	if after != before || afterHealth != beforeHealth {
		t.Fatalf("hard replay mutated artifacts before=%+v/%+v after=%+v/%+v",
			before, beforeHealth, after, afterHealth)
	}
}

func TestObservationCommitRejectsMismatchedPayloadIdentityWithoutMutation(t *testing.T) {
	ctx := context.Background()
	database, candidates := candidateStateTestStore(t, []CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
			Payload: "vless://a@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443?security=tls",
		},
	})
	a, b := candidates["a"], candidates["b"]
	base := time.Unix(1_800_000_000, 0)
	reservation, err := database.ReserveCandidateObservation(
		ctx, a, ObservationFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	beforeA, _ := observationHealth(t, database, a.ID)
	_, _, err = database.CommitCandidateProbeObservation(
		ctx,
		a,
		reservation,
		ProbeTransition{
			Fingerprint: b.Fingerprint, CandidateID: b.ID,
			SourceID: b.SourceID, Full: true, Success: true,
			At: base,
		},
		&CandidateHealth{CandidateID: b.ID, UpdatedAt: base},
		&ProbeSample{CandidateID: b.ID, CreatedAt: base},
	)
	if err == nil {
		t.Fatal("mismatched candidate payload was accepted")
	}
	afterA, _ := observationHealth(t, database, a.ID)
	if afterA != beforeA {
		t.Fatalf("identity error mutated reserved health before=%+v after=%+v",
			beforeA, afterA)
	}
	var bHealth, bSamples int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM candidate_health WHERE candidate_id=?`,
		b.ID,
	).Scan(&bHealth); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM probe_samples WHERE candidate_id=?`,
		b.ID,
	).Scan(&bSamples); err != nil {
		t.Fatal(err)
	}
	if bHealth != 0 || bSamples != 0 {
		t.Fatalf("identity error wrote candidate B health=%d samples=%d",
			bHealth, bSamples)
	}
}

func TestObservationCommitValidatesHealthAndSampleIdentity(t *testing.T) {
	for _, mismatch := range []string{"health", "sample"} {
		t.Run(mismatch, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := candidateStateTestStore(t, []CandidateInput{
				{
					Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
					Payload: "vless://a@example.net:443?security=tls",
				},
				{
					Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
					Payload: "vless://b@example.net:443?security=tls",
				},
			})
			a, b := candidates["a"], candidates["b"]
			at := time.Unix(1_800_000_000, 0)
			reservation, err := database.ReserveCandidateObservation(
				ctx, a, ObservationFull,
			)
			if err != nil {
				t.Fatal(err)
			}
			health := &CandidateHealth{CandidateID: a.ID, UpdatedAt: at}
			sample := &ProbeSample{CandidateID: a.ID, CreatedAt: at}
			if mismatch == "health" {
				health.CandidateID = b.ID
			} else {
				sample.CandidateID = b.ID
			}
			_, _, err = database.CommitCandidateProbeObservation(
				ctx,
				a,
				reservation,
				ProbeTransition{
					Fingerprint: a.Fingerprint, CandidateID: a.ID,
					SourceID: a.SourceID, Full: true, Success: true, At: at,
				},
				health,
				sample,
			)
			if err == nil {
				t.Fatalf("mismatched %s identity was accepted", mismatch)
			}
			var samples int
			if err := database.db.QueryRowContext(
				ctx, `SELECT count(*) FROM probe_samples`,
			).Scan(&samples); err != nil {
				t.Fatal(err)
			}
			if samples != 0 {
				t.Fatalf("mismatched %s wrote samples=%d", mismatch, samples)
			}
		})
	}
}

func TestObservationPlaceholderMarkerPreservesLegitimateRowsAndCrashSafety(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	at := time.Unix(1_800_000_000, 0)

	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidate.ID, UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFull,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || rows[0].CandidateID != candidate.ID {
		t.Fatalf("legitimate zero health hidden after reservation: rows=%+v err=%v",
			rows, err)
	}

	fast, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFast,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		fast,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, InfrastructureFailure: true, At: at,
		},
		nil,
		nil,
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("fast commit=%+v err=%v", commit, err)
	}
	states, err := database.ListCandidateProbeStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("non-placeholder zero probe state hidden: states=%+v err=%v",
			states, err)
	}
}

func TestObservationReservationOnlyPlaceholdersStayHiddenAcrossReopen(t *testing.T) {
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
	preview := sources.PreviewInput("https://placeholder.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourcesRows, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, sourcesRows[0].ID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "placeholder", Fingerprint: "placeholder",
		Payload: "vless://placeholder@example.net:443?security=tls",
	}}); err != nil {
		t.Fatal(err)
	}
	candidateRows, _ := database.ListCandidates(ctx, "")
	candidate := candidateRows[0]
	if _, err := database.ReserveCandidateObservations(ctx, []ObservationRequest{
		{Candidate: candidate, Stage: ObservationFast},
		{Candidate: candidate, Stage: ObservationFull},
	}); err != nil {
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
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 0 {
		t.Fatalf("reservation-only health after reopen=%+v err=%v", healthRows, err)
	}
	probeRows, err := database.ListCandidateProbeStates(ctx)
	if err != nil || len(probeRows) != 0 {
		t.Fatalf("reservation-only probe after reopen=%+v err=%v", probeRows, err)
	}
	var healthPlaceholder, probePlaceholder int
	if err := database.db.QueryRowContext(ctx, `
		SELECT observation_placeholder FROM candidate_health WHERE candidate_id=?
	`, candidate.ID).Scan(&healthPlaceholder); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT observation_placeholder
		FROM candidate_probe_state WHERE fingerprint=?
	`, candidate.Fingerprint).Scan(&probePlaceholder); err != nil {
		t.Fatal(err)
	}
	if healthPlaceholder != 1 || probePlaceholder != 1 {
		t.Fatalf("placeholder markers health=%d probe=%d",
			healthPlaceholder, probePlaceholder)
	}
}

func TestObservationFailedFullRemainsVisibleAfterSamplePruning(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	at := time.Unix(1_800_000_000, 0)
	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	_, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: false,
			ErrorCode: "full_probe_failed", At: at,
		},
		&CandidateHealth{CandidateID: candidate.ID, UpdatedAt: at},
		&ProbeSample{CandidateID: candidate.ID, Success: false, CreatedAt: at},
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v err=%v", commit, err)
	}
	if _, err := database.db.ExecContext(
		ctx, `DELETE FROM probe_samples WHERE candidate_id=?`, candidate.ID,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || rows[0].CandidateID != candidate.ID {
		t.Fatalf("failed full hidden after sample pruning: rows=%+v err=%v",
			rows, err)
	}
}

func TestObservationAppliedClockMigrationReplaysWithoutEncryptedPayloadLoss(
	t *testing.T,
) {
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
	preview := sources.PreviewInput("https://migration.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, _ := database.ListSources(ctx)
	const payload = "vless://encrypted@example.net:443?security=tls"
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "encrypted", Fingerprint: "encrypted",
		Payload: payload,
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, "")
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidates[0].ID,
		UpdatedAt:   time.Unix(1_800_000_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	for table, columns := range map[string][]string{
		"candidate_probe_state": {"observation_placeholder", "fast_applied_seq"},
		"candidate_health": {
			"observation_placeholder",
			"full_applied_seq",
			"active_applied_seq",
		},
	} {
		for _, column := range columns {
			var exists int
			if err := database.db.QueryRowContext(ctx, `
				SELECT count(*) FROM pragma_table_info(?) WHERE name=?
			`, table, column).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists == 0 {
				continue
			}
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE `+table+` DROP COLUMN `+column,
			); err != nil {
				t.Fatalf("drop %s.%s: %v", table, column, err)
			}
		}
	}
	if _, err := database.db.ExecContext(
		ctx, `DELETE FROM schema_migrations WHERE version=9`,
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
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()
	gotPayload, err := database.CandidatePayload(ctx, candidates[0].ID)
	if err != nil || gotPayload != payload {
		t.Fatalf("payload=%q err=%v", gotPayload, err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("legitimate migrated zero health=%+v err=%v", rows, err)
	}
	for table, columns := range map[string][]string{
		"candidate_probe_state": {"observation_placeholder", "fast_applied_seq"},
		"candidate_health": {
			"observation_placeholder",
			"full_applied_seq",
			"active_applied_seq",
		},
	} {
		for _, column := range columns {
			var (
				notNull int
				dflt    string
			)
			if err := database.db.QueryRowContext(ctx, `
				SELECT "notnull", dflt_value
				FROM pragma_table_info(?)
				WHERE name=?
			`, table, column).Scan(&notNull, &dflt); err != nil {
				t.Fatalf("inspect %s.%s: %v", table, column, err)
			}
			if notNull != 1 || dflt != "0" {
				t.Fatalf("%s.%s notnull=%d default=%q",
					table, column, notNull, dflt)
			}
		}
	}
	var migrations int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=9`,
	).Scan(&migrations); err != nil || migrations != 1 {
		t.Fatalf("migration count=%d err=%v", migrations, err)
	}
}

func TestObservationAppliedClockMigrationRepairsPartialV9Shape(t *testing.T) {
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
	preview := sources.PreviewInput("https://partial-v9.example/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	const payload = "vless://partial-v9@example.net:443?security=tls"
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "partial v9",
		Fingerprint: "partial-v9", Payload: payload,
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_800_000_000, 0)
	if _, err := database.RecordCandidateProbe(ctx, ProbeTransition{
		Fingerprint: candidate.Fingerprint,
		CandidateID: candidate.ID,
		SourceID:    candidate.SourceID,
		Full:        true,
		Success:     true,
		Score:       77,
		At:          base,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID:  candidate.ID,
		Score:        77,
		TCPQualified: true,
		Available:    true,
		UpdatedAt:    base,
	}); err != nil {
		t.Fatal(err)
	}
	for table, columns := range map[string][]string{
		"candidate_probe_state": {"fast_applied_seq"},
		"candidate_health": {
			"full_applied_seq",
			"active_applied_seq",
		},
	} {
		for _, column := range columns {
			if _, err := database.db.ExecContext(ctx,
				`ALTER TABLE `+table+` DROP COLUMN `+column,
			); err != nil {
				t.Fatalf("drop %s.%s: %v", table, column, err)
			}
		}
	}
	for _, table := range []string{"candidate_probe_state", "candidate_health"} {
		var placeholder int
		if err := database.db.QueryRowContext(ctx, `
			SELECT count(*) FROM pragma_table_info(?)
			WHERE name='observation_placeholder'
		`, table).Scan(&placeholder); err != nil || placeholder != 1 {
			t.Fatalf("%s placeholder count=%d err=%v",
				table, placeholder, err)
		}
	}
	var migrationCount int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=9`,
	).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("partial fixture migration count=%d err=%v",
			migrationCount, err)
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
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer database.Close()

	for table, columns := range map[string][]string{
		"candidate_probe_state": {"fast_applied_seq"},
		"candidate_health": {
			"full_applied_seq",
			"active_applied_seq",
		},
	} {
		for _, column := range columns {
			var (
				notNull int
				dflt    string
			)
			if err := database.db.QueryRowContext(ctx, `
				SELECT "notnull", dflt_value
				FROM pragma_table_info(?)
				WHERE name=?
			`, table, column).Scan(&notNull, &dflt); err != nil {
				t.Fatalf("inspect repaired %s.%s: %v", table, column, err)
			}
			if notNull != 1 || dflt != "0" {
				t.Fatalf("repaired %s.%s notnull=%d default=%q",
					table, column, notNull, dflt)
			}
		}
	}
	gotPayload, err := database.CandidatePayload(ctx, candidate.ID)
	if err != nil || gotPayload != payload {
		t.Fatalf("payload=%q err=%v", gotPayload, err)
	}
	legacyState, err := database.CandidateProbeState(
		ctx, candidate.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacyState.LastScore != 77 ||
		!legacyState.LastFullProbeAt.Equal(base) {
		t.Fatalf("legacy probe state=%+v", legacyState)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 ||
		healthRows[0].CandidateID != candidate.ID ||
		healthRows[0].Score != 77 {
		t.Fatalf("legacy health=%+v err=%v", healthRows, err)
	}

	fast, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFast,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		fast,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint,
			CandidateID: candidate.ID,
			SourceID:    candidate.SourceID,
			Success:     true,
			At:          base.Add(time.Minute),
		},
		nil,
		nil,
	); err != nil || !commit.Accepted {
		t.Fatalf("fast commit after repair=%+v err=%v", commit, err)
	}
	full, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	fullAt := base.Add(2 * time.Minute)
	if _, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint,
			CandidateID: candidate.ID,
			SourceID:    candidate.SourceID,
			Full:        true,
			Success:     true,
			Score:       88,
			At:          fullAt,
		},
		&CandidateHealth{
			CandidateID: candidate.ID,
			Score:       88,
			Available:   true,
			UpdatedAt:   fullAt,
		},
		nil,
	); err != nil || !commit.Accepted {
		t.Fatalf("full commit after repair=%+v err=%v", commit, err)
	}
	active, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, active, false, base.Add(3*time.Minute),
	); err != nil || !commit.Accepted {
		t.Fatalf("active commit after repair=%+v err=%v", commit, err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=9`,
	).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("repaired migration count=%d err=%v",
			migrationCount, err)
	}
}

func TestObservationOrderingDelayedFullSuccessRejectedAfterActiveHardFailure(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	active, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	_, activeCommit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, active, base.Add(time.Second),
	)
	if err != nil || !activeCommit.Accepted {
		t.Fatalf("active commit=%+v err=%v", activeCommit, err)
	}
	before := observationMutationCounts(t, database, candidate)
	beforeHealth, _ := observationHealth(t, database, candidate.ID)
	health := CandidateHealth{
		CandidateID: candidate.ID, Score: 99, TCPQualified: true,
		UDPQualified: true, Available: true, LatencyMS: 10,
		ThroughputMbps: 50, UpdatedAt: base.Add(2 * time.Second),
	}
	sample := ProbeSample{
		CandidateID: candidate.ID, Success: true, CreatedAt: health.UpdatedAt,
	}
	_, fullCommit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: true,
			Score: health.Score, At: health.UpdatedAt,
		},
		&health,
		&sample,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fullCommit.Accepted {
		t.Fatal("delayed full success was accepted after a newer hard failure")
	}
	after := observationMutationCounts(t, database, candidate)
	if after != before {
		t.Fatalf("rejected full mutated artifacts: before=%+v after=%+v", before, after)
	}
	afterHealth, _ := observationHealth(t, database, candidate.ID)
	if afterHealth != beforeHealth {
		t.Fatalf("rejected full mutated health: before=%+v after=%+v",
			beforeHealth, afterHealth)
	}
}

func TestObservationOrderingDelayedActiveSuccessRejectedByNewerActiveFailure(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	success, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	_, failureCommit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, failure, base.Add(time.Second),
	)
	if err != nil || !failureCommit.Accepted {
		t.Fatalf("failure commit=%+v err=%v", failureCommit, err)
	}
	successCommit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, success, true, base.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if successCommit.Accepted {
		t.Fatal("delayed active success was accepted after a newer active failure")
	}
	health, generation := observationHealth(t, database, candidate.ID)
	if health.Available || generation != 1 {
		t.Fatalf("health=%+v failure_generation=%d", health, generation)
	}
}

func TestObservationOrderingContinuousActiveSuccessesDoNotStarveFull(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	failure, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, failure, base.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("failure commit=%+v err=%v", commit, err)
	}
	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		active, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := database.CommitCandidateActiveObservation(
			ctx, candidate, active, true, base.Add(time.Duration(index+2)*time.Second),
		)
		if err != nil || !commit.Accepted {
			t.Fatalf("active success %d commit=%+v err=%v", index, commit, err)
		}
	}
	at := base.Add(10 * time.Second)
	health := CandidateHealth{
		CandidateID: candidate.ID, Score: 98, TCPQualified: true,
		UDPQualified: true, Available: true, LatencyMS: 12,
		ThroughputMbps: 47, UpdatedAt: at,
	}
	state, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: true,
			Score: health.Score, At: at,
		},
		&health,
		&ProbeSample{CandidateID: candidate.ID, Success: true, CreatedAt: at},
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("full state=%+v commit=%+v err=%v", state, commit, err)
	}
	persisted, generation := observationHealth(t, database, candidate.ID)
	if persisted.Score != 98 || !persisted.Available || generation != 1 {
		t.Fatalf("health=%+v failure_generation=%d", persisted, generation)
	}
}

func TestObservationOrderingFastAndFullDoNotSuppressEachOther(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)

	fast, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFast)
	if err != nil {
		t.Fatal(err)
	}
	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Second)
	health := CandidateHealth{
		CandidateID: candidate.ID, Score: 96, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: at,
	}
	_, fullCommit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: true,
			Score: health.Score, At: at,
		},
		&health,
		nil,
	)
	if err != nil || !fullCommit.Accepted {
		t.Fatalf("full commit=%+v err=%v", fullCommit, err)
	}
	state, fastCommit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		fast,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Success: true, At: base.Add(2 * time.Second),
		},
		nil,
		nil,
	)
	if err != nil || !fastCommit.Accepted {
		t.Fatalf("fast state=%+v commit=%+v err=%v", state, fastCommit, err)
	}
	if state.LastFastProbeAt.IsZero() || state.LastFullProbeAt.IsZero() {
		t.Fatalf("independent stage state was not retained: %+v", state)
	}
}

func TestObservationFailureGenerationIgnoresInfrastructureFailure(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	_, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true,
			InfrastructureFailure: true, ErrorCode: "agent_unavailable",
			At: base.Add(time.Second),
		},
		nil,
		nil,
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v err=%v", commit, err)
	}
	_, generation := observationHealth(t, database, candidate.ID)
	if generation != 0 {
		t.Fatalf("infrastructure failure_generation=%d, want 0", generation)
	}
	var evidence int
	if err := database.db.QueryRowContext(
		ctx, `SELECT count(*) FROM failure_domain_evidence`,
	).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if evidence != 0 {
		t.Fatalf("infrastructure failure wrote domain evidence=%d", evidence)
	}
}

func TestObservationFailureGenerationIncrementsForAcceptedFullHardFailure(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	saveObservationHealth(t, database, candidate.ID, base, 91)

	full, err := database.ReserveCandidateObservation(ctx, candidate, ObservationFull)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Second)
	health := CandidateHealth{
		CandidateID: candidate.ID, Available: false, UpdatedAt: at,
	}
	_, commit, err := database.CommitCandidateProbeObservation(
		ctx,
		candidate,
		full,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: false,
			ErrorCode: "full_probe_failed", At: at,
		},
		&health,
		&ProbeSample{CandidateID: candidate.ID, Success: false, CreatedAt: at},
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v err=%v", commit, err)
	}
	_, generation := observationHealth(t, database, candidate.ID)
	if generation != 1 {
		t.Fatalf("full hard failure_generation=%d, want 1", generation)
	}
}

func TestObservationActiveAvailabilityPreservesFullScoreAndGates(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	original := CandidateHealth{
		CandidateID: candidate.ID, Score: 93, TCPQualified: true,
		UDPQualified: true, Available: true, LatencyMS: 27,
		ThroughputMbps: 44, UpdatedAt: base,
	}
	if err := database.SaveCandidateHealth(ctx, original); err != nil {
		t.Fatal(err)
	}
	active, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, active, false, base.Add(time.Second),
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v err=%v", commit, err)
	}
	persisted, _ := observationHealth(t, database, candidate.ID)
	if persisted.Score != original.Score ||
		persisted.TCPQualified != original.TCPQualified ||
		persisted.UDPQualified != original.UDPQualified ||
		persisted.LatencyMS != original.LatencyMS ||
		persisted.ThroughputMbps != original.ThroughputMbps ||
		persisted.Available {
		t.Fatalf("active availability clobbered full fields: before=%+v after=%+v",
			original, persisted)
	}
}

type observationCounts struct {
	Samples    int
	Events     int
	Evidence   int
	Failures   int
	Generation int64
}

func observationMutationCounts(
	t *testing.T,
	database *Store,
	candidate Candidate,
) observationCounts {
	t.Helper()
	ctx := context.Background()
	var counts observationCounts
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM probe_samples WHERE candidate_id=?`,
		candidate.ID,
	).Scan(&counts.Samples); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM events WHERE candidate_id=?`,
		candidate.ID,
	).Scan(&counts.Events); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM failure_domain_evidence WHERE candidate_id=?`,
		candidate.ID,
	).Scan(&counts.Evidence); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT failure_streak
		FROM candidate_probe_state
		WHERE fingerprint=?
	`, candidate.Fingerprint).Scan(&counts.Failures); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `
		SELECT failure_generation
		FROM candidate_health
		WHERE candidate_id=?
	`, candidate.ID).Scan(&counts.Generation); err != nil {
		t.Fatal(err)
	}
	return counts
}

func observationHealth(
	t *testing.T,
	database *Store,
	candidateID string,
) (CandidateHealth, int64) {
	t.Helper()
	var (
		health     CandidateHealth
		updated    int64
		generation int64
	)
	if err := database.db.QueryRowContext(context.Background(), `
		SELECT candidate_id, score, tcp_qualified, udp_qualified, available,
		       latency_ms, throughput_mbps, updated_at, failure_generation
		FROM candidate_health
		WHERE candidate_id=?
	`, candidateID).Scan(
		&health.CandidateID, &health.Score, &health.TCPQualified,
		&health.UDPQualified, &health.Available, &health.LatencyMS,
		&health.ThroughputMbps, &updated, &generation,
	); err != nil {
		t.Fatal(err)
	}
	health.UpdatedAt = time.Unix(updated, 0)
	return health, generation
}

func observationTestStore(t *testing.T) (*Store, map[string]Candidate) {
	t.Helper()
	return candidateStateTestStore(t, []CandidateInput{{
		Kind: sources.KindVLESS, Label: "candidate", Fingerprint: "candidate",
		Payload:       "vless://candidate@example.net:443?security=tls",
		FailureDomain: "domain-hash",
	}})
}

func saveObservationHealth(
	t *testing.T,
	database *Store,
	candidateID string,
	at time.Time,
	score float64,
) {
	t.Helper()
	if err := database.SaveCandidateHealth(context.Background(), CandidateHealth{
		CandidateID: candidateID, Score: score, TCPQualified: true,
		UDPQualified: true, Available: true, LatencyMS: 20,
		ThroughputMbps: 40, UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
}
