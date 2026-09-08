package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestFailureDomainMigrationCreatesVersionSixTablesIdempotently(t *testing.T) {
	database := failureDomainTestStore(t)
	for _, table := range []string{"failure_domain_state", "failure_domain_evidence"} {
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
	if err := database.migrateFailureDomains(context.Background()); err != nil {
		t.Fatalf("replay migration: %v", err)
	}
	var versions int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM schema_migrations WHERE version=6`,
	).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("version count=%d err=%v", versions, err)
	}
}

func TestFailureDomainRejectsEmptyOpaqueIdentifiers(t *testing.T) {
	database := failureDomainTestStore(t)
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name      string
		domain    string
		candidate string
	}{
		{name: "empty domain", candidate: "candidate-hash"},
		{name: "empty candidate", domain: "domain-hash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := database.RecordFailureDomainFailure(
				context.Background(), test.domain, test.candidate, now,
			); err == nil {
				t.Fatal("empty opaque identifier was accepted")
			}
		})
	}
	if err := database.RecordFailureDomainSuccess(
		context.Background(), "", now,
	); err == nil {
		t.Fatal("empty success domain was accepted")
	}
}

func TestFailureDomainCountsDistinctCandidatesAndUsesInclusiveFiveMinuteBoundary(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)

	for index := 0; index < 4; index++ {
		state, err := database.RecordFailureDomainFailure(ctx, "domain-hash", "z-hash", base.Add(time.Duration(index)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if state.FailureCount != 1 || !state.OpenUntil.IsZero() {
			t.Fatalf("repeated candidate opened circuit: %+v", state)
		}
	}
	if _, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "y-hash", base.Add(4*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	state, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "x-hash", base.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 3 ||
		!state.WindowStartedAt.Equal(base.Add(3*time.Minute)) ||
		!state.OpenUntil.Equal(base.Add(15*time.Minute)) ||
		state.CanaryCandidate != "x-hash" {
		t.Fatalf("opened state=%+v", state)
	}
}

func TestFailureDomainPrunesEvidenceOlderThanFiveMinutes(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)

	if _, err := database.RecordFailureDomainFailure(ctx, "domain-hash", "a-hash", base); err != nil {
		t.Fatal(err)
	}
	state, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "b-hash", base.Add(5*time.Minute+time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 1 ||
		!state.WindowStartedAt.Equal(base.Add(5*time.Minute+time.Second)) ||
		!state.OpenUntil.IsZero() {
		t.Fatalf("expired evidence remained: %+v", state)
	}
}

func TestFailureDomainOpenStateOnlyCanaryExtendsAndClockSkewCannotShorten(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, candidate := range []string{"c-hash", "a-hash", "b-hash"} {
		if _, err := database.RecordFailureDomainFailure(ctx, "domain-hash", candidate, base); err != nil {
			t.Fatal(err)
		}
	}

	unchanged, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "unrelated-hash", base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged.OpenUntil.Equal(base.Add(10*time.Minute)) ||
		unchanged.CanaryCandidate != "a-hash" ||
		!unchanged.UpdatedAt.Equal(base) {
		t.Fatalf("unrelated failure changed open state: %+v", unchanged)
	}

	extended, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", base.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !extended.OpenUntil.Equal(base.Add(12*time.Minute)) ||
		!extended.UpdatedAt.Equal(base.Add(2*time.Minute)) {
		t.Fatalf("canary failure did not extend from now: %+v", extended)
	}

	skewed, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !skewed.OpenUntil.Equal(extended.OpenUntil) ||
		!skewed.UpdatedAt.Equal(extended.UpdatedAt) {
		t.Fatalf("backward clock shortened or rewound state: %+v", skewed)
	}
}

func TestFailureDomainEventOrderingFailureWinsTimestampTies(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)

	state, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", base,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 1 || !state.UpdatedAt.Equal(base) {
		t.Fatalf("initial failure=%+v", state)
	}

	stale, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "stale-hash", base.Add(-time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if stale.FailureCount != 1 || !stale.UpdatedAt.Equal(base) {
		t.Fatalf("older failure mutated state=%+v", stale)
	}
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", base,
	); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 1 {
		t.Fatalf("equal-time success beat failure: %+v", states)
	}

	state, err = database.RecordFailureDomainFailure(
		ctx, "domain-hash", "b-hash", base,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 2 || !state.UpdatedAt.Equal(base) {
		t.Fatalf("equal-time distinct failure was rejected=%+v", state)
	}

	successAt := base.Add(time.Second)
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", successAt,
	); err != nil {
		t.Fatal(err)
	}
	states, err = database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 0 ||
		!states[0].UpdatedAt.Equal(successAt) {
		t.Fatalf("newer success did not close state=%+v", states)
	}

	stale, err = database.RecordFailureDomainFailure(
		ctx, "domain-hash", "stale-after-success", base,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stale.FailureCount != 0 || !stale.UpdatedAt.Equal(successAt) {
		t.Fatalf("older failure seeded evidence after success=%+v", stale)
	}
	state, err = database.RecordFailureDomainFailure(
		ctx, "domain-hash", "tie-after-success", successAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 1 || state.CanaryCandidate != "" ||
		!state.UpdatedAt.Equal(successAt) {
		t.Fatalf("equal-time failure did not win success tie=%+v", state)
	}
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", successAt,
	); err != nil {
		t.Fatal(err)
	}
	states, err = database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 1 {
		t.Fatalf("equal-time success closed failure=%+v", states)
	}
}

func TestFailureDomainDelayedEventsCannotUndoOpenExtensionOrNewerSuccess(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, candidateID := range []string{"a-hash", "b-hash", "c-hash"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidateID, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	extendedAt := base.Add(2 * time.Second)
	extended, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", extendedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !extended.OpenUntil.Equal(extendedAt.Add(10*time.Minute)) ||
		!extended.UpdatedAt.Equal(extendedAt) {
		t.Fatalf("extension=%+v", extended)
	}

	delayedAt := base.Add(time.Second)
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", delayedAt,
	); err != nil {
		t.Fatal(err)
	}
	delayed, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", delayedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !delayed.OpenUntil.Equal(extended.OpenUntil) ||
		!delayed.UpdatedAt.Equal(extendedAt) {
		t.Fatalf("delayed event changed extension=%+v", delayed)
	}

	successAt := base.Add(3 * time.Second)
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", successAt,
	); err != nil {
		t.Fatal(err)
	}
	stale, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "late-hash", extendedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stale.FailureCount != 0 || !stale.OpenUntil.IsZero() ||
		!stale.UpdatedAt.Equal(successAt) {
		t.Fatalf("delayed failure undid newer success=%+v", stale)
	}
}

func TestFailureDomainEventsUsePersistedSecondPrecision(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)

	state, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "a-hash", base.Add(900*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !state.UpdatedAt.Equal(base) {
		t.Fatalf("failure returned unpersisted precision=%+v", state)
	}
	if err := database.RecordFailureDomainSuccess(
		ctx, "domain-hash", base.Add(100*time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	state, err = database.RecordFailureDomainFailure(
		ctx, "domain-hash", "b-hash", base.Add(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 2 || !state.UpdatedAt.Equal(base) {
		t.Fatalf("same persisted second did not use tie rules=%+v", state)
	}
}

func TestFailureDomainSuccessDoesNotCreateNeverFailedState(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for index := 0; index < 5; index++ {
		if err := database.RecordFailureDomainSuccess(
			ctx,
			"never-failed-domain",
			base.Add(time.Duration(index)*time.Second),
		); err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("successful probes grew failure-domain table: %+v", states)
	}
}

func TestFailureDomainCanaryElectionIsDeterministicPersistedAndDoesNotShorten(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, candidate := range []string{"gone-a", "gone-b", "gone-c"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidate, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	electedAt := base.Add(2*time.Minute + 900*time.Millisecond)
	state, err := database.ElectFailureDomainCanary(
		ctx,
		"domain-hash",
		[]string{"current-z", "current-a", "current-b"},
		electedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.CanaryCandidate != "current-a" ||
		!state.OpenUntil.Equal(base.Add(10*time.Minute)) ||
		!state.UpdatedAt.Equal(base) {
		t.Fatalf("elected state=%+v", state)
	}
	reordered, err := database.ElectFailureDomainCanary(
		ctx,
		"domain-hash",
		[]string{"current-b", "current-z", "current-a"},
		base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reordered.CanaryCandidate != "current-a" ||
		!reordered.OpenUntil.Equal(state.OpenUntil) ||
		!reordered.UpdatedAt.Equal(state.UpdatedAt) {
		t.Fatalf("reordered or backward election changed state=%+v", reordered)
	}

	extended, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "current-a", base.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !extended.OpenUntil.Equal(base.Add(13 * time.Minute)) {
		t.Fatalf("persisted canary was not authoritative: %+v", extended)
	}
}

func TestFailureDomainCanaryElectionRequiresOpenDomainAndOpaqueCandidates(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name       string
		domain     string
		candidates []string
	}{
		{name: "empty domain", candidates: []string{"candidate-hash"}},
		{name: "no candidates", domain: "domain-hash"},
		{name: "empty candidate", domain: "domain-hash", candidates: []string{""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := database.ElectFailureDomainCanary(
				ctx, test.domain, test.candidates, base,
			); err == nil {
				t.Fatal("invalid canary election was accepted")
			}
		})
	}
	if _, err := database.ElectFailureDomainCanary(
		ctx, "domain-hash", []string{"candidate-hash"}, base,
	); !errors.Is(err, ErrFailureDomainNotOpen) {
		t.Fatalf("closed domain error=%v", err)
	}

	for _, candidate := range []string{"a-hash", "b-hash", "c-hash"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidate, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ElectFailureDomainCanary(
		ctx,
		"domain-hash",
		[]string{"current-hash"},
		base.Add(10*time.Minute),
	); !errors.Is(err, ErrFailureDomainNotOpen) {
		t.Fatalf("exact open boundary error=%v", err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].CanaryCandidate != "a-hash" ||
		!states[0].OpenUntil.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("closed election mutated state=%+v", states)
	}
}

func TestFailureDomainCircuitIsClosedAtExactTenMinuteBoundary(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, candidate := range []string{"a-hash", "b-hash", "c-hash"} {
		if _, err := database.RecordFailureDomainFailure(ctx, "domain-hash", candidate, base); err != nil {
			t.Fatal(err)
		}
	}

	state, err := database.RecordFailureDomainFailure(
		ctx, "domain-hash", "new-hash", base.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureCount != 1 || state.CanaryCandidate != "" ||
		!state.OpenUntil.IsZero() || !state.WindowStartedAt.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("exact open boundary remained open: %+v", state)
	}
}

func TestFailureDomainConcurrentDistinctFailuresOpenExactlyOnce(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	candidates := []string{"c-hash", "a-hash", "b-hash"}
	errs := make(chan error, 60)
	var calls sync.WaitGroup
	for index := 0; index < 60; index++ {
		candidate := candidates[index%len(candidates)]
		calls.Add(1)
		go func() {
			defer calls.Done()
			_, err := database.RecordFailureDomainFailure(ctx, "domain-hash", candidate, now)
			errs <- err
		}()
	}
	calls.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 3 ||
		states[0].CanaryCandidate != "a-hash" ||
		!states[0].OpenUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("concurrent state=%+v", states)
	}
}

func TestFailureDomainConcurrentStoreConnectionsPreserveDistinctEvidence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	now := time.Unix(1_800_000_000, 0)
	type call struct {
		database  *Store
		candidate string
	}
	calls := []call{
		{database: first, candidate: "c-hash"},
		{database: second, candidate: "a-hash"},
		{database: first, candidate: "b-hash"},
		{database: second, candidate: "c-hash"},
		{database: first, candidate: "a-hash"},
		{database: second, candidate: "b-hash"},
	}
	start := make(chan struct{})
	errs := make(chan error, len(calls))
	var pending sync.WaitGroup
	for _, item := range calls {
		item := item
		pending.Add(1)
		go func() {
			defer pending.Done()
			<-start
			_, err := item.database.RecordFailureDomainFailure(
				ctx, "domain-hash", item.candidate, now,
			)
			errs <- err
		}()
	}
	close(start)
	pending.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	states, err := first.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 3 ||
		states[0].CanaryCandidate != "a-hash" ||
		!states[0].OpenUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("cross-connection state=%+v", states)
	}
}

func TestFailureDomainFullSuccessClosesAndResetsEvidence(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	for _, candidate := range []string{"a-hash", "b-hash", "c-hash"} {
		if _, err := database.RecordFailureDomainFailure(ctx, "domain-hash", candidate, base); err != nil {
			t.Fatal(err)
		}
	}
	successAt := base.Add(time.Minute)
	if err := database.RecordFailureDomainSuccess(ctx, "domain-hash", successAt); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("states=%+v", states)
	}
	state := states[0]
	if state.FailureCount != 0 || state.CanaryCandidate != "" ||
		!state.WindowStartedAt.IsZero() || !state.OpenUntil.IsZero() ||
		!state.UpdatedAt.Equal(successAt) {
		t.Fatalf("success did not reset state: %+v", state)
	}
	var evidence int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM failure_domain_evidence WHERE domain=?`, "domain-hash",
	).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("evidence=%d err=%v", evidence, err)
	}
}

func TestRecordActiveVLESSHardFailureCommitsAllState(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	now := time.Unix(1_800_000_000, 0)
	healthy := CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
	}
	if err := database.SaveCandidateHealth(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	unavailable := healthy
	unavailable.Available = false
	unavailable.UpdatedAt = now

	domainState, err := database.RecordActiveVLESSHardFailure(
		ctx, candidate, unavailable, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if domainState.FailureCount != 1 ||
		domainState.Domain != candidate.FailureDomain {
		t.Fatalf("domain state=%+v", domainState)
	}
	probeState, err := database.CandidateProbeState(
		ctx, candidate.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if probeState.FailureStreak != 1 ||
		probeState.LastErrorCode != "active_hard_failure" ||
		!probeState.LastFailureAt.Equal(now) {
		t.Fatalf("probe state=%+v", probeState)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 || healthRows[0].Available {
		t.Fatalf("health=%+v err=%v", healthRows, err)
	}
}

func TestActiveVLESSHardFailureAcceptsOrderedCompletionAfterNewerReservation(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	base := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		Available: true, UpdatedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	slowFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	newerInFlight, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if newerInFlight.Sequence != slowFailure.Sequence+1 {
		t.Fatalf("reservations=%d/%d", slowFailure.Sequence, newerInFlight.Sequence)
	}
	state, commit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, slowFailure, base.Add(350*time.Millisecond),
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("slow hard commit=%+v state=%+v err=%v", commit, state, err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || rows[0].Available ||
		!rows[0].ActiveHardFailure {
		t.Fatalf("slow hard health=%+v err=%v", rows, err)
	}
}

func TestActiveVLESSHardFailureRejectsOldFailureAfterNewerSuccess(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	base := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(ctx, CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		Available: true, UpdatedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	oldFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	newerSuccess, err := database.ReserveCandidateObservation(
		ctx, candidate, ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, newerSuccess, true, base.Add(300*time.Millisecond),
	); err != nil || !commit.Accepted {
		t.Fatalf("newer success=%+v err=%v", commit, err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		ctx, candidate, oldFailure, base.Add(350*time.Millisecond),
	); err != nil || commit.Accepted {
		t.Fatalf("old failure after newer success=%+v err=%v", commit, err)
	}
	rows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(rows) != 1 || !rows[0].Available ||
		rows[0].ActiveHardFailure {
		t.Fatalf("newer success overwritten=%+v err=%v", rows, err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 0 {
		t.Fatalf("old failure wrote domain evidence=%+v err=%v", states, err)
	}
}

func TestRecordActiveVLESSHardFailureIgnoresOlderThanClosedTombstone(t *testing.T) {
	database, candidate, beforeProbe, healthy, successAt :=
		closedFailureDomainCandidate(t)
	ctx := context.Background()
	delayedAt := successAt.Add(-time.Second)
	unavailable := healthy
	unavailable.Available = false
	unavailable.UpdatedAt = delayedAt

	domainState, err := database.RecordActiveVLESSHardFailure(
		ctx, candidate, unavailable, delayedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if domainState.FailureCount != 0 || !domainState.OpenUntil.IsZero() ||
		!domainState.UpdatedAt.Equal(successAt) {
		t.Fatalf("delayed active failure changed tombstone=%+v", domainState)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 || states[0] != domainState {
		t.Fatalf("persisted tombstone=%+v returned=%+v err=%v", states, domainState, err)
	}
	var evidence int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM failure_domain_evidence`,
	).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("delayed active evidence=%d err=%v", evidence, err)
	}
	afterProbe, err := database.CandidateProbeState(
		ctx, candidate.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if afterProbe != beforeProbe {
		t.Fatalf("delayed active failure mutated probe: before=%+v after=%+v", beforeProbe, afterProbe)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 || healthRows[0] != healthy {
		t.Fatalf("delayed active failure mutated health=%+v err=%v", healthRows, err)
	}
}

func TestRecordActiveVLESSHardFailureAcceptsClosedTombstoneTimestampTie(t *testing.T) {
	database, candidate, beforeProbe, healthy, successAt :=
		closedFailureDomainCandidate(t)
	ctx := context.Background()
	unavailable := healthy
	unavailable.Available = false
	unavailable.UpdatedAt = successAt

	domainState, err := database.RecordActiveVLESSHardFailure(
		ctx, candidate, unavailable, successAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if domainState.FailureCount != 1 || !domainState.OpenUntil.IsZero() ||
		!domainState.UpdatedAt.Equal(successAt) {
		t.Fatalf("equal-time active failure was not accepted=%+v", domainState)
	}
	afterProbe, err := database.CandidateProbeState(
		ctx, candidate.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if afterProbe.FailureStreak != beforeProbe.FailureStreak+1 ||
		afterProbe.LastErrorCode != "active_hard_failure" ||
		!afterProbe.LastFailureAt.Equal(successAt) {
		t.Fatalf("equal-time active probe state=%+v", afterProbe)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 || healthRows[0].Available ||
		!healthRows[0].UpdatedAt.Equal(successAt) {
		t.Fatalf("equal-time active health=%+v err=%v", healthRows, err)
	}
}

func TestRecordActiveVLESSHardFailureRejectsStaleCandidateWithoutMutation(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	now := time.Unix(1_800_000_000, 0)
	healthy := CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
	}
	if err := database.SaveCandidateHealth(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	beforeProbe, err := database.RecordCandidateProbe(
		ctx,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint,
			CandidateID: candidate.ID,
			SourceID:    candidate.SourceID,
			Full:        true,
			Success:     true,
			At:          now.Add(-time.Second),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	sourcesBefore, err := database.ListSources(ctx)
	if err != nil || len(sourcesBefore) != 1 {
		t.Fatalf("sources=%+v err=%v", sourcesBefore, err)
	}
	if err := database.UpdateSource(
		ctx, candidate.SourceID, sourcesBefore[0].Label, false,
	); err != nil {
		t.Fatal(err)
	}
	unavailable := healthy
	unavailable.Available = false
	unavailable.UpdatedAt = now

	if _, err := database.RecordActiveVLESSHardFailure(
		ctx, candidate, unavailable, now,
	); !errors.Is(err, ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 0 {
		t.Fatalf("stale candidate wrote domain state=%+v err=%v", states, err)
	}
	var evidence int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM failure_domain_evidence`,
	).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("stale evidence=%d err=%v", evidence, err)
	}
	afterProbe, err := database.CandidateProbeState(
		ctx, candidate.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if afterProbe.FailureStreak != beforeProbe.FailureStreak ||
		afterProbe.LastErrorCode != beforeProbe.LastErrorCode ||
		!afterProbe.UpdatedAt.Equal(beforeProbe.UpdatedAt) {
		t.Fatalf("stale candidate mutated probe: before=%+v after=%+v", beforeProbe, afterProbe)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 || !healthRows[0].Available ||
		!healthRows[0].UpdatedAt.Equal(healthy.UpdatedAt) {
		t.Fatalf("stale candidate mutated health=%+v err=%v", healthRows, err)
	}
}

func TestRecordActiveVLESSHardFailureRollsBackEveryMutation(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	now := time.Unix(1_800_000_000, 0)
	healthy := CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
	}
	if err := database.SaveCandidateHealth(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`
		CREATE TRIGGER reject_atomic_active_probe_state
		BEFORE INSERT ON candidate_probe_state
		BEGIN
		  SELECT RAISE(ABORT, 'injected atomic probe-state failure');
		END
	`); err != nil {
		t.Fatal(err)
	}
	unavailable := healthy
	unavailable.Available = false
	unavailable.UpdatedAt = now
	if _, err := database.RecordActiveVLESSHardFailure(
		ctx, candidate, unavailable, now,
	); err == nil {
		t.Fatal("injected candidate-state failure was not returned")
	}

	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 0 {
		t.Fatalf("rolled-back domain state=%+v err=%v", states, err)
	}
	var evidence int
	if err := database.db.QueryRow(
		`SELECT count(*) FROM failure_domain_evidence`,
	).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("rolled-back evidence=%d err=%v", evidence, err)
	}
	probeStates, err := database.ListCandidateProbeStates(ctx)
	if err != nil || len(probeStates) != 0 {
		t.Fatalf("rolled-back probe state=%+v err=%v", probeStates, err)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 1 || !healthRows[0].Available ||
		!healthRows[0].UpdatedAt.Equal(healthy.UpdatedAt) {
		t.Fatalf("rolled-back health=%+v err=%v", healthRows, err)
	}
}

func TestRecordActiveVLESSHardFailureConcurrentDistinctCandidates(t *testing.T) {
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidates := failureDomainVLESSCandidates(
		t, database, "a-hash", "b-hash", "c-hash",
	)
	now := time.Unix(1_800_000_000, 0)
	start := make(chan struct{})
	errs := make(chan error, len(candidates))
	var pending sync.WaitGroup
	for _, candidate := range candidates {
		candidate := candidate
		healthy := CandidateHealth{
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
		}
		if err := database.SaveCandidateHealth(ctx, healthy); err != nil {
			t.Fatal(err)
		}
		healthy.Available = false
		healthy.UpdatedAt = now
		pending.Add(1)
		go func() {
			defer pending.Done()
			<-start
			_, err := database.RecordActiveVLESSHardFailure(
				ctx, candidate, healthy, now,
			)
			errs <- err
		}()
	}
	close(start)
	pending.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 3 ||
		!states[0].OpenUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("concurrent atomic state=%+v", states)
	}
	probeStates, err := database.ListCandidateProbeStates(ctx)
	if err != nil || len(probeStates) != 3 {
		t.Fatalf("concurrent probe states=%+v err=%v", probeStates, err)
	}
	healthRows, err := database.ListCandidateHealth(ctx)
	if err != nil || len(healthRows) != 3 {
		t.Fatalf("concurrent health=%+v err=%v", healthRows, err)
	}
	for _, health := range healthRows {
		if health.Available {
			t.Fatalf("concurrent failure left health available=%+v", healthRows)
		}
	}
}

func closedFailureDomainCandidate(
	t *testing.T,
) (*Store, Candidate, CandidateProbeState, CandidateHealth, time.Time) {
	t.Helper()
	database := failureDomainTestStore(t)
	ctx := context.Background()
	candidate := failureDomainVLESSCandidates(
		t, database, "candidate-hash",
	)["candidate-hash"]
	base := time.Unix(1_800_000_000, 0)
	successAt := base.Add(2 * time.Second)
	if _, err := database.RecordFailureDomainFailure(
		ctx, candidate.FailureDomain, candidate.ID, base,
	); err != nil {
		t.Fatal(err)
	}
	healthy := CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: successAt,
	}
	beforeProbe, err := database.RecordCandidateProbeResult(
		ctx,
		ProbeTransition{
			Fingerprint: candidate.Fingerprint,
			CandidateID: candidate.ID,
			SourceID:    candidate.SourceID,
			Full:        true,
			Success:     true,
			Score:       healthy.Score,
			At:          successAt,
		},
		&healthy,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RecordFailureDomainSuccess(
		ctx, candidate.FailureDomain, successAt,
	); err != nil {
		t.Fatal(err)
	}
	return database, candidate, beforeProbe, healthy, successAt
}

func failureDomainVLESSCandidates(
	t *testing.T,
	database *Store,
	fingerprints ...string,
) map[string]Candidate {
	t.Helper()
	ctx := context.Background()
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	inputs := make([]CandidateInput, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		inputs = append(inputs, CandidateInput{
			Kind:          sources.KindVLESS,
			Label:         fingerprint,
			Fingerprint:   fingerprint,
			Payload:       "vless://" + fingerprint + "@example.net:443?security=tls",
			FailureDomain: "domain-hash",
		})
	}
	if err := database.ReplaceCandidates(
		ctx, sourceRows[0].ID, inputs,
	); err != nil {
		t.Fatal(err)
	}
	candidateRows, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidateRows) != len(fingerprints) {
		t.Fatalf("candidates=%+v err=%v", candidateRows, err)
	}
	result := make(map[string]Candidate, len(candidateRows))
	for _, candidate := range candidateRows {
		result[candidate.Fingerprint] = candidate
	}
	return result
}

func failureDomainTestStore(t *testing.T) *Store {
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
	return database
}
