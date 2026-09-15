package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/qualifier"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestActiveMonitorObservationReservationOccursBeforeAgentRPC(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	agent := &reservationInspectingActiveAgent{
		database: database, candidate: candidates[0],
	}
	monitor := ActiveMonitor{Store: database, Agent: agent}
	if err := monitor.Run(
		context.Background(), time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}
	if agent.inside.CandidateID != candidateID || agent.inside.Sequence != 2 {
		t.Fatalf("agent-side reservation=%+v, controller did not reserve before RPC",
			agent.inside)
	}
}

func TestActiveMonitorPersistsPerResultCompletionTime(t *testing.T) {
	database, _ := activeMonitorStore(t)
	startedAt := time.Unix(1_900_000_000, 0)
	completedAt := startedAt.Add(3 * time.Second)
	monitor := ActiveMonitor{
		Store: database,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: completedAt},
	}
	if err := monitor.Run(context.Background(), startedAt); err != nil {
		t.Fatal(err)
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || !rows[0].ActiveObservedAt.Equal(completedAt) {
		t.Fatalf("active completion timestamp=%+v want=%s", rows, completedAt)
	}
}

func TestActiveMonitorFirstCompleteFailureIsOnlySuspect(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	proofAt := base
	seedActiveMonitorProof(t, database, candidate, proofAt)
	trigger := make(chan struct{}, 1)
	hardFailures := NewHardFailureMailbox()
	monitor := &ActiveMonitor{
		Store: database, Trigger: trigger, HardFailures: hardFailures,
		HardFailureDeadline: 3 * time.Second, ProofFreshness: 30 * time.Second,
	}
	reservation := applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base.Add(time.Second), base.Add(1500*time.Millisecond),
	)

	row := mustCandidateHealth(t, database)[0]
	if !row.Available || !row.ActiveSuccess || !row.ActiveCurrent ||
		!row.ActiveObservedAt.Equal(proofAt) {
		t.Fatalf("first complete failure changed route health: %+v", row)
	}
	snapshot, err := database.LoadRoutingEvidenceSnapshot(
		context.Background(), []string{candidateID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Candidates) != 1 ||
		snapshot.Candidates[0].ActiveAppliedSequence != reservation.Sequence {
		t.Fatalf("first failure reservation was not accepted: %+v", snapshot.Candidates)
	}
	assertNoActiveHardFailure(t, database, trigger, hardFailures)
}

func TestActiveMonitorProductionConfirmsHardFailureInsideOneProbeCycle(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	hardFailures := NewHardFailureMailbox()
	monitor := &ActiveMonitor{
		Store: database, HardFailures: hardFailures,
		ConfirmCompleteFailureInCycle: true, HardFailureDeadline: 3 * time.Second,
	}
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base.Add(time.Second), base.Add(1500*time.Millisecond),
	)
	row := mustCandidateHealth(t, database)[0]
	if row.Available || !row.ActiveHardFailure {
		t.Fatalf("two-check liveness failure was not applied in one cycle: %+v", row)
	}
	event, ok := hardFailures.Pop()
	if !ok || event.CandidateID != candidateID {
		t.Fatalf("hard failure event=%+v ok=%t", event, ok)
	}
}

func TestActiveMonitorRoutedDNSFailuresDoNotQuarantineLiveRoute(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	monitor := &ActiveMonitor{
		Store: database, Slots: 1, ConfirmCompleteFailureInCycle: true,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			return agentapi.ProbeResponse{
				Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
				QoE:         &qoe.Observation{ErrorCode: qoe.ReasonDNSRoute},
			}, nil
		}),
		Clock: fixedActiveMonitorClock{now: base.Add(time.Second)},
	}
	if err := monitor.Run(context.Background(), base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("one routed DNS failure quarantined route: %+v", row)
	}
	monitor.Clock = fixedActiveMonitorClock{now: base.Add(3 * time.Second)}
	if err := monitor.Run(context.Background(), base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available || row.ActiveHardFailure {
		t.Fatalf("DNS-only failures quarantined live route: %+v", row)
	}
}

func TestActiveMonitorRoutedDNSSuccessResetsFailureSequence(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	dnsObservation := qoe.Observation{ErrorCode: qoe.ReasonDNSRoute}
	monitor := &ActiveMonitor{
		Store: database, Slots: 1, ConfirmCompleteFailureInCycle: true,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			observation := dnsObservation
			return agentapi.ProbeResponse{
				Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
				QoE:         &observation,
			}, nil
		}),
	}
	for index, observation := range []qoe.Observation{
		{ErrorCode: qoe.ReasonDNSRoute},
		{Success: true},
		{ErrorCode: qoe.ReasonDNSRoute},
	} {
		dnsObservation = observation
		at := base.Add(time.Duration(index+1) * 2 * time.Second)
		monitor.Clock = fixedActiveMonitorClock{now: at}
		if err := monitor.Run(context.Background(), at); err != nil {
			t.Fatal(err)
		}
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("non-consecutive routed DNS failures quarantined route: %+v", row)
	}
}

func TestActiveMonitorInfrastructureDNSGapBreaksFailureSequence(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	monitor := &ActiveMonitor{
		Store: database, ConfirmCompleteFailureInCycle: true,
		AvailabilityFailureFreshness: 6 * time.Second,
	}
	for index, availability := range []*qoe.Observation{
		{ErrorCode: qoe.ReasonDNSRoute},
		{Infrastructure: true, ErrorCode: "dns_control_unavailable"},
		nil,
		{ErrorCode: qoe.ReasonDNSRoute},
	} {
		applyTimestampedActiveAvailabilityObservation(
			t, monitor, database, candidate, availability,
			base.Add(time.Duration(index+1)*2*time.Second),
		)
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("DNS failures separated by infrastructure gaps quarantined route: %+v", row)
	}
}

func TestActiveMonitorAgentInfrastructureBreaksDNSFailureSequence(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	responses := []agentapi.ProbeResponse{
		{
			Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
			QoE:         &qoe.Observation{ErrorCode: qoe.ReasonDNSRoute},
		},
		{FailureClass: agentapi.FailureInfrastructure, ErrorCode: "dns_control_unavailable"},
		{
			Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
			QoE:         &qoe.Observation{ErrorCode: qoe.ReasonDNSRoute},
		},
	}
	index := 0
	monitor := &ActiveMonitor{
		Store: database, Slots: 1, ConfirmCompleteFailureInCycle: true,
		AvailabilityFailureFreshness: 6 * time.Second,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			response := responses[index]
			index++
			return response, nil
		}),
	}
	for cycle := range responses {
		at := base.Add(time.Duration(cycle+1) * 2 * time.Second)
		monitor.Clock = fixedActiveMonitorClock{now: at}
		if err := monitor.Run(context.Background(), at); err != nil {
			t.Fatal(err)
		}
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("agent infrastructure gap preserved DNS streak: %+v", row)
	}
}

func TestActiveMonitorDNSFailureExpiresBeforeNextObservation(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	monitor := &ActiveMonitor{
		Store: database, ConfirmCompleteFailureInCycle: true,
		AvailabilityFailureFreshness: 5 * time.Second,
	}
	for _, at := range []time.Time{base.Add(time.Second), base.Add(10 * time.Second)} {
		applyTimestampedActiveAvailabilityObservation(
			t, monitor, database, candidate,
			&qoe.Observation{ErrorCode: qoe.ReasonDNSRoute}, at,
		)
	}
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("expired DNS failure sequence quarantined route: %+v", row)
	}
}

func TestActiveMonitorSkippedDNSSequenceCannotConfirmFailure(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	seedActiveMonitorProof(t, database, candidate, base)
	reservations := make([]store.ObservationReservation, 3)
	for index := range reservations {
		var err error
		reservations[index], err = database.ReserveCandidateObservation(
			context.Background(), candidate, store.ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	monitor := &ActiveMonitor{
		Store: database, ConfirmCompleteFailureInCycle: true,
		AvailabilityFailureFreshness: 6 * time.Second,
	}
	apply := func(reservation store.ObservationReservation, availability *qoe.Observation, at time.Time) {
		t.Helper()
		if err := monitor.applyReservedObservations(
			context.Background(), at,
			map[string]activeObservation{candidateID: {
				observation:  health.Observation{PrimaryOK: true, ConfirmationOK: true},
				availability: availability, reservation: reservation, completedAt: at,
			}}, nil, map[string]store.Candidate{candidateID: candidate},
		); err != nil {
			t.Fatal(err)
		}
	}
	failure := &qoe.Observation{ErrorCode: qoe.ReasonDNSRoute}
	apply(reservations[0], failure, base.Add(time.Second))
	apply(reservations[2], failure, base.Add(3*time.Second))
	apply(reservations[1], &qoe.Observation{Success: true}, base.Add(4*time.Second))
	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("non-adjacent DNS reservations quarantined route: %+v", row)
	}
}

func TestActiveMonitorOverlappingCompleteFailureCannotConfirm(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	trigger := make(chan struct{}, 1)
	hardFailures := NewHardFailureMailbox()
	monitor := &ActiveMonitor{
		Store: database, Trigger: trigger, HardFailures: hardFailures,
		HardFailureDeadline: 3 * time.Second,
	}
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base, base.Add(time.Second),
	)
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base.Add(500*time.Millisecond), base.Add(2*time.Second),
	)

	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("overlapping failure confirmed route failure: %+v", row)
	}
	assertNoActiveHardFailure(t, database, trigger, hardFailures)
}

func TestActiveMonitorStaleFailureSuspectCannotConfirm(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	trigger := make(chan struct{}, 1)
	hardFailures := NewHardFailureMailbox()
	monitor := &ActiveMonitor{
		Store: database, Trigger: trigger, HardFailures: hardFailures,
		HardFailureDeadline: 3 * time.Second, ProofFreshness: 5 * time.Second,
	}
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base, base.Add(time.Second),
	)
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base.Add(10*time.Second), base.Add(11*time.Second),
	)

	if row := mustCandidateHealth(t, database)[0]; !row.Available {
		t.Fatalf("stale suspect confirmed a later unrelated failure: %+v", row)
	}
	assertNoActiveHardFailure(t, database, trigger, hardFailures)
}

func TestActiveMonitorNonOverlappingCompleteFailureConfirms(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidate := mustActiveMonitorCandidate(t, database)
	base := time.Unix(1_900_000_000, 0)
	firstCompletedAt := base.Add(time.Second)
	confirmStartedAt := firstCompletedAt
	confirmCompletedAt := base.Add(3 * time.Second)
	trigger := make(chan struct{}, 1)
	hardFailures := NewHardFailureMailbox()
	monitor := &ActiveMonitor{
		Store:               database,
		Trigger:             trigger,
		HardFailures:        hardFailures,
		HardFailureDeadline: 3 * time.Second,
	}
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base, firstCompletedAt,
	)
	// This failed probe was already in flight at the first completion. Its later
	// completion must not move the original confirmation boundary.
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		base.Add(500*time.Millisecond), base.Add(2*time.Second),
	)
	applyTimestampedActiveObservation(
		t, monitor, database, candidate, health.Observation{},
		confirmStartedAt, confirmCompletedAt,
	)
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available ||
		!rows[0].ActiveObservedAt.Equal(confirmCompletedAt) {
		t.Fatalf("hard failure completion health=%+v want=%s", rows, confirmCompletedAt)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].CandidateID != candidateID ||
		!events[0].CreatedAt.Equal(confirmCompletedAt) {
		t.Fatalf("hard failure completion events=%+v want=%s", events, confirmCompletedAt)
	}
	select {
	case <-trigger:
	default:
		t.Fatal("route-level hard failure did not trigger placement")
	}
	event, ok := hardFailures.Pop()
	if !ok {
		t.Fatal("route-level hard failure did not publish typed event")
	}
	if event.CandidateID != candidateID || !event.ProbeStartedAt.Equal(confirmStartedAt) ||
		!event.DetectedAt.Equal(confirmCompletedAt) ||
		!event.Deadline.Equal(confirmStartedAt.Add(3*time.Second)) {
		t.Fatalf("hard failure event=%+v", event)
	}
}

func TestActiveMonitorSuccessfulObservationClearsFailureSuspect(t *testing.T) {
	for name, observation := range map[string]health.Observation{
		"primary only":      {PrimaryOK: true},
		"confirmation only": {ConfirmationOK: true},
		"full success":      {PrimaryOK: true, ConfirmationOK: true},
	} {
		t.Run(name, func(t *testing.T) {
			database, _ := activeMonitorStore(t)
			candidate := mustActiveMonitorCandidate(t, database)
			base := time.Unix(1_900_000_000, 0)
			seedActiveMonitorProof(t, database, candidate, base)
			trigger := make(chan struct{}, 1)
			hardFailures := NewHardFailureMailbox()
			monitor := &ActiveMonitor{
				Store: database, Trigger: trigger, HardFailures: hardFailures,
				HardFailureDeadline: 3 * time.Second, ProofFreshness: 30 * time.Second,
			}
			applyTimestampedActiveObservation(
				t, monitor, database, candidate, health.Observation{},
				base.Add(time.Second), base.Add(2*time.Second),
			)
			applyTimestampedActiveObservation(
				t, monitor, database, candidate, observation,
				base.Add(2100*time.Millisecond), base.Add(2200*time.Millisecond),
			)
			// This starts after the old boundary, but the accepted success must
			// make it the first failure of a new confirmation sequence.
			applyTimestampedActiveObservation(
				t, monitor, database, candidate, health.Observation{},
				base.Add(3*time.Second), base.Add(4*time.Second),
			)

			if row := mustCandidateHealth(t, database)[0]; !row.Available {
				t.Fatalf("failure after accepted success confirmed stale suspect: %+v", row)
			}
			assertNoActiveHardFailure(t, database, trigger, hardFailures)
		})
	}
}

func mustActiveMonitorCandidate(t *testing.T, database *store.Store) store.Candidate {
	t.Helper()
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	return candidates[0]
}

func seedActiveMonitorProof(
	t *testing.T,
	database *store.Store,
	candidate store.Candidate,
	at time.Time,
) {
	t.Helper()
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		context.Background(), candidate, reservation, true, at,
	); err != nil || !commit.Accepted {
		t.Fatalf("seed active proof commit=%+v err=%v", commit, err)
	}
}

func applyTimestampedActiveObservation(
	t *testing.T,
	monitor *ActiveMonitor,
	database *store.Store,
	candidate store.Candidate,
	observation health.Observation,
	probeStartedAt time.Time,
	completedAt time.Time,
) store.ObservationReservation {
	t.Helper()
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.applyReservedObservations(
		context.Background(), completedAt,
		map[string]activeObservation{candidate.ID: {
			observation: observation, reservation: reservation,
			probeStartedAt: probeStartedAt, completedAt: completedAt,
		}},
		nil,
		map[string]store.Candidate{candidate.ID: candidate},
	); err != nil {
		t.Fatal(err)
	}
	return reservation
}

func applyTimestampedActiveAvailabilityObservation(
	t *testing.T,
	monitor *ActiveMonitor,
	database *store.Store,
	candidate store.Candidate,
	availability *qoe.Observation,
	completedAt time.Time,
) store.ObservationReservation {
	t.Helper()
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.applyReservedObservations(
		context.Background(), completedAt,
		map[string]activeObservation{candidate.ID: {
			observation:  health.Observation{PrimaryOK: true, ConfirmationOK: true},
			availability: availability, reservation: reservation,
			completedAt: completedAt,
		}}, nil, map[string]store.Candidate{candidate.ID: candidate},
	); err != nil {
		t.Fatal(err)
	}
	return reservation
}

func assertNoActiveHardFailure(
	t *testing.T,
	database *store.Store,
	trigger <-chan struct{},
	hardFailures *HardFailureMailbox,
) {
	t.Helper()
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind == "candidate_hard_failure" {
			t.Fatalf("unexpected hard-failure event: %+v", event)
		}
	}
	select {
	case <-trigger:
		t.Fatal("ambiguous failure triggered placement")
	default:
	}
	if event, ok := hardFailures.Pop(); ok {
		t.Fatalf("ambiguous failure published hard-failure event: %+v", event)
	}
}

func TestActiveMonitorDoesNotTreatAgentTimeoutAsRouteFailure(t *testing.T) {
	database, _ := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), candidates[0], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	proofAt := time.Unix(1_800_000_000, 0)
	if commit, err := database.CommitCandidateActiveObservation(
		context.Background(), candidates[0], reservation, true, proofAt,
	); err != nil || !commit.Accepted {
		t.Fatalf("seed proof commit=%+v err=%v", commit, err)
	}
	before := mustCandidateHealth(t, database)[0]
	trigger := make(chan struct{}, 1)
	monitor := ActiveMonitor{
		Store: database,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			return agentapi.ProbeResponse{
				FailureClass: agentapi.FailureInfrastructure,
			}, context.DeadlineExceeded
		}),
		Clock:   fixedActiveMonitorClock{now: before.UpdatedAt.Add(time.Minute)},
		Trigger: trigger,
	}
	if err := monitor.Run(context.Background(), before.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	after := mustCandidateHealth(t, database)[0]
	if after.Available != before.Available ||
		!after.UpdatedAt.Equal(before.UpdatedAt) ||
		!after.ActiveObservedAt.Equal(before.ActiveObservedAt) ||
		!after.ActiveCurrent || !after.ActiveSuccess {
		t.Fatalf("infrastructure timeout changed route health: before=%+v after=%+v",
			before, after)
	}
	select {
	case <-trigger:
		t.Fatal("infrastructure timeout triggered route placement")
	default:
	}
}

type fixedActiveMonitorClock struct{ now time.Time }

func (clock fixedActiveMonitorClock) Now() time.Time { return clock.now }

type mutableActiveMonitorClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *mutableActiveMonitorClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *mutableActiveMonitorClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

type sequenceActiveMonitorClock struct {
	mu    sync.Mutex
	times []time.Time
	next  int
}

func (clock *sequenceActiveMonitorClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.next >= len(clock.times) {
		return clock.times[len(clock.times)-1]
	}
	now := clock.times[clock.next]
	clock.next++
	return now
}

type activeProbeAgentFunc func(
	context.Context,
	agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error)

func (function activeProbeAgentFunc) ProbeActive(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return function(ctx, request)
}

func (function activeProbeAgentFunc) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return function(ctx, request)
}

func TestActiveMonitorProbesProviderTargetAndSignalsEligibilityTransition(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "assigned", Fingerprint: "assigned",
			Payload: "vless://assigned@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "prospective", Fingerprint: "prospective",
			Payload: "vless://prospective@example.net:443?security=tls",
		},
	})
	prospective := candidates["prospective"]
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	var observed []string
	promotions := make(chan struct{}, 1)
	targets := activeTargetProviderFunc(func(
		context.Context, time.Time,
	) ([]ActiveTarget, error) {
		return []ActiveTarget{{
			Candidate: prospective, TriggerPlacementOnSuccess: true,
		}}, nil
	})
	monitor := ActiveMonitor{
		Store: database,
		Agent: activeProbeAgentFunc(func(
			_ context.Context, request agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			observed = append(observed, request.CandidateID)
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Targets: targets, Promotions: promotions,
		Clock: fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(ctx, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, []string{prospective.ID}) {
		t.Fatalf("provider targets observed=%v", observed)
	}
	rows := mustCandidateHealth(t, database)
	var active store.CandidateHealth
	for _, row := range rows {
		if row.CandidateID == prospective.ID {
			active = row
		}
	}
	if !active.ActiveSuccess || !active.ActiveCurrent ||
		!active.ActiveObservedAt.Equal(now) {
		t.Fatalf("prospective target active evidence=%+v", active)
	}
	select {
	case <-promotions:
	default:
		t.Fatal("active eligibility transition did not trigger placement")
	}
}

func TestActiveMonitorCachedTargetsKeepProbeStartGapIndependentOfPlanning(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "critical", Fingerprint: "critical",
		Payload: "vless://critical@example.net:443?security=tls",
	}})
	candidate := candidates["critical"]
	if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var providerCalls atomic.Int32
	probeStarts := make(chan time.Time, 3)
	monitor := ActiveMonitor{
		Store: database, Slots: 3, PlanningDeadline: 5 * time.Second,
		ProbeDeadline: 875 * time.Millisecond,
		Targets: activeTargetProviderFunc(func(
			ctx context.Context, _ time.Time,
		) ([]ActiveTarget, error) {
			if providerCalls.Add(1) == 2 {
				close(refreshStarted)
				select {
				case <-releaseRefresh:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return []ActiveTarget{{Candidate: candidate, Role: ActiveTargetCritical}}, nil
		}),
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probeStarts <- time.Now()
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
	}

	if err := monitor.WarmTargets(ctx, time.Now()); err != nil {
		t.Fatalf("warm target snapshot: %v", err)
	}
	select {
	case <-probeStarts:
		t.Fatal("target warmup issued a network probe")
	default:
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- monitor.Run(ctx, time.Now()) }()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("slow target refresh did not start")
	}
	var secondStart time.Time
	select {
	case secondStart = <-probeStarts:
	case <-time.After(750 * time.Millisecond):
		t.Fatal("cached critical probe waited for target refresh")
	}

	time.Sleep(300 * time.Millisecond)
	thirdDone := make(chan error, 1)
	go func() { thirdDone <- monitor.Run(ctx, time.Now()) }()
	var thirdStart time.Time
	select {
	case thirdStart = <-probeStarts:
	case <-time.After(750 * time.Millisecond):
		t.Fatal("overlapping critical probe waited for in-flight target refresh")
	}
	if gap := thirdStart.Sub(secondStart); gap > 800*time.Millisecond {
		t.Fatalf("cached probe-start gap=%s exceeds acceptance bound", gap)
	}

	close(releaseRefresh)
	if err := <-secondDone; err != nil {
		t.Fatalf("refreshing run: %v", err)
	}
	if err := <-thirdDone; err != nil {
		t.Fatalf("overlapping run: %v", err)
	}
}

func TestActiveMonitorAppliedGenerationPromotesNewRouteDuringSlowRefresh(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "a", Fingerprint: "a", Payload: "vless://a@example.net:443"},
		{Kind: sources.KindVLESS, Label: "b", Fingerprint: "b", Payload: "vless://b@example.net:443"},
	})
	now := time.Now()
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "client", Name: "client", Address: "10.44.0.2/32", PublicKey: "key",
	}, "config"); err != nil {
		t.Fatal(err)
	}
	applyGeneration := func(generation int64, candidateID string) {
		t.Helper()
		if err := database.SetAssignment(ctx, store.AssignmentRecord{
			ClientID: "client", TCPOutbound: candidateID, UDPOutbound: candidateID,
			TCPSince: now, UDPSince: now,
		}); err != nil {
			t.Fatal(err)
		}
		plan := []byte(fmt.Sprintf(`{"generation":%d}`, generation))
		if err := database.SaveDesiredPlan(ctx, generation, plan); err != nil {
			t.Fatal(err)
		}
		if err := database.MarkAppliedPlan(ctx, generation, plan); err != nil {
			t.Fatal(err)
		}
	}
	applyGeneration(1, candidates["a"].ID)

	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var providerCalls atomic.Int32
	agent := &laneRecordingActiveAgent{}
	monitor := ActiveMonitor{
		Store: database, Agent: agent, Slots: 2, CriticalLimit: 16,
		PlanningDeadline: 5 * time.Second, ProbeDeadline: 875 * time.Millisecond,
		Targets: activeTargetProviderFunc(func(
			ctx context.Context, _ time.Time,
		) ([]ActiveTarget, error) {
			if providerCalls.Add(1) > 1 {
				close(refreshStarted)
				select {
				case <-releaseRefresh:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return []ActiveTarget{
					{Candidate: candidates["a"], Role: ActiveTargetProspective},
					{Candidate: candidates["b"], Role: ActiveTargetCritical},
				}, nil
			}
			return []ActiveTarget{
				{Candidate: candidates["a"], Role: ActiveTargetCritical},
				{Candidate: candidates["b"], Role: ActiveTargetProspective},
			}, nil
		}),
	}
	if err := monitor.WarmTargets(ctx, now); err != nil {
		t.Fatal(err)
	}
	applyGeneration(2, candidates["b"].ID)

	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx, now.Add(time.Second)) }()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("generation refresh did not start")
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	for {
		agent.mu.Lock()
		critical := append([]string(nil), agent.critical...)
		background := append([]string(nil), agent.background...)
		agent.mu.Unlock()
		if slices.Contains(critical, candidates["b"].ID) {
			if slices.Contains(background, candidates["b"].ID) {
				t.Fatalf("new applied route used prospective lane: %v", background)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new applied route was not promoted immediately: critical=%v background=%v",
				critical, background)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(releaseRefresh)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestActiveMonitorLateRefreshCannotReplaceNewerReconciledGeneration(t *testing.T) {
	newer := ActiveTarget{Candidate: store.Candidate{ID: "newer"}, Role: ActiveTargetCritical}
	older := ActiveTarget{Candidate: store.Candidate{ID: "older"}, Role: ActiveTargetCritical}
	monitor := ActiveMonitor{
		targetsReady: true,
		targetsSnapshot: activeTargetSnapshot{
			targets: []ActiveTarget{newer}, appliedGeneration: 2,
		},
		targetsPlanning: true,
		targetsPlanDone: make(chan struct{}),
	}
	monitor.finishTargetPlanning(activeTargetSnapshot{
		targets: []ActiveTarget{older}, appliedGeneration: 1,
	}, nil)
	if monitor.targetsSnapshot.appliedGeneration != 2 ||
		len(monitor.targetsSnapshot.targets) != 1 ||
		monitor.targetsSnapshot.targets[0].Candidate.ID != newer.Candidate.ID {
		t.Fatalf("late refresh replaced newer snapshot: %+v", monitor.targetsSnapshot)
	}
}

func TestActiveMonitorCapacityChangesOnlyForAcceptedSemanticTransition(t *testing.T) {
	ctx := context.Background()
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_900_000_000, 0)
	capacityChanges := make(chan struct{}, 1)
	mode := "success"
	targetMode := "candidate"
	monitor := ActiveMonitor{
		Store: database,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			switch mode {
			case "infrastructure":
				return agentapi.ProbeResponse{
					FailureClass: agentapi.FailureInfrastructure,
				}, context.DeadlineExceeded
			case "degraded":
				return agentapi.ProbeResponse{
					FailureClass: agentapi.FailureCandidate,
					Observation:  health.Observation{PrimaryOK: true},
				}, nil
			case "failure":
				return agentapi.ProbeResponse{
					FailureClass: agentapi.FailureCandidate,
					Observation:  health.Observation{},
				}, nil
			default:
				return agentapi.ProbeResponse{Observation: health.Observation{
					PrimaryOK: true, ConfirmationOK: true,
				}}, nil
			}
		}),
		Targets: activeTargetProviderFunc(func(
			context.Context, time.Time,
		) ([]ActiveTarget, error) {
			switch targetMode {
			case "none":
				return nil, nil
			case "coverage-error":
				return nil, ErrActiveCriticalCoverageExceeded
			default:
				return []ActiveTarget{{
					Candidate: candidate, Role: ActiveTargetCritical,
					ProofFreshAfter: base.Add(-time.Second),
				}}, nil
			}
		}),
		CapacityChanges: capacityChanges,
	}
	run := func(at time.Time) error {
		t.Helper()
		monitor.Clock = fixedActiveMonitorClock{now: at}
		return monitor.Run(ctx, at)
	}
	wantSignal := func(label string) {
		t.Helper()
		select {
		case <-capacityChanges:
		default:
			t.Fatalf("%s did not signal semantic capacity transition", label)
		}
	}
	wantNoSignal := func(label string) {
		t.Helper()
		select {
		case <-capacityChanges:
			t.Fatalf("%s repeated/no-op capacity signal", label)
		default:
		}
	}

	if err := run(base); err != nil {
		t.Fatal(err)
	}
	wantSignal("first fresh proof")
	if err := run(base.Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("repeated fresh proof")

	mode = "degraded"
	if err := run(base.Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("bounded degraded proof retention")

	mode = "failure"
	if err := run(base.Add(750 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("hard failure uses dedicated placement signal")
	if err := run(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("repeated proof failure")

	mode = "infrastructure"
	if err := run(base.Add(1250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("infrastructure failure")
	targetMode = "none"
	if err := run(base.Add(1500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wantNoSignal("no targets")
	targetMode = "coverage-error"
	if err := run(base.Add(1750 * time.Millisecond)); !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatalf("coverage error=%v", err)
	}
	wantNoSignal("coverage error")
	if rows := mustCandidateHealth(t, database); len(rows) != 1 ||
		rows[0].CandidateID != candidateID || rows[0].Available ||
		!rows[0].ActiveHardFailure {
		t.Fatalf("candidate health=%+v", rows)
	}
}

func TestActiveMonitorCompletionCutoffRecoversProofThatAgedDuringProbe(t *testing.T) {
	base := time.Unix(1_900_000_000, 0)
	startedAt := base.Add(500 * time.Millisecond)
	staleAt := base.Add(750 * time.Millisecond)
	completedAt := base.Add(800 * time.Millisecond)
	database, candidates := newEngineQoEFixture(t, base, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, base, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", base, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	for _, candidate := range candidates {
		setEngineActiveObservationAt(t, database, candidate, base)
	}
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(250*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	capacityChanges := make(chan struct{}, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	var starts atomic.Int32
	clock := &mutableActiveMonitorClock{now: startedAt}
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		ProofFreshness:  500 * time.Millisecond,
		CapacityChanges: capacityChanges,
		Clock:           clock,
		Agent: activeProbeAgentFunc(func(
			ctx context.Context, _ agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			if starts.Add(1) == 2 {
				close(started)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return agentapi.ProbeResponse{}, ctx.Err()
			}
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
	}
	done := make(chan error, 1)
	go func() { done <- monitor.Run(context.Background(), startedAt) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("both in-flight probes did not start")
	}
	if err := engine.CapacityReady(context.Background(), staleAt); !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatalf("periodic readiness at stale boundary=%v", err)
	}
	if err := engine.CycleForReason(
		context.Background(), staleAt, PlacementStartupNormalization,
	); !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatalf("stale normalization=%v", err)
	}
	clock.Set(completedAt)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-capacityChanges:
	default:
		t.Fatal("completion-time fresh proof did not wake capacity recovery")
	}
	select {
	case <-capacityChanges:
		t.Fatal("one accepted proof batch emitted duplicate capacity changes")
	default:
	}
	if err := engine.CycleForReason(
		context.Background(), completedAt, PlacementStartupNormalization,
	); err != nil {
		t.Fatalf("immediate completion-time normalization=%v", err)
	}
	if err := engine.CapacityReady(context.Background(), completedAt); err != nil {
		t.Fatalf("completion-time proof readiness=%v", err)
	}
	for _, row := range mustCandidateHealth(t, database) {
		if !row.ActiveObservedAt.Equal(completedAt) {
			t.Fatalf("accepted proof completion=%s want=%s", row.ActiveObservedAt, completedAt)
		}
	}
}

func TestRuntimeGivesBootstrapPlanningAndCriticalProbesSeparateFreshBudgets(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "a", Fingerprint: "a", Payload: "vless://a@example.net:443"},
		{Kind: sources.KindVLESS, Label: "b", Fingerprint: "b", Payload: "vless://b@example.net:443"},
	})
	now := time.Now()
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var providerCalls atomic.Int32
	var probeCalls atomic.Int32
	var minimumProbeBudget atomic.Int64
	minimumProbeBudget.Store(int64(time.Hour))
	monitor := &ActiveMonitor{
		Store: database, Slots: 2, CriticalLimit: 16,
		PlanningDeadline: 450 * time.Millisecond,
		ProbeDeadline:    1500 * time.Millisecond,
		Targets: activeTargetProviderFunc(func(
			ctx context.Context, _ time.Time,
		) ([]ActiveTarget, error) {
			providerCalls.Add(1)
			select {
			case <-time.After(350 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return []ActiveTarget{
				{Candidate: candidates["a"], Role: ActiveTargetCritical},
				{Candidate: candidates["b"], Role: ActiveTargetCritical},
			}, nil
		}),
		Agent: activeProbeAgentFunc(func(
			ctx context.Context, _ agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probeCalls.Add(1)
			if deadline, ok := ctx.Deadline(); ok {
				remaining := int64(time.Until(deadline))
				for {
					current := minimumProbeBudget.Load()
					if remaining >= current || minimumProbeBudget.CompareAndSwap(current, remaining) {
						break
					}
				}
			}
			select {
			case <-time.After(525 * time.Millisecond):
				return agentapi.ProbeResponse{Observation: health.Observation{
					PrimaryOK: true, ConfirmationOK: true,
				}}, nil
			case <-ctx.Done():
				return agentapi.ProbeResponse{}, ctx.Err()
			}
		}),
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		Active: func(ctx context.Context, at time.Time) error {
			err := monitor.Run(ctx, at)
			cancel()
			return err
		},
		ActiveDeadline:         1500 * time.Millisecond,
		ActivePlanningDeadline: 450 * time.Millisecond,
		SourceRefreshInterval:  time.Hour,
		QualificationInterval:  time.Hour,
		PlacementInterval:      time.Hour,
		ActiveInterval:         time.Hour,
	}
	if err := runtime.Start(runCtx); err != nil {
		t.Fatal(err)
	}
	if providerCalls.Load() != 1 || probeCalls.Load() != 2 {
		t.Fatalf("provider calls=%d probe calls=%d", providerCalls.Load(), probeCalls.Load())
	}
	if budget := time.Duration(minimumProbeBudget.Load()); budget < 1250*time.Millisecond {
		t.Fatalf("critical probes inherited spent planning budget: %s", budget)
	}
	rows := mustCandidateHealth(t, database)
	for _, row := range rows {
		if !row.ActiveSuccess || !row.ActiveCurrent {
			t.Fatalf("long bootstrap probe was not persisted: %+v", row)
		}
	}
}

func TestActiveMonitorPlanningBudgetIncludesContendedPlannerAdmission(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	t.Cleanup(func() { engine.clearBootstrapCoverageCache() })
	planningStarted := make(chan struct{})
	monitor := &ActiveMonitor{
		Store: database, CriticalLimit: 16,
		PlanningDeadline: ActiveCriticalCoveragePlanningBudget,
		Targets: activeTargetProviderFunc(func(
			ctx context.Context, at time.Time,
		) ([]ActiveTarget, error) {
			close(planningStarted)
			return engine.ActiveTargets(ctx, at)
		}),
	}

	engine.bootstrapCoverageMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := monitor.planActiveTargets(context.Background(), now.Add(3*time.Minute))
		done <- err
	}()
	<-planningStarted
	time.Sleep(activeCriticalCoverageWallBudget + 25*time.Millisecond)
	engine.bootstrapCoverageMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target planning did not progress after planner admission")
	}
}

func TestActiveMonitorRoutesCriticalAndProspectiveToIsolatedAgentLanes(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "critical", Fingerprint: "critical", Payload: "vless://critical@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective", Fingerprint: "prospective", Payload: "vless://prospective@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	agent := &laneRecordingActiveAgent{}
	monitor := ActiveMonitor{
		Store: database, Agent: agent, Slots: 2,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return []ActiveTarget{
				{Candidate: candidates["critical"], Role: ActiveTargetCritical},
				{Candidate: candidates["prospective"], Role: ActiveTargetProspective},
			}, nil
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(agent.critical, []string{candidates["critical"].ID}) ||
		!reflect.DeepEqual(agent.background, []string{candidates["prospective"].ID}) {
		t.Fatalf("critical=%v background=%v", agent.critical, agent.background)
	}
}

func TestActiveMonitorCriticalLimitCountsUniqueCriticalCandidatesOnly(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "critical-1", Fingerprint: "critical-1", Payload: "vless://critical-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "critical-2", Fingerprint: "critical-2", Payload: "vless://critical-2@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective", Fingerprint: "prospective", Payload: "vless://prospective@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	targets := []ActiveTarget{
		{Candidate: candidates["critical-1"], Role: ActiveTargetCritical},
		{Candidate: candidates["critical-1"], Role: ActiveTargetCritical},
		{Candidate: candidates["prospective"], Role: ActiveTargetProspective},
	}
	monitor := ActiveMonitor{
		Store: database, Agent: &laneRecordingActiveAgent{}, Slots: 3,
		CriticalLimit: 1,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return targets, nil
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(ctx, now); err != nil {
		t.Fatalf("duplicate critical/prospective consumed critical capacity: %v", err)
	}
	targets = append(targets, ActiveTarget{
		Candidate: candidates["critical-2"], Role: ActiveTargetCritical,
	})
	if err := monitor.Run(ctx, now.Add(time.Second)); !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatalf("critical over-limit error=%v", err)
	}
}

func TestRuntimeOverlappingActiveGenerationDetectsWhilePriorPeerHangs(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "a", Fingerprint: "a", Payload: "vless://a@example.net:443"},
		{Kind: sources.KindVLESS, Label: "b", Fingerprint: "b", Payload: "vless://b@example.net:443"},
	})
	now := time.Now()
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var aCalls atomic.Int32
	var bInFlight atomic.Int32
	var bMaxInFlight atomic.Int32
	hardFailures := NewHardFailureMailbox()
	monitor := ActiveMonitor{
		Store: database, Slots: 48, CriticalLimit: 16,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return []ActiveTarget{
				{Candidate: candidates["a"], Role: ActiveTargetCritical},
				{Candidate: candidates["b"], Role: ActiveTargetCritical},
			}, nil
		}),
		Agent: activeProbeAgentFunc(func(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			if request.CandidateID == candidates["b"].ID {
				inFlight := bInFlight.Add(1)
				defer bInFlight.Add(-1)
				for {
					maximum := bMaxInFlight.Load()
					if inFlight <= maximum || bMaxInFlight.CompareAndSwap(maximum, inFlight) {
						break
					}
				}
				<-ctx.Done()
				return agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, ctx.Err()
			}
			if aCalls.Add(1) == 1 {
				return agentapi.ProbeResponse{Observation: health.Observation{
					PrimaryOK: true, ConfirmationOK: true,
				}}, nil
			}
			return agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				Observation:  health.Observation{},
			}, nil
		}),
		HardFailures: hardFailures, HardFailureDeadline: 1575 * time.Millisecond,
	}
	runtimeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hardDone := make(chan time.Time, 1)
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error { return store.ErrCandidateInventoryChanged },
		Active:  monitor.Run,
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				hardDone <- time.Now()
				cancel()
			}
			return nil
		},
		HardFailureEvents:     hardFailures,
		ActiveOverlap:         3,
		ActiveInterval:        250 * time.Millisecond,
		ActiveDeadline:        625 * time.Millisecond,
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runtimeCtx) }()
	select {
	case <-hardDone:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("overlapping active generation did not trigger hard placement")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls := aCalls.Load(); calls < 3 {
		t.Fatalf("candidate A probe starts=%d", calls)
	}
	if maximum := bMaxInFlight.Load(); maximum < 2 {
		t.Fatalf("hanging candidate B max concurrent probes=%d", maximum)
	}
}

func TestActiveMonitorOverlappingFailureNeedsPostBoundaryConfirmation(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "slow", Fingerprint: "slow",
		Payload: "vless://slow@example.net:443", FailureDomain: "domain-hash",
	}})
	candidate := candidates["slow"]
	now := time.Now()
	if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: candidate.ID, Score: 90, TCPQualified: true,
		Available: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	thirdStarted := make(chan time.Time, 1)
	releaseThird := make(chan struct{})
	hardFailures := NewHardFailureMailbox()
	monitor := ActiveMonitor{
		Store: database, Slots: 48, CriticalLimit: 16,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return []ActiveTarget{{Candidate: candidate, Role: ActiveTargetCritical}}, nil
		}),
		Agent: activeProbeAgentFunc(func(ctx context.Context, _ agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			switch calls.Add(1) {
			case 1:
				close(firstStarted)
				select {
				case <-releaseFirst:
				case <-ctx.Done():
					return agentapi.ProbeResponse{}, ctx.Err()
				}
			case 2:
				close(secondStarted)
				select {
				case <-releaseSecond:
				case <-ctx.Done():
					return agentapi.ProbeResponse{}, ctx.Err()
				}
			default:
				select {
				case thirdStarted <- time.Now():
				default:
				}
				select {
				case <-releaseThird:
				case <-ctx.Done():
					return agentapi.ProbeResponse{}, ctx.Err()
				}
			}
			return agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				Observation:  health.Observation{},
			}, nil
		}),
		HardFailures: hardFailures, HardFailureDeadline: 5 * time.Second,
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 3)
	run := func(at time.Time) {
		go func() { runDone <- monitor.Run(runCtx, at) }()
	}
	run(now)
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first active reservation did not start")
	}
	run(now.Add(100 * time.Millisecond))
	select {
	case <-secondStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("overlapping active reservation did not start")
	}
	close(releaseFirst)
	var suspectAt time.Time
	suspectDeadline := time.Now().Add(2 * time.Second)
	for suspectAt.IsZero() && time.Now().Before(suspectDeadline) {
		monitor.trackerMu.Lock()
		suspectAt = monitor.hardFailureSuspects[candidate.ID]
		monitor.trackerMu.Unlock()
		if suspectAt.IsZero() {
			time.Sleep(time.Millisecond)
		}
	}
	if suspectAt.IsZero() {
		t.Fatal("first completed failure did not establish a suspect boundary")
	}
	run(now.Add(200 * time.Millisecond))
	close(releaseSecond)
	var confirmingStartedAt time.Time
	select {
	case confirmingStartedAt = <-thirdStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("non-overlapping confirming probe did not start")
	}
	if confirmingStartedAt.Before(suspectAt) {
		t.Fatalf("confirming probe started at %s before suspect boundary %s",
			confirmingStartedAt, suspectAt)
	}
	select {
	case <-hardFailures.Wake():
		t.Fatal("overlapping probe confirmed hard failure before later probe completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseThird)
	select {
	case <-hardFailures.Wake():
	case <-time.After(2 * time.Second):
		t.Fatal("non-overlapping hard result was not accepted")
	}
	event, ok := hardFailures.Pop()
	if !ok || event.CandidateID != candidate.ID {
		t.Fatalf("hard failure event=%+v ok=%t", event, ok)
	}
	for range 3 {
		if err := <-runDone; err != nil {
			t.Fatal(err)
		}
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available || !rows[0].ActiveHardFailure {
		t.Fatalf("slow overlapping hard health=%+v", rows)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Kind == "candidate_hard_failure" && event.CandidateID == candidate.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("slow overlapping hard event missing: %+v", events)
	}
	t.Logf("confirmed hard failure after boundary in %s", event.DetectedAt.Sub(suspectAt))
}

func TestActiveMonitorGlobalCriticalCapacityAndProspectiveIsolation(t *testing.T) {
	inputs := make([]store.CandidateInput, 0, 17)
	for index := 0; index < 16; index++ {
		name := fmt.Sprintf("critical-%02d", index)
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindVLESS, Label: name, Fingerprint: name,
			Payload: "vless://" + name + "@example.net:443",
		})
	}
	inputs = append(inputs, store.CandidateInput{
		Kind: sources.KindVLESS, Label: "prospective", Fingerprint: "prospective",
		Payload: "vless://prospective@example.net:443",
	})
	ctx := context.Background()
	database, candidates := qualificationStore(t, inputs)
	now := time.Now()
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	targets := make([]ActiveTarget, 0, 17)
	for index := 0; index < 16; index++ {
		candidate := candidates[fmt.Sprintf("critical-%02d", index)]
		targets = append(targets, ActiveTarget{
			Candidate: candidate, Role: ActiveTargetCritical,
		})
	}
	targets = append(targets, ActiveTarget{
		Candidate: candidates["prospective"], Role: ActiveTargetProspective,
	})
	agent := newCapacityActiveAgent()
	monitor := ActiveMonitor{
		Store: database, Agent: agent, Slots: 48, CriticalLimit: 16,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return targets, nil
		}),
	}
	done := make(chan error, 4)
	for generation := 0; generation < 3; generation++ {
		go func(offset int) {
			done <- monitor.Run(ctx, now.Add(time.Duration(offset)*250*time.Millisecond))
		}(generation)
	}
	// The store deliberately serializes SQLite access through one connection.
	// Under a full-package or race run, starting 48 reserved observations can
	// legitimately take longer than the old five-second test-only deadline.
	deadline := time.Now().Add(15 * time.Second)
	for (agent.CriticalCurrent() < 48 || agent.BackgroundMaximum() < 1) &&
		time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if current, maximum := agent.CriticalCurrent(), agent.CriticalMaximum(); current != 48 || maximum > 48 {
		close(agent.release)
		t.Fatalf("critical global current/max=%d/%d", current, maximum)
	}
	if maximum := agent.BackgroundMaximum(); maximum != 1 {
		close(agent.release)
		t.Fatalf("prospective concurrent generations=%d", maximum)
	}
	go func() {
		done <- monitor.Run(ctx, now.Add(750*time.Millisecond))
	}()
	time.Sleep(100 * time.Millisecond)
	if current, maximum := agent.CriticalCurrent(), agent.CriticalMaximum(); current != 48 || maximum != 48 {
		close(agent.release)
		t.Fatalf("critical global current/max after fourth generation=%d/%d", current, maximum)
	}
	if maximum := agent.BackgroundMaximum(); maximum != 1 {
		close(agent.release)
		t.Fatalf("prospective concurrent generations after fourth generation=%d", maximum)
	}
	close(agent.release)
	for generation := 0; generation < 4; generation++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

type capacityActiveAgent struct {
	mu                sync.Mutex
	criticalCurrent   int
	criticalMaximum   int
	backgroundCurrent int
	backgroundMaximum int
	release           chan struct{}
}

func newCapacityActiveAgent() *capacityActiveAgent {
	return &capacityActiveAgent{release: make(chan struct{})}
}

func (agent *capacityActiveAgent) ProbeActive(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.backgroundCurrent++
	if agent.backgroundCurrent > agent.backgroundMaximum {
		agent.backgroundMaximum = agent.backgroundCurrent
	}
	agent.mu.Unlock()
	defer func() {
		agent.mu.Lock()
		agent.backgroundCurrent--
		agent.mu.Unlock()
	}()
	return agent.wait(ctx, request)
}

func (agent *capacityActiveAgent) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.criticalCurrent++
	if agent.criticalCurrent > agent.criticalMaximum {
		agent.criticalMaximum = agent.criticalCurrent
	}
	agent.mu.Unlock()
	defer func() {
		agent.mu.Lock()
		agent.criticalCurrent--
		agent.mu.Unlock()
	}()
	return agent.wait(ctx, request)
}

func (agent *capacityActiveAgent) wait(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	select {
	case <-ctx.Done():
		return agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, ctx.Err()
	case <-agent.release:
		return agentapi.ProbeResponse{
			CandidateID: request.CandidateID,
			Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
		}, nil
	}
}

func (agent *capacityActiveAgent) CriticalCurrent() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.criticalCurrent
}

func (agent *capacityActiveAgent) CriticalMaximum() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.criticalMaximum
}

func (agent *capacityActiveAgent) BackgroundMaximum() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.backgroundMaximum
}

type laneRecordingActiveAgent struct {
	mu         sync.Mutex
	critical   []string
	background []string
}

func (agent *laneRecordingActiveAgent) ProbeActive(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.background = append(agent.background, request.CandidateID)
	agent.mu.Unlock()
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
	}, nil
}

func (agent *laneRecordingActiveAgent) ProbeActiveCritical(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.critical = append(agent.critical, request.CandidateID)
	agent.mu.Unlock()
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
	}, nil
}

func TestActiveMonitorPartialEndpointSuccessNeverCreatesProofOrPromotion(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation health.Observation
	}{
		{name: "primary only", observation: health.Observation{PrimaryOK: true}},
		{name: "confirmation only", observation: health.Observation{ConfirmationOK: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := qualificationStore(t, []store.CandidateInput{{
				Kind: sources.KindVLESS, Label: "prospective",
				Fingerprint: "prospective",
				Payload:     "vless://prospective@example.net:443?security=tls",
			}})
			candidate := candidates["prospective"]
			now := time.Unix(1_900_000_000, 0)
			if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
				CandidateID: candidate.ID, Score: 95, TCPQualified: true,
				UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			promotions := make(chan struct{}, 1)
			monitor := ActiveMonitor{
				Store: database,
				Agent: activeProbeAgentFunc(func(
					context.Context, agentapi.ProbeRequest,
				) (agentapi.ProbeResponse, error) {
					return agentapi.ProbeResponse{Observation: test.observation}, nil
				}),
				Targets: activeTargetProviderFunc(func(
					context.Context, time.Time,
				) ([]ActiveTarget, error) {
					return []ActiveTarget{{
						Candidate: candidate, TriggerPlacementOnSuccess: true,
						ProofFreshAfter: now.Add(-2 * time.Minute),
					}}, nil
				}),
				Promotions: promotions,
				Clock:      fixedActiveMonitorClock{now: now},
			}
			if err := monitor.Run(ctx, now); err != nil {
				t.Fatal(err)
			}
			rows := mustCandidateHealth(t, database)
			if len(rows) != 1 || !rows[0].Available || rows[0].ActiveSuccess {
				t.Fatalf("partial endpoint persisted health=%+v", rows)
			}
			select {
			case <-promotions:
				t.Fatal("partial endpoint success triggered promotion")
			default:
			}
		})
	}
}

func TestActiveMonitorPartialEndpointSuccessRetainsFreshProof(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation health.Observation
	}{
		{name: "primary only", observation: health.Observation{PrimaryOK: true}},
		{name: "confirmation only", observation: health.Observation{ConfirmationOK: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := qualificationStore(t, []store.CandidateInput{{
				Kind: sources.KindVLESS, Label: "applied",
				Fingerprint: "applied",
				Payload:     "vless://applied@example.net:443?security=tls",
			}})
			candidate := candidates["applied"]
			base := time.Unix(1_900_000_000, 0)
			if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
				CandidateID: candidate.ID, Score: 95, TCPQualified: true,
				UDPQualified: true, Available: true, UpdatedAt: base,
			}); err != nil {
				t.Fatal(err)
			}
			seed, err := database.ReserveCandidateObservation(
				ctx, candidate, store.ObservationActive,
			)
			if err != nil {
				t.Fatal(err)
			}
			proofAt := base.Add(time.Second)
			if commit, err := database.CommitCandidateActiveOutcome(
				ctx, candidate, seed, store.ActiveObservationOutcome{
					Available: true, ProofSuccess: true,
				}, proofAt,
			); err != nil || !commit.Accepted {
				t.Fatalf("seed proof commit=%+v err=%v", commit, err)
			}

			observation := test.observation
			capacityChanges := make(chan struct{}, 1)
			promotions := make(chan struct{}, 1)
			partialAt := proofAt.Add(time.Second)
			monitor := ActiveMonitor{
				Store: database,
				Agent: activeProbeAgentFunc(func(
					context.Context, agentapi.ProbeRequest,
				) (agentapi.ProbeResponse, error) {
					return agentapi.ProbeResponse{Observation: observation}, nil
				}),
				Targets: activeTargetProviderFunc(func(
					context.Context, time.Time,
				) ([]ActiveTarget, error) {
					return []ActiveTarget{{
						Candidate: candidate, Role: ActiveTargetCritical,
					}}, nil
				}),
				CapacityChanges: capacityChanges,
				Promotions:      promotions,
				ProofFreshness:  15 * time.Second,
				Clock:           fixedActiveMonitorClock{now: partialAt},
			}
			if err := monitor.Run(ctx, partialAt); err != nil {
				t.Fatal(err)
			}
			rows := mustCandidateHealth(t, database)
			if len(rows) != 1 || !rows[0].Available || !rows[0].ActiveSuccess ||
				!rows[0].ActiveCurrent || !rows[0].ActiveObservedAt.Equal(proofAt) {
				t.Fatalf("partial endpoint replaced prior proof: %+v", rows)
			}
			select {
			case <-capacityChanges:
				t.Fatal("retained proof signaled capacity change")
			default:
			}
			select {
			case <-promotions:
				t.Fatal("retained proof triggered promotion")
			default:
			}

			engine := NewEngine(
				database, &engineAgent{}, nil, nil, []byte("secret"),
				WithActiveProofFreshness(15*time.Second),
			)
			if !engine.reserveActiveObservationFresh(proofAt.Add(14*time.Second), proofAt) {
				t.Fatal("retained proof expired before grace elapsed")
			}
			if engine.reserveActiveObservationFresh(proofAt.Add(16*time.Second), proofAt) {
				t.Fatal("retained proof stayed fresh after grace elapsed")
			}

			recoveryAt := proofAt.Add(3 * time.Second)
			observation = health.Observation{PrimaryOK: true, ConfirmationOK: true}
			monitor.Clock = fixedActiveMonitorClock{now: recoveryAt}
			if err := monitor.Run(ctx, recoveryAt); err != nil {
				t.Fatal(err)
			}
			rows = mustCandidateHealth(t, database)
			if len(rows) != 1 || !rows[0].ActiveSuccess ||
				!rows[0].ActiveObservedAt.Equal(recoveryAt) {
				t.Fatalf("full recovery did not refresh proof: %+v", rows)
			}
		})
	}
}

func TestActiveMonitorPromotesWhenPriorFullProofIsOlderThanRequired(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "prospective", Fingerprint: "prospective",
		Payload: "vless://prospective@example.net:443?security=tls",
	}})
	candidate := candidates["prospective"]
	base := time.Unix(1_900_000_000, 0)
	if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldProofAt := base.Add(time.Minute)
	commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidate, reservation, store.ActiveObservationOutcome{
			Available: true, ProofSuccess: true,
		}, oldProofAt,
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("seed proof commit=%+v err=%v", commit, err)
	}

	now := oldProofAt.Add(3 * time.Minute)
	promotions := make(chan struct{}, 1)
	monitor := ActiveMonitor{
		Store: database,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Targets: activeTargetProviderFunc(func(
			context.Context, time.Time,
		) ([]ActiveTarget, error) {
			return []ActiveTarget{{
				Candidate: candidate, TriggerPlacementOnSuccess: true,
				ProofFreshAfter: oldProofAt.Add(time.Second),
			}}, nil
		}),
		Promotions: promotions,
		Clock:      fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-promotions:
	default:
		t.Fatal("fresh full proof did not promote after prior proof became stale")
	}
}

func TestActiveMonitorDispatcherReservesProspectiveLaneAndCapsInflight(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "critical-1", Fingerprint: "critical-1", Payload: "vless://critical-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "critical-2", Fingerprint: "critical-2", Payload: "vless://critical-2@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-1", Fingerprint: "prospective-1", Payload: "vless://prospective-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-2", Fingerprint: "prospective-2", Payload: "vless://prospective-2@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	targets := []ActiveTarget{
		{Candidate: candidates["critical-1"], Role: ActiveTargetCritical},
		{Candidate: candidates["critical-2"], Role: ActiveTargetCritical},
		{Candidate: candidates["prospective-1"], Role: ActiveTargetProspective},
		{Candidate: candidates["prospective-2"], Role: ActiveTargetProspective},
	}
	started := make(chan string, len(targets))
	release := make(chan struct{}, len(targets))
	var lock sync.Mutex
	running, maximum := 0, 0
	monitor := ActiveMonitor{
		Store: database, Slots: 2,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return targets, nil
		}),
		Agent: activeProbeAgentFunc(func(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			lock.Lock()
			running++
			if running > maximum {
				maximum = running
			}
			lock.Unlock()
			started <- request.CandidateID
			<-release
			lock.Lock()
			running--
			lock.Unlock()
			return agentapi.ProbeResponse{Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx, now) }()
	first := <-started
	second := <-started
	critical := map[string]bool{candidates["critical-1"].ID: true, candidates["critical-2"].ID: true}
	prospective := map[string]bool{candidates["prospective-1"].ID: true, candidates["prospective-2"].ID: true}
	if !(critical[first] && prospective[second]) && !(prospective[first] && critical[second]) {
		t.Fatalf("initial lanes=%q,%q want critical+prospective", first, second)
	}
	select {
	case third := <-started:
		t.Fatalf("third probe queued past local cap before completion: %s", third)
	case <-time.After(50 * time.Millisecond):
	}
	for range targets {
		release <- struct{}{}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not drain")
	}
	lock.Lock()
	defer lock.Unlock()
	if maximum != 2 {
		t.Fatalf("max in-flight=%d want=2", maximum)
	}
}

func TestActiveMonitorSingleSlotFairlyAlternatesTargetRoles(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "critical-1", Fingerprint: "critical-1", Payload: "vless://critical-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "critical-2", Fingerprint: "critical-2", Payload: "vless://critical-2@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-1", Fingerprint: "prospective-1", Payload: "vless://prospective-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-2", Fingerprint: "prospective-2", Payload: "vless://prospective-2@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: candidate.ID, Score: 90, TCPQualified: true, UDPQualified: true, Available: true, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	targets := []ActiveTarget{
		{Candidate: candidates["critical-1"], Role: ActiveTargetCritical},
		{Candidate: candidates["critical-2"], Role: ActiveTargetCritical},
		{Candidate: candidates["prospective-1"], Role: ActiveTargetProspective},
		{Candidate: candidates["prospective-2"], Role: ActiveTargetProspective},
	}
	var observed []string
	monitor := ActiveMonitor{
		Store: database, Slots: 1,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) { return targets, nil }),
		Agent: activeProbeAgentFunc(func(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			observed = append(observed, request.CandidateID)
			return agentapi.ProbeResponse{Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates["critical-1"].ID, candidates["prospective-1"].ID, candidates["critical-2"].ID, candidates["prospective-2"].ID}
	if !reflect.DeepEqual(observed, want) {
		t.Fatalf("dispatch order=%v want=%v", observed, want)
	}
}

func TestActiveMonitorPersistentRoleCursorsCoverEveryCandidateAcrossTimedOutRuns(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "critical-1", Fingerprint: "critical-1", Payload: "vless://critical-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "critical-2", Fingerprint: "critical-2", Payload: "vless://critical-2@example.net:443"},
		{Kind: sources.KindVLESS, Label: "critical-3", Fingerprint: "critical-3", Payload: "vless://critical-3@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-1", Fingerprint: "prospective-1", Payload: "vless://prospective-1@example.net:443"},
		{Kind: sources.KindVLESS, Label: "prospective-2", Fingerprint: "prospective-2", Payload: "vless://prospective-2@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 90, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	criticalIDs := []string{
		candidates["critical-1"].ID,
		candidates["critical-2"].ID,
		candidates["critical-3"].ID,
	}
	prospectiveIDs := []string{
		candidates["prospective-1"].ID,
		candidates["prospective-2"].ID,
	}
	sort.Strings(criticalIDs)
	sort.Strings(prospectiveIDs)
	targets := make([]ActiveTarget, 0, 5)
	for _, id := range criticalIDs {
		targets = append(targets, ActiveTarget{
			Candidate: engineCandidateByID(t, candidates, id), Role: ActiveTargetCritical,
		})
	}
	for _, id := range prospectiveIDs {
		targets = append(targets, ActiveTarget{
			Candidate: engineCandidateByID(t, candidates, id), Role: ActiveTargetProspective,
		})
	}
	var observed []string
	started := make(chan string)
	monitor := ActiveMonitor{
		Store: database, Slots: 1,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return targets, nil
		}),
		Agent: activeProbeAgentFunc(func(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			select {
			case started <- request.CandidateID:
			case <-ctx.Done():
				return agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, ctx.Err()
			}
			<-ctx.Done()
			return agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, ctx.Err()
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	for run := 0; run < 6; run++ {
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func(at time.Time) {
			done <- monitor.Run(runCtx, at)
		}(now.Add(time.Duration(run) * time.Second))
		select {
		case candidateID := <-started:
			observed = append(observed, candidateID)
			cancel()
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("active probe did not start")
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		criticalIDs[0], prospectiveIDs[0], criticalIDs[1],
		prospectiveIDs[1], criticalIDs[2], prospectiveIDs[0],
	}
	if !reflect.DeepEqual(observed, want) {
		t.Fatalf("timed-out dispatch order=%v want=%v", observed, want)
	}
}

func TestActiveMonitorStreamsCompletedResultBeforeSlowPeerFinishes(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "fast", Fingerprint: "fast", Payload: "vless://fast@example.net:443"},
		{Kind: sources.KindVLESS, Label: "slow", Fingerprint: "slow", Payload: "vless://slow@example.net:443"},
	})
	now := time.Unix(1_900_000_000, 0)
	for _, candidate := range candidates {
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: candidate.ID, Score: 90, TCPQualified: true, UDPQualified: true, Available: true, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	monitor := ActiveMonitor{
		Store: database, Slots: 2,
		Targets: activeTargetProviderFunc(func(context.Context, time.Time) ([]ActiveTarget, error) {
			return []ActiveTarget{{Candidate: candidates["fast"], Role: ActiveTargetCritical}, {Candidate: candidates["slow"], Role: ActiveTargetCritical}}, nil
		}),
		Agent: activeProbeAgentFunc(func(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
			if request.CandidateID == candidates["slow"].ID {
				close(slowStarted)
				<-releaseSlow
			}
			return agentapi.ProbeResponse{Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx, now) }()
	<-slowStarted
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		rows := mustCandidateHealth(t, database)
		for _, row := range rows {
			if row.CandidateID == candidates["fast"].ID && row.ActiveObservedAt.Equal(now) {
				close(releaseSlow)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			close(releaseSlow)
			t.Fatal("fast result was held behind slow peer")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type activeTargetProviderFunc func(
	context.Context, time.Time,
) ([]ActiveTarget, error)

func (function activeTargetProviderFunc) ActiveTargets(
	ctx context.Context,
	now time.Time,
) ([]ActiveTarget, error) {
	return function(ctx, now)
}

func TestActiveMonitorObservationLegacyVLESSReservesBeforeObserveRPC(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_800_000_000, 0)
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(
			ctx context.Context,
			_ []qualifier.Input,
		) []qualifier.ActiveResult {
			newer, err := database.ReserveCandidateObservation(
				ctx, candidate, store.ObservationActive,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
				ctx, candidate, newer, base.Add(time.Second),
			); err != nil || !commit.Accepted {
				t.Fatalf("hard failure commit=%+v err=%v", commit, err)
			}
			return []qualifier.ActiveResult{{
				CandidateID: candidateID,
				Observation: health.Observation{
					PrimaryOK: true, ConfirmationOK: true,
				},
			}}
		}),
	}
	if err := monitor.Run(context.Background(), base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("legacy delayed active success crossed newer failure: %+v", rows)
	}
}

func TestActiveMonitorObservationRejectedOldFailureDoesNotPoisonTracker(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_800_000_000, 0)
	oldFailure, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	newSuccess, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	monitor := ActiveMonitor{Store: database}
	candidateByID := map[string]store.Candidate{candidateID: candidate}
	healthy := mustCandidateHealth(t, database)[0]
	if err := monitor.applyReservedObservations(
		context.Background(),
		base.Add(time.Second),
		map[string]activeObservation{candidateID: {
			observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			},
			reservation: newSuccess,
		}},
		map[string]store.CandidateHealth{candidateID: healthy},
		candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	if err := monitor.applyReservedObservations(
		context.Background(),
		base.Add(2*time.Second),
		map[string]activeObservation{candidateID: {
			observation: health.Observation{},
			reservation: oldFailure,
		}},
		map[string]store.CandidateHealth{candidateID: healthy},
		candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	tracker := monitor.trackers[candidateID]
	if tracker == nil || !tracker.State(base.Add(2*time.Second)).Available {
		t.Fatal("rejected old failure poisoned active tracker")
	}
}

func TestActiveMonitorObservationRejectedOldSuccessDoesNotCausePrematureRecovery(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	oldSuccess, err := database.ReserveCandidateObservation(
		ctx, candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	newFailure, err := database.ReserveCandidateObservation(
		ctx, candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	monitor := ActiveMonitor{Store: database}
	candidateByID := map[string]store.Candidate{candidateID: candidate}
	available := mustCandidateHealth(t, database)[0]
	if err := monitor.applyReservedObservations(
		ctx,
		base,
		map[string]activeObservation{candidateID: {
			observation: health.Observation{},
			reservation: newFailure,
		}},
		map[string]store.CandidateHealth{candidateID: available},
		candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	unavailable := mustCandidateHealth(t, database)[0]
	healthyObservation := health.Observation{
		PrimaryOK: true, ConfirmationOK: true,
	}
	if err := monitor.applyReservedObservations(
		ctx,
		base.Add(time.Second),
		map[string]activeObservation{candidateID: {
			observation: healthyObservation,
			reservation: oldSuccess,
		}},
		map[string]store.CandidateHealth{candidateID: unavailable},
		candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		reservation, err := database.ReserveCandidateObservation(
			ctx, candidate, store.ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.applyReservedObservations(
			ctx,
			base.Add(5*time.Minute+time.Duration(index)*time.Second),
			map[string]activeObservation{candidateID: {
				observation: healthyObservation,
				reservation: reservation,
			}},
			map[string]store.CandidateHealth{
				candidateID: mustCandidateHealth(t, database)[0],
			},
			candidateByID,
		); err != nil {
			t.Fatal(err)
		}
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("rejected old success caused premature recovery: %+v", rows)
	}
}

type reservationInspectingActiveAgent struct {
	database  *store.Store
	candidate store.Candidate
	inside    store.ObservationReservation
}

func (agent *reservationInspectingActiveAgent) ProbeActive(
	ctx context.Context,
	_ agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	reservation, err := agent.database.ReserveCandidateObservation(
		ctx, agent.candidate, store.ObservationActive,
	)
	if err != nil {
		return agentapi.ProbeResponse{}, err
	}
	agent.inside = reservation
	return agentapi.ProbeResponse{
		CandidateID:  agent.candidate.ID,
		FailureClass: agentapi.FailureInfrastructure,
	}, nil
}

func (agent *reservationInspectingActiveAgent) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.ProbeActive(ctx, request)
}

func TestActiveMonitorDiscardsHardFailureWhenSourceDisabledWhileInFlight(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidates[0]
	agent := newBlockingActiveAgent()
	trigger := make(chan struct{}, 1)
	monitor := ActiveMonitor{
		Store: database, Agent: agent, Trigger: trigger,
		hardFailureSuspects: map[string]time.Time{
			candidateID: time.Unix(1_799_999_999, 0),
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- monitor.Run(context.Background(), time.Unix(1_800_000_000, 0))
	}()
	agent.waitStarted(t)
	if err := database.ReplaceCandidates(context.Background(), candidate.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
			Payload: "vless://replacement@example.net:443?security=tls",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateSource(
		context.Background(), candidate.SourceID, "disabled source", false,
	); err != nil {
		t.Fatal(err)
	}
	close(agent.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidateHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.CandidateID == candidateID && !row.Available {
			t.Fatalf("stale active probe quarantined removed candidate: %+v", row)
		}
	}
	for _, state := range mustProbeStates(t, database) {
		if state.Fingerprint == candidate.Fingerprint {
			t.Fatalf("stale active probe wrote state: %+v", state)
		}
	}
	domainStates, err := database.ListFailureDomainStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(domainStates) != 0 {
		t.Fatalf("stale active probe wrote domain evidence: %+v", domainStates)
	}
	select {
	case <-trigger:
		t.Fatal("stale active probe triggered placement")
	default:
	}
	if _, exists := monitor.hardFailureSuspects[candidateID]; exists {
		t.Fatal("removed candidate retained an obsolete hard-failure suspect")
	}
}

func TestActiveMonitorDiscardsObservationWhenSourceDisabledWhileInFlight(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "removed", Fingerprint: "removed",
			Payload: "vless://removed@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		},
	})
	removed := candidates["removed"]
	current := candidates["current"]
	before := time.Unix(1_799_999_000, 0)
	for index, candidate := range []store.Candidate{removed, current} {
		if err := database.PutClient(context.Background(), store.ClientRecord{
			ID: candidate.ID, Name: candidate.ID,
			Address: fmt.Sprintf("10.44.0.%d/32", index+2), PublicKey: candidate.ID,
		}, "config"); err != nil {
			t.Fatal(err)
		}
		if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
			ClientID: candidate.ID, TCPOutbound: candidate.ID, UDPOutbound: candidate.ID,
			TCPSince: before, UDPSince: before, UpdatedAt: before,
		}); err != nil {
			t.Fatal(err)
		}
		if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: before,
		}); err != nil {
			t.Fatal(err)
		}
	}
	agent := newSelectiveBlockingActiveAgent(removed.ID)
	monitor := ActiveMonitor{Store: database, Agent: agent}
	now := time.Unix(1_800_000_000, 0)
	done := make(chan error, 1)
	go func() {
		done <- monitor.Run(context.Background(), now)
	}()
	agent.waitStarted(t)
	if err := database.ReplaceCandidates(context.Background(), removed.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateSource(
		context.Background(), removed.SourceID, "disabled source", false,
	); err != nil {
		t.Fatal(err)
	}
	close(agent.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	healthRows := mustCandidateHealth(t, database)
	for _, row := range healthRows {
		switch row.CandidateID {
		case removed.ID:
			if !row.UpdatedAt.Equal(before) {
				t.Fatalf("stale non-hard observation updated removed health: %+v", row)
			}
		case current.ID:
			// This independent result may commit before the blocked candidate is
			// released. Streaming completion intentionally does not hold it behind
			// the slow peer.
		}
	}
	if _, exists := monitor.trackers[removed.ID]; exists {
		t.Fatal("removed candidate retained an obsolete active tracker")
	}
}

type selectiveBlockingActiveAgent struct {
	blockedID string
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func newSelectiveBlockingActiveAgent(candidateID string) *selectiveBlockingActiveAgent {
	return &selectiveBlockingActiveAgent{
		blockedID: candidateID, started: make(chan struct{}), release: make(chan struct{}),
	}
}

func (agent *selectiveBlockingActiveAgent) ProbeActive(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	if request.CandidateID == agent.blockedID {
		agent.once.Do(func() { close(agent.started) })
		select {
		case <-agent.release:
		case <-ctx.Done():
			return agentapi.ProbeResponse{}, ctx.Err()
		}
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
	}, nil
}

func (agent *selectiveBlockingActiveAgent) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.ProbeActive(ctx, request)
}

func (agent *selectiveBlockingActiveAgent) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("non-hard active probe did not block")
	}
}

type blockingActiveAgent struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingActiveAgent() *blockingActiveAgent {
	return &blockingActiveAgent{started: make(chan struct{}), release: make(chan struct{})}
}

func (agent *blockingActiveAgent) ProbeActive(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.once.Do(func() { close(agent.started) })
	select {
	case <-agent.release:
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Observation: health.Observation{},
	}, nil
}

func (agent *blockingActiveAgent) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.ProbeActive(ctx, request)
}

func (agent *blockingActiveAgent) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("active probe did not start")
	}
}

func TestActiveMonitorHardFailureQuarantinesAndTriggersPlacement(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	now := time.Unix(1_800_000_000, 0)
	trigger := make(chan struct{}, 1)
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(context.Context, []qualifier.Input) []qualifier.ActiveResult {
			return []qualifier.ActiveResult{{CandidateID: candidateID, Observation: health.Observation{}}}
		}),
		Trigger: trigger,
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListCandidateHealth(context.Background())
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("health=%+v", rows)
	}
	select {
	case <-trigger:
	default:
		t.Fatal("hard failure did not request immediate placement")
	}
}

func TestActiveMonitorHardFailurePersistsCandidateFailureStreak(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, _ := database.ListCandidates(context.Background(), "")
	now := time.Unix(1_800_000_000, 0)
	_, _ = database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
		Fingerprint: candidates[0].Fingerprint, CandidateID: candidateID,
		SourceID: candidates[0].SourceID, Full: true, Success: true, Score: 95,
		At: now.Add(-time.Minute),
	})
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(context.Context, []qualifier.Input) []qualifier.ActiveResult {
			return []qualifier.ActiveResult{{CandidateID: candidateID, Observation: health.Observation{}}}
		}),
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	state, err := database.CandidateProbeState(context.Background(), candidates[0].Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureStreak != 1 || state.LastErrorCode != "active_hard_failure" {
		t.Fatalf("state=%+v", state)
	}
}

func TestActiveMonitorRecordsOnlyDistinctVLESSHardFailureTransitionsForDomain(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
			Payload: "vless://a@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "c", Fingerprint: "c",
			Payload: "vless://c@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	monitor := ActiveMonitor{Store: database}
	healthByID := make(map[string]store.CandidateHealth, len(candidates))
	candidateByID := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		healthByID[candidate.ID] = store.CandidateHealth{
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
		}
		if err := database.SaveCandidateHealth(ctx, healthByID[candidate.ID]); err != nil {
			t.Fatal(err)
		}
		candidateByID[candidate.ID] = candidate
	}

	first := candidates["a"]
	if err := monitor.applyObservations(
		ctx, now,
		map[string]health.Observation{first.ID: {}},
		map[string]store.CandidateHealth{first.ID: healthByID[first.ID]},
		candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 3; index++ {
		rows := mustCandidateHealth(t, database)
		var current store.CandidateHealth
		for _, row := range rows {
			if row.CandidateID == first.ID {
				current = row
			}
		}
		if err := monitor.applyObservations(
			ctx, now.Add(time.Duration(index)*time.Second),
			map[string]health.Observation{first.ID: {}},
			map[string]store.CandidateHealth{first.ID: current},
			candidateByID,
		); err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 1 || !states[0].OpenUntil.IsZero() {
		t.Fatalf("repeated non-transition failure opened domain: %+v", states)
	}

	for _, fingerprint := range []string{"b", "c"} {
		candidate := candidates[fingerprint]
		if err := monitor.applyObservations(
			ctx, now.Add(time.Minute),
			map[string]health.Observation{candidate.ID: {}},
			map[string]store.CandidateHealth{candidate.ID: healthByID[candidate.ID]},
			candidateByID,
		); err != nil {
			t.Fatal(err)
		}
	}
	states, err = database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].FailureCount != 3 ||
		!states[0].OpenUntil.Equal(now.Add(11*time.Minute)) {
		t.Fatalf("distinct VLESS hard failures did not open domain: %+v", states)
	}
}

func TestActiveMonitorHealthyVLESSProofClosesDomainAndSignalsCapacity(t *testing.T) {
	ctx := context.Background()
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_800_000_000, 0)
	healthy := health.Observation{PrimaryOK: true, ConfirmationOK: true}
	capacityChanges := make(chan struct{}, 1)
	monitor := ActiveMonitor{
		Store: database, CapacityChanges: capacityChanges,
	}
	candidateByID := map[string]store.Candidate{candidateID: candidate}

	// Seed an already-current active proof so the later signal can only be
	// caused by closing the shared-domain circuit, not by a new proof.
	if err := monitor.applyObservations(
		ctx, base,
		map[string]health.Observation{candidateID: healthy},
		nil, candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capacityChanges:
	default:
		t.Fatal("initial proof did not signal capacity")
	}

	for _, failedCandidate := range []string{"failed-a", "failed-b", "failed-c"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, candidate.FailureDomain, failedCandidate, base.Add(time.Second),
		); err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 || states[0].OpenUntil.IsZero() {
		t.Fatalf("domain did not open: states=%+v err=%v", states, err)
	}

	if err := monitor.applyObservations(
		ctx, base.Add(2*time.Second),
		map[string]health.Observation{candidateID: healthy},
		nil, candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	states, err = database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 || states[0].FailureCount != 0 ||
		!states[0].OpenUntil.IsZero() || states[0].CanaryCandidate != "" {
		t.Fatalf("healthy active proof did not close domain: states=%+v err=%v",
			states, err)
	}
	select {
	case <-capacityChanges:
	default:
		t.Fatal("closed domain did not signal capacity")
	}
}

func TestActiveMonitorQuarantinedVLESSSuccessDoesNotCloseDomain(t *testing.T) {
	ctx := context.Background()
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	base := time.Unix(1_800_000_000, 0)
	monitor := ActiveMonitor{Store: database}
	candidateByID := map[string]store.Candidate{candidateID: candidate}

	for _, failedCandidate := range []string{"failed-a", "failed-b", "failed-c"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, candidate.FailureDomain, failedCandidate, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := monitor.applyObservations(
		ctx, base.Add(time.Second),
		map[string]health.Observation{candidateID: {}},
		nil, candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	if err := monitor.applyObservations(
		ctx, base.Add(2*time.Second),
		map[string]health.Observation{candidateID: {
			PrimaryOK: true, ConfirmationOK: true,
		}},
		nil, candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("single recovery unexpectedly restored candidate: %+v", rows)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 || states[0].FailureCount == 0 ||
		states[0].OpenUntil.IsZero() {
		t.Fatalf("quarantined success closed domain: states=%+v err=%v", states, err)
	}
}

func TestActiveMonitorRollsBackDomainEvidenceWhenUnavailabilityWriteFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "candidate", Fingerprint: "candidate",
		Payload:       "vless://candidate@example.net:443?security=tls",
		FailureDomain: "domain-hash",
	}}); err != nil {
		t.Fatal(err)
	}
	candidateRows, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidateRows) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidateRows, err)
	}
	candidate := candidateRows[0]
	now := time.Unix(1_800_000_000, 0)
	healthy := store.CandidateHealth{
		CandidateID: candidate.ID, Score: 95, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now.Add(-time.Minute),
	}
	if err := database.SaveCandidateHealth(ctx, healthy); err != nil {
		t.Fatal(err)
	}

	failureDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = failureDB.Close() })
	if _, err := failureDB.Exec(`
		CREATE TRIGGER reject_active_unavailability
		BEFORE INSERT ON candidate_probe_state
		BEGIN
		  SELECT RAISE(ABORT, 'injected candidate-state failure');
		END
	`); err != nil {
		t.Fatal(err)
	}
	monitor := ActiveMonitor{Store: database}
	observations := map[string]health.Observation{candidate.ID: {}}
	healthByID := map[string]store.CandidateHealth{candidate.ID: healthy}
	candidateByID := map[string]store.Candidate{candidate.ID: candidate}
	if err := monitor.applyObservations(
		ctx, now, observations, healthByID, candidateByID,
	); err == nil {
		t.Fatal("injected candidate-state write failure was not returned")
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 0 {
		t.Fatalf("failed transition committed domain evidence: states=%+v err=%v", states, err)
	}
	healthRows := mustCandidateHealth(t, database)
	if len(healthRows) != 1 || !healthRows[0].Available {
		t.Fatalf("failed transition committed unavailability: %+v", healthRows)
	}

	if _, err := failureDB.Exec(`DROP TRIGGER reject_active_unavailability`); err != nil {
		t.Fatal(err)
	}
	if err := monitor.applyObservations(
		ctx, now.Add(time.Second), observations, healthByID, candidateByID,
	); err != nil {
		t.Fatal(err)
	}
	states, err = database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 || states[0].FailureCount != 1 ||
		!states[0].OpenUntil.IsZero() {
		t.Fatalf("retry overcounted domain evidence: states=%+v err=%v", states, err)
	}
	healthRows = mustCandidateHealth(t, database)
	if len(healthRows) != 1 || healthRows[0].Available {
		t.Fatalf("retry did not commit unavailability: %+v", healthRows)
	}
}

func TestActiveMonitorDoesNotRecordTorHardFailureAsDomainEvidence(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor",
		Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}})
	candidate := candidates["tor"]
	candidate.FailureDomain = "must-not-record"
	now := time.Unix(1_800_000_000, 0)
	monitor := ActiveMonitor{Store: database}
	if err := monitor.applyObservations(
		ctx, now,
		map[string]health.Observation{candidate.ID: {}},
		map[string]store.CandidateHealth{candidate.ID: {
			CandidateID: candidate.ID, Score: 95, TCPQualified: true,
			Available: true, UpdatedAt: now.Add(-time.Minute),
		}},
		map[string]store.Candidate{candidate.ID: candidate},
	); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("Tor failure recorded domain evidence: %+v", states)
	}
}

func TestActiveMonitorRequiresQuarantineAndThreeRecoveries(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	now := time.Unix(1_800_000_000, 0)
	observation := health.Observation{}
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(context.Context, []qualifier.Input) []qualifier.ActiveResult {
			return []qualifier.ActiveResult{{CandidateID: candidateID, Observation: observation}}
		}),
		Clock: fixedActiveMonitorClock{now: now},
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	observation = health.Observation{PrimaryOK: true, ConfirmationOK: true}
	for index := 1; index <= 3; index++ {
		at := now.Add(time.Duration(index) * time.Minute)
		monitor.Clock = fixedActiveMonitorClock{now: at}
		if err := monitor.Run(context.Background(), at); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := database.ListCandidateHealth(context.Background())
	if rows[0].Available {
		t.Fatal("candidate recovered before quarantine elapsed")
	}
	monitor.Clock = fixedActiveMonitorClock{now: now.Add(5 * time.Minute)}
	if err := monitor.Run(context.Background(), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, _ = database.ListCandidateHealth(context.Background())
	if !rows[0].Available {
		t.Fatal("candidate did not recover after quarantine and three successful probes")
	}
}

func TestActiveMonitorDoesNotRecoverGateFailedCandidate(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	now := time.Unix(1_800_000_000, 0)
	_ = database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidateID, Score: 20, TCPQualified: false, UDPQualified: false, Available: false, UpdatedAt: now,
	})
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(context.Context, []qualifier.Input) []qualifier.ActiveResult {
			return []qualifier.ActiveResult{{CandidateID: candidateID, Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true}}}
		}),
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListCandidateHealth(context.Background())
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("active liveness bypassed service gates: %+v", rows)
	}
}

func TestActiveMonitorObservesAssignedDrainingCandidate(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates[0]
	if err := database.ReplaceCandidates(
		context.Background(),
		candidate.SourceID,
		[]store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
			Payload: "vless://replacement@example.net:443?security=tls",
		}},
		15*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	var observed []string
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(
			_ context.Context,
			inputs []qualifier.Input,
		) []qualifier.ActiveResult {
			results := make([]qualifier.ActiveResult, 0, len(inputs))
			for _, input := range inputs {
				observed = append(observed, input.ID)
				results = append(results, qualifier.ActiveResult{
					CandidateID: input.ID,
					Observation: health.Observation{
						PrimaryOK: true, ConfirmationOK: true,
					},
				})
			}
			return results
		}),
	}
	if err := monitor.Run(
		context.Background(), time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0] != candidateID {
		t.Fatalf("observed=%v, want assigned draining %s", observed, candidateID)
	}
}

func TestActiveMonitorRejectsDrainingResultAfterAssignmentClears(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation health.Observation
	}{
		{
			name: "success",
			observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			},
		},
		{name: "hard failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidateID := activeMonitorStore(t)
			candidates, err := database.ListCandidates(ctx, "")
			if err != nil || len(candidates) != 1 {
				t.Fatalf("candidates=%+v err=%v", candidates, err)
			}
			candidate := candidates[0]
			before := mustCandidateHealth(t, database)[0]
			agent := newConfigurableBlockingActiveAgent(test.observation)
			trigger := make(chan struct{}, 1)
			monitor := ActiveMonitor{
				Store: database, Agent: agent, Trigger: trigger,
			}
			done := make(chan error, 1)
			go func() {
				done <- monitor.Run(ctx, time.Unix(1_800_000_000, 0))
			}()
			agent.waitStarted(t)
			if err := database.ReplaceCandidates(
				ctx,
				candidate.SourceID,
				[]store.CandidateInput{{
					Kind: sources.KindVLESS, Label: "replacement",
					Fingerprint: "replacement",
					Payload:     "vless://replacement@example.net:443?security=tls",
				}},
			); err != nil {
				t.Fatal(err)
			}
			if err := database.SetAssignment(ctx, store.AssignmentRecord{
				ClientID: "client", TCPSince: before.UpdatedAt,
				UDPSince: before.UpdatedAt,
			}); err != nil {
				t.Fatal(err)
			}
			close(agent.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			afterRows := mustCandidateHealth(t, database)
			for _, after := range afterRows {
				if after.CandidateID == candidateID &&
					(!after.UpdatedAt.Equal(before.UpdatedAt) ||
						after.Available != before.Available) {
					t.Fatalf("stale draining result changed health: before=%+v after=%+v",
						before, after)
				}
			}
			domains, err := database.ListFailureDomainStates(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(domains) != 0 {
				t.Fatalf("stale draining hard failure wrote domain evidence: %+v",
					domains)
			}
			select {
			case <-trigger:
				t.Fatal("stale draining result signaled placement")
			default:
			}
		})
	}
}

type configurableBlockingActiveAgent struct {
	observation health.Observation
	started     chan struct{}
	release     chan struct{}
}

func newConfigurableBlockingActiveAgent(
	observation health.Observation,
) *configurableBlockingActiveAgent {
	return &configurableBlockingActiveAgent{
		observation: observation,
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (agent *configurableBlockingActiveAgent) ProbeActive(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	close(agent.started)
	select {
	case <-agent.release:
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Observation: agent.observation,
	}, nil
}

func (agent *configurableBlockingActiveAgent) ProbeActiveCritical(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.ProbeActive(ctx, request)
}

func (agent *configurableBlockingActiveAgent) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("active probe did not start")
	}
}

func TestActiveMonitorDoesNotQuarantineOnProbeInfrastructureFailure(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	monitor := ActiveMonitor{
		Store: database,
		VLESS: activeVLESSFunc(func(context.Context, []qualifier.Input) []qualifier.ActiveResult {
			return []qualifier.ActiveResult{{CandidateID: candidateID, Err: errors.New("probe Xray API unavailable")}}
		}),
	}
	if err := monitor.Run(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListCandidateHealth(context.Background())
	if len(rows) != 1 || !rows[0].Available {
		t.Fatalf("probe infrastructure failure quarantined candidate: %+v", rows)
	}
}

func activeMonitorStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	_ = database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "v", Fingerprint: "v",
			Payload:       "vless://id@example.net:443?security=tls",
			FailureDomain: "domain-hash",
		},
	})
	candidates, _ := database.ListCandidates(context.Background(), "")
	candidateID := candidates[0].ID
	_ = database.PutClient(context.Background(), store.ClientRecord{ID: "client", Name: "client", Address: "10.44.0.2/32", PublicKey: "key"}, "config")
	_ = database.SetAssignment(context.Background(), store.AssignmentRecord{ClientID: "client", TCPOutbound: candidateID, UDPOutbound: candidateID, TCPSince: time.Now(), UDPSince: time.Now()})
	_ = database.SaveCandidateHealth(context.Background(), store.CandidateHealth{CandidateID: candidateID, Score: 95, TCPQualified: true, UDPQualified: true, Available: true, UpdatedAt: time.Now()})
	return database, candidateID
}

type activeVLESSFunc func(context.Context, []qualifier.Input) []qualifier.ActiveResult

func (function activeVLESSFunc) Observe(ctx context.Context, inputs []qualifier.Input) []qualifier.ActiveResult {
	return function(ctx, inputs)
}
