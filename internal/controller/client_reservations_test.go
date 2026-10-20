package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestDormantDevicesShareBootstrapAndRevalidateOnReturn(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	db, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "a", kind: sources.KindVLESS, score: 95, tcp: true, udp: true, failureDomain: "a"},
		{name: "b", kind: sources.KindVLESS, score: 94, tcp: true, udp: true, failureDomain: "b"},
		{name: "c", kind: sources.KindVLESS, score: 93, tcp: true, udp: true, failureDomain: "c"},
	})
	qualifyEngineReserveCandidates(t, db, now, candidates)
	for i, name := range []string{"a", "b", "c"} {
		putEngineQoEClient(t, db, name, fmt.Sprintf("10.44.0.%d/32", i+2), now, false, candidates[name].ID, candidates[name].ID)
	}
	agent := &engineAgent{}
	engine := NewEngine(db, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16), WithClientReservations())
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	assignments, _ := db.ListAssignments(ctx)
	for _, assignment := range assignments {
		if assignment.TCPOutbound != assignments[0].TCPOutbound {
			t.Fatalf("idle clients retained personal routes: %+v", assignments)
		}
	}
	for _, route := range agent.plans[len(agent.plans)-1].Clients {
		if !route.Dormant {
			t.Fatalf("idle lease persisted: %+v", route)
		}
	}
	if err := engine.CapacityReady(ctx, now); err != nil {
		t.Fatalf("shared bootstrap not ready: %v", err)
	}
	old := assignments[0].TCPOutbound
	if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: old, Available: false, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Cycle(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assignments, _ = db.ListAssignments(ctx)
	for _, assignment := range assignments {
		if assignment.TCPOutbound == old || assignment.TCPOutbound == "" {
			t.Fatalf("unavailable cached route survived: %+v", assignments)
		}
	}
	if err := engine.CapacityReady(ctx, now.Add(time.Second)); err != nil {
		t.Fatalf("replacement bootstrap not ready: %v", err)
	}
	if err := db.RecordActivity(ctx, "b", now, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordActivity(ctx, "b", now.Add(time.Second), 100, 100); err != nil {
		t.Fatal(err)
	}
	changed, err := engine.ReservationChanges(ctx, now.Add(time.Second))
	if err != nil || !changed {
		t.Fatalf("return not detected: %v %v", changed, err)
	}
	if err := engine.CycleForReason(ctx, now.Add(time.Second), PlacementClientLifecycle); err != nil {
		t.Fatal(err)
	}
	for _, route := range agent.plans[len(agent.plans)-1].Clients {
		if route.ClientID == "b" && route.Dormant {
			t.Fatal("returning client remained dormant")
		}
	}
}

func TestReturningDeviceDoesNotReuseLostBootstrapWithoutEligibleRoute(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	db, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "a", kind: sources.KindVLESS, score: 95, tcp: true, udp: true, failureDomain: "a"},
		{name: "b", kind: sources.KindVLESS, score: 94, tcp: true, udp: true, failureDomain: "b"},
	})
	qualifyEngineReserveCandidates(t, db, now, candidates)
	putEngineQoEClient(t, db, "idle", "10.44.0.2/32", now, false, candidates["a"].ID, candidates["a"].ID)
	agent := &engineAgent{}
	engine := NewEngine(db, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16), WithClientReservations())
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: candidate.ID, Available: false, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecordActivity(ctx, "idle", now, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordActivity(ctx, "idle", now.Add(time.Second), 100, 100); err != nil {
		t.Fatal(err)
	}
	if err := engine.CycleForReason(ctx, now.Add(time.Second), PlacementClientLifecycle); err != nil {
		t.Fatal(err)
	}
	route := agent.plans[len(agent.plans)-1].Clients[0]
	if route.Dormant || !route.BlockTCP || !route.BlockUDP || route.TCPOutbound != "" || route.UDPOutbound != "" {
		t.Fatalf("return reused an unqualified cached route: %+v", route)
	}
	if err := engine.CapacityReady(ctx, now.Add(time.Second)); err == nil {
		t.Fatal("missing route incorrectly reported ready")
	}
}

type blockingActivityAgent struct {
	engineAgent
	started chan struct{}
	release chan struct{}
}

func (agent *blockingActivityAgent) Activity(ctx context.Context) ([]wireguard.PeerActivity, error) {
	select {
	case agent.started <- struct{}{}:
	default:
	}
	select {
	case <-agent.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestActivityAdmissionHonorsCancelledContext(t *testing.T) {
	db, _ := newEngineQoEFixture(t, time.Now(), []engineQoECandidateSpec{{name: "test", kind: sources.KindVLESS}})
	agent := &blockingActivityAgent{started: make(chan struct{}, 1), release: make(chan struct{})}
	engine := NewEngine(db, agent, nil, nil, nil)
	first := make(chan error, 1)
	go func() { first <- engine.SyncActivity(context.Background(), time.Now()) }()
	<-agent.started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second := make(chan error, 1)
	go func() { second <- engine.SyncActivity(ctx, time.Now()) }()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err=%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("cancelled poll blocked behind another activity request")
	}
	close(agent.release)
	<-first
}

func TestRuntimeReservationWakeDoesNotWaitForPeriodicPlacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	placed := make(chan PlacementReason, 4)
	runtime := Runtime{
		Reservations:        func(context.Context, time.Time) (bool, error) { return true, nil },
		ReservationInterval: 10 * time.Millisecond,
		Place:               func(_ context.Context, _ time.Time, reason PlacementReason) error { placed <- reason; return nil },
		PlacementInterval:   time.Hour, ActiveInterval: time.Hour, QualificationInterval: time.Hour, SourceRefreshInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case reason := <-placed:
		if reason != PlacementClientLifecycle {
			t.Fatalf("reason=%s", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("return waited for periodic placement")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reservation worker did not stop")
	}
}
