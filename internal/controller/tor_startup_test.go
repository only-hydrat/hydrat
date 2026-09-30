package controller

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestEngineStartupReplacesMissingTorProfile(t *testing.T) {
	now := time.Now()
	engine, warm, torID := missingTorStartupFixture(t, now, true)
	engine.activeCriticalRouteLimit = 16
	warm.Store(false)
	beforeAssignments, err := engine.store.ListAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.NormalizeActiveCriticalRoutes(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatalf("missing Tor profile prevented qualified VLESS replacement: %v", err)
	}
	assignments, err := engine.store.ListAssignments(context.Background())
	if err != nil || len(assignments) != 1 {
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
	if assignments[0].TCPOutbound == "" || assignments[0].TCPOutbound == torID {
		t.Fatalf("missing Tor primary retained: %+v", assignments[0])
	}
	if assignments[0].UDPOutbound != beforeAssignments[0].UDPOutbound {
		t.Fatalf("Tor TCP recovery changed serving UDP: before=%+v after=%+v", beforeAssignments, assignments)
	}
	state, err := engine.store.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := decodePersistedPlan("applied", state.AppliedGeneration, state.AppliedPlan)
	if err != nil || planReferencesTor(plan) || plan.Clients[0].BlockTCP {
		t.Fatalf("replacement plan=%+v err=%v", plan, err)
	}
}

func TestEngineMissingTorWithoutReplacementPreservesAppliedState(t *testing.T) {
	now := time.Now()
	engine, warm, _ := missingTorStartupFixture(t, now, false)
	before, err := engine.store.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	warm.Store(false)
	err = engine.CycleForReason(context.Background(), now.Add(time.Second), PlacementStartupNormalization)
	if err == nil || !retryablePlacementError(err) || !recoverableCapacityNormalizationError(err) {
		t.Fatalf("missing runtime profile must enter recoverable startup, got %v", err)
	}
	after, err := engine.store.LoadPlanState(context.Background())
	if err != nil || before.DesiredGeneration != after.DesiredGeneration || before.AppliedGeneration != after.AppliedGeneration || !bytes.Equal(before.AppliedPlan, after.AppliedPlan) {
		t.Fatalf("missing profile replaced durable plan: before=%+v after=%+v err=%v", before, after, err)
	}
	warm.Store(true)
	if err := engine.CycleForReason(context.Background(), now.Add(2*time.Second), PlacementStartupNormalization); err != nil {
		t.Fatalf("profile return did not recover placement: %v", err)
	}
}

func TestRuntimeMissingTorProfileKeepsRecoveryWorkersAlive(t *testing.T) {
	engine, warm, _ := missingTorStartupFixture(t, time.Now(), false)
	warm.Store(false)
	var repairAllowed atomic.Bool
	unready := make(chan error, 1)
	ready := make(chan struct{}, 4)
	qualified := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cycle := func(ctx context.Context, at time.Time) error {
		return engine.CycleForReason(ctx, at, PlacementStartupNormalization)
	}
	runtime := Runtime{
		StartupNormalize: cycle,
		ProfileRepair: func(context.Context, time.Time) (bool, error) {
			if repairAllowed.Load() {
				warm.Store(true)
				return true, nil
			}
			return false, nil
		},
		Qualify:                    func(context.Context, time.Time) error { qualified <- struct{}{}; return nil },
		Place:                      func(ctx context.Context, at time.Time, _ PlacementReason) error { return cycle(ctx, at) },
		Unready:                    func(err error) { unready <- err },
		Ready:                      func() { ready <- struct{}{} },
		ProfileRepairInterval:      10 * time.Millisecond,
		PlacementRetryBase:         10 * time.Millisecond,
		PlacementRetryMax:          20 * time.Millisecond,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             time.Hour,
		NormalizationRetryInterval: time.Hour,
	}
	go func() { done <- runtime.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("runtime did not stop")
		}
	})
	select {
	case <-unready:
	case err := <-done:
		done <- err
		t.Fatalf("runtime exited instead of recovering: %v", err)
	case <-time.After(time.Second):
		t.Fatal("readiness did not report missing profile")
	}
	select {
	case <-qualified:
	case err := <-done:
		done <- err
		t.Fatalf("runtime stopped recovery workers: %v", err)
	case <-time.After(time.Second):
		t.Fatal("qualification did not run while Tor was unavailable")
	}
	select {
	case <-ready:
		t.Fatal("runtime marked ready before Tor recovery")
	default:
	}
	repairAllowed.Store(true)
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatalf("runtime exited during repair: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not recover after profile repair")
	}
}

func missingTorStartupFixture(t *testing.T, now time.Time, replacements bool) (*Engine, *atomic.Bool, string) {
	t.Helper()
	specs := []engineQoECandidateSpec{{name: "tor", kind: sources.KindTorBridge, score: 100, tcp: true, failureDomain: "tor-domain"}}
	if replacements {
		specs = append(specs, engineQoECandidateSpec{name: "vless-a", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "vless-a"}, engineQoECandidateSpec{name: "vless-b", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "vless-b"})
	}
	database, candidates := newEngineQoEFixture(t, now, specs)
	qualifyEngineReserveCandidates(t, database, now, candidates)
	torID := candidates["tor"].ID
	udpID := ""
	if replacements {
		udpID = candidates["vless-a"].ID
	}
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, torID, udpID)
	warm := &atomic.Bool{}
	warm.Store(true)
	profiles := profileProviderFunc(func() []torpool.Profile {
		if !warm.Load() {
			return nil
		}
		return []torpool.Profile{{Slot: 0, CandidateID: torID, SocksAddr: "127.0.0.1:19050", Role: "warm"}}
	})
	engine := NewEngine(database, &engineAgent{}, profiles, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute))
	if err := engine.CycleForReason(context.Background(), now, PlacementStartupNormalization); err != nil {
		t.Fatal(err)
	}
	return engine, warm, torID
}
