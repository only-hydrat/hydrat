package controller

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"slices"
	"testing"
	"time"
)

func TestOnionOnlyProfilesReceiveActiveMonitoring(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	db, cs := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "vless-main", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"},
		{name: "vless-reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "b"},
		{name: "tor-main", kind: sources.KindTorBridge, score: 10, tcp: true, failureDomain: "c"},
		{name: "tor-reserve", kind: sources.KindTorBridge, score: 9, tcp: true, failureDomain: "d"},
	})
	qualifyEngineReserveCandidates(t, db, now, cs)
	putEngineQoEClient(t, db, "alice", "10.44.0.2/32", now, true, cs["vless-main"].ID, cs["vless-main"].ID)
	if err := db.SetOnionEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	profiles := []torpool.Profile{{Slot: 0, CandidateID: cs["tor-main"].ID, Role: "warm", SocksAddr: "127.0.0.1:19050", OnionReady: true}, {Slot: 1, CandidateID: cs["tor-reserve"].ID, Role: "warm", SocksAddr: "127.0.0.1:19051", OnionReady: true}}
	e := NewEngine(db, &engineAgent{}, profileProviderFunc(func() []torpool.Profile { return profiles }), scheduler.New(scheduler.PolicyDefaults()), []byte("test"), WithQoEEnabled(false))
	if err := e.Cycle(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	state, err := db.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	route := decodeClientRoutes(state.AppliedPlan)["alice"]
	if route.OnionOutbound == "" || route.OnionReserveOutbound == "" {
		t.Fatal("setup missing onion routes")
	}
	if candidateIDFromHandler(route.TCPOutbound, "alice") == cs["tor-main"].ID || candidateIDFromHandler(route.TCPOutbound, "alice") == cs["tor-reserve"].ID {
		t.Fatal("setup selected Tor for ordinary TCP")
	}
	targets, err := e.ActiveTargets(ctx, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tor-main", "tor-reserve"} {
		found := false
		for _, target := range targets {
			if target.Candidate.ID == cs[name].ID && target.Role == ActiveTargetProspective {
				found = true
			}
		}
		if !found {
			t.Errorf("assigned onion profile %s is not an active target in the bounded noncritical lane (targets=%v)", name, targets)
		}
	}
	// The ordinary critical budget is already full. Onion checks must still
	// run, without changing that budget or taking the critical RPC lane.
	agent := &laneRecordingActiveAgent{}
	m := &ActiveMonitor{Store: db, Agent: agent, Targets: e, Slots: 2, CriticalLimit: 1, Clock: fixedActiveMonitorClock{now: now.Add(4 * time.Second)}}
	if err := m.Run(ctx, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(agent.critical, cs["vless-main"].ID) {
		t.Fatal("ordinary primary lost its critical probe")
	}
	for _, name := range []string{"tor-main", "tor-reserve"} {
		if !slices.Contains(agent.background, cs[name].ID) || slices.Contains(agent.critical, cs[name].ID) {
			t.Fatalf("onion profile %s probed in wrong lane", name)
		}
	}
	// A stale cached target snapshot must also pick up the applied onion
	// generation before the next asynchronous target refresh completes.
	ordinary, err := e.ordinaryActiveTargets(ctx, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := m.reconcileAppliedTargetGeneration(ctx, activeTargetSnapshot{targets: ordinary, appliedGeneration: state.AppliedGeneration - 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tor-main", "tor-reserve"} {
		if !slices.ContainsFunc(reconciled.targets, func(target ActiveTarget) bool { return target.Candidate.ID == cs[name].ID }) {
			t.Fatalf("cached snapshot missed %s", name)
		}
	}
	// A confirmed onion failure should cause onion failover, while healthy
	// ordinary TCP/UDP assignments stay on their existing candidate.
	failed := candidateIDFromHandler(route.OnionOutbound, "onion-alice")
	m.Agent = activeProbeAgentFunc(func(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
		observation := health.Observation{PrimaryOK: true, ConfirmationOK: true}
		if request.CandidateID == failed {
			observation = health.Observation{}
		}
		return agentapi.ProbeResponse{Observation: observation}, nil
	})
	for i := 5; i <= 7; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		m.Clock = fixedActiveMonitorClock{now: at}
		if err := m.Run(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Cycle(ctx, now.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	after, err := db.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := decodeClientRoutes(after.AppliedPlan)["alice"]
	if next.OnionOutbound != route.OnionReserveOutbound {
		t.Fatalf("onion did not fail over: before=%+v after=%+v", route, next)
	}
	if next.TCPOutbound != route.TCPOutbound || next.UDPOutbound != route.UDPOutbound {
		t.Fatal("onion failure changed ordinary assignments")
	}
}
