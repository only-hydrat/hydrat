package controller

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestRecoveredPrimarySurvivesWorkingPoolPromotionAndPeriodicDwell(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "a", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"},
		{name: "b", kind: sources.KindVLESS, score: 95, tcp: true, udp: true, failureDomain: "b"},
		{name: "c", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "c"},
		{name: "d", kind: sources.KindVLESS, score: 85, tcp: true, udp: true, failureDomain: "d"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["a"].ID, candidates["a"].ID)
	agent := &scopedRecoveryRecordingAgent{}
	newEngine := func() *Engine {
		return NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(3))
	}
	engine := newEngine()
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	fail := func(candidate store.Candidate, at time.Time) {
		t.Helper()
		reservation, err := database.ReserveCandidateObservation(ctx, candidate, store.ObservationActive)
		if err != nil {
			t.Fatal(err)
		}
		if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, candidate, reservation, at); err != nil || !commit.Accepted {
			t.Fatalf("failure commit=%+v err=%v", commit, err)
		}
		if err := engine.CycleForReason(ctx, at, PlacementHardFailure); err != nil {
			t.Fatal(err)
		}
	}
	fail(candidates["a"], now.Add(time.Second))
	recovered := engineQoEAssignment(t, database, "alice")
	if recovered.TCPOutbound == candidates["a"].ID || recovered.TCPOutbound == "" {
		t.Fatal("fixture did not recover A")
	}
	active := []string{}
	for _, candidate := range candidates {
		if candidate.ID != candidates["a"].ID && candidate.ID != recovered.TCPOutbound {
			active = append(active, candidate.Fingerprint)
		}
	}
	// Still qualified and serving, but not a member of the new working pool.
	if err := database.ReplaceWorkingPool(ctx, active, nil); err != nil {
		t.Fatal(err)
	}
	targets, err := engine.ActiveTargets(ctx, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	monitored := false
	for _, target := range targets {
		monitored = monitored || target.Candidate.ID == recovered.TCPOutbound
	}
	if !monitored {
		t.Fatal("reserve-repair proof set dropped the recovered primary outside working pool")
	}
	for i, reason := range []PlacementReason{PlacementPromotion, PlacementPeriodic, PlacementStartupNormalization, PlacementClientLifecycle} {
		if i == 2 {
			engine = newEngine()
		}
		if err := engine.CycleForReason(ctx, now.Add(time.Duration(i+2)*time.Second), reason); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
		got := engineQoEAssignment(t, database, "alice")
		if got.TCPOutbound != recovered.TCPOutbound || got.UDPOutbound != recovered.UDPOutbound || !got.TCPSince.Equal(recovered.TCPSince) || !got.UDPSince.Equal(recovered.UDPSince) {
			t.Fatalf("%s moved healthy recovered route: before=%+v after=%+v", reason, recovered, got)
		}
		if err := engine.CapacityReady(ctx, now.Add(time.Duration(i+2)*time.Second)); err != nil {
			t.Fatalf("%s did not repair reserves: %v", reason, err)
		}
	}
	if len(agent.scopes) != 1 {
		t.Fatalf("reserve repair reset TCP: %+v", agent.scopes)
	}
	// The stability preference must not strand the client on a second failure.
	fail(engineCandidateByID(t, candidates, recovered.TCPOutbound), now.Add(7*time.Second))
	if after := engineQoEAssignment(t, database, "alice"); after.TCPOutbound == recovered.TCPOutbound {
		t.Fatal("dwell blocked repeated hard failure")
	}
}

func TestCoverageWitnessRetainsAdmissibleAppliedReserve(t *testing.T) {
	now := time.Unix(1900000000, 0)
	candidates := []scheduler.Candidate{
		{ID: "p", Protocol: scheduler.ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "installed", Protocol: scheduler.ProtocolVLESS, Score: 80, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "rank-winner", Protocol: scheduler.ProtocolVLESS, Score: 1000, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
	}
	clients := []scheduler.Client{{ID: "alice", PreserveTCP: true, PreserveUDP: true,
		Assignment:     scheduler.Assignment{TCP: "p", UDP: "p", TCPSince: now, UDPSince: now},
		AppliedReserve: scheduler.ReserveSelection{TCP: "installed", UDP: "installed"}}}
	covered, err := evaluateCriticalCoverage(context.Background(), now, scheduler.New(scheduler.PolicyDefaults()), clients, candidates, criticalCoverageRequirements(clients))
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	for _, id := range covered.witnessIDs {
		installed = installed || id == "installed"
		if id == "rank-winner" {
			t.Fatal("coverage simulated replacing an admissible installed reserve")
		}
	}
	if !installed {
		t.Fatal("coverage witness omitted installed reserve")
	}
}
