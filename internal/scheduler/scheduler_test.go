package scheduler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestReserveSelectorPrefersDistinctVLESSFailureDomains(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{ID: "primary", Protocol: ProtocolVLESS, RouteKey: "route-primary", FailureDomain: "domain-a", Score: 100, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "same-domain", Protocol: ProtocolVLESS, RouteKey: "route-same", FailureDomain: "domain-a", Score: 200, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "diverse", Protocol: ProtocolVLESS, RouteKey: "route-diverse", FailureDomain: "domain-b", Score: 10, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
	}
	selection := New(PolicyDefaults()).SelectReserves(
		now, "alice", Assignment{TCP: "primary", UDP: "primary"}, candidates,
	)
	if selection.TCP != "diverse" || selection.UDP != "diverse" {
		t.Fatalf("reserves=%+v want diverse VLESS", selection)
	}
}

func TestReserveSelectorPrefersStableCandidateOverLearningCandidate(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{ID: "primary", Protocol: ProtocolVLESS, FailureDomain: "domain-a",
			Score: 100, TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, QoETracked: true,
			QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEEffective: time.Second},
		{ID: "learning", Protocol: ProtocolVLESS, FailureDomain: "domain-b",
			Score: 100, TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
			QoETracked: true, QoEStatus: qoe.StatusLearning},
		{ID: "stable", Protocol: ProtocolVLESS, FailureDomain: "domain-c",
			Score: 90, TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, QoETracked: true,
			QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEEffective: time.Second},
	}
	selection := New(PolicyDefaults()).SelectReserves(
		now, "alice", Assignment{TCP: "primary", UDP: "primary"}, candidates,
	)
	if selection.TCP != "stable" || selection.UDP != "stable" {
		t.Fatalf("reserves=%+v", selection)
	}
}

func TestAppliedReserveStaysReadyWhenOnlyQoEPreferenceAges(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{ID: "primary", Protocol: ProtocolVLESS, FailureDomain: "primary", Score: 100, TCPQualified: true, UDPQualified: true},
		{ID: "applied", Protocol: ProtocolVLESS, FailureDomain: "applied", Score: 70, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, QoETracked: true, QoEStatus: qoe.StatusHealthy},
		{ID: "preferred", Protocol: ProtocolVLESS, FailureDomain: "preferred", Score: 100, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, QoETracked: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEEffective: time.Second},
	}
	placement := New(PolicyDefaults())
	assignment := Assignment{TCP: "primary", UDP: "primary"}
	if selected := placement.SelectReserves(now, "alice", assignment, candidates); selected.TCP != "preferred" || selected.UDP != "preferred" {
		t.Fatalf("new reserve preference=%+v", selected)
	}
	valid, err := placement.ValidateReserveSelectionContext(context.Background(), now, "alice", assignment, ReserveSelection{TCP: "applied", UDP: "applied"}, candidates)
	if err != nil || !valid.TCP || !valid.UDP {
		t.Fatalf("active-proven applied reserve rejected after QoE sample aged: valid=%+v err=%v", valid, err)
	}
}

func TestValidateReserveSelectionAcceptsEligibleNonWinner(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{
			ID: "primary", Protocol: ProtocolVLESS, RouteKey: "route-primary",
			FailureDomain: "domain-primary", Score: 100,
			TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
		},
		{
			ID: "reserve-a", Protocol: ProtocolVLESS, RouteKey: "route-a",
			FailureDomain: "domain-a", Score: 100,
			TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
		},
		{
			ID: "reserve-b", Protocol: ProtocolVLESS, RouteKey: "route-b",
			FailureDomain: "domain-b", Score: 100,
			TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
		},
	}
	assignment := Assignment{TCP: "primary", UDP: "primary"}
	var clientID string
	var winner ReserveSelection
	var placement *Scheduler
	for index := 0; index < 1_000; index++ {
		candidateClientID := fmt.Sprintf("client-%d", index)
		candidateScheduler := New(PolicyDefaults())
		selected := candidateScheduler.SelectReserves(
			now, candidateClientID, assignment, candidates,
		)
		if selected.TCP == "reserve-a" && selected.UDP == "reserve-a" {
			clientID = candidateClientID
			winner = selected
			placement = candidateScheduler
			break
		}
	}
	if clientID == "" {
		t.Fatal("no client ID selected reserve-a as the deterministic TCP/UDP winner")
	}

	versionBefore := placement.version
	validation, err := placement.ValidateReserveSelectionContext(
		context.Background(), now, clientID, assignment,
		ReserveSelection{TCP: "reserve-b", UDP: "reserve-b"}, candidates,
	)
	if err != nil || !validation.TCP || !validation.UDP {
		t.Fatalf("eligible non-winner validation=%+v error=%v", validation, err)
	}
	if placement.version != versionBefore {
		t.Fatalf("validation changed scheduler version: before=%d after=%d", versionBefore, placement.version)
	}
	if selected := placement.SelectReserves(
		now, clientID, assignment, candidates,
	); !reflect.DeepEqual(selected, winner) {
		t.Fatalf("deterministic winner changed: before=%+v after=%+v", winner, selected)
	}
}

func TestValidateReserveSelectionRejectsIneligibleAppliedCandidates(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	primary := Candidate{
		ID: "primary", Protocol: ProtocolVLESS, RouteKey: "route-primary",
		FailureDomain: "domain-primary", Score: 100,
		TCPQualified: true, UDPQualified: true,
	}
	valid := Candidate{
		ID: "valid", Protocol: ProtocolVLESS, RouteKey: "route-valid",
		FailureDomain: "domain-valid", Score: 100,
		TCPQualified: true, UDPQualified: true, ReserveEligible: true,
		ActiveEligible: true, ActiveFresh: true,
	}
	appliedBase := Candidate{
		ID: "applied", Protocol: ProtocolVLESS, RouteKey: "route-applied",
		FailureDomain: "domain-applied", Score: 100,
		TCPQualified: true, UDPQualified: true, ReserveEligible: true,
		ActiveEligible: true, ActiveFresh: true,
	}

	tests := []struct {
		name       string
		change     func(*Candidate)
		exclude    bool
		wantTCP    bool
		wantUDP    bool
		assignment Assignment
		primary    Candidate
		valid      Candidate
	}{
		{name: "below preferred quality tier", change: func(candidate *Candidate) { candidate.Score = 79 }, wantTCP: true, wantUDP: true},
		{name: "same route identity", change: func(candidate *Candidate) { candidate.RouteKey = primary.RouteKey }},
		{name: "not fully qualified", change: func(candidate *Candidate) { candidate.ReserveEligible = false }},
		{name: "failed active proof", change: func(candidate *Candidate) { candidate.ActiveEligible = false }},
		{name: "stale active proof", change: func(candidate *Candidate) { candidate.ActiveFresh = false }},
		{name: "excluded", exclude: true},
		{name: "degraded QoE", change: func(candidate *Candidate) { candidate.QoEStatus = qoe.StatusDegraded }},
		{name: "open circuit", change: func(candidate *Candidate) { candidate.CircuitOpen = true }},
		{name: "retiring", change: func(candidate *Candidate) { candidate.Retiring = true }},
		{
			name:    "not TCP qualified",
			change:  func(candidate *Candidate) { candidate.TCPQualified = false },
			wantUDP: true,
		},
		{
			name:    "not UDP qualified",
			change:  func(candidate *Candidate) { candidate.UDPQualified = false },
			wantTCP: true,
		},
		{
			name: "cold Tor",
			change: func(candidate *Candidate) {
				candidate.Protocol = ProtocolTor
				candidate.ProfileID = "slot-applied"
				candidate.Warm = false
			},
			assignment: Assignment{TCP: "tor-primary", UDP: "tor-primary"},
			primary: Candidate{
				ID: "tor-primary", Protocol: ProtocolTor, ProfileID: "slot-primary",
				FailureDomain: "domain-primary", Score: 100, TCPQualified: true,
			},
			valid: Candidate{
				ID: "valid", Protocol: ProtocolTor, ProfileID: "slot-valid",
				FailureDomain: "domain-valid", Score: 100, TCPQualified: true,
				ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true,
			},
		},
		{
			name:   "weaker primary domain",
			change: func(candidate *Candidate) { candidate.FailureDomain = primary.FailureDomain },
		},
		{
			name: "weaker Tor protocol for VLESS TCP primary",
			change: func(candidate *Candidate) {
				candidate.Protocol = ProtocolTor
				candidate.ProfileID = "slot-applied"
				candidate.Warm = true
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testPrimary := primary
			if test.primary.ID != "" {
				testPrimary = test.primary
			}
			testValid := valid
			if test.valid.ID != "" {
				testValid = test.valid
			}
			assignment := Assignment{TCP: testPrimary.ID, UDP: testPrimary.ID}
			if test.assignment.TCP != "" || test.assignment.UDP != "" {
				assignment = test.assignment
			}
			applied := appliedBase
			if test.change != nil {
				test.change(&applied)
			}
			placement := New(PolicyDefaults())
			if test.exclude {
				placement.Exclude("alice", applied.ID, now.Add(time.Hour))
			}
			validation, err := placement.ValidateReserveSelectionContext(
				context.Background(), now, "alice", assignment,
				ReserveSelection{TCP: applied.ID, UDP: applied.ID},
				[]Candidate{testPrimary, testValid, applied},
			)
			if err != nil {
				t.Fatalf("validation error=%v", err)
			}
			if validation.TCP != test.wantTCP || validation.UDP != test.wantUDP {
				t.Fatalf(
					"validation=%+v want TCP=%t UDP=%t",
					validation, test.wantTCP, test.wantUDP,
				)
			}
		})
	}
}

func TestScheduleContextStopsInsideCandidateLoopsAtDeadline(t *testing.T) {
	placement := New(PolicyDefaults())
	placement.loopHook = func() { time.Sleep(2 * time.Millisecond) }
	candidates := make([]Candidate, 200)
	for index := range candidates {
		candidates[index] = Candidate{
			ID: fmt.Sprintf("candidate-%03d", index), Protocol: ProtocolVLESS,
			TCPQualified: true, UDPQualified: true,
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := placement.ScheduleContext(ctx, time.Now(), []Client{{ID: "alice"}}, candidates)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ScheduleContext error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("ScheduleContext ignored deadline for %s", elapsed)
	}
}

func TestPreviewAndReserveSelectionHonorContextDeadline(t *testing.T) {
	placement := New(PolicyDefaults())
	placement.loopHook = func() { time.Sleep(2 * time.Millisecond) }
	preview := placement.BeginPreview()
	candidates := make([]Candidate, 200)
	for index := range candidates {
		candidates[index] = Candidate{
			ID: fmt.Sprintf("candidate-%03d", index), Protocol: ProtocolVLESS,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true,
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := preview.ScheduleContext(
		ctx, time.Now(), []Client{{ID: "alice"}}, candidates,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Preview.ScheduleContext error=%v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := placement.SelectReservesContext(
		ctx, time.Now(), "alice", Assignment{TCP: candidates[0].ID}, candidates,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SelectReservesContext error=%v", err)
	}
}

func TestReserveSelectorIsStableForIdenticalSemanticInputs(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	assignment := Assignment{TCP: "primary", UDP: "primary"}
	candidates := []Candidate{
		{ID: "primary", Protocol: ProtocolVLESS, FailureDomain: "domain-a", Score: 100, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "one", Protocol: ProtocolVLESS, FailureDomain: "domain-b", Score: 80, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "two", Protocol: ProtocolVLESS, FailureDomain: "domain-c", Score: 80, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
	}
	first := New(PolicyDefaults()).SelectReserves(now, "alice", assignment, candidates)
	reversed := []Candidate{candidates[2], candidates[1], candidates[0]}
	second := New(PolicyDefaults()).SelectReserves(now, "alice", assignment, reversed)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("candidate ordering changed reserves: first=%+v second=%+v", first, second)
	}
}

func TestReserveSelectorAllowsOnlyDistinctLiveWarmTorForTorPrimary(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{ID: "tor-primary", Protocol: ProtocolTor, ProfileID: "slot-1", Score: 100, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
		{ID: "same-profile", Protocol: ProtocolTor, ProfileID: "slot-1", Score: 200, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
		{ID: "retiring", Protocol: ProtocolTor, ProfileID: "slot-2", Score: 190, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true, Retiring: true},
		{ID: "cold", Protocol: ProtocolTor, ProfileID: "slot-3", Score: 180, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "tor-reserve", Protocol: ProtocolTor, ProfileID: "slot-4", Score: 70, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
	}
	selection := New(PolicyDefaults()).SelectReserves(
		now, "alice", Assignment{TCP: "tor-primary"}, candidates,
	)
	if selection.TCP != "tor-reserve" || selection.UDP != "" {
		t.Fatalf("Tor reserves=%+v", selection)
	}
}

func TestEmergencySelectorTreatsTorAsFirstClassTCPRoute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	selection := New(PolicyDefaults()).SelectEmergency(
		now, "alice", "tcp", "failed", []Candidate{
			{ID: "failed", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
				FailureDomain: "domain-a"},
			{ID: "vless", Protocol: ProtocolVLESS, Score: 80, TCPQualified: true,
				ActiveEligible: true, ActiveFresh: true, FailureDomain: "domain-b"},
			{ID: "tor", Protocol: ProtocolTor, Score: 95, TCPQualified: true,
				ActiveEligible: true, ActiveFresh: true, Warm: true, FailureDomain: "domain-c"},
		}, nil, nil,
	)
	if selection != "tor" {
		t.Fatalf("emergency TCP selection=%q want Tor", selection)
	}
}

func TestEmergencySelectorUsesOnlyUDPQualifiedVLESS(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	selection := New(PolicyDefaults()).SelectEmergency(
		now, "alice", "udp", "failed", []Candidate{
			{ID: "failed", Protocol: ProtocolVLESS, Score: 100, UDPQualified: true},
			{ID: "tor", Protocol: ProtocolTor, Score: 100, UDPQualified: true,
				ActiveEligible: true, ActiveFresh: true},
			{ID: "tcp-only", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
				ActiveEligible: true, ActiveFresh: true},
			{ID: "udp", Protocol: ProtocolVLESS, Score: 80, UDPQualified: true,
				ActiveEligible: true, ActiveFresh: true},
		}, nil, nil,
	)
	if selection != "udp" {
		t.Fatalf("emergency UDP selection=%q want VLESS UDP", selection)
	}
}

func TestEmergencySelectorPrefersFreshActiveProof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	selection := New(PolicyDefaults()).SelectEmergency(
		now, "alice", "tcp", "failed", []Candidate{
			{ID: "failed", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
			{ID: "unproved", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
			{ID: "proved", Protocol: ProtocolVLESS, Score: 70, TCPQualified: true,
				ActiveEligible: true, ActiveFresh: true},
		}, nil, nil,
	)
	if selection != "proved" {
		t.Fatalf("emergency selection=%q want fresh proof", selection)
	}
}

func TestReserveSelectorAvoidsPrimaryDomainWhenOnlyTorDiversityExists(t *testing.T) {
	scheduler := New(PolicyDefaults())
	candidates := []Candidate{
		{ID: "vless-primary", Protocol: ProtocolVLESS, FailureDomain: "domain-a", Score: 100, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "same-domain-tor", Protocol: ProtocolTor, FailureDomain: "domain-a", Score: 80, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
		{ID: "distinct-domain-tor", Protocol: ProtocolTor, FailureDomain: "domain-b", Score: 80, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
	}
	for index := 0; index < 100; index++ {
		selected := scheduler.SelectReserves(
			time.Unix(1_900_000_000, 0), fmt.Sprintf("client-%d", index),
			Assignment{TCP: "vless-primary"}, candidates,
		)
		if selected.TCP != "distinct-domain-tor" {
			t.Fatalf("client %d reserve=%q, want distinct failure domain", index, selected.TCP)
		}
	}
}

func TestReserveSelectorRejectsEveryIneligibleState(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	base := Candidate{
		Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true,
		ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
	}
	invalid := []Candidate{
		candidateWith(base, "not-fully-qualified", func(candidate *Candidate) { candidate.ReserveEligible = false }),
		candidateWith(base, "failed-active", func(candidate *Candidate) { candidate.ActiveEligible = false }),
		candidateWith(base, "stale-active", func(candidate *Candidate) { candidate.ActiveFresh = false }),
		candidateWith(base, "draining", func(candidate *Candidate) { candidate.Retiring = true }),
		candidateWith(base, "circuit-open", func(candidate *Candidate) { candidate.CircuitOpen = true }),
		candidateWith(base, "qoe-degraded", func(candidate *Candidate) { candidate.QoEStatus = qoe.StatusDegraded }),
	}
	candidates := append([]Candidate{{
		ID: "primary", Protocol: ProtocolVLESS, Score: 100,
		TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
	}}, invalid...)
	selection := New(PolicyDefaults()).SelectReserves(
		now, "alice", Assignment{TCP: "primary", UDP: "primary"}, candidates,
	)
	if selection.TCP != "" || selection.UDP != "" {
		t.Fatalf("ineligible reserve selected: %+v", selection)
	}
}

func TestReserveSelectorRejectsPrimaryRouteIdentityAndAllowsAsymmetricCoverage(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []Candidate{
		{ID: "vless-primary", Protocol: ProtocolVLESS, RouteKey: "same-route", Score: 100, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "vless-clone", Protocol: ProtocolVLESS, RouteKey: "same-route", Score: 200, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "tor-primary", Protocol: ProtocolTor, ProfileID: "slot-1", Score: 100, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
		{ID: "tor-reserve", Protocol: ProtocolTor, ProfileID: "slot-2", Score: 80, TCPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Warm: true},
	}
	selection := New(PolicyDefaults()).SelectReserves(
		now, "alice", Assignment{TCP: "tor-primary", UDP: "vless-primary"}, candidates,
	)
	if selection.TCP == "" || selection.TCP == "tor-primary" || selection.UDP != "" {
		t.Fatalf("asymmetric reserves=%+v", selection)
	}
}

func TestSelectProspectiveReservesIgnoresOnlyActiveEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	assignment := Assignment{TCP: "primary", UDP: "primary"}
	candidates := []Candidate{
		{
			ID: "primary", Protocol: ProtocolVLESS, FailureDomain: "domain-a",
			TCPQualified: true, UDPQualified: true,
		},
		{
			ID: "not-qualified", Protocol: ProtocolVLESS,
			FailureDomain: "domain-b", Score: 200,
			TCPQualified: true, UDPQualified: true,
			ReserveEligible: false,
		},
		{
			ID: "needs-active-proof", Protocol: ProtocolVLESS,
			FailureDomain: "domain-c", Score: 80,
			TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: false, ActiveFresh: false,
		},
	}
	placement := New(PolicyDefaults())
	if strict := placement.SelectReserves(
		now, "alice", assignment, candidates,
	); strict.TCP != "" || strict.UDP != "" {
		t.Fatalf("strict reserves used missing active proof: %+v", strict)
	}
	prospective := placement.SelectProspectiveReserves(
		now, "alice", assignment, candidates,
	)
	if prospective.TCP != "needs-active-proof" ||
		prospective.UDP != "needs-active-proof" {
		t.Fatalf("prospective reserves=%+v", prospective)
	}
}

func candidateWith(base Candidate, id string, change func(*Candidate)) Candidate {
	base.ID = id
	base.FailureDomain = "domain-" + id
	change(&base)
	return base
}

func TestInactiveAssignmentsDoNotReserveCandidateCapacity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	clients := make([]Client, 0, 51)
	for index := 0; index < 50; index++ {
		clients = append(clients, Client{
			ID: fmt.Sprintf("inactive-%d", index), LastTraffic: now.Add(-10 * time.Minute),
			Assignment: Assignment{TCP: "best", UDP: "best", TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour)},
		})
	}
	clients = append(clients, Client{ID: "active", LastTraffic: now})
	candidates := []Candidate{{ID: "best", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true}}
	result := scheduler.Schedule(now, clients, candidates)
	if result.Assignments["active"].TCP != "best" || result.Load["best"] != 1 {
		t.Fatalf("active client was blocked by inactive accounts: assignment=%+v load=%+v", result.Assignments["active"], result.Load)
	}
}

func TestVLESSHasPriorityOverTorByDefaultAndCoAssignsUDP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	candidates := []Candidate{
		{ID: "tor-fast", Protocol: ProtocolTor, Score: 100, TCPQualified: true},
		{ID: "vless", Protocol: ProtocolVLESS, Score: 70, TCPQualified: true, UDPQualified: true},
	}
	result := scheduler.Schedule(now, []Client{{ID: "alice", LastTraffic: now}}, candidates)
	assignment := result.Assignments["alice"]
	if assignment.TCP != "vless" || assignment.UDP != "vless" {
		t.Fatalf("assignment=%+v, want VLESS for both TCP and UDP", assignment)
	}
}

func TestTorIsUsedWhenNoVLESSCandidatesExist(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	candidates := []Candidate{
		{ID: "tor-fast", Protocol: ProtocolTor, Score: 100, TCPQualified: true},
	}
	result := scheduler.Schedule(now, []Client{{ID: "alice", LastTraffic: now}}, candidates)
	assignment := result.Assignments["alice"]
	if assignment.TCP != "tor-fast" || assignment.UDP != "" {
		t.Fatalf("assignment=%+v, want Tor for TCP and empty for UDP", assignment)
	}
}

func TestSchedulerSharesTopQualityCandidateBeforeScatteringToLowQuality(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	candidates := []Candidate{
		{ID: "top", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true, FailureDomain: "domain-a"},
		{ID: "low", Protocol: ProtocolVLESS, Score: 70, TCPQualified: true, UDPQualified: true, FailureDomain: "domain-b"},
	}
	clients := []Client{
		{ID: "alice", LastTraffic: now},
		{ID: "bob", LastTraffic: now},
	}
	result := scheduler.Schedule(now, clients, candidates)
	if alice := result.Assignments["alice"]; alice.TCP != "top" || alice.UDP != "top" {
		t.Fatalf("alice was pushed off top candidate: %+v", alice)
	}
	if bob := result.Assignments["bob"]; bob.TCP != "top" || bob.UDP != "top" {
		t.Fatalf("bob was forced onto low-quality candidate: %+v", bob)
	}
}

func TestScoreJitterAroundThirtyPercentDoesNotAccumulateMigrationStreak(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{TCP: "stable", TCPSince: now.Add(-time.Hour)},
	}
	for snapshot, alternativeScore := range []float64{131, 129, 131, 131, 129, 131, 131} {
		at := now.Add(time.Duration(snapshot) * time.Minute)
		client.LastTraffic = at
		result := placement.Schedule(at, []Client{client}, []Candidate{
			{ID: "stable", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
			{ID: "jitter", Protocol: ProtocolVLESS, Score: alternativeScore, TCPQualified: true},
		})
		if assignment := result.Assignments[client.ID]; assignment.TCP != "stable" {
			t.Fatalf("snapshot %d score=%v moved on jitter: %+v", snapshot, alternativeScore, result)
		}
	}
}

func TestHardFailureAndManualExclusionSwitchImmediately(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	scheduler.Exclude("alice", "failed", now.Add(30*time.Minute))
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{TCP: "failed", UDP: "failed", TCPSince: now.Add(-time.Minute), UDPSince: now.Add(-time.Minute)},
	}
	candidates := []Candidate{
		{ID: "failed", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true},
		{ID: "backup", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true, UDPQualified: true},
	}
	result := scheduler.Schedule(now, []Client{client}, candidates)
	if result.Assignments["alice"].TCP != "backup" || result.Assignments["alice"].UDP != "backup" {
		t.Fatalf("hard failover did not bypass dwell: %+v", result.Assignments["alice"])
	}
}

func TestSchedulerExcludeCoalescesDuplicateCandidateUntilLongestDeadline(t *testing.T) {
	now := time.Now()
	placement := New(PolicyDefaults())
	placement.Exclude("alice", "route", now.Add(time.Hour))
	placement.Exclude("alice", "route", now.Add(30*time.Minute))
	placement.Exclude("alice", "route", now.Add(2*time.Hour))

	placement.mu.Lock()
	items := append([]exclusion(nil), placement.exclusions["alice"]...)
	placement.mu.Unlock()
	if len(items) != 1 || items[0].CandidateID != "route" ||
		!items[0].Until.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("coalesced exclusions=%+v", items)
	}
}

func TestPlanningFingerprintCompactsLegacyExpiredAndDuplicateExclusions(t *testing.T) {
	now := time.Now()
	placement := New(PolicyDefaults())
	placement.exclusions["alice"] = []exclusion{
		{CandidateID: "expired", Until: now.Add(-time.Minute)},
		{CandidateID: "route", Until: now.Add(time.Hour)},
		{CandidateID: "route", Until: now.Add(2 * time.Hour)},
		{CandidateID: "other", Until: now.Add(30 * time.Minute)},
	}
	clients := []Client{{ID: "alice"}}
	before := placement.PlanningFingerprint(now, clients)
	after := placement.PlanningFingerprint(now, clients)
	if before != after {
		t.Fatalf("semantic fingerprint changed after compaction: %s != %s", before, after)
	}
	placement.mu.Lock()
	items := append([]exclusion(nil), placement.exclusions["alice"]...)
	placement.mu.Unlock()
	if len(items) != 2 {
		t.Fatalf("compacted exclusions=%+v", items)
	}
	byID := make(map[string]time.Time, len(items))
	for _, item := range items {
		byID[item.CandidateID] = item.Until
	}
	if !byID["route"].Equal(now.Add(2*time.Hour)) ||
		!byID["other"].Equal(now.Add(30*time.Minute)) {
		t.Fatalf("compacted exclusions=%+v", items)
	}
}

func TestScheduleContextPrunesExpiredExclusionsForRemovedClients(t *testing.T) {
	now := time.Now()
	placement := New(PolicyDefaults())
	placement.exclusions["removed-client"] = []exclusion{{
		CandidateID: "expired-route", Until: now.Add(-time.Minute),
	}}
	placement.exclusions["active-client"] = []exclusion{{
		CandidateID: "live-route", Until: now.Add(time.Hour),
	}}

	if _, err := placement.ScheduleContext(
		context.Background(), now,
		[]Client{{ID: "current-client"}},
		[]Candidate{{ID: "route", TCPQualified: true}},
	); err != nil {
		t.Fatal(err)
	}
	placement.mu.Lock()
	defer placement.mu.Unlock()
	if _, exists := placement.exclusions["removed-client"]; exists {
		t.Fatalf("expired removed-client exclusions survived: %+v", placement.exclusions)
	}
	if items := placement.exclusions["active-client"]; len(items) != 1 ||
		items[0].CandidateID != "live-route" {
		t.Fatalf("live exclusions changed: %+v", placement.exclusions)
	}
	if len(placement.exclusions) != 1 {
		t.Fatalf("empty exclusion keys survived: %+v", placement.exclusions)
	}
}

func TestFailureDomainsDiversifyActiveAssignmentsDeterministically(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clients := []Client{
		{ID: "alice", LastTraffic: now},
		{ID: "bob", LastTraffic: now},
	}
	candidates := []Candidate{
		{
			ID: "a-1", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, FailureDomain: "domain-a",
		},
		{
			ID: "a-2", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, FailureDomain: "domain-a",
		},
		{
			ID: "b-1", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, FailureDomain: "domain-b",
		},
	}

	first := New(PolicyDefaults()).Schedule(now, clients, candidates)
	reversedClients := []Client{clients[1], clients[0]}
	reversedCandidates := []Candidate{candidates[2], candidates[1], candidates[0]}
	second := New(PolicyDefaults()).Schedule(now, reversedClients, reversedCandidates)
	if fmt.Sprint(first.Assignments) != fmt.Sprint(second.Assignments) {
		t.Fatalf("call ordering changed placement:\nfirst=%+v\nsecond=%+v", first.Assignments, second.Assignments)
	}
	byID := map[string]Candidate{
		"a-1": candidates[0], "a-2": candidates[1], "b-1": candidates[2],
	}
	aliceDomain := byID[first.Assignments["alice"].TCP].FailureDomain
	bobDomain := byID[first.Assignments["bob"].TCP].FailureDomain
	if aliceDomain == "" || bobDomain == "" || aliceDomain == bobDomain {
		t.Fatalf("clients were not diversified across domains: %+v", first.Assignments)
	}
}

func TestFailureDomainSameDomainFallbackRemainsUsable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{
		{ID: "alice", LastTraffic: now},
		{ID: "bob", LastTraffic: now},
	}, []Candidate{
		{
			ID: "a-1", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, FailureDomain: "domain-a",
		},
		{
			ID: "a-2", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, FailureDomain: "domain-a",
		},
	})
	if result.Assignments["alice"].TCP == "" || result.Assignments["bob"].TCP == "" {
		t.Fatalf("single-domain fallback blocked traffic: %+v", result.Assignments)
	}
}

func TestOpenOnlyFailureDomainPreservesExistingAndNewRoutesAcrossCycles(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	candidates := []Candidate{
		{
			ID: "open-a", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true,
			FailureDomain: "domain-open", CircuitOpen: true,
		},
		{
			ID: "open-b", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, UDPQualified: true,
			FailureDomain: "domain-open",
		},
	}
	clients := []Client{
		{
			ID: "alice", LastTraffic: now,
			Assignment: Assignment{
				TCP: "open-a", UDP: "open-a",
				TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
			},
		},
		{
			ID: "bob", LastTraffic: now,
			Assignment: Assignment{
				TCP: "open-b", UDP: "open-b",
				TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
			},
		},
		{ID: "new-client", LastTraffic: now},
	}
	placement := New(PolicyDefaults())
	for cycle := 0; cycle < 3; cycle++ {
		at := now.Add(time.Duration(cycle) * time.Minute)
		for index := range clients {
			clients[index].LastTraffic = at
		}
		result := placement.Schedule(at, clients, candidates)
		if assignment := result.Assignments["alice"]; assignment.TCP != "open-a" ||
			assignment.UDP != "open-a" {
			t.Fatalf("cycle %d cleared or rotated alice: %+v", cycle, assignment)
		}
		if assignment := result.Assignments["bob"]; assignment.TCP != "open-b" ||
			assignment.UDP != "open-b" {
			t.Fatalf("cycle %d cleared or rotated bob: %+v", cycle, assignment)
		}
		if assignment := result.Assignments["new-client"]; assignment.TCP == "" ||
			assignment.UDP == "" {
			t.Fatalf("cycle %d left new client route-less: %+v", cycle, assignment)
		}
		for index := range clients {
			clients[index].Assignment = result.Assignments[clients[index].ID]
		}
	}
}

func TestActiveHardFailureFallsBackToQualifiedOpenSiblingAcrossCycles(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	candidates := []Candidate{
		{
			ID: "unqualified", Protocol: ProtocolVLESS, Score: 100,
			FailureDomain: "domain-open", CircuitOpen: true,
		},
		{
			ID: "retiring", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, Retiring: true,
			FailureDomain: "domain-open",
		},
		{
			ID: "degraded", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusDegraded,
			FailureDomain: "domain-open",
		},
		{
			ID: "healthy-sibling", Protocol: ProtocolVLESS, Score: 80,
			TCPQualified: true, UDPQualified: true,
			FailureDomain: "domain-open",
		},
	}
	clients := []Client{
		{
			ID: "failed-client", LastTraffic: now,
			// Active monitoring removed the hard-failed candidate from the
			// usable inventory while its persisted assignment still refers to it.
			Assignment: Assignment{
				TCP: "failed-candidate", UDP: "failed-candidate",
				TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
			},
		},
		{ID: "new-client", LastTraffic: now},
	}
	policy := PolicyDefaults()
	policy.MaxPlannedMoves = 2
	placement := New(policy)
	for cycle := 0; cycle < 3; cycle++ {
		at := now.Add(time.Duration(cycle) * time.Minute)
		for index := range clients {
			clients[index].LastTraffic = at
		}
		result := placement.Schedule(at, clients, candidates)
		for _, clientID := range []string{"failed-client", "new-client"} {
			assignment := result.Assignments[clientID]
			if assignment.TCP != "healthy-sibling" ||
				assignment.UDP != "healthy-sibling" {
				t.Fatalf(
					"cycle %d client %s did not use healthy open sibling: %+v",
					cycle, clientID, assignment,
				)
			}
		}
		if cycle == 0 &&
			(result.HardMoves != 2 || result.PlannedMoves != 2) {
			t.Fatalf("initial fallback move accounting=%+v", result)
		}
		if cycle > 0 &&
			(result.HardMoves != 0 || result.PlannedMoves != 0) {
			t.Fatalf("stable fallback rotated on cycle %d: %+v", cycle, result)
		}
		for index := range clients {
			clients[index].Assignment = result.Assignments[clients[index].ID]
		}
	}
}

func TestActiveHardFailureDoesNotUseIneligibleOpenSibling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	placement.Exclude("client", "excluded", now.Add(time.Hour))
	result := placement.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "failed-candidate"},
	}}, []Candidate{
		{
			ID: "excluded", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, FailureDomain: "domain-open", CircuitOpen: true,
		},
		{
			ID: "retiring", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, Retiring: true, FailureDomain: "domain-open",
		},
		{
			ID: "degraded", Protocol: ProtocolVLESS, Score: 80,
			TCPQualified: true, QoEStatus: qoe.StatusDegraded,
			FailureDomain: "domain-open",
		},
	})
	if got := result.Assignments["client"].TCP; got != "" {
		t.Fatalf("ineligible open sibling selected: %q", got)
	}
}

func TestActiveHardFailureOpenSiblingHonorsMoveCap(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.MaxPlannedMoves = 1
	result := New(policy).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{
			TCP: "failed-candidate", UDP: "failed-candidate",
		},
	}}, []Candidate{{
		ID: "healthy-sibling", Protocol: ProtocolVLESS, Score: 100,
		TCPQualified: true, UDPQualified: true,
		FailureDomain: "domain-open", CircuitOpen: true,
	}})
	if assignment := result.Assignments["client"]; assignment.TCP != "healthy-sibling" ||
		assignment.UDP != "failed-candidate" {
		t.Fatalf("move cap was not applied to open fallback: %+v", assignment)
	}
	if result.HardMoves != 1 || result.PlannedMoves != 1 {
		t.Fatalf("capped fallback accounting=%+v", result)
	}
}

func TestOpenDomainFallbackIsDeterministicAndHonorsEligibility(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	candidates := []Candidate{
		{
			ID: "unqualified", Protocol: ProtocolVLESS, Score: 100,
			FailureDomain: "domain-a", CircuitOpen: true,
		},
		{
			ID: "retiring", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, Retiring: true,
			FailureDomain: "domain-b", CircuitOpen: true,
		},
		{
			ID: "degraded", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, QoEStatus: qoe.StatusDegraded,
			FailureDomain: "domain-c", CircuitOpen: true,
		},
		{
			ID: "valid", Protocol: ProtocolVLESS, Score: 80,
			TCPQualified: true, FailureDomain: "domain-d", CircuitOpen: true,
		},
	}
	client := []Client{{ID: "new-client", LastTraffic: now}}
	first := New(PolicyDefaults()).Schedule(now, client, candidates)
	reversed := []Candidate{candidates[3], candidates[2], candidates[1], candidates[0]}
	second := New(PolicyDefaults()).Schedule(now, client, reversed)
	if first.Assignments["new-client"].TCP != "valid" ||
		second.Assignments["new-client"].TCP != "valid" {
		t.Fatalf("fallback was unsafe or order-dependent: first=%+v second=%+v", first, second)
	}
}

func TestEmptyFailureDomainsAreIndependentLegacyFallbacks(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{
		{ID: "alice", LastTraffic: now},
		{ID: "bob", LastTraffic: now},
	}, []Candidate{
		{ID: "legacy-a", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
		{ID: "legacy-b", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
	})
	if result.Assignments["alice"].TCP == "" ||
		result.Assignments["bob"].TCP == "" ||
		result.Assignments["alice"].TCP == result.Assignments["bob"].TCP {
		t.Fatalf("empty domains collapsed into one correlated domain: %+v", result.Assignments)
	}
}

func TestOpenFailureDomainMigratesWithinMoveCapWithoutSameDomainRotation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.MaxPlannedMoves = 1
	result := New(policy).Schedule(now, []Client{
		{
			ID: "alice", LastTraffic: now,
			Assignment: Assignment{TCP: "a-1", TCPSince: now.Add(-time.Hour)},
		},
		{
			ID: "bob", LastTraffic: now,
			Assignment: Assignment{TCP: "a-2", TCPSince: now.Add(-time.Hour)},
		},
	}, []Candidate{
		{
			ID: "a-1", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			FailureDomain: "domain-a", CircuitOpen: true,
		},
		{
			ID: "a-2", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			FailureDomain: "domain-a",
		},
		{
			ID: "b-1", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			FailureDomain: "domain-b",
		},
	})
	moved := 0
	for clientID, original := range map[string]string{"alice": "a-1", "bob": "a-2"} {
		got := result.Assignments[clientID].TCP
		if got == "b-1" {
			moved++
			continue
		}
		if got != original {
			t.Fatalf("%s rotated within open domain from %q to %q", clientID, original, got)
		}
	}
	if moved != 1 || result.PlannedMoves != 1 || result.HardMoves != 1 {
		t.Fatalf("open-domain move cap not enforced: %+v", result)
	}
}

func TestOpenFailureDomainMigrationHonorsAllAlternativeEligibilityGates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	placement.Exclude("client", "excluded", now.Add(time.Hour))
	result := placement.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{
			TCP: "open", UDP: "open",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
		},
	}}, []Candidate{
		{
			ID: "open", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true,
			FailureDomain: "domain-open", CircuitOpen: true,
		},
		{
			ID: "excluded", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, FailureDomain: "domain-excluded",
		},
		{
			ID: "retiring", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, Retiring: true,
			FailureDomain: "domain-retiring",
		},
		{
			ID: "tcp-only", Protocol: ProtocolVLESS, Score: 95,
			TCPQualified: true, FailureDomain: "domain-tcp",
		},
		{
			ID: "valid", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, UDPQualified: true, FailureDomain: "domain-valid",
		},
	})
	assignment := result.Assignments["client"]
	if (assignment.TCP != "tcp-only" && assignment.TCP != "valid") ||
		assignment.UDP != "open" {
		t.Fatalf("eligibility or move cap violated: %+v", assignment)
	}
}

func TestRetiringRouteSwitchesImmediatelyAndReceivesNoNewAssignments(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	clients := []Client{
		{
			ID: "assigned", LastTraffic: now.Add(-time.Hour),
			Assignment: Assignment{
				TCP: "retiring", TCPSince: now.Add(-time.Minute),
			},
		},
		{ID: "new", LastTraffic: now},
	}
	candidates := []Candidate{
		{
			ID: "retiring", Protocol: ProtocolTor, Score: 100,
			TCPQualified: true, Retiring: true,
		},
		{ID: "replacement", Protocol: ProtocolTor, Score: 70, TCPQualified: true},
	}
	result := placement.Schedule(now, clients, candidates)
	if got := result.Assignments["assigned"].TCP; got != "replacement" {
		t.Fatalf("retiring assignment remained on %q", got)
	}
	if got := result.Assignments["new"].TCP; got != "replacement" {
		t.Fatalf("new client received %q", got)
	}
	if result.HardMoves != 1 {
		t.Fatalf("hard moves=%d", result.HardMoves)
	}
}

func TestRetiringRouteStaysUntilReplacementIsAvailable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	client := Client{
		ID: "assigned", LastTraffic: now,
		Assignment: Assignment{TCP: "retiring", TCPSince: now.Add(-time.Hour)},
	}
	result := placement.Schedule(now, []Client{client}, []Candidate{{
		ID: "retiring", Protocol: ProtocolTor, Score: 100,
		TCPQualified: true, Retiring: true,
	}})
	if got := result.Assignments["assigned"].TCP; got != "retiring" {
		t.Fatalf("route was dropped before replacement existed: %q", got)
	}
}

func TestHealthyOptimizationNeedsThreeSnapshotsThirtyPercentAndMovesOneClient(t *testing.T) {
	policy := PolicyDefaults()
	scheduler := New(policy)
	start := time.Unix(1_800_000_000, 0)
	clients := []Client{
		{ID: "alice", LastTraffic: start, Assignment: Assignment{TCP: "old", UDP: "old", TCPSince: start.Add(-time.Hour), UDPSince: start.Add(-time.Hour)}},
		{ID: "bob", LastTraffic: start, Assignment: Assignment{TCP: "old", UDP: "old", TCPSince: start.Add(-time.Hour), UDPSince: start.Add(-time.Hour)}},
	}
	candidates := []Candidate{
		{ID: "old", Protocol: ProtocolVLESS, Score: 60, TCPQualified: true, UDPQualified: true},
		{ID: "new", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true},
	}
	for snapshot := 0; snapshot < 2; snapshot++ {
		now := start.Add(time.Duration(snapshot) * 5 * time.Minute)
		clients[0].LastTraffic, clients[1].LastTraffic = now, now
		result := scheduler.Schedule(now, clients, candidates)
		if result.Assignments["alice"].TCP != "old" || result.Assignments["bob"].TCP != "old" {
			t.Fatalf("moved before three snapshots: %+v", result.Assignments)
		}
	}
	now := start.Add(10 * time.Minute)
	clients[0].LastTraffic, clients[1].LastTraffic = now, now
	result := scheduler.Schedule(now, clients, candidates)
	moved := 0
	for _, assignment := range result.Assignments {
		if assignment.TCP == "new" {
			moved++
		}
	}
	if moved != 1 || result.PlannedMoves != 1 {
		t.Fatalf("planned move limit failed: moved=%d result=%+v", moved, result)
	}
}

func TestSuppressedQualityCyclePreservesPeriodicImprovementEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 2
	placement := New(policy)
	client := Client{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "current", TCPSince: now.Add(-time.Hour)},
	}
	candidates := []Candidate{
		{ID: "current", Protocol: ProtocolVLESS, Score: 60, TCPQualified: true,
			QoETracked: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true},
		{ID: "better", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			QoETracked: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true,
			QoEPromotionReady: true},
	}
	if got := placement.Schedule(now, []Client{client}, candidates).Assignments[client.ID].TCP; got != "current" {
		t.Fatalf("first periodic snapshot moved to %q", got)
	}
	if got := placement.ScheduleWithOptions(
		now.Add(time.Second), []Client{client}, candidates,
		ScheduleOptions{SuppressQualityMoves: true},
	).Assignments[client.ID].TCP; got != "current" {
		t.Fatalf("suppressed cycle moved to %q", got)
	}
	if got := placement.Schedule(
		now.Add(2*time.Second), []Client{client}, candidates,
	).Assignments[client.ID].TCP; got != "better" {
		t.Fatalf("suppressed cycle erased periodic evidence: got %q", got)
	}
}

func TestHealthyOptimizationRequiresFreshHealthyQoETargetWhenTracked(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 1
	placement := New(policy)
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{TCP: "current", TCPSince: now.Add(-time.Hour)},
	}
	current := Candidate{
		ID: "current", Protocol: ProtocolVLESS, Score: 60, TCPQualified: true,
		QoETracked: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true,
	}
	target := Candidate{
		ID: "target", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
		QoETracked: true, QoEStatus: qoe.StatusLearning, QoEFresh: true,
	}

	result := placement.Schedule(now, []Client{client}, []Candidate{current, target})
	if got := result.Assignments[client.ID].TCP; got != current.ID {
		t.Fatalf("learning target received planned traffic: %q", got)
	}

	target.QoEStatus = qoe.StatusHealthy
	target.QoEFresh = false
	result = placement.Schedule(now.Add(time.Second), []Client{client}, []Candidate{current, target})
	if got := result.Assignments[client.ID].TCP; got != current.ID {
		t.Fatalf("stale QoE target received planned traffic: %q", got)
	}

	target.QoEFresh = true
	result = placement.Schedule(now.Add(2*time.Second), []Client{client}, []Candidate{current, target})
	if got := result.Assignments[client.ID].TCP; got != current.ID {
		t.Fatalf("target without promotion-grade QoE evidence was selected: %q", got)
	}

	target.QoEPromotionReady = true
	result = placement.Schedule(now.Add(3*time.Second), []Client{client}, []Candidate{current, target})
	if got := result.Assignments[client.ID].TCP; got != target.ID || result.PlannedMoves != 1 {
		t.Fatalf("promotion-ready healthy target was not selected: result=%+v", result)
	}
}

func TestPreviewDiscardDoesNotAdvanceStreakOrPruneExclusions(t *testing.T) {
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 3
	placement := New(policy)
	now := time.Unix(1_800_000_000, 0)
	placement.Exclude("alice", "excluded", now.Add(time.Hour))
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{
			TCP: "old", TCPSince: now.Add(-time.Hour),
		},
	}
	candidates := []Candidate{
		{
			ID: "old", Protocol: ProtocolVLESS, Score: 60,
			TCPQualified: true,
		},
		{
			ID: "new", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true,
		},
		{
			ID: "excluded", Protocol: ProtocolVLESS, Score: 200,
			TCPQualified: true,
		},
	}
	preview := placement.BeginPreview()
	for attempt := 0; attempt < 2; attempt++ {
		result := preview.Scheduler().Schedule(
			now.Add(time.Duration(attempt)*time.Minute),
			[]Client{client},
			candidates,
		)
		if result.Assignments["alice"].TCP != "old" {
			t.Fatalf("preview moved before third snapshot: %+v", result)
		}
	}
	preview.Discard()

	for snapshot := 0; snapshot < 2; snapshot++ {
		result := placement.Schedule(
			now.Add(time.Duration(snapshot)*time.Minute),
			[]Client{client},
			candidates,
		)
		if result.Assignments["alice"].TCP != "old" {
			t.Fatalf("discarded preview leaked streak/exclusion: %+v", result)
		}
	}
	result := placement.Schedule(
		now.Add(2*time.Minute), []Client{client}, candidates,
	)
	if result.Assignments["alice"].TCP != "new" {
		t.Fatalf("committed scheduler did not move on own third snapshot: %+v",
			result)
	}
}

func TestPreviewCommitPublishesDeepCopiedState(t *testing.T) {
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 2
	placement := New(policy)
	now := time.Unix(1_800_000_000, 0)
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{
			TCP: "old", TCPSince: now.Add(-time.Hour),
		},
	}
	candidates := []Candidate{
		{
			ID: "old", Protocol: ProtocolVLESS, Score: 60,
			TCPQualified: true,
		},
		{
			ID: "new", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true,
		},
	}
	preview := placement.BeginPreview()
	if got := preview.Scheduler().Schedule(
		now, []Client{client}, candidates,
	).Assignments["alice"].TCP; got != "old" {
		t.Fatalf("first preview snapshot=%q", got)
	}
	preview.Commit()
	if got := placement.Schedule(
		now.Add(time.Minute), []Client{client}, candidates,
	).Assignments["alice"].TCP; got != "new" {
		t.Fatalf("committed preview did not publish streak: %q", got)
	}
}

func TestBeginPreviewDoesNotHoldOwnerLockAndReadViewIsIndependent(t *testing.T) {
	placement := New(PolicyDefaults())
	preview := placement.BeginPreview()
	defer preview.Discard()
	done := make(chan ReserveSelection, 1)
	go func() {
		view := placement.ReadView()
		done <- view.SelectProspectiveReserves(
			time.Unix(1_800_000_000, 0), "alice",
			Assignment{TCP: "primary"},
			[]Candidate{
				{ID: "primary", Protocol: ProtocolVLESS, TCPQualified: true},
				{ID: "reserve", Protocol: ProtocolVLESS, TCPQualified: true,
					ReserveEligible: true},
			},
		)
	}()
	select {
	case selected := <-done:
		if selected.TCP != "reserve" {
			t.Fatalf("read view reserve=%q", selected.TCP)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("live scheduler lock stayed held for preview lifetime")
	}
}

func TestPreviewCommitRejectsConcurrentSchedulerMutation(t *testing.T) {
	placement := New(PolicyDefaults())
	preview := placement.BeginPreview()
	placement.Exclude(
		"alice", "newly-excluded", time.Unix(1_800_000_000, 0).Add(time.Hour),
	)
	published := false
	err := preview.CommitAfter(func() error {
		published = true
		return nil
	})
	var temporary interface{ Temporary() bool }
	if !errors.Is(err, ErrPreviewChanged) ||
		!errors.As(err, &temporary) || !temporary.Temporary() {
		t.Fatalf("commit error=%v was not typed preview conflict", err)
	}
	if published {
		t.Fatal("preview CAS conflict executed durable publisher")
	}
}

func TestPreviewCommitAfterPublishFailureLeavesOwnerStateUnchanged(t *testing.T) {
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 2
	placement := New(policy)
	now := time.Unix(1_800_000_000, 0)
	client := Client{
		ID: "alice", LastTraffic: now,
		Assignment: Assignment{TCP: "old", TCPSince: now.Add(-time.Hour)},
	}
	candidates := []Candidate{
		{ID: "old", Protocol: ProtocolVLESS, Score: 60, TCPQualified: true},
		{ID: "new", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
	}
	preview := placement.BeginPreview()
	if got := preview.Scheduler().Schedule(
		now, []Client{client}, candidates,
	).Assignments["alice"].TCP; got != "old" {
		t.Fatalf("first preview snapshot=%q", got)
	}
	cause := errors.New("SQLite desired publish failed")
	if err := preview.CommitAfter(func() error { return cause }); !errors.Is(err, cause) {
		t.Fatalf("CommitAfter error=%v want=%v", err, cause)
	}
	if got := placement.Schedule(
		now.Add(time.Minute), []Client{client}, candidates,
	).Assignments["alice"].TCP; got != "old" {
		t.Fatalf("failed publisher leaked preview state: assignment=%q", got)
	}
}

func TestDegradedCurrentRequiresDwellAndThreeBetterSnapshots(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.QoEAlternativeSpeedup = 1.3
	placement := New(policy)
	client := Client{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)},
	}
	candidates := []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "fast", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true},
	}
	for snapshot := 1; snapshot <= 2; snapshot++ {
		result := placement.Schedule(now.Add(time.Duration(snapshot)*time.Second), []Client{client}, candidates)
		if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
			t.Fatalf("snapshot %d moved early: result=%+v", snapshot, result)
		}
	}
	result := placement.Schedule(now.Add(3*time.Second), []Client{client}, candidates)
	if result.Assignments["client"].TCP != "fast" || result.QoEMoves != 1 || result.PlannedMoves != 1 {
		t.Fatalf("third snapshot result=%+v", result)
	}
}

func TestConfirmedApplicationGateDegradationBypassesQualityHysteresis(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	placement := New(policy)
	result := placement.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "blocked", TCPSince: now.Add(-time.Second)},
	}}, []Candidate{
		{ID: "blocked", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: time.Second, QoEFresh: true,
			QoEReason: qoe.ReasonApplicationGates},
		{ID: "working-but-slower", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true,
			ActiveEligible: true, ActiveFresh: true},
	})
	if result.Assignments["client"].TCP != "working-but-slower" ||
		result.QoEMoves != 1 {
		t.Fatalf("confirmed application failure did not fail over: result=%+v", result)
	}
}

func TestNewAssignmentPrefersFreshActiveProof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	result := placement.Schedule(now, []Client{{ID: "client"}}, []Candidate{
		{ID: "unproved", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true},
		{ID: "proved", Protocol: ProtocolVLESS, Score: 80, TCPQualified: true, UDPQualified: true,
			ActiveEligible: true, ActiveFresh: true},
	})
	assignment := result.Assignments["client"]
	if assignment.TCP != "proved" || assignment.UDP != "proved" {
		t.Fatalf("new assignment=%+v want active-proved route", assignment)
	}
}

func TestConfirmedRouteTimeoutUsesActiveProvedAlternative(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	placement := New(PolicyDefaults())
	result := placement.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "timed-out", TCPSince: now.Add(-time.Second)},
	}}, []Candidate{
		{ID: "timed-out", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: time.Second, QoEFresh: true,
			QoEReason: qoe.ReasonRouteTimeout},
		{ID: "unproved-fast", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 500 * time.Millisecond, QoEFresh: true},
		{ID: "proved", Protocol: ProtocolVLESS, Score: 80, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true,
			ActiveEligible: true, ActiveFresh: true},
	})
	if got := result.Assignments["client"].TCP; got != "proved" {
		t.Fatalf("timeout failover=%q want active-proved alternative", got)
	}
}

func TestConfirmedAvailabilityFailureMovesEveryAffectedClientInOneCycle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.MaxPlannedMoves = 1
	placement := New(policy)
	clients := []Client{
		{ID: "alice", Assignment: Assignment{TCP: "failed", TCPSince: now}},
		{ID: "bob", Assignment: Assignment{TCP: "failed", TCPSince: now}},
	}
	result := placement.Schedule(now, clients, []Candidate{
		{ID: "failed", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: time.Second, QoEFresh: true,
			QoEReason: qoe.ReasonApplicationGates},
		{ID: "proved", Protocol: ProtocolVLESS, Score: 80, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true,
			ActiveEligible: true, ActiveFresh: true},
	})
	for _, clientID := range []string{"alice", "bob"} {
		if got := result.Assignments[clientID].TCP; got != "proved" {
			t.Fatalf("%s stayed on failed route: %+v", clientID, result)
		}
	}
	if result.QoEMoves != 2 || result.PlannedMoves != 2 {
		t.Fatalf("move accounting=%+v want two affected clients", result)
	}
}

func TestDegradedCurrentDoesNotBypassMinimumDwell(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.QoEAlternativeSpeedup = 1.3
	placement := New(policy)
	client := Client{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Minute)},
	}
	candidates := []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "fast", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true},
	}
	for snapshot := 1; snapshot <= policy.RequiredSnapshots+1; snapshot++ {
		result := placement.Schedule(now.Add(time.Duration(snapshot)*time.Second), []Client{client}, candidates)
		if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
			t.Fatalf("snapshot %d bypassed dwell: result=%+v", snapshot, result)
		}
	}
}

func TestDegradedMovesRespectGlobalPlannedMoveBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.QoEAlternativeSpeedup = 1.3
	policy.RequiredSnapshots = 1
	policy.MaxPlannedMoves = 1
	result := New(policy).Schedule(now, []Client{
		{ID: "alice", LastTraffic: now, Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)}},
		{ID: "bob", LastTraffic: now, Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)}},
	}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "fast", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2 * time.Second, QoEFresh: true},
	})
	moved := 0
	for _, assignment := range result.Assignments {
		if assignment.TCP == "fast" {
			moved++
		}
	}
	if moved != 1 || result.QoEMoves != 1 || result.PlannedMoves != 1 {
		t.Fatalf("result=%+v moved=%d", result, moved)
	}
}

func TestQualityMoveBudgetCountsClientOnceAcrossTCPAndUDP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.QoEAlternativeSpeedup = 1.3
	policy.RequiredSnapshots = 1
	policy.MaxPlannedMoves = 1
	result := New(policy).Schedule(now, []Client{
		{ID: "alice", LastTraffic: now, Assignment: Assignment{
			TCP: "slow", UDP: "slow",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
		}},
		{ID: "bob", LastTraffic: now, Assignment: Assignment{
			TCP: "slow", UDP: "slow",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
		}},
	}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99,
			TCPQualified: true, UDPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "fast", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, UDPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
	})
	if assignment := result.Assignments["alice"]; assignment.TCP != "fast" || assignment.UDP != "fast" {
		t.Fatalf("alice assignment=%+v", assignment)
	}
	if assignment := result.Assignments["bob"]; assignment.TCP != "slow" || assignment.UDP != "slow" {
		t.Fatalf("bob bypassed client move budget: %+v", assignment)
	}
	if result.PlannedMoves != 1 || result.QoEMoves != 2 {
		t.Fatalf("move accounting=%+v", result)
	}
}

func TestEmergencyMoveCannotWeakenMinimumAlternativeSpeedup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.QoEAlternativeSpeedup = 0.5
	result := New(policy).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Minute)},
	}}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "slower", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 5 * time.Second, QoEFresh: true},
	})
	if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
		t.Fatalf("unsafe policy weakened QoE gate: result=%+v", result)
	}
}

func TestDegradedCurrentIsPreservedWithoutSubstantiallyBetterRoute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	result := scheduler.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Minute)},
	}}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "not-enough", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 2100 * time.Millisecond, QoEFresh: true},
	})
	if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestDegradedCandidatesReceiveNoNewAssignments(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
	}}, []Candidate{{
		ID: "degraded", Protocol: ProtocolVLESS, Score: 100,
		TCPQualified: true, UDPQualified: true,
		QoEStatus: qoe.StatusDegraded, QoEEffective: time.Second, QoEFresh: true,
	}})
	if assignment := result.Assignments["client"]; assignment.TCP != "" || assignment.UDP != "" {
		t.Fatalf("degraded candidate received new assignment: %+v", assignment)
	}
}

func TestLearningCandidateRemainsEligibleForOrdinaryPlacement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
	}}, []Candidate{{
		ID: "learning", Protocol: ProtocolVLESS, Score: 100,
		TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusLearning,
	}})
	if assignment := result.Assignments["client"]; assignment.TCP != "learning" || assignment.UDP != "learning" {
		t.Fatalf("learning candidate was not ordinarily eligible: %+v", assignment)
	}
}

func TestOrdinaryPlacementPrefersStableCandidateOverLearningCandidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
	}}, []Candidate{
		{ID: "learning", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, QoETracked: true,
			QoEStatus: qoe.StatusLearning},
		{ID: "stable", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, UDPQualified: true, QoETracked: true,
			QoEStatus: qoe.StatusHealthy, QoEFresh: true,
			QoEEffective: time.Second},
	})
	if assignment := result.Assignments["client"]; assignment.TCP != "stable" || assignment.UDP != "stable" {
		t.Fatalf("assignment=%+v", assignment)
	}
}

func TestEmergencySelectionPrefersStableCandidateOverLearningCandidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	candidates := []Candidate{
		{ID: "failed", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, FailureDomain: "failed"},
		{ID: "learning", Protocol: ProtocolVLESS, Score: 100,
			TCPQualified: true, QoETracked: true, QoEStatus: qoe.StatusLearning,
			FailureDomain: "learning"},
		{ID: "stable", Protocol: ProtocolVLESS, Score: 90,
			TCPQualified: true, QoETracked: true, QoEStatus: qoe.StatusHealthy,
			QoEFresh: true, QoEEffective: time.Second, FailureDomain: "stable"},
	}
	selected := New(PolicyDefaults()).SelectEmergency(
		now, "client", "tcp", "failed", candidates,
		map[string]int{}, map[string]int{},
	)
	if selected != "stable" {
		t.Fatalf("selected=%q", selected)
	}
}

func TestEmergencyMoveRejectsStaleAndUnhealthyAlternatives(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name      string
		status    qoe.Status
		fresh     bool
		effective time.Duration
	}{
		{name: "stale", status: qoe.StatusHealthy, effective: time.Second},
		{name: "degraded", status: qoe.StatusDegraded, fresh: true, effective: time.Second},
		{name: "zero effective time", status: qoe.StatusHealthy, fresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := New(PolicyDefaults()).Schedule(now, []Client{{
				ID: "client", LastTraffic: now,
				Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)},
			}}, []Candidate{
				{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
					QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
				{ID: "alternative", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
					QoEStatus: test.status, QoEEffective: test.effective, QoEFresh: test.fresh},
			})
			if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestEmergencyUDPRequiresQualifiedVLESSAlternative(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, alternative := range []Candidate{
		{ID: "tor", Protocol: ProtocolTor, Score: 90, UDPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
		{ID: "tcp-only", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
	} {
		t.Run(alternative.ID, func(t *testing.T) {
			result := New(PolicyDefaults()).Schedule(now, []Client{{
				ID: "client", LastTraffic: now,
				Assignment: Assignment{UDP: "slow", UDPSince: now.Add(-time.Hour)},
			}}, []Candidate{
				{ID: "slow", Protocol: ProtocolVLESS, Score: 99, UDPQualified: true,
					QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
				alternative,
			})
			if result.Assignments["client"].UDP != "slow" || result.QoEMoves != 0 {
				t.Fatalf("alternative=%+v result=%+v", alternative, result)
			}
		})
	}
}

func TestEmergencyMoveHonorsExclusions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	scheduler := New(PolicyDefaults())
	scheduler.Exclude("client", "fast", now.Add(time.Hour))
	result := scheduler.Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)},
	}}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "fast", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
	})
	if result.Assignments["client"].TCP != "slow" || result.QoEMoves != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestHardUnavailableDegradedCurrentUsesExistingHardMovePath(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := New(PolicyDefaults()).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "failed", TCPSince: now.Add(-time.Minute)},
	}}, []Candidate{
		{ID: "failed", Protocol: ProtocolVLESS, Score: 100,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true},
		{ID: "backup", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
	})
	if result.Assignments["client"].TCP != "backup" || result.HardMoves != 1 || result.QoEMoves != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestEmergencyMoveChoosesLowestEffectiveTimeThenCandidateID(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 1
	result := New(policy).Schedule(now, []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: "slow", TCPSince: now.Add(-time.Hour)},
	}}, []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
			QoEStatus: qoe.StatusDegraded, QoEEffective: 6 * time.Second, QoEFresh: true},
		{ID: "later", Protocol: ProtocolVLESS, Score: 99, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true},
		{ID: "z-tie", Protocol: ProtocolVLESS, Score: 1, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 500 * time.Millisecond, QoEFresh: true},
		{ID: "a-tie", Protocol: ProtocolVLESS, Score: 1, TCPQualified: true,
			QoEStatus: qoe.StatusHealthy, QoEEffective: 500 * time.Millisecond, QoEFresh: true},
	})
	if result.Assignments["client"].TCP != "a-tie" || result.QoEMoves != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestEmergencyMoveUsesSameDomainOnlyWhenNoDistinctQualifiedDomainExists(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := PolicyDefaults()
	policy.RequiredSnapshots = 1
	current := Candidate{
		ID: "slow", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true,
		QoEStatus: qoe.StatusDegraded, QoEEffective: 3 * time.Second, QoEFresh: true,
		FailureDomain: "domain-a",
	}
	sameDomain := Candidate{
		ID: "same-fast", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
		QoEStatus: qoe.StatusHealthy, QoEEffective: 500 * time.Millisecond, QoEFresh: true,
		FailureDomain: "domain-a",
	}
	distinctDomain := Candidate{
		ID: "distinct-fast-enough", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true,
		QoEStatus: qoe.StatusHealthy, QoEEffective: time.Second, QoEFresh: true,
		FailureDomain: "domain-b",
	}
	client := []Client{{
		ID: "client", LastTraffic: now,
		Assignment: Assignment{TCP: current.ID, TCPSince: now.Add(-time.Hour)},
	}}

	result := New(policy).Schedule(
		now, client, []Candidate{current, sameDomain, distinctDomain},
	)
	if result.Assignments["client"].TCP != distinctDomain.ID {
		t.Fatalf("same-domain route won despite qualified distinct domain: %+v", result)
	}

	distinctDomain.QoEEffective = 2500 * time.Millisecond
	result = New(policy).Schedule(
		now, client, []Candidate{current, sameDomain, distinctDomain},
	)
	if result.Assignments["client"].TCP != sameDomain.ID {
		t.Fatalf("same-domain fallback was not used: %+v", result)
	}
}
