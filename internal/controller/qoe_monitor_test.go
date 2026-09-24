package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestQoEWakeIntervalUsesShortestPositiveConfiguredCadence(t *testing.T) {
	for _, test := range []struct {
		name                   string
		active, idle, degraded time.Duration
		want                   time.Duration
	}{
		{name: "idle shortest", active: 2 * time.Minute, idle: 30 * time.Second, degraded: time.Minute, want: 30 * time.Second},
		{name: "degraded shortest", active: 2 * time.Minute, idle: 5 * time.Minute, degraded: time.Minute, want: time.Minute},
		{name: "active shortest", active: 15 * time.Second, idle: 5 * time.Minute, degraded: time.Minute, want: 15 * time.Second},
		{name: "ignores non-positive", active: -time.Second, idle: 30 * time.Second, want: 30 * time.Second},
		{name: "falls back", want: defaultQoEActiveInterval},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := QoEWakeInterval(test.active, test.idle, test.degraded); got != test.want {
				t.Fatalf("QoEWakeInterval()=%s want=%s", got, test.want)
			}
		})
	}
}

func TestQoEMonitorAssignedAndDegradedCadence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name             string
		assigned         bool
		active           bool
		degraded         bool
		healthy          bool
		lastAge          time.Duration
		activeInterval   time.Duration
		idleInterval     time.Duration
		degradedInterval time.Duration
		wantProbes       int
	}{
		{name: "active due at thirty seconds", assigned: true, active: true, lastAge: 30 * time.Second, wantProbes: 1},
		{name: "active not due early", assigned: true, active: true, lastAge: 29 * time.Second},
		{name: "idle due at five minutes", assigned: true, lastAge: 5 * time.Minute, wantProbes: 1},
		{name: "idle not due early", assigned: true, lastAge: 5*time.Minute - time.Second},
		{name: "assigned idle degraded due at one minute", assigned: true, degraded: true, lastAge: time.Minute, wantProbes: 1},
		{name: "assigned idle degraded not due early", assigned: true, degraded: true, lastAge: time.Minute - time.Second},
		{name: "assigned active degraded due at thirty seconds", assigned: true, active: true, degraded: true, lastAge: 30 * time.Second, wantProbes: 1},
		{name: "assigned active degraded not due early", assigned: true, active: true, degraded: true, lastAge: 29 * time.Second},
		{name: "degraded due at one minute", degraded: true, lastAge: time.Minute, wantProbes: 1},
		{name: "degraded not due early", degraded: true, lastAge: time.Minute - time.Second},
		{name: "custom active degraded uses shorter degraded interval", assigned: true, active: true, degraded: true, lastAge: time.Minute, activeInterval: 2 * time.Minute, idleInterval: 5 * time.Minute, degradedInterval: time.Minute, wantProbes: 1},
		{name: "custom active degraded is not due before shortest interval", assigned: true, active: true, degraded: true, lastAge: time.Minute - time.Second, activeInterval: 2 * time.Minute, idleInterval: 5 * time.Minute, degradedInterval: time.Minute},
		{name: "custom idle degraded uses shorter idle interval", assigned: true, degraded: true, lastAge: 30 * time.Second, activeInterval: 2 * time.Minute, idleInterval: 30 * time.Second, degradedInterval: time.Minute, wantProbes: 1},
		{name: "custom healthy active ignores shorter non-applicable intervals", assigned: true, active: true, healthy: true, lastAge: time.Minute, activeInterval: 2 * time.Minute, idleInterval: 30 * time.Second, degradedInterval: 10 * time.Second},
		{name: "custom healthy active remains due at active interval", assigned: true, active: true, healthy: true, lastAge: 2 * time.Minute, activeInterval: 2 * time.Minute, idleInterval: 30 * time.Second, degradedInterval: 10 * time.Second, wantProbes: 1},
		{name: "custom healthy idle ignores shorter non-applicable degraded interval", assigned: true, healthy: true, lastAge: time.Minute, activeInterval: 30 * time.Second, idleInterval: 2 * time.Minute, degradedInterval: 10 * time.Second},
		{name: "custom healthy idle remains due at idle interval", assigned: true, healthy: true, lastAge: 2 * time.Minute, activeInterval: 30 * time.Second, idleInterval: 2 * time.Minute, degradedInterval: 10 * time.Second, wantProbes: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
			candidate := candidates["route"]
			if test.assigned {
				assignQoECandidate(t, database, candidate.ID, now, test.active)
			}
			if test.degraded {
				seedDegradedQoE(t, database, candidate, now.Add(-test.lastAge))
			} else if test.healthy {
				seedHealthyBaseline(t, database, candidate, now.Add(-test.lastAge))
			} else {
				seedQoEObservation(t, database, candidate, qoe.Observation{
					At: now.Add(-test.lastAge), Success: true, TTFB: 200 * time.Millisecond,
					Bytes: 65536, TransferDuration: 30 * time.Millisecond, ThroughputMbps: 20,
				})
			}
			agent := &recordingQoEAgent{now: now}
			monitor := &QoEMonitor{
				Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1,
				ActiveInterval: test.activeInterval, IdleInterval: test.idleInterval,
				DegradedInterval: test.degradedInterval,
			}
			if err := monitor.Run(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if got := len(agent.callIDs()); got != test.wantProbes {
				t.Fatalf("probes=%d want=%d calls=%v", got, test.wantProbes, agent.callIDs())
			}
		})
	}
}

func TestQoEMonitorChangesOnlyUDPHealthWithFailureAndRecoveryHysteresis(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 91}})
	candidate := candidates["route"]
	before := candidateHealthByID(t, database, candidate.ID)
	trigger := make(chan struct{}, 4)
	monitor := &QoEMonitor{Store: database, Trigger: trigger}

	if changed, err := monitor.applyUDPObservation(context.Background(), candidate.ID, false); err != nil || changed {
		t.Fatalf("first failure changed=%v err=%v", changed, err)
	}
	if changed, err := monitor.applyUDPObservation(context.Background(), candidate.ID, false); err != nil || !changed {
		t.Fatalf("second failure changed=%v err=%v", changed, err)
	}
	health := candidateHealthByID(t, database, candidate.ID)
	if !health.TCPQualified || health.UDPQualified || health.Score != 91 || !health.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("health after UDP failure=%+v", health)
	}
	assertQoETrigger(t, trigger)

	for attempt := 1; attempt <= 2; attempt++ {
		if changed, err := monitor.applyUDPObservation(context.Background(), candidate.ID, true); err != nil || changed {
			t.Fatalf("recovery %d changed=%v err=%v", attempt, changed, err)
		}
	}
	if changed, err := monitor.applyUDPObservation(context.Background(), candidate.ID, true); err != nil || !changed {
		t.Fatalf("third recovery changed=%v err=%v", changed, err)
	}
	health = candidateHealthByID(t, database, candidate.ID)
	if !health.TCPQualified || !health.UDPQualified || health.Score != 91 || !health.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("health after UDP recovery=%+v", health)
	}
	assertQoETrigger(t, trigger)
}

func candidateHealthByID(t *testing.T, database *store.Store, candidateID string) store.CandidateHealth {
	t.Helper()
	rows, err := database.ListCandidateHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.CandidateID == candidateID {
			return row
		}
	}
	t.Fatalf("candidate health %s is missing", candidateID)
	return store.CandidateHealth{}
}

func assertQoETrigger(t *testing.T, trigger <-chan struct{}) {
	t.Helper()
	select {
	case <-trigger:
	default:
		t.Fatal("planning trigger is missing")
	}
}

func TestQoEMonitorRefreshesActivityBeforeCadenceSelection(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	candidate := candidates["route"]
	assignQoECandidate(t, database, candidate.ID, now, false)
	seedQoEObservation(t, database, candidate, healthyQoE(now.Add(-15*time.Second)))

	syncCalls := 0
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1,
		ActiveInterval: 15 * time.Second, IdleInterval: 5 * time.Minute,
		SyncActivity: func(ctx context.Context, at time.Time) error {
			syncCalls++
			clientID := "client-" + candidate.ID
			if err := database.RecordActivity(ctx, clientID, at, 0, 0); err != nil {
				return err
			}
			return database.RecordActivity(ctx, clientID, at, 1, 1)
		},
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 1 {
		t.Fatalf("activity sync calls=%d want=1", syncCalls)
	}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint([]string{candidate.ID}) {
		t.Fatalf("calls=%v want active probe for %s", got, candidate.ID)
	}
}

func TestQoEMonitorStopsBeforeCadenceSelectionWhenActivitySyncFails(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, _ := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	agent := &recordingQoEAgent{now: now}
	syncErr := errors.New("activity unavailable")
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1,
		SyncActivity: func(context.Context, time.Time) error { return syncErr },
	}

	err := monitor.Run(context.Background(), now)
	if !errors.Is(err, syncErr) || !strings.Contains(err.Error(), "sync WireGuard activity") {
		t.Fatalf("error=%v want wrapped activity failure", err)
	}
	if got := agent.callIDs(); len(got) != 0 {
		t.Fatalf("QoE probes started with stale activity: %v", got)
	}
}

func TestQoEMonitorSelectsTopThreeTCPAndUDPStandbyVLESSDeduplicated(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "both-100", tcp: true, udp: true, score: 100},
		{name: "udp-95", udp: true, score: 95},
		{name: "tcp-90", tcp: true, score: 90},
		{name: "udp-85", udp: true, score: 85},
		{name: "tcp-80", tcp: true, score: 80},
		{name: "udp-75", udp: true, score: 75},
		{name: "tcp-70", tcp: true, score: 70},
	})
	agent := &recordingQoEAgent{now: time.Unix(1_800_000_000, 0)}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, StandbyCandidates: 3}
	if err := monitor.Run(context.Background(), agent.now); err != nil {
		t.Fatal(err)
	}
	want := []string{
		candidates["both-100"].ID, candidates["udp-95"].ID, candidates["tcp-90"].ID,
		candidates["udp-85"].ID, candidates["tcp-80"].ID,
	}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorSelectsAssignedAndWarmTorOnly(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "assigned-missing-warm", kind: sources.KindTorBridge, tcp: true, score: 100},
		{name: "warm-standby", kind: sources.KindTorBridge, tcp: true, score: 90},
		{name: "non-warm", kind: sources.KindTorBridge, tcp: true, score: 80},
	})
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidates["assigned-missing-warm"].ID, now, false)
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{
			{CandidateID: candidates["warm-standby"].ID, Role: "warm", SocksAddr: "127.0.0.1:19050"},
			{CandidateID: candidates["non-warm"].ID, Role: "explorer", SocksAddr: "127.0.0.1:19051"},
		}
	})
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Profiles: profiles, Policy: qoe.DefaultPolicy(), Workers: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates["assigned-missing-warm"].ID, candidates["warm-standby"].ID}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorRechecksPromotionStandbyAtActiveCadence(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "vless", tcp: true, udp: true, score: 100},
		{name: "tor", kind: sources.KindTorBridge, tcp: true, score: 90},
	})
	now := time.Unix(1_800_000_000, 0)
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{{
			CandidateID: candidates["tor"].ID, Role: "warm", SocksAddr: "127.0.0.1:19050",
		}}
	})
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Profiles: profiles,
		Policy: qoe.DefaultPolicy(), Workers: 1,
		ActiveInterval: 15 * time.Second, IdleInterval: 5 * time.Minute,
		StandbyCandidates: 1,
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := len(agent.callIDs()); got != 2 {
		t.Fatalf("initial probes=%d calls=%v", got, agent.callIDs())
	}
	agent.now = now.Add(14 * time.Second)
	if err := monitor.Run(context.Background(), agent.now); err != nil {
		t.Fatal(err)
	}
	if got := len(agent.callIDs()); got != 2 {
		t.Fatalf("standby probed before active cadence: calls=%v", agent.callIDs())
	}
	agent.now = now.Add(15 * time.Second)
	if err := monitor.Run(context.Background(), agent.now); err != nil {
		t.Fatal(err)
	}
	if got := len(agent.callIDs()); got != 4 {
		t.Fatalf("standby was not rechecked at active cadence: calls=%v", agent.callIDs())
	}
}

func TestQoEMonitorUnassignedDegradedTorRequiresLiveWarmProfile(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "warm-degraded", kind: sources.KindTorBridge, tcp: true, score: 90},
		{name: "explorer-degraded", kind: sources.KindTorBridge, tcp: true, score: 80},
	})
	now := time.Unix(1_800_000_000, 0)
	seedDegradedQoE(t, database, candidates["warm-degraded"], now.Add(-time.Minute))
	seedDegradedQoE(t, database, candidates["explorer-degraded"], now.Add(-time.Minute))
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{
			{CandidateID: candidates["warm-degraded"].ID, Role: "warm", SocksAddr: "127.0.0.1:19050"},
			{CandidateID: candidates["explorer-degraded"].ID, Role: "explorer", SocksAddr: "127.0.0.1:19051"},
		}
	})
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Profiles: profiles, Policy: qoe.DefaultPolicy(), Workers: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates["warm-degraded"].ID}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorSelectsAssignedCandidateWithoutHealthOrProbeMembership(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "assigned", Fingerprint: "assigned",
		Payload: "vless://assigned@example.net:443?security=tls",
	}})
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidates["assigned"].ID, now, true)
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates["assigned"].ID}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorSelectsDegradedVLESSOutsideWorkingPool(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "degraded", tcp: true, score: 90}})
	candidate := candidates["degraded"]
	now := time.Unix(1_800_000_000, 0)
	seedDegradedQoE(t, database, candidate, now.Add(-time.Minute))
	if err := database.ReplaceWorkingPool(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidate.ID}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorPrioritizesAssignedThenDegradedThenStandby(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "standby", tcp: true, score: 100},
		{name: "degraded", tcp: true, score: 80},
		{name: "assigned", tcp: true, score: 60},
	})
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidates["assigned"].ID, now, true)
	seedDegradedQoE(t, database, candidates["degraded"], now.Add(-time.Minute))
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, StandbyCandidates: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates["assigned"].ID, candidates["degraded"].ID, candidates["standby"].ID}
	if got := agent.callIDs(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
}

func TestQoEMonitorCoalescesConcurrentProbeForCandidate(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "assigned", tcp: true, score: 90}})
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidates["assigned"].ID, now, true)
	release := make(chan struct{})
	agent := &recordingQoEAgent{now: now, release: release, started: make(chan string, 4)}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 4}
	first := runQoEMonitor(monitor, now)
	waitQoEStarts(t, agent.started, 1)
	second := runQoEMonitor(monitor, now)
	if err := waitQoERunWithin(t, second, 100*time.Millisecond); err != nil {
		t.Fatalf("overlapping tick: %v", err)
	}
	if got := len(agent.callIDs()); got != 1 {
		t.Fatalf("concurrent calls=%v", agent.callIDs())
	}
	close(release)
	if err := waitQoERun(t, first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if got := len(agent.callIDs()); got != 1 {
		t.Fatalf("calls after completion=%v", agent.callIDs())
	}
}

func TestQoEMonitorCapsWorkersAtFour(t *testing.T) {
	specs := make([]qoeCandidateSpec, 8)
	for index := range specs {
		specs[index] = qoeCandidateSpec{name: fmt.Sprintf("route-%d", index), tcp: true, udp: true, score: float64(100 - index)}
	}
	database, candidates := qoeMonitorStore(t, specs)
	now := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		assignQoECandidate(t, database, candidate.ID, now, true)
	}
	release := make(chan struct{})
	agent := &recordingQoEAgent{now: now, release: release, started: make(chan string, len(specs))}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 20}
	done := runQoEMonitor(monitor, now)
	waitQoEStarts(t, agent.started, 4)
	select {
	case fifth := <-agent.started:
		t.Fatalf("fifth probe %s started before a worker was released", fifth)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := waitQoERun(t, done); err != nil {
		t.Fatal(err)
	}
	if got := agent.maximum(); got != 4 {
		t.Fatalf("maximum concurrency=%d want=4", got)
	}
}

func TestQoEMonitorQueuedProbeUsesActualCompletionTime(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "first", tcp: true, score: 100},
		{name: "queued", tcp: true, score: 90},
	})
	sweepAt := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		seedHealthyBaseline(t, database, candidate, sweepAt.Add(-30*time.Minute))
		seedQoEObservation(t, database, candidate, failedQoE(sweepAt.Add(-10*time.Minute), "qoe_route_timeout"))
	}
	release := make(chan struct{}, 2)
	agent := &recordingQoEAgent{
		now: sweepAt.Add(-24 * time.Hour), release: release, started: make(chan string, 2),
		response:       candidateFailureResponse(sweepAt.Add(-24*time.Hour), "qoe_route_timeout"),
		customResponse: true,
	}
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1,
		StandbyCandidates: 2,
	}
	clock := &controlledQoEClock{now: sweepAt}
	monitor.Now = clock.Now
	done := runQoEMonitor(monitor, sweepAt)
	waitQoEStarts(t, agent.started, 1)
	clock.Advance(10 * time.Minute)
	release <- struct{}{}

	var queuedID string
	select {
	case queuedID = <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("queued QoE probe did not start")
	}
	queuedStartedAt := clock.Now()
	clock.Advance(time.Minute)
	release <- struct{}{}
	if err := waitQoERun(t, done); err != nil {
		t.Fatal(err)
	}

	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var queuedState qoe.State
	for _, state := range states {
		if state.CandidateID == queuedID {
			queuedState = state
			break
		}
	}
	if !queuedState.LastValidAt.After(queuedStartedAt) {
		t.Fatalf("queued sample timestamp=%s, want completion after start=%s", queuedState.LastValidAt, queuedStartedAt)
	}
	monitor.mu.Lock()
	lastAttempt := monitor.lastAttempt[queuedID]
	monitor.mu.Unlock()
	if !lastAttempt.Equal(queuedState.LastValidAt) {
		t.Fatalf("last attempt=%s, sample=%s; want completion-based cadence", lastAttempt, queuedState.LastValidAt)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.CandidateID == queuedID && event.Kind == "candidate_qoe_degraded" {
			found = true
			if !event.CreatedAt.Equal(queuedState.LastValidAt) {
				t.Fatalf("event timestamp=%s, sample=%s", event.CreatedAt, queuedState.LastValidAt)
			}
		}
	}
	if !found {
		t.Fatalf("missing degradation event for queued candidate %s: %+v", queuedID, events)
	}
}

type controlledQoEClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *controlledQoEClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *controlledQoEClock) Advance(elapsed time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(elapsed)
	clock.mu.Unlock()
}

func TestQoEMonitorInfrastructureAndTransportFailuresDoNotPersistOrTrigger(t *testing.T) {
	for _, test := range []struct {
		name     string
		response agentapi.ProbeResponse
		err      error
	}{
		{name: "infrastructure response", response: agentapi.ProbeResponse{
			FailureClass: agentapi.FailureInfrastructure,
			QoE:          &qoe.Observation{Infrastructure: true, ErrorCode: "qoe_endpoint_unavailable"},
		}},
		{name: "transport error", err: errors.New("agent unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, _ := qoeMonitorStore(t, []qoeCandidateSpec{{name: "standby", tcp: true, score: 90}})
			trigger := make(chan struct{}, 1)
			agent := &recordingQoEAgent{now: time.Unix(1_800_000_000, 0), response: test.response, err: test.err, customResponse: true}
			monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Trigger: trigger}
			if err := monitor.Run(context.Background(), agent.now); err != nil {
				t.Fatal(err)
			}
			states, err := database.ListCandidateQoEStates(context.Background())
			if err != nil || len(states) != 0 {
				t.Fatalf("states=%+v err=%v", states, err)
			}
			if events, _ := database.ListEvents(context.Background(), 10); len(events) != 0 {
				t.Fatalf("events=%+v", events)
			}
			select {
			case <-trigger:
				t.Fatal("infrastructure failure triggered placement")
			default:
			}
		})
	}
}

func TestQoEMonitorInfrastructureFailureRetriesOnlyAtCadence(t *testing.T) {
	database, _ := qoeMonitorStore(t, []qoeCandidateSpec{{name: "standby", tcp: true, score: 90}})
	now := time.Unix(1_800_000_000, 0)
	agent := &recordingQoEAgent{now: now, response: agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, customResponse: true}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1}
	for _, at := range []time.Time{now, now.Add(time.Second), now.Add(5 * time.Minute)} {
		agent.now = at
		if err := monitor.Run(context.Background(), at); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(agent.callIDs()); got != 2 {
		t.Fatalf("calls=%v want initial and five-minute retry", agent.callIDs())
	}
}

func TestQoEMonitorCanceledQueuedJobsDoNotConsumeCadence(t *testing.T) {
	specs := []qoeCandidateSpec{
		{name: "assigned-a", tcp: true, score: 90},
		{name: "assigned-b", tcp: true, score: 80},
		{name: "assigned-c", tcp: true, score: 70},
		{name: "assigned-d", tcp: true, score: 60},
	}
	database, candidates := qoeMonitorStore(t, specs)
	now := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		assignQoECandidate(t, database, candidate.ID, now, true)
	}
	release := make(chan struct{})
	agent := &recordingQoEAgent{now: now, release: release, started: make(chan string, len(specs))}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx, now) }()
	waitQoEStarts(t, agent.started, 1)
	cancel()
	if err := waitQoERun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run error=%v want context.Canceled", err)
	}
	close(release)
	if got := len(agent.callIDs()); got != 1 {
		t.Fatalf("calls after canceled run=%v want one started probe", agent.callIDs())
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := len(agent.callIDs()); got != len(specs) {
		t.Fatalf("calls after immediate retry=%v want all %d candidates attempted once", agent.callIDs(), len(specs))
	}
}

func TestQoEMonitorDiscardsResultWhenSourceDisabledWhileInFlight(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "removed", tcp: true, score: 90}})
	candidate := candidates["removed"]
	now := time.Unix(1_800_000_000, 0)
	release := make(chan struct{})
	agent := &recordingQoEAgent{now: now, release: release, started: make(chan string, 1)}
	trigger := make(chan struct{}, 1)
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Trigger: trigger}
	done := runQoEMonitor(monitor, now)
	waitQoEStarts(t, agent.started, 1)
	if err := database.ReplaceCandidates(context.Background(), candidate.SourceID, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
		Payload: "vless://replacement@example.net:443?security=tls",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateSource(
		context.Background(), candidate.SourceID, "disabled source", false,
	); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := waitQoERun(t, done); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 0 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	if events, _ := database.ListEvents(context.Background(), 10); len(events) != 0 {
		t.Fatalf("events=%+v", events)
	}
	select {
	case <-trigger:
		t.Fatal("stale result triggered placement")
	default:
	}
}

func TestQoEMonitorObservesAssignedDrainingCandidate(t *testing.T) {
	database, candidates := qoeMonitorStore(
		t,
		[]qoeCandidateSpec{
			{name: "assigned", tcp: true, score: 90},
			{name: "replacement", tcp: true, score: 80},
		},
	)
	candidate := candidates["assigned"]
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidate.ID, now, true)
	if err := database.ReplaceCandidates(
		context.Background(),
		candidate.SourceID,
		[]store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "replacement",
			Fingerprint: "replacement",
			Payload:     "vless://replacement@example.net:443?security=tls",
		}},
		15*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1,
	}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	calls := agent.callIDs()
	if len(calls) == 0 || calls[0] != candidate.ID {
		t.Fatalf("calls=%v, want assigned draining candidate first", calls)
	}
}

func TestQoEMonitorRejectsDrainingResultAfterAssignmentClears(t *testing.T) {
	ctx := context.Background()
	database, candidates := qoeMonitorStore(
		t,
		[]qoeCandidateSpec{
			{name: "assigned", tcp: true, score: 90},
			{name: "replacement", tcp: true, score: 80},
		},
	)
	candidate := candidates["assigned"]
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidate.ID, now, true)
	seedHealthyBaseline(t, database, candidate, now.Add(-30*time.Second))
	for _, at := range []time.Time{
		now.Add(-17 * time.Second),
		now.Add(-16 * time.Second),
	} {
		seedQoEObservation(
			t, database, candidate, failedQoE(at, "qoe_route_timeout"),
		)
	}
	beforeSamples := mustQoESampleCount(t, database, candidate.ID, 100)
	beforeState := mustSingleQoEState(t, database)
	release := make(chan struct{})
	agent := &recordingQoEAgent{
		now: now, release: release, started: make(chan string, 1),
		response:       candidateFailureResponse(now, "qoe_route_timeout"),
		customResponse: true,
	}
	trigger := make(chan struct{}, 1)
	monitor := &QoEMonitor{
		Store: database, Agent: agent, Policy: qoe.DefaultPolicy(),
		Workers: 1, Trigger: trigger,
	}
	done := runQoEMonitor(monitor, now)
	waitQoEStarts(t, agent.started, 1)
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
		ClientID: "client-" + candidate.ID,
		TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := waitQoERun(t, done); err != nil {
		t.Fatal(err)
	}
	if after := mustQoESampleCount(
		t, database, candidate.ID, 100,
	); after != beforeSamples {
		t.Fatalf("stale draining QoE wrote sample count %d -> %d",
			beforeSamples, after)
	}
	states, err := database.ListCandidateQoEStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var afterState qoe.State
	for _, state := range states {
		if state.CandidateID == candidate.ID {
			afterState = state
			break
		}
	}
	if !reflect.DeepEqual(afterState, beforeState) {
		t.Fatalf("stale draining QoE changed state: before=%+v after=%+v",
			beforeState, afterState)
	}
	select {
	case <-trigger:
		t.Fatal("stale draining QoE signaled placement")
	default:
	}
}

func TestQoEMonitorEmitsDegradationTransitionAndSignalsOnce(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "assigned", tcp: true, score: 90}})
	candidate := candidates["assigned"]
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidate.ID, now, true)
	seedHealthyBaseline(t, database, candidate, now.Add(-60*time.Second))
	seedQoEObservation(t, database, candidate, failedQoE(now.Add(-31*time.Second), "qoe_route_timeout"))
	trigger := make(chan struct{}, 2)
	agent := &recordingQoEAgent{now: now, response: candidateFailureResponse(now, "qoe_route_timeout"), customResponse: true}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Trigger: trigger}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 || events[0].Kind != "candidate_qoe_degraded" || events[0].CandidateID != candidate.ID {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if !strings.Contains(events[0].Message, "reason=qoe_route_timeout ttfb_ms=0 throughput_mbps=0.000 window_bad=2 window_valid=5") {
		t.Fatalf("unsafe or unexpected event message %q", events[0].Message)
	}
	select {
	case <-trigger:
	default:
		t.Fatal("degradation did not trigger placement")
	}
	select {
	case <-trigger:
		t.Fatal("degradation signaled more than once")
	default:
	}
	retryAt := now.Add(defaultQoEActiveInterval)
	agent.now = retryAt
	if err := monitor.Run(context.Background(), retryAt); err != nil {
		t.Fatal(err)
	}
	events, err = database.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("unchanged degradation events=%+v err=%v", events, err)
	}
	select {
	case <-trigger:
		t.Fatal("unchanged degradation triggered placement")
	default:
	}
}

func TestQoEMonitorRollsBackTransitionWhenEventWriteFailsAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database, candidates := qoeMonitorStoreAtPath(t, path, []qoeCandidateSpec{{name: "assigned", tcp: true, score: 90}})
	candidate := candidates["assigned"]
	now := time.Unix(1_800_000_000, 0)
	assignQoECandidate(t, database, candidate.ID, now, true)
	seedHealthyBaseline(t, database, candidate, now.Add(-60*time.Second))
	seedQoEObservation(t, database, candidate, failedQoE(now.Add(-31*time.Second), "qoe_route_timeout"))
	beforeState := mustSingleQoEState(t, database)
	beforeSamples := mustQoESampleCount(t, database, candidate.ID, 20)

	failureDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = failureDB.Close() })
	if _, err := failureDB.Exec(`
		CREATE TRIGGER reject_qoe_transition_event
		BEFORE INSERT ON events
		WHEN NEW.kind = 'candidate_qoe_degraded'
		BEGIN SELECT RAISE(ABORT, 'forced qoe event failure'); END
	`); err != nil {
		t.Fatal(err)
	}

	trigger := make(chan struct{}, 2)
	agent := &recordingQoEAgent{now: now, response: candidateFailureResponse(now, "qoe_route_timeout"), customResponse: true}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Trigger: trigger}
	if err := monitor.Run(context.Background(), now); err == nil || !strings.Contains(err.Error(), "forced qoe event failure") {
		t.Fatalf("Run error=%v, want forced event failure", err)
	}
	if got := mustSingleQoEState(t, database); got != beforeState {
		t.Fatalf("state changed after event failure: before=%+v after=%+v", beforeState, got)
	}
	if got := mustQoESampleCount(t, database, candidate.ID, 20); got != beforeSamples {
		t.Fatalf("samples=%d want rollback to %d", got, beforeSamples)
	}
	if events, err := database.ListEvents(context.Background(), 10); err != nil || len(events) != 0 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	select {
	case <-trigger:
		t.Fatal("failed transition triggered placement")
	default:
	}

	if _, err := failureDB.Exec(`DROP TRIGGER reject_qoe_transition_event`); err != nil {
		t.Fatal(err)
	}
	retryAt := now.Add(defaultQoEActiveInterval)
	agent.now = retryAt
	if err := monitor.Run(context.Background(), retryAt); err != nil {
		t.Fatal(err)
	}
	afterState := mustSingleQoEState(t, database)
	if afterState.Status != qoe.StatusDegraded {
		t.Fatalf("state=%+v want degraded", afterState)
	}
	if got := mustQoESampleCount(t, database, candidate.ID, 20); got != beforeSamples+1 {
		t.Fatalf("samples=%d want=%d", got, beforeSamples+1)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 || events[0].Kind != "candidate_qoe_degraded" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	select {
	case <-trigger:
	default:
		t.Fatal("committed degradation did not trigger placement")
	}
}

func TestQoEMonitorEmitsRecoveryWithoutPlacementSignal(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, score: 90}})
	candidate := candidates["route"]
	now := time.Unix(1_800_000_000, 0)
	seedHealthyBaseline(t, database, candidate, now.Add(-20*time.Minute))
	for index := 0; index < 3; index++ {
		seedQoEObservation(t, database, candidate, failedQoE(now.Add(-10*time.Minute+time.Duration(index)*time.Second), "qoe_route_timeout"))
	}
	for index := 0; index < 18; index++ {
		seedQoEObservation(t, database, candidate, healthyQoE(now.Add(-3*time.Minute+time.Duration(index)*time.Second)))
	}
	beforeEvents, err := database.ListEvents(context.Background(), 10)
	if err != nil || len(beforeEvents) != 1 || beforeEvents[0].Kind != "candidate_qoe_degraded" {
		t.Fatalf("seed events=%+v err=%v", beforeEvents, err)
	}
	trigger := make(chan struct{}, 1)
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Trigger: trigger}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil || len(events) != len(beforeEvents)+1 || events[0].Kind != "candidate_qoe_recovered" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	select {
	case <-trigger:
		t.Fatal("recovery triggered placement")
	default:
	}
}

func TestQoEMonitorPrunesRetentionAtMostHourlyInBoundedBatches(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, score: 90}})
	candidate := candidates["route"]
	now := time.Unix(1_800_000_000, 0)
	for index := 0; index < qoeRetentionBatch+1; index++ {
		seedQoEObservation(t, database, candidate, healthyQoE(now.Add(-8*24*time.Hour+time.Duration(index)*time.Second)))
	}
	agent := &recordingQoEAgent{now: now, response: agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure}, customResponse: true}
	monitor := &QoEMonitor{Store: database, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1, Retention: 7 * 24 * time.Hour}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	remaining := mustQoESampleCount(t, database, candidate.ID, qoeRetentionBatch+2)
	if remaining != 1 {
		t.Fatalf("remaining after bounded prune=%d want=1", remaining)
	}
	if err := monitor.Run(context.Background(), now.Add(59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := mustQoESampleCount(t, database, candidate.ID, qoeRetentionBatch+2); got != remaining {
		t.Fatalf("pruned again inside hour: samples=%d want=%d", got, remaining)
	}
	if err := monitor.Run(context.Background(), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := mustQoESampleCount(t, database, candidate.ID, qoeRetentionBatch+2); got != 0 {
		t.Fatalf("samples after hourly prune=%d", got)
	}
}

type qoeCandidateSpec struct {
	name     string
	kind     sources.Kind
	tcp, udp bool
	score    float64
}

func qoeMonitorStore(t *testing.T, specs []qoeCandidateSpec) (*store.Store, map[string]store.Candidate) {
	t.Helper()
	return qoeMonitorStoreAtPath(t, filepath.Join(t.TempDir(), "state.db"), specs)
}

func qoeMonitorStoreAtPath(t *testing.T, path string, specs []qoeCandidateSpec) (*store.Store, map[string]store.Candidate) {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	inputs := make([]store.CandidateInput, 0, len(specs))
	for index, spec := range specs {
		kind := spec.kind
		if kind == "" {
			kind = sources.KindVLESS
		}
		payload := fmt.Sprintf("vless://%s@example.net:443?security=tls", spec.name)
		if kind == sources.KindTorBridge {
			payload = fmt.Sprintf("Bridge 192.0.2.%d:443 %040d", index+1, index+1)
		}
		inputs = append(inputs, store.CandidateInput{Kind: kind, Label: spec.name, Fingerprint: spec.name, Payload: payload})
	}
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(context.Background())
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(context.Background(), sourceRows[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	candidates := make(map[string]store.Candidate, len(rows))
	for _, candidate := range rows {
		candidates[candidate.Fingerprint] = candidate
	}
	now := time.Unix(1_799_000_000, 0)
	fingerprints := make([]string, 0, len(specs))
	for _, spec := range specs {
		candidate := candidates[spec.name]
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
				Full: true, Success: true, Score: spec.score, At: now.Add(time.Duration(attempt) * time.Second),
				ResetWindow: 5 * time.Hour,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
			CandidateID: candidate.ID, Score: spec.score, TCPQualified: spec.tcp,
			UDPQualified: spec.udp, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		fingerprints = append(fingerprints, candidate.Fingerprint)
	}
	if err := database.ReplaceWorkingPool(context.Background(), fingerprints, nil); err != nil {
		t.Fatal(err)
	}
	return database, candidates
}

func assignQoECandidate(t *testing.T, database *store.Store, candidateID string, now time.Time, active bool) {
	t.Helper()
	clientID := "client-" + candidateID
	if err := database.PutClient(context.Background(), store.ClientRecord{
		ID: clientID, Name: clientID, Address: qoeClientAddress(candidateID), PublicKey: clientID,
	}, "config"); err != nil {
		t.Fatal(err)
	}
	if active {
		if err := database.RecordActivity(context.Background(), clientID, now, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := database.RecordActivity(context.Background(), clientID, now, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
		ClientID: clientID, TCPOutbound: candidateID, TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

func qoeClientAddress(candidateID string) string {
	var sum int
	for _, char := range candidateID {
		sum += int(char)
	}
	return fmt.Sprintf("10.88.%d.%d/32", (sum/250)%250, sum%250+1)
}

func seedHealthyBaseline(t *testing.T, database *store.Store, candidate store.Candidate, last time.Time) {
	t.Helper()
	for index := 4; index >= 0; index-- {
		seedQoEObservation(t, database, candidate, healthyQoE(last.Add(-time.Duration(index)*time.Second)))
	}
}

func seedDegradedQoE(t *testing.T, database *store.Store, candidate store.Candidate, last time.Time) {
	t.Helper()
	for index := 2; index >= 0; index-- {
		seedQoEObservation(t, database, candidate, failedQoE(last.Add(-time.Duration(index)*time.Second), "qoe_route_timeout"))
	}
}

func seedQoEObservation(t *testing.T, database *store.Store, candidate store.Candidate, observation qoe.Observation) {
	t.Helper()
	if _, _, err := database.RecordCandidateQoE(context.Background(), candidate, observation, qoe.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
}

func healthyQoE(at time.Time) qoe.Observation {
	return qoe.Observation{At: at, Success: true, TTFB: 200 * time.Millisecond, TransferDuration: 30 * time.Millisecond, Bytes: 65536, ThroughputMbps: 20}
}

func failedQoE(at time.Time, code string) qoe.Observation {
	return qoe.Observation{At: at, ErrorCode: code}
}

func candidateFailureResponse(at time.Time, code string) agentapi.ProbeResponse {
	observation := failedQoE(at, code)
	return agentapi.ProbeResponse{FailureClass: agentapi.FailureCandidate, ErrorCode: code, QoE: &observation}
}

func mustQoESampleCount(t *testing.T, database *store.Store, candidateID string, limit int) int {
	t.Helper()
	samples, err := database.ListCandidateQoESamples(context.Background(), candidateID, limit)
	if err != nil {
		t.Fatal(err)
	}
	return len(samples)
}

func mustSingleQoEState(t *testing.T, database *store.Store) qoe.State {
	t.Helper()
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	return states[0]
}

type recordingQoEAgent struct {
	mu             sync.Mutex
	now            time.Time
	response       agentapi.ProbeResponse
	err            error
	customResponse bool
	release        <-chan struct{}
	started        chan string
	calls          []agentapi.ProbeRequest
	active         int
	maxActive      int
}

func (agent *recordingQoEAgent) ProbeQoE(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.calls = append(agent.calls, request)
	agent.active++
	if agent.active > agent.maxActive {
		agent.maxActive = agent.active
	}
	agent.mu.Unlock()
	defer func() {
		agent.mu.Lock()
		agent.active--
		agent.mu.Unlock()
	}()
	if agent.started != nil {
		agent.started <- request.CandidateID
	}
	if agent.release != nil {
		select {
		case <-agent.release:
		case <-ctx.Done():
			return agentapi.ProbeResponse{}, ctx.Err()
		}
	}
	if agent.customResponse {
		response := agent.response
		if response.CandidateID == "" {
			response.CandidateID = request.CandidateID
		}
		return response, agent.err
	}
	observation := healthyQoE(agent.now)
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true, QoE: &observation}, nil
}

func (agent *recordingQoEAgent) callIDs() []string {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	ids := make([]string, len(agent.calls))
	for index, call := range agent.calls {
		ids[index] = call.CandidateID
	}
	return ids
}

func (agent *recordingQoEAgent) maximum() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.maxActive
}

func runQoEMonitor(monitor *QoEMonitor, now time.Time) <-chan error {
	done := make(chan error, 1)
	go func() { done <- monitor.Run(context.Background(), now) }()
	return done
}

func waitQoEStarts(t *testing.T, started <-chan string, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d/%d probes started", index, count)
		}
	}
}

func waitQoERun(t *testing.T, done <-chan error) error {
	t.Helper()
	return waitQoERunWithin(t, done, 3*time.Second)
}

func waitQoERunWithin(t *testing.T, done <-chan error, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatal("QoE monitor did not finish")
		return nil
	}
}
