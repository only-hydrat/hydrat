package controller

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"testing"
	"time"
)

func TestQoEMonitorFastAvailabilityRecheck(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, reason string
		age          time.Duration
		active       bool
		want         int
	}{
		{"confirmed timeout", qoe.ReasonRouteTimeout, 5 * time.Second, true, 1},
		{"confirmed TLS", qoe.ReasonRouteTLS, 5 * time.Second, true, 1},
		{"not before five seconds", qoe.ReasonRouteTimeout, 4 * time.Second, true, 0},

		{"idle unchanged", qoe.ReasonRouteTimeout, 5 * time.Second, false, 0},
		{"speed unchanged", qoe.ReasonSustainedThroughput, 5 * time.Second, true, 0},
		{"success restores cadence", "", 5 * time.Second, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
			c := candidates["route"]
			assignQoECandidate(t, db, c.ID, now, tc.active)
			obs := healthyQoE(now.Add(-tc.age))
			if tc.reason != "" {
				obs = failedQoE(now.Add(-tc.age), tc.reason)
			}
			seedQoEObservation(t, db, c, obs)
			agent := &recordingQoEAgent{now: now}
			m := &QoEMonitor{Store: db, Agent: agent, Policy: qoe.DefaultPolicy(), Workers: 1}
			if err := m.Run(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if got := len(agent.callIDs()); got != tc.want {
				t.Fatalf("probes=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestFastAvailabilityRecheckBounds(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name  string
		state qoe.State
		want  bool
	}{
		{"fresh", qoe.State{LastReason: qoe.ReasonRouteTimeout, LastValidAt: now}, true},
		{"future", qoe.State{LastReason: qoe.ReasonRouteTimeout, LastValidAt: now.Add(time.Second)}, false},
		{"expired", qoe.State{LastReason: qoe.ReasonRouteTimeout, LastValidAt: now.Add(-time.Minute - time.Second)}, false},
		{"missing", qoe.State{LastReason: qoe.ReasonRouteTimeout}, false},
		{"already degraded", qoe.State{Status: qoe.StatusDegraded, LastReason: qoe.ReasonRouteTimeout, LastValidAt: now}, false},
		{"infra", qoe.State{LastReason: "agent_unavailable", LastValidAt: now}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsFastAvailabilityRecheck(now, tc.state); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func TestFastRechecksStillRequireThreeAcceptedFailures(t *testing.T) {
	now := time.Unix(1800000000, 0)
	db, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	c := candidates["route"]
	trigger := make(chan struct{}, 4)
	agent := &recordingQoEAgent{customResponse: true}
	m := &QoEMonitor{Store: db, Agent: agent, Policy: qoe.DefaultPolicy(), Trigger: trigger}
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * 6 * time.Second)
		agent.response = candidateFailureResponse(at, qoe.ReasonRouteTimeout)
		if err := m.probe(context.Background(), at, time.Now(), qoeProbeJob{candidate: c}); err != nil {
			t.Fatal(err)
		}
		state := mustSingleQoEState(t, db)
		if i < 2 {
			if state.Status == qoe.StatusDegraded {
				t.Fatal("evacuated early")
			}
			select {
			case <-trigger:
				t.Fatal("early planning signal")
			default:
			}
		} else {
			if state.Status != qoe.StatusDegraded {
				t.Fatalf("not degraded: %+v", state)
			}
			assertQoETrigger(t, trigger)
		}
	}
}
