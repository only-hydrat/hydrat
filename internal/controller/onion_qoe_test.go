package controller

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"sync"
	"testing"
	"time"
)

type scopeQoEAgent struct {
	mu    sync.Mutex
	calls []agentapi.ProbeRequest
}

func (a *scopeQoEAgent) ProbeQoE(_ context.Context, r agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	a.mu.Lock()
	a.calls = append(a.calls, r)
	a.mu.Unlock()
	o := healthyQoE(time.Now())
	if r.Onion {
		o.ComparisonPolicy = qoe.OnionComparisonPolicy
		o.ThroughputMbps = 0
		o.ApplicationChecks = []qoe.HTTPCheck{{Service: "onion_search", Path: "route", OK: true, Code: "ok"}}
	}
	return agentapi.ProbeResponse{CandidateID: r.CandidateID, Success: true, ProfileInstance: r.ProfileInstance, QoE: &o}, nil
}
func TestOnionQoEUsesSharedBudgetAndStopsWithoutDemand(t *testing.T) {
	db, cs := qoeMonitorStore(t, []qoeCandidateSpec{{name: "tor", kind: sources.KindTorBridge, tcp: true, score: 90}, {name: "vless", tcp: true, score: 80}})
	now := time.Now()
	c := cs["tor"]
	assignQoECandidate(t, db, cs["vless"].ID, now, true)
	if err := db.SetOnionEnabled(t.Context(), "client-"+cs["vless"].ID, true); err != nil {
		t.Fatal(err)
	}
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{{CandidateID: c.ID, Instance: "instance-a", Role: "warm", OnionReady: true, StartedAt: now.Add(-time.Hour)}}
	})
	agent := &scopeQoEAgent{}
	m := &QoEMonitor{Store: db, Agent: agent, Profiles: profiles, Workers: 2}
	if err := m.Run(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if len(agent.calls) > 2 {
		t.Fatalf("worker budget exceeded %d", len(agent.calls))
	}
	foundOnion, foundOrdinary := false, false
	for _, r := range agent.calls {
		foundOnion = foundOnion || r.Onion
		foundOrdinary = foundOrdinary || !r.Onion
	}
	if !foundOnion || !foundOrdinary {
		t.Fatalf("scoped jobs=%+v", agent.calls)
	}
	states, err := db.ListOnionQoEStates(t.Context())
	if err != nil || len(states) != 1 || states[0].State.WindowValid != 1 {
		t.Fatalf("onion not recorded %+v %v", states, err)
	}
	if samples, err := db.ListCandidateQoESamples(t.Context(), c.ID, 10); err != nil || len(samples) != 0 {
		t.Fatal("onion wrote ordinary samples", samples, err)
	}
	if err := db.SetOnionEnabled(t.Context(), "client-"+cs["vless"].ID, false); err != nil {
		t.Fatal(err)
	}
	agent.calls = nil
	if err := m.Run(t.Context(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, r := range agent.calls {
		if r.Onion {
			t.Fatal("onion probe after permission removed")
		}
	}
}
func TestOnionPoolIncludesQualifiedBridgesOutsideWorkingSubset(t *testing.T) {
	db, cs := qoeMonitorStore(t, []qoeCandidateSpec{{name: "a", kind: sources.KindTorBridge, tcp: true, score: 90}, {name: "b", kind: sources.KindTorBridge, tcp: true, score: 80}, {name: "c", kind: sources.KindTorBridge, tcp: true, score: 70}})
	if err := db.ReplaceWorkingPool(t.Context(), []string{cs["a"].Fingerprint}, nil); err != nil {
		t.Fatal(err)
	}
	req := store.TorProfileSetRequest{UsePersistedWorkingPool: true}
	before, err := db.LoadTorProfileSetSnapshot(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Candidates) != 1 {
		t.Fatal("unexpected ordinary pool", len(before.Candidates))
	}
	if err := db.PutClient(t.Context(), store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetOnionEnabled(t.Context(), "alice", true); err != nil {
		t.Fatal(err)
	}
	after, err := db.LoadTorProfileSetSnapshot(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Candidates) != 3 {
		t.Fatal("qualified discovery starved", len(after.Candidates))
	}
}

func TestOnionComparisonWorksWithExistingTorInventory(t *testing.T) {
	for _, peerOK := range []bool{true, false} {
		t.Run(map[bool]string{true: "independent success", false: "shared outage"}[peerOK], func(t *testing.T) {
			db, cs := qoeMonitorStore(t, []qoeCandidateSpec{{name: "a", kind: sources.KindTorBridge, tcp: true, score: 90}, {name: "b", kind: sources.KindTorBridge, tcp: true, score: 80}})
			now := time.Now()
			ps := profileProviderFunc(func() []torpool.Profile {
				return []torpool.Profile{{CandidateID: cs["a"].ID, Instance: "a", OnionReady: true, Role: "warm"}, {CandidateID: cs["b"].ID, Instance: "b", OnionReady: true, Role: "warm"}}
			})
			agent := &recordingQoEAgent{customResponse: true}
			m := &QoEMonitor{Store: db, Agent: agent, Profiles: ps, controlRequests: map[string]time.Time{cs["a"].ID: now}}
			for i := 0; i < 3; i++ {
				peer := qoe.Observation{Success: peerOK, Infrastructure: !peerOK, UnconfirmedHTTP: !peerOK, ComparisonPolicy: qoe.OnionComparisonPolicy, TTFB: time.Second, ApplicationChecks: []qoe.HTTPCheck{{Service: "onion_search", Path: "route", OK: peerOK, Code: "ok"}}}
				if !peerOK {
					peer.ErrorCode = qoe.ReasonApplicationGates
					peer.ApplicationChecks[0].Code = "timeout"
				}
				agent.response = agentapi.ProbeResponse{CandidateID: cs["b"].ID, ProfileInstance: "b", QoE: &peer}
				if err := m.probe(t.Context(), now, m.clockNow(), qoeProbeJob{candidate: cs["b"], onionInstance: "b"}); err != nil {
					t.Fatal(err)
				}
				fail := qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: qoe.OnionComparisonPolicy, ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: []qoe.HTTPCheck{{Service: "onion_search", Path: "route", Code: "timeout"}}}
				agent.response = agentapi.ProbeResponse{CandidateID: cs["a"].ID, ProfileInstance: "a", QoE: &fail}
				if err := m.probe(t.Context(), now.Add(40*time.Second), m.clockNow(), qoeProbeJob{candidate: cs["a"], onionInstance: "a"}); err != nil {
					t.Fatal(err)
				}
				now = now.Add(43 * time.Second)
			}
			if _, exists := m.controlRequests[cs["a"].ID]; !exists {
				t.Fatal("onion confirmation removed ordinary control request")
			}
			states, err := db.ListOnionQoEStates(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			degraded := false
			for _, s := range states {
				if s.State.CandidateID == cs["a"].ID {
					degraded = s.State.Status == qoe.StatusDegraded
				}
			}
			if degraded != peerOK {
				t.Fatalf("confirmed degradation=%v peerOK=%v", degraded, peerOK)
			}
		})
	}
}
