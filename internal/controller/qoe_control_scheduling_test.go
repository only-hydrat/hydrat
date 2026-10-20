package controller

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestQoEControlJobsShareWorkerBudgetWithoutRecursiveRequestsOrFreshnessExtension(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{
		{name: "target", domain: "a", tcp: true, score: 95},
		{name: "peer-b", domain: "b", tcp: true, score: 94},
		{name: "peer-c", domain: "c", tcp: true, score: 93},
		{name: "standby-d", domain: "d", tcp: true, score: 92},
		{name: "standby-e", domain: "e", tcp: true, score: 91},
	})
	at := time.Unix(1800000000, 0)
	target := candidates["target"]
	assignQoECandidate(t, database, target.ID, at, true)
	seedHealthyBaseline(t, database, target, at.Add(-time.Minute))
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v %v", states, err)
	}
	before := states[0]
	unknown := qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: "policy", ErrorCode: qoe.ReasonRouteTimeout, ApplicationChecks: []qoe.HTTPCheck{{Service: "qoe_endpoint", Path: "route", Code: "timeout"}}}
	agent := &recordingQoEAgent{customResponse: true, response: agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure, QoE: &unknown}}
	monitor := &QoEMonitor{Store: database, Agent: agent, Workers: 4}
	monitor.requestQoEControl(target, at)
	byID := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	controls := monitor.requestedQoEControls(at, byID, func(string) bool { return true })
	if len(controls) != 2 {
		t.Fatalf("controls=%v", controls)
	}
	if err := monitor.Run(context.Background(), at); err != nil {
		t.Fatal(err)
	}
	if calls := agent.callIDs(); len(calls) > 4 || agent.maximum() > 4 {
		t.Fatalf("control work escaped worker budget: calls=%v max=%d", calls, agent.maximum())
	}
	for _, id := range agent.callIDs() {
		if controls[id] {
			if _, recursive := monitor.controlRequests[id]; recursive {
				t.Fatalf("control %s recursively requested another control", id)
			}
		}
	}
	states, err = database.ListCandidateQoEStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.CandidateID == target.ID && (!state.LastValidAt.Equal(before.LastValidAt) || state.Status != before.Status || state.WindowValid != before.WindowValid) {
			t.Fatalf("unknown changed healthy evidence: before=%+v after=%+v", before, state)
		}
	}
}
