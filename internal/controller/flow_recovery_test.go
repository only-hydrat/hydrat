package controller

import (
	"encoding/json"
	"testing"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestFlowRecoveryRequiresPersistedHardFailureTransition(t *testing.T) {
	old := dataplane.DesiredPlan{Generation: 1, FailClosed: true, DirectSuffixes: []string{".ru"}, Outbounds: []dataplane.Outbound{{ID: "old", Protocol: dataplane.ProtocolVLESS}},
		Clients: []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old", BlockUDP: true}}}
	next := old
	next.Generation = 2
	next.Clients = []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new"}}
	encoded, _ := json.Marshal(old)
	for _, reason := range []PlacementReason{PlacementPeriodic, PlacementClientLifecycle, PlacementHardFailure} {
		state := store.PlanState{DesiredGeneration: 2, AppliedGeneration: 1, DesiredReason: string(reason), AppliedPlan: encoded}
		got, err := confirmedFlowRecoveries(state, next)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if reason == PlacementHardFailure {
			want = 1
		}
		if len(got) != want {
			t.Fatalf("reason=%s scopes=%+v", reason, got)
		}
	}
	for _, route := range []dataplane.ClientRoute{
		{ClientID: "alice", SourceCIDR: "10.44.0.9/32", TCPOutbound: "new"},
		{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old"},
		{ClientID: "alice", SourceCIDR: "10.44.0.2/32", BlockTCP: true},
		{ClientID: "bob", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new"},
	} {
		next.Clients = []dataplane.ClientRoute{route}
		got, err := confirmedFlowRecoveries(store.PlanState{DesiredGeneration: 2, AppliedGeneration: 1, DesiredReason: string(PlacementHardFailure), AppliedPlan: encoded}, next)
		if err != nil || len(got) != 0 {
			t.Fatalf("unsafe transition %+v: %+v %v", route, got, err)
		}
	}
}
