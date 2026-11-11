package dataplane

import (
	"github.com/only-hydrat/hydrat/internal/xrayflow"
	"path/filepath"
	"testing"
)

func TestOnionRevokeDoesNotResetOrdinaryTraffic(t *testing.T) {
	old := DesiredPlan{Clients: []ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", TCPOutbound: "normal", OnionEnabled: true, OnionOutbound: "onion-a"}}}
	next := DesiredPlan{Clients: []ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", TCPOutbound: "normal"}}}
	scopes := onionRecoveries(old, next)
	if len(scopes) != 1 || scopes[0].FailedOutbound != "onion-a" || !scopes[0].Onion {
		t.Fatal(scopes)
	}
	if !recoveryStillApplicable(next, scopes[0]) {
		t.Fatal("revoke discarded")
	}
	if recoveryStillApplicable(old, scopes[0]) {
		t.Fatal("would reset reenabled route")
	}
	if !recoveryStillApplicable(DesiredPlan{}, scopes[0]) {
		t.Fatal("deleted client not revoked")
	}
}

func TestOnionRevocationClosesOnlyOnionFlows(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	r, err := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	old, _, _ := recoveryPlans()
	old.Clients[0].OnionEnabled = true
	old.Clients[0].OnionOutbound = "onion-a"
	old.Outbounds = append(old.Outbounds, Outbound{ID: "onion-a", Protocol: ProtocolTor})
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	onionClosed, normalClosed, otherClosed := 0, 0, 0
	_, f := a.registry.Track(t.Context(), "onion-a", "10.44.0.2", "tcp", func() { onionClosed++ })
	defer f()
	_, g := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { normalClosed++ })
	defer g()
	_, h := a.registry.Track(t.Context(), "onion-b", "10.44.0.3", "tcp", func() { otherClosed++ })
	defer h()
	next := old
	next.Generation++
	next.Clients = append([]ClientRoute(nil), old.Clients...)
	next.Clients[0].OnionEnabled = false
	next.Clients[0].OnionOutbound = ""
	if err := r.Apply(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if onionClosed != 1 || normalClosed != 0 || otherClosed != 0 {
		t.Fatal(onionClosed, normalClosed, otherClosed)
	}
}
