package controller

import (
	"context"
	"fmt"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"path/filepath"
	"testing"
	"time"
)

func TestOnionSelectionStickyIsolatedAndFailsClosed(t *testing.T) {
	e := &Engine{torSecret: []byte("test-secret")}
	profiles := map[string]torpool.Profile{"a": {CandidateID: "a", Slot: 0, SocksAddr: "127.0.0.1:19050", Role: "warm", OnionReady: true}, "b": {CandidateID: "b", Slot: 1, SocksAddr: "127.0.0.1:19051", Role: "warm", OnionReady: true}}
	candidates := []scheduler.Candidate{{ID: "a", Protocol: scheduler.ProtocolTor, TCPQualified: true, Warm: true, Score: 10}, {ID: "b", Protocol: scheduler.ProtocolTor, TCPQualified: true, Warm: true, Score: 20}}
	out := map[string]dataplane.Outbound{}
	r := dataplane.ClientRoute{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "ordinary"}
	c := store.ClientRecord{ID: "alice", OnionEnabled: true}
	e.attachOnion(&r, c, dataplane.ClientRoute{}, candidates, profiles, out, nil, time.Now())
	if r.OnionOutbound == "" || r.OnionReserveOutbound == "" || r.TCPOutbound != "ordinary" {
		t.Fatal(r)
	}
	old := r
	candidates[0].Score = 100
	e.attachOnion(&r, c, old, candidates, profiles, out, nil, time.Now())
	if r.OnionOutbound != old.OnionOutbound {
		t.Fatal("quality change moved onion stream")
	}
	candidates[1].TCPQualified = false
	e.attachOnion(&r, c, old, candidates, profiles, out, nil, time.Now())
	if r.OnionOutbound != old.OnionReserveOutbound {
		t.Fatal("did not promote reserve", r)
	}
	c.OnionEnabled = false
	e.attachOnion(&r, c, r, candidates, profiles, out, nil, time.Now())
	if r.OnionOutbound != "" || r.OnionEnabled {
		t.Fatal("revoke failed")
	}
}

func TestOnionEnginePersistsAndRevokesWithoutMovingOrdinaryTCP(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	preview := sources.PreviewInput("tor-bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567")
	if _, err := db.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := db.ListSources(ctx)
	if err := db.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{{Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor", Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"}}); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListCandidates(ctx, listed[0].ID)
	id := rows[0].ID
	if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: id, Score: 100, TCPQualified: true, Available: true, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutClient(ctx, store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.PutClient(ctx, store.ClientRecord{ID: "bob", Name: "Bob", Address: "10.44.0.3/32"}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetOnionEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	p := []torpool.Profile{{Slot: 0, CandidateID: id, SocksAddr: "127.0.0.1:19050", Role: "warm", OnionReady: true}}
	a := &engineAgent{}
	e := NewEngine(db, a, profileProviderFunc(func() []torpool.Profile { return p }), scheduler.New(scheduler.PolicyDefaults()), []byte("test"))
	if err := e.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	state, err := db.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := decodeClientRoutes(state.AppliedPlan)["alice"]
	if before.OnionOutbound == "" || before.OnionOutbound == before.TCPOutbound {
		t.Fatal(before)
	}
	if err := db.SetOnionEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	// No second Tor candidate exists for a full ordinary reserve cover. Revocation
	// must still be applied before that optional planning gate.
	e.activeCriticalRouteLimit = 1
	_ = e.CycleForReason(ctx, now.Add(time.Second), PlacementClientLifecycle)
	state, err = db.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := decodeClientRoutes(state.AppliedPlan)["alice"]
	if after.OnionOutbound != "" || after.OnionEnabled || after.TCPOutbound != before.TCPOutbound {
		t.Fatal(before, after)
	}
	// Pausing/deleting an onion client must not wait for ordinary reserves
	// belonging to the remaining client either.
	for _, action := range []string{"pause", "delete"} {
		e.activeCriticalRouteLimit = 0
		if err := db.UpdateClient(ctx, "alice", "Alice", false); err != nil {
			t.Fatal(err)
		}
		if err := db.SetOnionEnabled(ctx, "alice", true); err != nil {
			t.Fatal(err)
		}
		if err := e.Cycle(ctx, now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		state, _ = db.LoadPlanState(ctx)
		bob := decodeClientRoutes(state.AppliedPlan)["bob"]
		if decodeClientRoutes(state.AppliedPlan)["alice"].OnionOutbound == "" {
			t.Fatal("setup missing onion route")
		}
		if action == "pause" {
			err = db.UpdateClient(ctx, "alice", "Alice", true)
		} else {
			err = db.DeleteClient(ctx, "alice")
		}
		if err != nil {
			t.Fatal(err)
		}
		e.activeCriticalRouteLimit = 1
		_ = e.CycleForReason(ctx, now.Add(3*time.Second), PlacementClientLifecycle)
		state, _ = db.LoadPlanState(ctx)
		if r, exists := decodeClientRoutes(state.AppliedPlan)["alice"]; exists {
			t.Fatalf("%s retained client route: %+v", action, r)
		}
		if decodeClientRoutes(state.AppliedPlan)["bob"] != bob {
			t.Fatalf("%s moved another client", action)
		}
	}
}

func TestOnionSelectsThirdHealthyProfileWhenPairDegraded(t *testing.T) {
	now := time.Now()
	e := &Engine{torSecret: []byte("test")}
	p := map[string]torpool.Profile{}
	cs := []scheduler.Candidate{}
	qs := map[string]store.OnionQoEState{}
	for i, id := range []string{"a", "b", "c"} {
		p[id] = torpool.Profile{CandidateID: id, Instance: id, Slot: i, Role: "warm", OnionReady: true, SocksAddr: fmt.Sprintf("127.0.0.1:%d", 19050+i)}
		cs = append(cs, scheduler.Candidate{ID: id, Protocol: scheduler.ProtocolTor, TCPQualified: true, Score: float64(30 - i)})
		status := qoe.StatusDegraded
		if id == "c" {
			status = qoe.StatusHealthy
		}
		qs[id] = store.OnionQoEState{Instance: id, State: qoe.State{Status: status, WindowValid: 3, LastValidAt: now, MedianTTFB: time.Second}}
	}
	client := store.ClientRecord{ID: "alice", OnionEnabled: true}
	old := dataplane.ClientRoute{OnionOutbound: torProfileOutboundID("a", p["a"], "onion-alice"), OnionReserveOutbound: torProfileOutboundID("b", p["b"], "onion-alice")}
	r := dataplane.ClientRoute{ClientID: "alice", TCPOutbound: "ordinary"}
	e.attachOnion(&r, client, old, cs, p, map[string]dataplane.Outbound{}, qs, now)
	if r.OnionOutbound != torProfileOutboundID("c", p["c"], "onion-alice") || r.TCPOutbound != "ordinary" {
		t.Fatal(r)
	}
}
