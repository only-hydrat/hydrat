package controller

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"testing"
	"time"
)

func TestI2POnlyChangePreservesOrdinaryRoutes(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	db, cs := newEngineQoEFixture(t, now, []engineQoECandidateSpec{{name: "a", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"}, {name: "b", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "b"}})
	qualifyEngineReserveCandidates(t, db, now, cs)
	putEngineQoEClient(t, db, "alice", "10.44.0.2/32", now, true, cs["a"].ID, cs["a"].ID)
	e := NewEngine(db, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false))
	if err := e.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	before, _ := db.LoadPlanState(ctx)
	old := decodeClientRoutes(before.AppliedPlan)["alice"]
	if err := db.SetI2PEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if err := e.Cycle(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	after, _ := db.LoadPlanState(ctx)
	route := decodeClientRoutes(after.AppliedPlan)["alice"]
	if !route.I2PEnabled || route.I2POutbound == "" {
		t.Fatal("I2P not applied")
	}
	if route.TCPOutbound != old.TCPOutbound || route.UDPOutbound != old.UDPOutbound {
		t.Fatal("ordinary routes changed")
	}
}

func TestI2POutboundUsesDedicatedHandshakePolicy(t *testing.T) {
	e := &Engine{torSecret: []byte("secret")}
	out := map[string]dataplane.Outbound{}
	route := dataplane.ClientRoute{}
	e.attachI2P(&route, store.ClientRecord{ID: "alice", I2PEnabled: true}, out)
	var doc struct {
		Settings struct {
			Servers []struct{ Users []struct{ Level int } }
		}
	}
	if err := json.Unmarshal(out[route.I2POutbound].Config, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Settings.Servers[0].Users[0].Level != 19819 {
		t.Fatal("I2P inherits short ordinary handshake timeout")
	}
}
