package controller

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestReturningClientKeepsFreshQualifiedUncrowdedBootstrap(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	db, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "current", kind: sources.KindVLESS, score: 79, tcp: true, udp: true, failureDomain: "current"},
		{name: "faster", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "faster"},
		{name: "reserve", kind: sources.KindVLESS, score: 99, tcp: true, udp: true, failureDomain: "reserve"},
	})
	qualifyEngineReserveCandidates(t, db, now, candidates)
	current := candidates["current"].ID
	putEngineQoEClient(t, db, "phone", "10.44.0.2/32", now, false, current, current)
	agent := &engineAgent{}
	engine := NewEngine(db, agent, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithQoEEnabled(false), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16), WithClientReservations())
	if err := engine.CycleForReason(ctx, now, PlacementClientLifecycle); err != nil {
		t.Fatal(err)
	}
	assignments, _ := db.ListAssignments(ctx)
	if assignments[0].TCPOutbound != current {
		t.Fatal("idle fixture changed bootstrap unexpectedly")
	}
	if err := db.RecordActivity(ctx, "phone", now, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordActivity(ctx, "phone", now.Add(2*time.Second), 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := engine.CycleForReason(ctx, now.Add(2*time.Second), PlacementClientLifecycle); err != nil {
		t.Fatal(err)
	}
	assignments, _ = db.ListAssignments(ctx)
	if assignments[0].TCPOutbound != current || assignments[0].UDPOutbound != current {
		t.Fatalf("wakeup moved a healthy uncrowded route without failure or quality dwell: %+v", assignments[0])
	}
	if agent.plans[len(agent.plans)-1].Clients[0].Dormant {
		t.Fatal("returned client stayed dormant")
	}
}

func TestReturningAssignmentRevalidatesEachTransportAndCapacity(t *testing.T) {
	now := time.Now()
	client := scheduler.Client{ID: "returning", LastTraffic: now, Assignment: scheduler.Assignment{TCP: "a", UDP: "a", TCPSince: now.Add(-time.Minute), UDPSince: now.Add(-time.Minute)}}
	valid := scheduler.Candidate{ID: "a", RouteKey: "same-route", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true}
	for _, tc := range []struct {
		name     string
		change   func(*scheduler.Candidate)
		tcp, udp bool
	}{
		{"fresh", func(*scheduler.Candidate) {}, true, true},
		{"stale proof", func(c *scheduler.Candidate) { c.ActiveFresh = false }, false, false},
		{"failed proof", func(c *scheduler.Candidate) { c.ActiveEligible = false }, false, false},
		{"not qualified", func(c *scheduler.Candidate) { c.ReserveEligible = false }, false, false},
		{"retiring", func(c *scheduler.Candidate) { c.Retiring = true }, false, false},
		{"open domain", func(c *scheduler.Candidate) { c.CircuitOpen = true }, false, false},
		{"qoe degraded", func(c *scheduler.Candidate) { c.QoEStatus = qoe.StatusDegraded }, false, false},
		{"UDP lost", func(c *scheduler.Candidate) { c.UDPQualified = false }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			tc.change(&candidate)
			got := returningAssignment(now, client, []scheduler.Client{client}, []scheduler.Candidate{candidate})
			if (got.TCP != "") != tc.tcp || (got.UDP != "") != tc.udp {
				t.Fatalf("assignment=%+v", got)
			}
			if got.TCP != "" && !got.TCPSince.Equal(client.Assignment.TCPSince) {
				t.Fatal("TCP dwell reset")
			}
		})
	}
	alias := valid
	alias.ID = "alias"
	one := scheduler.Client{ID: "one", LastTraffic: now, Assignment: scheduler.Assignment{TCP: "a", UDP: "a"}}
	two := scheduler.Client{ID: "two", LastTraffic: now, Assignment: scheduler.Assignment{TCP: "alias", UDP: "alias"}}
	if got := returningAssignment(now, client, []scheduler.Client{client, one}, []scheduler.Candidate{valid, alias}); got.TCP == "" {
		t.Fatal("same-client transports double counted load")
	}
	if got := returningAssignment(now, client, []scheduler.Client{client, one, two}, []scheduler.Candidate{valid, alias}); got.TCP != "" || got.UDP != "" {
		t.Fatal("crowded route alias retained on wakeup")
	}
	two.LastTraffic = now.Add(-6 * time.Minute)
	if got := returningAssignment(now, client, []scheduler.Client{client, one, two}, []scheduler.Candidate{valid, alias}); got.TCP == "" {
		t.Fatal("idle client still consumes route capacity")
	}
}
