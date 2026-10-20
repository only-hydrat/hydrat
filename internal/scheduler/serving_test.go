package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestServingOnlyTCPDoesNotAdmitANewUDPAssignmentByAlignment(t *testing.T) {
	now := time.Unix(1900000000, 0)
	placement := New(PolicyDefaults())
	result := placement.Schedule(now, []Client{{ID: "alice", PreserveTCP: true,
		Assignment: Assignment{TCP: "retained", UDP: "failed", TCPSince: now, UDPSince: now}}}, []Candidate{
		{ID: "retained", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true, ServingOnly: true},
		{ID: "admitted", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true},
	})
	if got := result.Assignments["alice"]; got.TCP != "retained" || got.UDP != "admitted" {
		t.Fatalf("retention-only route received a new transport: %+v", got)
	}
}

func TestReserveRepairDoesNotCarryAnOldQualityStreakIntoRebalancing(t *testing.T) {
	now := time.Unix(1900000000, 0)
	placement := New(PolicyDefaults())
	client := Client{ID: "alice", LastTraffic: now, Assignment: Assignment{TCP: "stable", TCPSince: now.Add(-time.Hour)}}
	candidates := []Candidate{
		{ID: "stable", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true},
		{ID: "better", Protocol: ProtocolVLESS, Score: 200, TCPQualified: true},
	}
	for range 2 {
		if got := placement.Schedule(now, []Client{client}, candidates).Assignments["alice"]; got.TCP != "stable" {
			t.Fatalf("fixture moved before three snapshots: %+v", got)
		}
	}
	client.PreserveTCP = true
	placement.Schedule(now, []Client{client}, candidates)
	client.PreserveTCP = false
	for i := range 3 {
		got := placement.Schedule(now, []Client{client}, candidates).Assignments["alice"]
		if i < 2 && got.TCP != "stable" || i == 2 && got.TCP != "better" {
			t.Fatalf("snapshot %d after reserve repair: %+v", i, got)
		}
	}
}

func TestServingOnlyRouteCannotReceiveNewClientsOrReserves(t *testing.T) {
	now := time.Unix(1900000000, 0)
	p := Candidate{ID: "retained", Protocol: ProtocolVLESS, ServingOnly: true, Score: 1000, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEEffective: time.Millisecond}
	n := p
	n.ID = "new"
	n.ServingOnly = false
	n.Score = 100
	n.QoEEffective = time.Second
	placement := New(PolicyDefaults())
	result := placement.Schedule(now, []Client{{ID: "alice", LastTraffic: now, Assignment: Assignment{TCP: "retained", UDP: "retained", TCPSince: now, UDPSince: now}}, {ID: "bob", LastTraffic: now}}, []Candidate{p, n})
	if result.Assignments["alice"].TCP != "retained" || result.Assignments["bob"].TCP != "new" {
		t.Fatalf("assignments=%+v", result.Assignments)
	}
	if got := placement.SelectReserves(now, "bob", Assignment{TCP: "new", UDP: "new"}, []Candidate{p, n}); got.TCP != "" || got.UDP != "" {
		t.Fatalf("reference received reserve=%+v", got)
	}
	if got := placement.SelectEmergency(now, "bob", "tcp", "failed", []Candidate{p, n}, nil, nil); got != "new" {
		t.Fatalf("emergency chose %s", got)
	}
}

func TestPinnedTransportDoesNotMoveThroughTCPUDPAlignment(t *testing.T) {
	now := time.Unix(1900000000, 0)
	for _, tcpPinned := range []bool{true, false} {
		client := Client{ID: "alice", LastTraffic: now, PreserveTCP: tcpPinned, PreserveUDP: !tcpPinned, Assignment: Assignment{TCP: "tcp", UDP: "udp", TCPSince: now, UDPSince: now}}
		tcp := Candidate{ID: "tcp", Protocol: ProtocolVLESS, TCPQualified: tcpPinned, Score: 100}
		udp := Candidate{ID: "udp", Protocol: ProtocolVLESS, UDPQualified: !tcpPinned, Score: 100}
		dual := Candidate{ID: "dual", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true, Score: 200}
		got := New(PolicyDefaults()).Schedule(now, []Client{client}, []Candidate{tcp, udp, dual}).Assignments["alice"]
		if tcpPinned && (got.TCP != "tcp" || got.UDP != "dual") || !tcpPinned && (got.TCP != "dual" || got.UDP != "udp") {
			t.Fatalf("pinnedTCP=%t assignment=%+v", tcpPinned, got)
		}
	}
}

func TestAppliedReservePreferenceRetainsProofTargetButNeverBypassesAdmission(t *testing.T) {
	now := time.Unix(1900000000, 0)
	p := Candidate{ID: "p", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true, Score: 100}
	r := p
	r.ID = "r"
	r.ActiveFresh = false
	w := p
	w.ID = "winner"
	w.Score = 1000
	placement := New(PolicyDefaults())
	previous := ReserveSelection{TCP: "r", UDP: "r"}
	selectReserve := func(prospective bool, reserve Candidate) ReserveSelection {
		t.Helper()
		var got ReserveSelection
		var err error
		if prospective {
			got, err = placement.SelectProspectiveReservesContext(context.Background(), now, "alice", Assignment{TCP: "p", UDP: "p"}, []Candidate{p, reserve, w}, previous)
		} else {
			got, err = placement.SelectReservesContext(context.Background(), now, "alice", Assignment{TCP: "p", UDP: "p"}, []Candidate{p, reserve, w}, previous)
		}
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := selectReserve(true, r); got != previous {
		t.Fatalf("ranking moved proof target: %+v", got)
	}
	if got := selectReserve(false, r); got.TCP != "winner" || got.UDP != "winner" {
		t.Fatalf("stale reserve admitted: %+v", got)
	}
	r.ActiveFresh = true
	if got := selectReserve(false, r); got != previous {
		t.Fatalf("fresh installed reserve replaced: %+v", got)
	}
	for _, mutate := range []func(*Candidate){func(c *Candidate) { c.ServingOnly = true }, func(c *Candidate) { c.CircuitOpen = true }, func(c *Candidate) { c.Retiring = true }, func(c *Candidate) { c.ReserveEligible = false }, func(c *Candidate) { c.QoEStatus = qoe.StatusDegraded }, func(c *Candidate) { c.RouteKey = "same" }} {
		bad := r
		mutate(&bad)
		if bad.RouteKey == "same" {
			p.RouteKey = "same"
		} else {
			p.RouteKey = ""
		}
		if got := selectReserve(true, bad); got.TCP == "r" || got.UDP == "r" {
			t.Fatalf("invalid preferred reserve admitted: %+v", bad)
		}
	}
}
