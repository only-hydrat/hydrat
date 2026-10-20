package controller

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestServingPrimaryConstraintsRespectDwellAndUrgentOverrides(t *testing.T) {
	now := time.Unix(1900000000, 0)
	for _, test := range []struct {
		name     string
		reason   PlacementReason
		age      time.Duration
		change   func(*routeCandidateSnapshot, *scheduler.Client, *scheduler.Scheduler)
		tcp, udp bool
	}{
		{name: "promotion", reason: PlacementPromotion, age: time.Hour, tcp: true, udp: true},
		{name: "dwell", reason: PlacementPeriodic, age: 29 * time.Minute, tcp: true, udp: true},
		{name: "periodic after dwell", reason: PlacementPeriodic, age: 31 * time.Minute},
		{name: "reserve repair before quality", reason: PlacementPeriodic, age: time.Hour, tcp: true, udp: true, change: func(_ *routeCandidateSnapshot, c *scheduler.Client, _ *scheduler.Scheduler) {
			c.AppliedReserve = scheduler.ReserveSelection{}
		}},
		{name: "hard failed", reason: PlacementPromotion, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			h := s.healthByID["p"]
			h.ActiveHardFailure = true
			s.healthByID["p"] = h
		}},
		{name: "unavailable", reason: PlacementPromotion, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			h := s.healthByID["p"]
			h.Available = false
			s.healthByID["p"] = h
		}},
		{name: "revoked", reason: PlacementPromotion, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) { delete(s.allByID, "p") }},
		{name: "source draining", reason: PlacementPromotion, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			r := s.rowsByID["p"]
			r.Lifecycle = store.CandidateLifecycleDraining
			s.rowsByID["p"] = r
		}},
		{name: "manual exclusion", reason: PlacementManual, change: func(_ *routeCandidateSnapshot, _ *scheduler.Client, p *scheduler.Scheduler) {
			p.Exclude("alice", "p", now.Add(time.Hour))
		}},
		{name: "circuit open", reason: PlacementPromotion, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.CircuitOpen = true
			s.allByID["p"] = c
		}},
		{name: "application evacuation", reason: PlacementQoEDegraded, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.QoEStatus = qoe.StatusDegraded
			c.QoEReason = qoe.ReasonApplicationGates
			s.allByID["p"] = c
		}},
		{name: "sustained throughput evacuation", reason: PlacementPeriodic, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.QoEStatus = qoe.StatusDegraded
			c.QoEReason = qoe.ReasonSustainedThroughput
			s.allByID["p"] = c
		}},
		{name: "UDP loss only", reason: PlacementPromotion, tcp: true, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.UDPQualified = false
			s.allByID["p"] = c
		}},
		{name: "TCP loss only", reason: PlacementPromotion, udp: true, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.TCPQualified = false
			s.allByID["p"] = c
		}},
		{name: "probe-pool draining", reason: PlacementPromotion, tcp: true, udp: true, change: func(s *routeCandidateSnapshot, _ *scheduler.Client, _ *scheduler.Scheduler) {
			c := s.allByID["p"]
			c.Retiring = true
			s.allByID["p"] = c
		}},
		{name: "dormant", reason: PlacementPromotion, change: func(_ *routeCandidateSnapshot, c *scheduler.Client, _ *scheduler.Scheduler) { c.Dormant = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := scheduler.Candidate{ID: "p", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ActiveEligible: true, ActiveFresh: true, ReserveEligible: true}
			r := p
			r.ID = "r"
			snapshot := routeCandidateSnapshot{allByID: map[string]scheduler.Candidate{"p": p, "r": r}, rowsByID: map[string]store.Candidate{"p": {ID: "p", Lifecycle: store.CandidateLifecycleActive}}, healthByID: map[string]store.CandidateHealth{"p": {Available: true}}}
			client := scheduler.Client{ID: "alice", Assignment: scheduler.Assignment{TCP: "p", UDP: "p", TCPSince: now.Add(-test.age), UDPSince: now.Add(-test.age)}, AppliedReserve: scheduler.ReserveSelection{TCP: "r", UDP: "r"}}
			placement := scheduler.New(scheduler.PolicyDefaults())
			if test.change != nil {
				test.change(&snapshot, &client, placement)
			}
			snapshot.placementCandidates = []scheduler.Candidate{r}
			engine := &Engine{activeCriticalRouteLimit: 16}
			clients, _, err := engine.servingPrimaries(context.Background(), now, test.reason, placement, []scheduler.Client{client}, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if clients[0].PreserveTCP != test.tcp || clients[0].PreserveUDP != test.udp {
				t.Fatalf("constraints=%+v", clients[0])
			}
		})
	}
}
