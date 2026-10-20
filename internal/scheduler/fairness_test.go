package scheduler

import (
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEEvacuationSharesComparableRoutesAtMostTwice(t *testing.T) {
	now := time.Now()
	clients := make([]Client, 6)
	for i := range clients {
		clients[i] = Client{ID: fmt.Sprint(i), LastTraffic: now, Assignment: Assignment{TCP: "failed", UDP: "failed", TCPSince: now, UDPSince: now}}
	}
	candidates := []Candidate{{ID: "failed", Protocol: ProtocolVLESS, Score: 95, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusDegraded, QoEReason: qoe.ReasonRouteTimeout}}
	for i := 0; i < 3; i++ {
		candidates = append(candidates, Candidate{ID: fmt.Sprintf("good-%d", i), RouteKey: fmt.Sprintf("route-%d", i), Protocol: ProtocolVLESS, FailureDomain: fmt.Sprint(i), Score: 95, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: time.Second + time.Duration(i)*50*time.Millisecond})
	}
	result := New(PolicyDefaults()).Schedule(now, clients, candidates)
	for id, count := range result.Load {
		if id == "failed" || count > 2 {
			t.Fatalf("concentrated evacuation: %+v", result)
		}
	}
	if len(result.Load) < 3 {
		t.Fatalf("unused comparable alternatives: %+v", result.Load)
	}
}

func TestSoftSharingLimitDoesNotBlockOnlyHealthyRoute(t *testing.T) {
	now := time.Now()
	clients := make([]Client, 6)
	for i := range clients {
		clients[i] = Client{ID: fmt.Sprint(i), LastTraffic: now}
	}
	result := New(PolicyDefaults()).Schedule(now, clients, []Candidate{{ID: "only", Protocol: ProtocolVLESS, Score: 95, TCPQualified: true, UDPQualified: true}})
	if result.Load["only"] != 6 {
		t.Fatalf("soft cap blocked connectivity: %+v", result)
	}
}

func TestNewAssignmentUsesBalancedQualityRatherThanSmallFileTime(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{
		{ID: "slow", Protocol: ProtocolVLESS, Score: 95, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: 500 * time.Millisecond, QoEQuality: 2},
		{ID: "balanced", Protocol: ProtocolVLESS, Score: 90, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: time.Second, QoEQuality: 4},
	}
	result := New(PolicyDefaults()).Schedule(now, []Client{{ID: "alice", LastTraffic: now}}, candidates)
	if result.Assignments["alice"].TCP != "balanced" {
		t.Fatalf("small-file winner displaced balanced winner: %+v", result)
	}
	if got := New(PolicyDefaults()).SelectEmergency(now, "alice", "tcp", "failed", candidates, nil, nil); got != "balanced" {
		t.Fatalf("emergency selection ignored balanced ranking: %s", got)
	}
}

func TestOverloadedHealthyRouteRebalancesGraduallyAfterDwell(t *testing.T) {
	now := time.Now()
	clients := make([]Client, 6)
	for i := range clients {
		clients[i] = Client{ID: fmt.Sprint(i), LastTraffic: now, Assignment: Assignment{TCP: "a", UDP: "a", TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour)}}
	}
	candidates := []Candidate{}
	for i, name := range []string{"a", "b", "c"} {
		candidates = append(candidates, Candidate{ID: name, Protocol: ProtocolVLESS, Score: 95 - float64(i), TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: time.Second + time.Duration(i)*50*time.Millisecond})
	}
	s := New(PolicyDefaults())
	for i := 0; i < 18; i++ {
		result := s.Schedule(now.Add(time.Duration(i)*time.Second), clients, candidates)
		if result.PlannedMoves > 1 {
			t.Fatal("rebalance exceeded move budget")
		}
		for j := range clients {
			clients[j].Assignment = result.Assignments[clients[j].ID]
		}
	}
	for id, count := range activeLoad(now, clients, s.policy.InactiveAfter) {
		if count > 2 {
			t.Fatalf("healthy pool remains concentrated on %s: %d", id, count)
		}
	}
}

func TestDuplicateRouteLoadIncludesAliasOutsideFreshProofSet(t *testing.T) {
	now := time.Now()
	clients := []Client{
		{ID: "one", LastTraffic: now, Assignment: Assignment{TCP: "alias-old", UDP: "alias-old", TCPSince: now, UDPSince: now}},
		{ID: "two", LastTraffic: now, Assignment: Assignment{TCP: "alias-old", UDP: "alias-old", TCPSince: now, UDPSince: now}},
		{ID: "new", LastTraffic: now},
	}
	candidates := []Candidate{
		{ID: "alias-old", RouteKey: "same", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true},
		{ID: "alias-fresh", RouteKey: "same", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true, ActiveFresh: true, ActiveEligible: true},
		{ID: "other", RouteKey: "other", Protocol: ProtocolVLESS, Score: 97, TCPQualified: true, UDPQualified: true, ActiveFresh: true, ActiveEligible: true},
	}
	result := New(PolicyDefaults()).Schedule(now, clients, candidates)
	if result.Assignments["new"].TCP != "other" {
		t.Fatalf("duplicate identity bypassed cap: %+v", result)
	}
}

func TestNewAndEmergencyAssignmentsRankComparableQoEWithoutMoveHysteresis(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{
		{ID: "legacy-score", Protocol: ProtocolVLESS, Score: 100, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: time.Second, QoEQuality: 3.5},
		{ID: "balanced", Protocol: ProtocolVLESS, Score: 95, TCPQualified: true, UDPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, ActiveFresh: true, ActiveEligible: true, QoEEffective: time.Second, QoEQuality: 4},
	}
	s := New(PolicyDefaults())
	result := s.Schedule(now, []Client{{ID: "new", LastTraffic: now}}, candidates)
	if result.Assignments["new"].TCP != "balanced" {
		t.Errorf("new assignment incorrectly used migration hysteresis/legacy score: %+v", result)
	}
	if got := s.SelectEmergency(now, "new", "tcp", "failed", candidates, nil, nil); got != "balanced" {
		t.Errorf("emergency selected legacy score: %s", got)
	}
}
