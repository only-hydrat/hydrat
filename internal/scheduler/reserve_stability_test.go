package scheduler

import (
	"context"
	"testing"
	"time"
)

func TestAppliedReserveSurvivesDomainPreferenceChange(t *testing.T) {
	candidates := []Candidate{
		{ID: "primary", RouteKey: "primary", FailureDomain: "a", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true},
		{ID: "applied", RouteKey: "applied", FailureDomain: "a", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
	}
	selector := New(PolicyDefaults())
	now := time.Unix(1900000000, 0)
	assignment := Assignment{TCP: "primary", UDP: "primary"}
	reserve := ReserveSelection{TCP: "applied", UDP: "applied"}
	for _, added := range []bool{false, true} {
		if added {
			candidates = append(candidates, Candidate{ID: "new", RouteKey: "new", FailureDomain: "b", Protocol: ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true})
		}
		valid, err := selector.ValidateReserveSelectionContext(context.Background(), now, "alice", assignment, reserve, candidates)
		if err != nil || !valid.TCP || !valid.UDP {
			t.Fatalf("added alternative=%t: healthy applied reserve invalidated: %+v, %v", added, valid, err)
		}
	}
	selected := selector.SelectReserves(now, "alice", assignment, candidates)
	if selected.TCP != "new" || selected.UDP != "new" {
		t.Fatalf("new selection must still prefer independent domain: %+v", selected)
	}
	candidates[1].ReserveEligible = false
	valid, err := selector.ValidateReserveSelectionContext(context.Background(), now, "alice", assignment, reserve, candidates)
	if err != nil || valid.TCP || valid.UDP {
		t.Fatalf("failed reserve must be rejected: %+v, %v", valid, err)
	}
}
