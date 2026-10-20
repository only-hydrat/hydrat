package controller

import (
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
)

func TestQualityChallengersGetProofSlotsWithoutDisplacingCriticalRoutes(t *testing.T) {
	candidates := []scheduler.Candidate{
		{ID: "already", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, QoEQuality: 20},
		{ID: "fast", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, QoEQuality: 10},
		{ID: "stale", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, QoEStatus: qoe.StatusHealthy, QoEQuality: 100},
		{ID: "slow", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, QoEStatus: qoe.StatusHealthy, QoEFresh: true, QoEPromotionReady: true, QoEEffective: time.Second},
	}
	seen := map[string]ActiveTarget{"already": {}}
	selected := qualityChallengers(candidates, seen, 2)
	if len(selected) != 1 || selected[0] != "fast" {
		t.Fatalf("challengers exceeded remaining budget or admitted stale evidence: %v", selected)
	}
	if len(qualityChallengers(candidates, seen, 1)) != 0 {
		t.Fatal("challenger displaced critical target")
	}
}
