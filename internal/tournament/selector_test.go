package tournament

import (
	"fmt"
	"testing"
	"time"
)

func TestSelectorPromotesQualifiedCandidatesBeyondFirstTwoHundred(t *testing.T) {
	candidates := make([]Candidate, 0, 400)
	for index := 0; index < 400; index++ {
		score := float64(50 + index%20)
		inPool := index < 200
		if index >= 200 {
			score = float64(80 + index%20)
		}
		candidates = append(candidates, Candidate{
			Fingerprint: fmt.Sprintf("candidate-%03d", index),
			Status:      StatusQualified, FullSuccessStreak: 2,
			ConservativeScore: score, InWorkingPool: inPool,
		})
	}
	result := SelectWorkingPool(candidates, SelectionPolicy{
		PoolSize: 200, PromotionRatio: 0.15, Now: time.Unix(1_800_000_000, 0),
	})
	if len(result.Active) != 200 {
		t.Fatalf("active=%d", len(result.Active))
	}
	active := make(map[string]bool, len(result.Active))
	for _, fingerprint := range result.Active {
		active[fingerprint] = true
	}
	if !active["candidate-399"] {
		t.Fatalf("late high-scoring candidate was not considered: %+v", result.Active[:5])
	}
	if active["candidate-000"] {
		t.Fatal("worst original candidate was not displaced")
	}
}

func TestSelectorRequiresTwoSuccessesAndDrainsAssignedDemotion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	result := SelectWorkingPool([]Candidate{
		{Fingerprint: "working", Status: StatusQualified, FullSuccessStreak: 2, ConservativeScore: 50, InWorkingPool: true, Assigned: true},
		{Fingerprint: "weak-challenger", Status: StatusQualified, FullSuccessStreak: 2, ConservativeScore: 57},
		{Fingerprint: "strong-challenger", Status: StatusQualified, FullSuccessStreak: 2, ConservativeScore: 58},
		{Fingerprint: "one-success", Status: StatusPreflight, FullSuccessStreak: 1, ConservativeScore: 100},
		{Fingerprint: "banned", Status: StatusBanned, FullSuccessStreak: 2, ConservativeScore: 100, BannedUntil: now.Add(time.Hour)},
	}, SelectionPolicy{PoolSize: 1, PromotionRatio: 0.15, Now: now})
	if len(result.Active) != 1 || result.Active[0] != "strong-challenger" {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Draining) != 1 || result.Draining[0] != "working" {
		t.Fatalf("assigned demotion was not drained: %+v", result)
	}
}
