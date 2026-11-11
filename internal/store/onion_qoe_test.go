package store

import (
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"testing"
	"time"
)

func TestOnionQoEReusesWindowsWithoutChangingOrdinaryEvidence(t *testing.T) {
	db, c := qoeCandidateStore(t)
	c.Kind = sources.KindTorBridge
	if _, err := db.db.Exec(`UPDATE candidates SET kind=? WHERE id=?`, c.Kind, c.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	p := qoe.DefaultPolicy()
	_, _, err := db.RecordCandidateQoE(t.Context(), c, healthyQoEObservation(now.Unix()), p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := db.ListCandidateQoEStates(t.Context())
	for i := 0; i < 3; i++ {
		obs := qoe.Observation{At: now.Add(time.Duration(i) * time.Second), Success: true, TTFB: time.Second}
		if _, _, err := db.RecordOnionQoE(t.Context(), c, "process-a", obs, 0); err != nil {
			t.Fatal(err)
		}
	}
	states, err := db.ListOnionQoEStates(t.Context())
	if err != nil || len(states) != 1 || states[0].State.Status != qoe.StatusHealthy {
		t.Fatalf("onion evidence unavailable: %+v %v", states, err)
	}
	after, _ := db.ListCandidateQoEStates(t.Context())
	if len(after) != 1 || after[0] != before[0] {
		t.Fatal("onion changed ordinary QoE")
	}
	// Infrastructure/shared-service uncertainty is not a bad route sample.
	prev := states[0]
	_, _, err = db.RecordOnionQoE(t.Context(), c, "process-a", qoe.Observation{At: now.Add(4 * time.Second), Infrastructure: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	states, _ = db.ListOnionQoEStates(t.Context())
	if states[0].State != prev.State {
		t.Fatal("uncertainty degraded route")
	}
	// A restarted serving Tor process must establish a new window.
	_, _, err = db.RecordOnionQoE(t.Context(), c, "process-b", qoe.Observation{At: now.Add(5 * time.Second), Success: true, TTFB: time.Second}, 0)
	if err != nil {
		t.Fatal(err)
	}
	states, _ = db.ListOnionQoEStates(t.Context())
	if states[0].State.WindowValid != 1 || states[0].Instance != "process-b" {
		t.Fatal("old process evidence survived")
	}
}

func TestOnionQoESupersededFailureGeneration(t *testing.T) {
	db, c := qoeCandidateStore(t)
	c.Kind = sources.KindTorBridge
	if _, err := db.db.Exec(`UPDATE candidates SET kind=? WHERE id=?`, c.Kind, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCandidateHealth(t.Context(), CandidateHealth{CandidateID: c.ID, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE candidate_health SET failure_generation=1 WHERE candidate_id=?`, c.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := db.RecordOnionQoE(t.Context(), c, "a", qoe.Observation{At: time.Now(), Success: true}, 0)
	if err != ErrQoEObservationSuperseded {
		t.Fatalf("stale generation accepted: %v", err)
	}
}

func TestOnionQoEParticipatesInExistingPlanEvidenceFence(t *testing.T) {
	db, c := qoeCandidateStore(t)
	c.Kind = sources.KindTorBridge
	if _, err := db.db.Exec(`UPDATE candidates SET kind=? WHERE id=?`, c.Kind, c.ID); err != nil {
		t.Fatal(err)
	}
	before, err := db.LoadRoutingReferencesSnapshot(t.Context(), []string{c.ID})
	if err != nil || len(before.Candidates) != 1 {
		t.Fatal(err, before)
	}
	_, _, err = db.RecordOnionQoE(t.Context(), c, "a", qoe.Observation{At: time.Now(), Success: true, TTFB: time.Second}, 0)
	if err != nil {
		t.Fatal(err)
	}
	after, err := db.LoadRoutingReferencesSnapshot(t.Context(), []string{c.ID})
	if err != nil || len(after.Candidates) != 1 {
		t.Fatal(err, after)
	}
	if before.Candidates[0].Digest == after.Candidates[0].Digest {
		t.Fatal("onion evidence can change behind a plan publication")
	}
}
