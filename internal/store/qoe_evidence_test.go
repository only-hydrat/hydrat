package store

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEWindowExcludesExpiredFutureAndPreFailureSamples(t *testing.T) {
	for _, name := range []string{"expired", "future", "before failure"} {
		t.Run(name, func(t *testing.T) {
			database, candidate := qoeCandidateStore(t)
			ctx := context.Background()
			now := time.Unix(1_900_000_000, 0)
			oldAt := now.Add(-11 * time.Minute)
			if name == "future" {
				oldAt = now.Add(time.Minute)
			}
			if name == "before failure" {
				oldAt = now.Add(-time.Minute)
			}
			for i := 0; i < 5; i++ {
				if _, _, err := database.RecordCandidateQoE(ctx, candidate, healthyQoEObservation(oldAt.Add(time.Duration(i)*time.Second).Unix()), qoe.DefaultPolicy()); err != nil {
					t.Fatal(err)
				}
			}
			if name == "before failure" {
				_, err := database.RecordCandidateProbe(ctx, ProbeTransition{CandidateID: candidate.ID, SourceID: candidate.SourceID, Fingerprint: candidate.Fingerprint, At: now.Add(-time.Second), Full: true, ErrorCode: "full_probe_failed"})
				if err != nil {
					t.Fatal(err)
				}
			}
			state, _, err := database.RecordCandidateQoE(ctx, candidate, healthyQoEObservation(now.Unix()), qoe.DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if state.WindowValid != 1 || !state.WindowStartedAt.Equal(now) {
				t.Fatalf("old evidence survived: %+v", state)
			}
		})
	}
}
