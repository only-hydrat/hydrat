package store

import (
	"context"
	"testing"
	"time"
)

func TestInfrastructureAttemptPreservesSuccessAndRecordsAttemptForFairness(t *testing.T) {
	database, candidate := qoeCandidateStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	transition := ProbeTransition{CandidateID: candidate.ID, SourceID: candidate.SourceID, Fingerprint: candidate.Fingerprint, At: now, Full: true, Success: true, Score: 90}
	before, err := database.RecordCandidateProbe(ctx, transition)
	if err != nil {
		t.Fatal(err)
	}
	transition.At = now.Add(time.Minute)
	transition.Success, transition.InfrastructureFailure, transition.ErrorCode = false, true, "worker_timeout"
	after, err := database.RecordCandidateProbe(ctx, transition)
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastFullProbeAt.Equal(transition.At) || !after.LastSuccessAt.Equal(before.LastSuccessAt) || after.FailureStreak != before.FailureStreak || !after.LastFailureAt.Equal(before.LastFailureAt) {
		t.Fatalf("infrastructure changed route evidence: before=%+v after=%+v", before, after)
	}
}
