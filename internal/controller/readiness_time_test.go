package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessUsesRuntimeClockNotQueuedTickerTimestamp(t *testing.T) {
	logical := time.Unix(1900000000, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	runtime := Runtime{clock: newManualRuntimeClock(logical), ActiveInterval: time.Millisecond, CapacityReady: func(_ context.Context, at time.Time) error {
		if !at.Equal(logical) {
			return fmt.Errorf("stale ticker timestamp: %v, logical clock %v", at, logical)
		}
		if calls.Add(1) >= 2 {
			cancel()
		}
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readiness did not run")
	}
	if calls.Load() < 2 {
		t.Fatal("periodic check was not reached")
	}
}

func TestSnapshotDecisionTimeIncludesElapsedReadAndRejectsFutureProof(t *testing.T) {
	logical := time.Unix(1900000000, 0)
	started := time.Now()
	proof := logical.Add(time.Millisecond)
	<-time.After(3 * time.Millisecond)
	decision := snapshotDecisionTime(logical, started)
	if !activeObservationFresh(decision, proof, time.Minute) {
		t.Fatal("proof completed during the snapshot read rejected")
	}
	if activeObservationFresh(decision, decision.Add(time.Second), time.Minute) {
		t.Fatal("genuinely future proof accepted")
	}
}

func TestRecoveryBudgetExhaustionRetriesWithoutPretendingRuntimeStopped(t *testing.T) {
	err := routeRecoveryRetryError{}
	if expectedRuntimeStop(err) || !retryablePlacementError(err) || !recoverableCapacityNormalizationError(err) {
		t.Fatal("bounded repair cannot safely re-enter recovery lane")
	}
}
