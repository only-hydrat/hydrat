package controller

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

var ErrControllerStarting = errors.New("controller startup gates have not completed")

// ReadinessLatch is the controller's process-wide readiness state. It starts
// red so the portal cannot report a false healthy window before startup
// failover and active-critical normalization have both completed.
type ReadinessLatch struct {
	mu           sync.RWMutex
	err          error
	unreadySince time.Time
	sequence     uint64
}

func NewReadinessLatch() *ReadinessLatch {
	return &ReadinessLatch{err: ErrControllerStarting, unreadySince: time.Now()}
}

func (latch *ReadinessLatch) Unready(err error) {
	if err == nil {
		err = ErrControllerStarting
	}
	latch.mu.Lock()
	transition := latch.err == nil
	latch.err = err
	if transition {
		latch.unreadySince = time.Now()
		latch.sequence++
	}
	sequence := latch.sequence
	latch.mu.Unlock()
	if transition {
		log.Printf("controller_readiness state=unready reason=%s sequence=%d", readinessReason(err), sequence)
	}
}

func (latch *ReadinessLatch) Ready() {
	latch.mu.Lock()
	transition := latch.err != nil
	outage := time.Duration(0)
	if !latch.unreadySince.IsZero() {
		outage = time.Since(latch.unreadySince)
	}
	latch.err = nil
	if transition {
		latch.sequence++
	}
	sequence := latch.sequence
	latch.mu.Unlock()
	if transition {
		log.Printf("controller_readiness state=ready outage_ms=%d sequence=%d", outage.Milliseconds(), sequence)
	}
}

func readinessReason(err error) string {
	var coverage *ActiveCriticalCoveragePlanError
	if errors.As(err, &coverage) {
		switch coverage.Cause {
		case coverageReserveNotReady, coveragePrimaryUnusable, coverageGenerationPending, coverageCriticalLimit:
			return coverage.Cause
		}
		if coverage.SearchExhausted {
			return "search_budget"
		}
	}
	switch {
	case errors.Is(err, ErrControllerStarting):
		return "startup"
	case errors.Is(err, ErrActiveCriticalCoverageExceeded):
		return "active_critical_capacity"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "controller_gate"
	}
}

func (latch *ReadinessLatch) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	latch.mu.RLock()
	err := latch.err
	latch.mu.RUnlock()
	return err
}
