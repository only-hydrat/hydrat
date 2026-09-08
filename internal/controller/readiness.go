package controller

import (
	"context"
	"errors"
	"sync"
)

var ErrControllerStarting = errors.New("controller startup gates have not completed")

// ReadinessLatch is the controller's process-wide readiness state. It starts
// red so the portal cannot report a false healthy window before startup
// failover and active-critical normalization have both completed.
type ReadinessLatch struct {
	mu  sync.RWMutex
	err error
}

func NewReadinessLatch() *ReadinessLatch {
	return &ReadinessLatch{err: ErrControllerStarting}
}

func (latch *ReadinessLatch) Unready(err error) {
	if err == nil {
		err = ErrControllerStarting
	}
	latch.mu.Lock()
	latch.err = err
	latch.mu.Unlock()
}

func (latch *ReadinessLatch) Ready() {
	latch.mu.Lock()
	latch.err = nil
	latch.mu.Unlock()
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
