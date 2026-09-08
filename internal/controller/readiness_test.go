package controller

import (
	"context"
	"errors"
	"testing"
)

func TestReadinessLatchStartsRedAndPreservesControllerCause(t *testing.T) {
	latch := NewReadinessLatch()
	if err := latch.Health(context.Background()); !errors.Is(err, ErrControllerStarting) {
		t.Fatalf("initial readiness=%v want %v", err, ErrControllerStarting)
	}
	want := errors.New("active-critical cover unavailable")
	latch.Unready(want)
	if err := latch.Health(context.Background()); !errors.Is(err, want) {
		t.Fatalf("degraded readiness=%v want %v", err, want)
	}
	latch.Ready()
	if err := latch.Health(context.Background()); err != nil {
		t.Fatalf("ready health=%v", err)
	}
}
