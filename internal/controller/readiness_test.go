package controller

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestReadinessLogsOnlyTransitionsAndSafeReasons(t *testing.T) {
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	latch := NewReadinessLatch()
	latch.Ready()
	latch.Ready()
	latch.Unready(errors.New("private-token"))
	latch.Unready(errors.New("another-private-token"))
	latch.Ready()
	latch.Ready()
	text := output.String()
	if strings.Count(text, "controller_readiness") != 3 || strings.Contains(text, "private-token") || !strings.Contains(text, "outage_ms=") || !strings.Contains(text, "reason=controller_gate") {
		t.Fatalf("logs=%s", text)
	}
}

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
