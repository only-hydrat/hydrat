//go:build unix

package xrayapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExecRunnerReturnsContextCanceledForKilledInFlightProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- (ExecRunner{}).Run(ctx, "", "/bin/sh", "-c", "exec sleep 10")
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled subprocess did not exit")
	}
}

func TestExecRunnerReturnsDeadlineExceededForKilledProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := (ExecRunner{}).Run(ctx, "", "/bin/sh", "-c", "exec sleep 10")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error=%v want context.DeadlineExceeded", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("deadline did not terminate subprocess promptly: %s", time.Since(started))
	}
}
