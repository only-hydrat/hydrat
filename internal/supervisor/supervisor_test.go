package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSupervisorRestartsUnexpectedExitUntilContextStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &supervisorRunner{cancel: cancel}
	supervisor := Supervisor{Runner: runner, Backoff: time.Millisecond}
	if err := supervisor.Run(ctx, Spec{Name: "xray", Path: "xray", Args: []string{"run"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if runner.starts != 2 {
		t.Fatalf("starts=%d", runner.starts)
	}
}

type supervisorRunner struct {
	starts int
	cancel context.CancelFunc
}

func (runner *supervisorRunner) Start(context.Context, string, ...string) (Process, error) {
	runner.starts++
	if runner.starts == 2 {
		runner.cancel()
	}
	return processFunc(func() error { return errors.New("exited") }), nil
}

type processFunc func() error

func (function processFunc) Wait() error { return function() }
