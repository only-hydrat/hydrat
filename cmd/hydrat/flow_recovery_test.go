package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/supervisor"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func TestFlowControlPreservesNewAgentSocketParentAccess(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "new-agent")
	path, err := flowControlSocket(filepath.Join(parent, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(parent); err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("agent socket parent must remain traversable: info=%v err=%v", info, err)
	}
	if path != filepath.Join(parent, "flow-control", "xray.sock") {
		t.Fatalf("path=%s", path)
	}
}

func TestFlowControlEnvironmentOnlyOnMainChild(t *testing.T) {
	plain := newXraySupervisor(io.Discard).Runner.(supervisor.ExecRunner)
	main := flowControlledSupervisor(io.Discard, "/private/flows.sock").Runner.(supervisor.ExecRunner)
	if len(plain.Env) != 0 || len(main.Env) != 1 || main.Env[0] != xrayflow.SocketEnvironment+"=/private/flows.sock" {
		t.Fatalf("plain=%v main=%v", plain.Env, main.Env)
	}
}

func TestFlowRecoveryWorkerCancelsAndJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	group := &xraySupervisorGroup{ctx: ctx, cancel: cancel, retryInterval: time.Millisecond}
	entered := make(chan struct{})
	var calls atomic.Int32
	group.StartFlowRecovery(func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-ctx.Done()
		return ctx.Err()
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker not started")
	}
	joined := make(chan struct{})
	go func() { group.StopAndWait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("worker not joined")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
