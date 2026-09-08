package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestExecRunnerWritesChildOutputToConfiguredWriter(t *testing.T) {
	var output bytes.Buffer
	process, err := (ExecRunner{Output: &output}).Start(context.Background(), "sh", "-c", "printf child-output")
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "child-output" {
		t.Fatalf("output=%q", output.String())
	}
}

func TestExecRunnerWritesChildStderrToConfiguredWriter(t *testing.T) {
	var output bytes.Buffer
	process, err := (ExecRunner{Output: &output}).Start(context.Background(), "sh", "-c", "printf child-error >&2")
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "child-error" {
		t.Fatalf("output=%q", output.String())
	}
}

func TestExecRunnerUsesStdoutWhenOutputIsNil(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	previousStdout := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = previousStdout })

	process, err := (ExecRunner{}).Start(context.Background(), "sh", "-c", "printf stdout-fallback")
	os.Stdout = previousStdout
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(output) != "stdout-fallback" {
		t.Fatalf("output=%q", output)
	}
}

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
