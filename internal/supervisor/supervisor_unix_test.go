//go:build unix

package supervisor

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
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

func TestExecRunnerEnvironmentIsChildOnly(t *testing.T) {
	const key = "HYDRAT_CHILD_ENV_TEST"
	t.Setenv(key, "parent")
	var output bytes.Buffer
	process, err := (ExecRunner{Output: &output, Env: []string{key + "=child"}}).Start(t.Context(), "sh", "-c", "printenv HYDRAT_CHILD_ENV_TEST")
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "child\n" || os.Getenv(key) != "parent" {
		t.Fatalf("environment escaped child: %q", output.String())
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
