//go:build unix

package proberuntime

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecProcessStopTargetsOnlyOwnedChildAndIsIdempotent(t *testing.T) {
	if os.Getenv("HYDRAT_PROBE_RUNTIME_HELPER") == "1" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		fmt.Println("ready")
		<-signals
		return
	}

	first := startProbeRuntimeHelper(t)
	second := startProbeRuntimeHelper(t)
	t.Cleanup(func() {
		_ = first.Stop(100 * time.Millisecond)
		_ = second.Stop(100 * time.Millisecond)
	})

	if err := first.Stop(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := first.Stop(100 * time.Millisecond); err != nil {
		t.Fatalf("idempotent Stop error=%v", err)
	}
	if !channelClosed(first.Done()) {
		t.Fatal("owned child did not exit")
	}
	if channelClosed(second.Done()) {
		t.Fatal("stopping one owned child terminated a different child")
	}
}

func startProbeRuntimeHelper(t *testing.T) *execProcess {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=TestExecProcessStopTargetsOnlyOwnedChildAndIsIdempotent")
	command.Env = append(os.Environ(), "HYDRAT_PROBE_RUNTIME_HELPER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("helper readiness=%q err=%v", line, err)
	}
	process := &execProcess{command: command, done: make(chan struct{})}
	go func() {
		_ = command.Wait()
		process.publishExit()
	}()
	return process
}
