//go:build unix

package torpool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecProcessStopForcesChildThatIgnoresSIGTERM(t *testing.T) {
	if os.Getenv("HYDRAT_IGNORE_SIGTERM_HELPER") == "1" {
		signal.Ignore(syscall.SIGTERM)
		fmt.Println("ready")
		for {
			time.Sleep(time.Second)
		}
	}
	command := exec.Command(os.Args[0], "-test.run=TestExecProcessStopForcesChildThatIgnoresSIGTERM")
	command.Env = append(os.Environ(), "HYDRAT_IGNORE_SIGTERM_HELPER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper readiness=%q err=%v", line, err)
	}
	process := &execProcess{
		command: command, done: make(chan struct{}),
		gracePeriod: 50 * time.Millisecond, killWait: 200 * time.Millisecond,
	}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	defer func() {
		if !process.Exited() {
			_ = command.Process.Kill()
			<-process.done
		}
	}()

	stopped := make(chan error, 1)
	go func() { stopped <- process.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop did not force a SIGTERM-ignoring child to exit within the bound")
	}
	if !process.Exited() {
		t.Fatal("forced child was not reaped")
	}
}

func TestExecProcessStopHandlesGracefulAndAlreadyExitedChildren(t *testing.T) {
	command := exec.Command("sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &execProcess{command: command, done: make(chan struct{})}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	if err := process.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(); err != nil {
		t.Fatalf("already-exited Stop error=%v", err)
	}
}

func TestManagerCloseStopsProcessGroupBeforeCancel(t *testing.T) {
	switch os.Getenv("HYDRAT_MANAGER_GROUP_HELPER") {
	case "child":
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Second)
		}
	case "parent":
		signal.Ignore(syscall.SIGTERM)
		child := exec.Command(os.Args[0], "-test.run=TestManagerCloseStopsProcessGroupBeforeCancel")
		child.Env = append(os.Environ(), "HYDRAT_MANAGER_GROUP_HELPER=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		readyPath := os.Getenv("HYDRAT_MANAGER_READY_PATH")
		_ = os.WriteFile(
			readyPath,
			[]byte(fmt.Sprintf("%d %d", os.Getpid(), child.Process.Pid)),
			0o600,
		)
		for {
			time.Sleep(time.Second)
		}
	}

	readyPath := filepath.Join(t.TempDir(), "manager-processes")
	runner := &closeRaceRunner{readyPath: readyPath}
	manager, err := NewManager(Config{
		Binary: "ignored", DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 1, ExplorerProfiles: 0,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), []Candidate{{
		ID: "bridge", Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		Score: 100, Qualified: true,
	}}); err != nil {
		t.Fatal(err)
	}
	parentPID, childPID := waitManagerProcessPIDs(t, readyPath)
	t.Cleanup(func() {
		_ = syscall.Kill(-parentPID, syscall.SIGKILL)
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	})

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	waitProcessGone(t, parentPID)
	waitProcessGone(t, childPID)
}

type closeRaceRunner struct {
	readyPath string
}

func (runner *closeRaceRunner) Start(ctx context.Context, _ string, _ ...string) (Process, error) {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestManagerCloseStopsProcessGroupBeforeCancel")
	command.Env = append(
		os.Environ(),
		"HYDRAT_MANAGER_GROUP_HELPER=parent",
		"HYDRAT_MANAGER_READY_PATH="+runner.readyPath,
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &execProcess{
		command: command, done: make(chan struct{}),
		gracePeriod: 50 * time.Millisecond, killWait: 200 * time.Millisecond,
		processGroup: true,
	}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	return &cancelFirstProcess{ctx: ctx, process: process}, nil
}

type cancelFirstProcess struct {
	ctx     context.Context
	process *execProcess
}

func (process *cancelFirstProcess) Exited() bool {
	return process.process.Exited()
}

func (process *cancelFirstProcess) Stop() error {
	select {
	case <-process.ctx.Done():
		<-process.process.done
	default:
	}
	return process.process.Stop()
}

func waitManagerProcessPIDs(t *testing.T, path string) (int, int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		content, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(content))
			if len(fields) != 2 {
				t.Fatalf("manager helper pids=%q", content)
			}
			parentPID, parentErr := strconv.Atoi(fields[0])
			childPID, childErr := strconv.Atoi(fields[1])
			if parentErr != nil || childErr != nil {
				t.Fatalf("manager helper pids=%q parent_err=%v child_err=%v",
					content, parentErr, childErr)
			}
			return parentPID, childPID
		}
		if time.Now().After(deadline) {
			t.Fatalf("manager helper did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("process %d probe failed: %v", pid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d survived Manager.Close", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
