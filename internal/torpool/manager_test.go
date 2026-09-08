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

func TestManagerKeepsThreeWarmSingleBridgeProfilesAndOneExplorer(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		Binary: "tor", LyrebirdBinary: "/usr/local/bin/lyrebird", DataDir: filepath.Join(t.TempDir(), "profiles"),
		SocksPortBase: 19050, WarmProfiles: 3, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]Candidate, 5)
	for index := range candidates {
		candidates[index] = Candidate{
			ID: fmt.Sprintf("bridge-%d", index), Score: float64(100 - index), Qualified: true,
			Bridge: fmt.Sprintf("Bridge obfs4 192.0.2.%d:443 0123456789ABCDEF0123456789ABCDEF0123456%d cert=x iat-mode=0", index+1, index),
		}
	}
	profiles, err := manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 4 || runner.starts != 4 {
		t.Fatalf("profiles=%+v starts=%d", profiles, runner.starts)
	}
	dataDirs := make(map[string]bool)
	for _, invocation := range runner.invocations {
		joined := strings.Join(invocation, " ")
		if strings.Contains(joined, ".onion") {
			t.Fatalf("onion behavior enabled: %s", joined)
		}
		dataDirs[valueAfter(invocation, "--DataDirectory")] = true
		bridge := valueAfter(invocation, "--Bridge")
		if bridge == "" || strings.Contains(bridge, "\n") || strings.HasPrefix(bridge, "Bridge ") {
			t.Fatalf("profile is not single-bridge: %q", bridge)
		}
	}
	if len(dataDirs) != 4 {
		t.Fatalf("profiles share DataDir: %+v", dataDirs)
	}
	if _, err := manager.Reconcile(context.Background(), candidates); err != nil {
		t.Fatal(err)
	}
	if runner.starts != 4 {
		t.Fatalf("unchanged profiles restarted: starts=%d", runner.starts)
	}
	runner.processes[0].exited = true
	if _, err := manager.Reconcile(context.Background(), candidates); err != nil {
		t.Fatal(err)
	}
	if runner.starts != 5 {
		t.Fatalf("exited warm profile was not restarted: starts=%d", runner.starts)
	}

	if _, err := manager.ExploreNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.starts != 6 || !strings.Contains(strings.Join(runner.invocations[5], " "), "bridge-5") {
		// The bridge payload uses 192.0.2.5; candidate IDs are not command args.
		if !strings.Contains(strings.Join(runner.invocations[5], " "), "192.0.2.5:443") {
			t.Fatalf("explorer did not rotate to fifth bridge: %v", runner.invocations[5])
		}
	}
}

func TestManagerRejectsUnsafeProfileCounts(t *testing.T) {
	if _, err := NewManager(Config{WarmProfiles: 4, ExplorerProfiles: 1}, &torRunner{}); err == nil {
		t.Fatal("resource budget must cap Tor profiles at four")
	}
}

func TestProbeCandidateRejectsCanceledContextWithoutReplacingExplorer(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{DataDir: filepath.Join(t.TempDir(), "profiles"), ExplorerProfiles: 1}, runner)
	if err != nil {
		t.Fatal(err)
	}
	original := Candidate{
		ID:     "existing",
		Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}
	if _, err := manager.ProbeCandidate(context.Background(), original); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	replacement := Candidate{
		ID:     "replacement",
		Bridge: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
	}
	if _, err := manager.ProbeCandidate(ctx, replacement); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	profiles := manager.Profiles()
	if runner.starts != 1 || len(profiles) != 1 || profiles[0].CandidateID != original.ID {
		t.Fatalf("starts=%d profiles=%+v", runner.starts, profiles)
	}
	if runner.processes[0].stopped {
		t.Fatal("canceled probe stopped the existing explorer")
	}
}

func TestProbeCandidateCreatesNestedDataDirectoryBeforeStartingTor(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "tor", "profiles")
	runner := &dataDirCheckingRunner{}
	manager, err := NewManager(Config{
		DataDir: baseDir, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	profile, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID:     "bridge",
		Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.checked != profile.DataDir {
		t.Fatalf("checked data directory=%q, want %q", runner.checked, profile.DataDir)
	}
	info, err := os.Stat(profile.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("profile data directory mode=%v", info.Mode())
	}
}

func TestProfilesOmitsExitedTorProcess(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID:     "bridge",
		Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}); err != nil {
		t.Fatal(err)
	}

	runner.processes[0].exited = true

	if profiles := manager.Profiles(); len(profiles) != 0 {
		t.Fatalf("exited Tor process remained available: %+v", profiles)
	}
}

func TestProbeCandidateRestartsExitedProcessForSameCandidate(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	candidate := Candidate{
		ID:     "bridge",
		Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}
	if _, err := manager.ProbeCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.processes[0].exited = true

	if _, err := manager.ProbeCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if runner.starts != 2 {
		t.Fatalf("Tor starts=%d, want exited candidate to restart", runner.starts)
	}
}

func TestReconcilePromotesLiveExplorerWithoutRestartingTor(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 1, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	qualified := Candidate{
		ID:        "qualified",
		Bridge:    "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		Score:     90,
		Qualified: true,
	}
	explorer, err := manager.ProbeCandidate(context.Background(), qualified)
	if err != nil {
		t.Fatal(err)
	}

	profiles, err := manager.Reconcile(context.Background(), []Candidate{qualified})
	if err != nil {
		t.Fatal(err)
	}
	if runner.starts != 1 || runner.processes[0].stopped {
		t.Fatalf("qualified explorer restarted: starts=%d stopped=%v", runner.starts, runner.processes[0].stopped)
	}
	if len(profiles) != 1 || profiles[0].Role != "warm" || profiles[0].Slot != explorer.Slot {
		t.Fatalf("promoted profiles=%+v, explorer=%+v", profiles, explorer)
	}

	next := Candidate{
		ID:     "next",
		Bridge: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
	}
	nextProfile, err := manager.ProbeCandidate(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if nextProfile.Role != "explorer" || nextProfile.Slot == explorer.Slot {
		t.Fatalf("next explorer replaced warm route: warm=%+v next=%+v", explorer, nextProfile)
	}
	profiles = manager.Profiles()
	if len(profiles) != 2 || profiles[0].CandidateID == profiles[1].CandidateID {
		t.Fatalf("warm and explorer profiles=%+v", profiles)
	}
}

func TestReconcileKeepsAssignedDrainingWarmUntilSlotIsReleased(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 3, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	candidates := []Candidate{
		{ID: "old", Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567", Score: 100, Qualified: true, Assigned: true},
		{ID: "second", Bridge: "Bridge 192.0.2.2:443 1123456789ABCDEF0123456789ABCDEF01234567", Score: 90, Qualified: true},
		{ID: "third", Bridge: "Bridge 192.0.2.3:443 2123456789ABCDEF0123456789ABCDEF01234567", Score: 80, Qualified: true},
		{ID: "challenger", Bridge: "Bridge 192.0.2.4:443 3123456789ABCDEF0123456789ABCDEF01234567", Score: 70, Qualified: true},
	}
	if _, err := manager.Reconcile(context.Background(), candidates); err != nil {
		t.Fatal(err)
	}
	if runner.starts != 4 {
		t.Fatalf("initial starts=%d", runner.starts)
	}

	candidates[0].Draining = true
	candidates[3].Score = 110
	profiles, err := manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if runner.starts != 4 {
		t.Fatalf("promotion restarted Tor: starts=%d", runner.starts)
	}
	for _, process := range runner.processes {
		if process.stopped {
			t.Fatal("promotion stopped a profile before placement drained it")
		}
	}
	if len(profiles) != 4 {
		t.Fatalf("profiles=%+v", profiles)
	}
	for _, profile := range profiles {
		if profile.Role != "warm" {
			t.Fatalf("draining assigned profile exposed as replaceable explorer: %+v", profiles)
		}
	}
	if _, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID: "next", Bridge: "Bridge 192.0.2.5:443 4123456789ABCDEF0123456789ABCDEF01234567",
	}); err == nil {
		t.Fatal("discovery replaced an assigned draining profile in a full pool")
	}
	for _, process := range runner.processes {
		if process.stopped {
			t.Fatal("failed discovery stopped a warm profile")
		}
	}

	active := []Candidate{candidates[1], candidates[2], candidates[3]}
	if _, err := manager.Reconcile(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if !runner.processes[0].stopped {
		t.Fatal("released draining profile was not stopped")
	}
	if _, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID: "next", Bridge: "Bridge 192.0.2.5:443 4123456789ABCDEF0123456789ABCDEF01234567",
	}); err != nil {
		t.Fatalf("discovery did not resume after drain: %v", err)
	}
}

func TestReconcileDropsUnassignedDrainingProfilesBeyondRuntimeCapacity(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 3, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	candidates := []Candidate{
		{ID: "assigned", Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567", Qualified: true, Draining: true, Assigned: true},
		{ID: "draining-1", Bridge: "Bridge 192.0.2.2:443 1123456789ABCDEF0123456789ABCDEF01234567", Qualified: true, Draining: true},
		{ID: "draining-2", Bridge: "Bridge 192.0.2.3:443 2123456789ABCDEF0123456789ABCDEF01234567", Qualified: true, Draining: true},
		{ID: "draining-3", Bridge: "Bridge 192.0.2.4:443 3123456789ABCDEF0123456789ABCDEF01234567", Qualified: true, Draining: true},
		{ID: "draining-4", Bridge: "Bridge 192.0.2.5:443 4123456789ABCDEF0123456789ABCDEF01234567", Qualified: true, Draining: true},
		{ID: "active", Bridge: "Bridge 192.0.2.6:443 5123456789ABCDEF0123456789ABCDEF01234567", Score: 100, Qualified: true},
	}
	profiles, err := manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		seen[profile.CandidateID] = true
	}
	if !seen["assigned"] || !seen["active"] {
		t.Fatalf("continuity or active profile missing: %+v", profiles)
	}
	for index := 1; index <= 4; index++ {
		if seen[fmt.Sprintf("draining-%d", index)] {
			t.Fatalf("unassigned draining profile remained materialized: %+v", profiles)
		}
	}
}

func TestReconcileProtectsAssignedCandidateEvictedFromLocalWarmRanking(t *testing.T) {
	runner := &torRunner{}
	manager, err := NewManager(Config{
		DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 3, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	candidates := []Candidate{
		{ID: "old", Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567", Score: 100, Qualified: true},
		{ID: "second", Bridge: "Bridge 192.0.2.2:443 1123456789ABCDEF0123456789ABCDEF01234567", Score: 90, Qualified: true},
		{ID: "third", Bridge: "Bridge 192.0.2.3:443 2123456789ABCDEF0123456789ABCDEF01234567", Score: 80, Qualified: true},
		{ID: "challenger", Bridge: "Bridge 192.0.2.4:443 3123456789ABCDEF0123456789ABCDEF01234567", Score: 70, Qualified: true},
	}
	if _, err := manager.Reconcile(context.Background(), candidates); err != nil {
		t.Fatal(err)
	}

	candidates[0].Assigned = true
	candidates[0].Score = 60
	candidates[3].Score = 110
	profiles, err := manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if runner.starts != 4 {
		t.Fatalf("local rank promotion restarted Tor: starts=%d", runner.starts)
	}
	for _, process := range runner.processes {
		if process.stopped {
			t.Fatal("local rank promotion stopped an assigned route")
		}
	}
	old := profileByCandidateID(t, profiles, "old")
	if old.Role != "warm" || !old.Retiring {
		t.Fatalf("assigned evicted route=%+v, profiles=%+v", old, profiles)
	}
	if _, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID: "next", Bridge: "Bridge 192.0.2.5:443 4123456789ABCDEF0123456789ABCDEF01234567",
	}); err == nil {
		t.Fatal("discovery replaced assigned route while local Tor pool was full")
	}

	candidates[0].Assigned = false
	profiles, err = manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	old = profileByCandidateID(t, profiles, "old")
	if old.Role != "explorer" || old.Retiring {
		t.Fatalf("released route did not become replaceable explorer: %+v", old)
	}
	if _, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID: "next", Bridge: "Bridge 192.0.2.5:443 4123456789ABCDEF0123456789ABCDEF01234567",
	}); err != nil {
		t.Fatalf("discovery did not resume after route switch: %v", err)
	}
}

func profileByCandidateID(t *testing.T, profiles []Profile, candidateID string) Profile {
	t.Helper()
	for _, profile := range profiles {
		if profile.CandidateID == candidateID {
			return profile
		}
	}
	t.Fatalf("candidate %q missing from profiles %+v", candidateID, profiles)
	return Profile{}
}

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

func TestManagerCloseAggregatesStopErrorsAndStillCancels(t *testing.T) {
	firstErr := errors.New("first stop")
	secondErr := errors.New("second stop")
	manager, err := NewManager(Config{WarmProfiles: 1}, &torRunner{})
	if err != nil {
		t.Fatal(err)
	}
	first := &errorProcess{err: firstErr}
	second := &errorProcess{err: secondErr}
	manager.profiles[0] = managedProfile{process: first}
	manager.profiles[1] = managedProfile{process: second}

	closeErr := manager.Close()
	if !errors.Is(closeErr, firstErr) || !errors.Is(closeErr, secondErr) {
		t.Fatalf("Close error=%v, want both stop errors", closeErr)
	}
	if first.stops != 1 || second.stops != 1 {
		t.Fatalf("stop calls first=%d second=%d", first.stops, second.stops)
	}
	select {
	case <-manager.processCtx.Done():
	default:
		t.Fatal("Manager.Close did not cancel process context after stop errors")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("idempotent Close error=%v", err)
	}
}

type errorProcess struct {
	err   error
	stops int
}

func (process *errorProcess) Stop() error {
	process.stops++
	return process.err
}

func (*errorProcess) Exited() bool {
	return false
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

type torRunner struct {
	starts      int
	invocations [][]string
	processes   []*torProcess
}

type dataDirCheckingRunner struct {
	checked string
}

func (runner *dataDirCheckingRunner) Start(_ context.Context, _ string, args ...string) (Process, error) {
	runner.checked = valueAfter(args, "--DataDirectory")
	if _, err := os.Stat(runner.checked); err != nil {
		return nil, fmt.Errorf("Tor data directory unavailable at start: %w", err)
	}
	return &torProcess{}, nil
}

func (runner *torRunner) Start(_ context.Context, name string, args ...string) (Process, error) {
	runner.starts++
	runner.invocations = append(runner.invocations, append([]string{name}, args...))
	process := &torProcess{}
	runner.processes = append(runner.processes, process)
	return process, nil
}

type torProcess struct {
	stopped bool
	exited  bool
}

func (process *torProcess) Stop() error  { process.stopped = true; return nil }
func (process *torProcess) Exited() bool { return process.exited }

func valueAfter(values []string, key string) string {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == key {
			return values[index+1]
		}
	}
	return ""
}
