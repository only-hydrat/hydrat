package torpool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Binary           string
	LyrebirdBinary   string
	DataDir          string
	SocksPortBase    int
	WarmProfiles     int
	ExplorerProfiles int
}

type Candidate struct {
	ID        string
	Bridge    string
	Score     float64
	Qualified bool
	Draining  bool
	Assigned  bool
}

type Profile struct {
	Slot        int    `json:"slot"`
	Role        string `json:"role"`
	CandidateID string `json:"candidate_id"`
	SocksAddr   string `json:"socks_addr"`
	DataDir     string `json:"data_dir"`
	Retiring    bool   `json:"retiring,omitempty"`
}

type ProfileStatus struct {
	Profile Profile
	Exited  bool
}

type Process interface {
	Stop() error
	Exited() bool
}

type Runner interface {
	Start(context.Context, string, ...string) (Process, error)
}

type managedProfile struct {
	profile Profile
	process Process
}

type desiredProfile struct {
	candidate Candidate
	role      string
	retiring  bool
}

type Manager struct {
	config       Config
	runner       Runner
	profiles     map[int]managedProfile
	candidates   []Candidate
	explorerNext int
	mu           sync.Mutex
	processCtx   context.Context
	cancel       context.CancelFunc
}

func NewManager(config Config, runner Runner) (*Manager, error) {
	if config.WarmProfiles < 0 || config.ExplorerProfiles < 0 || config.WarmProfiles+config.ExplorerProfiles > 4 {
		return nil, errors.New("Tor profile budget must be between zero and four")
	}
	if config.WarmProfiles+config.ExplorerProfiles == 0 {
		return nil, errors.New("at least one Tor profile is required")
	}
	if config.Binary == "" {
		config.Binary = "tor"
	}
	if config.DataDir == "" {
		config.DataDir = "/data/tor/profiles"
	}
	if config.SocksPortBase == 0 {
		config.SocksPortBase = 19050
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	processCtx, cancel := context.WithCancel(context.Background())
	return &Manager{config: config, runner: runner, profiles: make(map[int]managedProfile), processCtx: processCtx, cancel: cancel}, nil
}

func (manager *Manager) Reconcile(ctx context.Context, candidates []Candidate) ([]Profile, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	active := make([]Candidate, 0, len(candidates))
	draining := make([]Candidate, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Qualified || candidate.ID == "" ||
			strings.TrimSpace(candidate.Bridge) == "" || seen[candidate.ID] {
			continue
		}
		seen[candidate.ID] = true
		if candidate.Draining {
			// A draining candidate only needs a runtime slot while it still
			// carries traffic (or was marked mandatory by the controller).
			// Keeping every logical working-pool member materialized can exceed
			// the fixed four-profile runtime budget and deadlock retirement.
			if candidate.Assigned {
				draining = append(draining, candidate)
			}
			continue
		}
		active = append(active, candidate)
	}
	sort.SliceStable(active, func(i, j int) bool {
		if active[i].Score == active[j].Score {
			return active[i].ID < active[j].ID
		}
		return active[i].Score > active[j].Score
	})
	sort.SliceStable(draining, func(i, j int) bool {
		return draining[i].ID < draining[j].ID
	})
	capacity := manager.config.WarmProfiles + manager.config.ExplorerProfiles
	if len(draining) > capacity {
		return nil, fmt.Errorf(
			"Tor draining profiles exceed capacity: have %d, capacity %d",
			len(draining), capacity,
		)
	}
	desired := make([]desiredProfile, 0, capacity)
	desiredIDs := make(map[string]bool, capacity)
	for _, candidate := range draining {
		desired = append(desired, desiredProfile{
			candidate: candidate, role: "warm", retiring: true,
		})
		desiredIDs[candidate.ID] = true
	}
	topActive := manager.config.WarmProfiles
	if topActive > len(active) {
		topActive = len(active)
	}
	topActiveIDs := make(map[string]bool, topActive)
	for index := 0; index < topActive; index++ {
		topActiveIDs[active[index].ID] = true
	}
	for _, candidate := range active {
		if candidate.Assigned && !topActiveIDs[candidate.ID] {
			desired = append(desired, desiredProfile{
				candidate: candidate, role: "warm", retiring: true,
			})
			desiredIDs[candidate.ID] = true
		}
	}
	if len(desired) > capacity {
		return nil, fmt.Errorf(
			"Tor protected profiles exceed capacity: have %d, capacity %d",
			len(desired), capacity,
		)
	}
	for index := 0; index < topActive && len(desired) < capacity; index++ {
		if desiredIDs[active[index].ID] {
			continue
		}
		desired = append(desired, desiredProfile{candidate: active[index], role: "warm"})
		desiredIDs[active[index].ID] = true
	}

	manager.candidates = manager.candidates[:0]
	for _, candidate := range active {
		if !desiredIDs[candidate.ID] && !candidate.Assigned {
			manager.candidates = append(manager.candidates, candidate)
		}
	}
	manager.explorerNext = 0
	for explorers := 0; explorers < manager.config.ExplorerProfiles &&
		manager.explorerNext < len(manager.candidates) &&
		len(desired) < capacity; explorers++ {
		desired = append(desired, desiredProfile{
			candidate: manager.candidates[manager.explorerNext],
			role:      "explorer",
		})
		manager.explorerNext++
	}
	if err := manager.reconcileProfiles(ctx, desired); err != nil {
		return nil, err
	}
	return manager.profileList(), nil
}

func (manager *Manager) ExploreNext(ctx context.Context) ([]Profile, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.config.ExplorerProfiles == 0 || len(manager.candidates) == 0 {
		return manager.profileList(), nil
	}
	if manager.explorerNext >= len(manager.candidates) {
		manager.explorerNext = 0
	}
	slot, err := manager.explorerSlot()
	if err != nil {
		return manager.profileList(), err
	}
	candidate := manager.candidates[manager.explorerNext]
	manager.explorerNext++
	if err := manager.replaceProfile(ctx, slot, "explorer", false, candidate); err != nil {
		return nil, err
	}
	return manager.profileList(), nil
}

// ProbeCandidate temporarily places a candidate in the dedicated explorer
// profile. Warm profiles carrying client traffic are never replaced.
func (manager *Manager) ProbeCandidate(ctx context.Context, candidate Candidate) (Profile, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	if manager.config.ExplorerProfiles <= 0 {
		return Profile{}, errors.New("Tor explorer profile is disabled")
	}
	if candidate.ID == "" || strings.TrimSpace(candidate.Bridge) == "" {
		return Profile{}, errors.New("Tor probe candidate is invalid")
	}
	for _, current := range manager.profiles {
		if current.profile.CandidateID == candidate.ID && !current.process.Exited() {
			return current.profile, nil
		}
	}
	slot, err := manager.explorerSlot()
	if err != nil {
		return Profile{}, err
	}
	if err := manager.replaceProfile(ctx, slot, "explorer", false, candidate); err != nil {
		return Profile{}, err
	}
	return manager.profiles[slot].profile, nil
}

func (manager *Manager) Profiles() []Profile {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.profileList()
}

func (manager *Manager) ProfileStatus(candidateID string) (ProfileStatus, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, current := range manager.profiles {
		if current.profile.CandidateID == candidateID {
			return ProfileStatus{
				Profile: current.profile,
				Exited:  current.process.Exited(),
			}, true
		}
	}
	return ProfileStatus{}, false
}

func (manager *Manager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	var stopErrors []error
	for slot, profile := range manager.profiles {
		if err := profile.process.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("stop Tor profile %d: %w", slot, err))
		}
		delete(manager.profiles, slot)
	}
	manager.cancel()
	return errors.Join(stopErrors...)
}

func (manager *Manager) reconcileProfiles(ctx context.Context, desired []desiredProfile) error {
	desiredByCandidate := make(map[string]desiredProfile, len(desired))
	for _, profile := range desired {
		desiredByCandidate[profile.candidate.ID] = profile
	}
	for slot, current := range manager.profiles {
		if current.process.Exited() {
			delete(manager.profiles, slot)
			continue
		}
		target, exists := desiredByCandidate[current.profile.CandidateID]
		if !exists {
			if err := current.process.Stop(); err != nil {
				return err
			}
			delete(manager.profiles, slot)
			continue
		}
		current.profile.Role = target.role
		current.profile.Retiring = target.retiring
		manager.profiles[slot] = current
	}

	existing := make(map[string]bool, len(manager.profiles))
	for _, current := range manager.profiles {
		existing[current.profile.CandidateID] = true
	}
	for _, target := range desired {
		if existing[target.candidate.ID] {
			continue
		}
		slot, err := manager.freeSlot(target.role)
		if err != nil {
			return err
		}
		if err := manager.replaceProfile(
			ctx, slot, target.role, target.retiring, target.candidate,
		); err != nil {
			return err
		}
		existing[target.candidate.ID] = true
	}
	return nil
}

func (manager *Manager) replaceProfile(
	ctx context.Context,
	slot int,
	role string,
	retiring bool,
	candidate Candidate,
) error {
	if current, exists := manager.profiles[slot]; exists {
		if current.profile.CandidateID == candidate.ID && !current.process.Exited() {
			current.profile.Role = role
			current.profile.Retiring = retiring
			manager.profiles[slot] = current
			return nil
		}
	}
	dataDir := fmt.Sprintf("%s/profile-%d", strings.TrimRight(manager.config.DataDir, "/"), slot)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create Tor profile data directory %d: %w", slot, err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return fmt.Errorf("secure Tor profile data directory %d: %w", slot, err)
	}
	if current, exists := manager.profiles[slot]; exists {
		if err := current.process.Stop(); err != nil {
			return err
		}
	}
	bridge := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(candidate.Bridge), "Bridge "))
	socksAddr := fmt.Sprintf("127.0.0.1:%d", manager.config.SocksPortBase+slot)
	args := []string{
		"--ClientOnly", "1", "--UseBridges", "1", "--DataDirectory", dataDir,
		"--SocksPort", socksAddr + " IsolateSOCKSAuth", "--Bridge", bridge,
		"--Log", "notice stdout", "--AvoidDiskWrites", "1",
	}
	transport := strings.Fields(bridge)[0]
	if !strings.Contains(transport, ":") {
		if manager.config.LyrebirdBinary == "" {
			return fmt.Errorf("bridge %s requires a pluggable transport", candidate.ID)
		}
		args = append(args, "--ClientTransportPlugin", transport+" exec "+manager.config.LyrebirdBinary)
	}
	process, err := manager.runner.Start(manager.processCtx, manager.config.Binary, args...)
	if err != nil {
		return fmt.Errorf("start Tor profile %d: %w", slot, err)
	}
	manager.profiles[slot] = managedProfile{
		profile: Profile{
			Slot: slot, Role: role, CandidateID: candidate.ID,
			SocksAddr: socksAddr, DataDir: dataDir,
			Retiring: retiring,
		},
		process: process,
	}
	return nil
}

func (manager *Manager) explorerSlot() (int, error) {
	for slot, current := range manager.profiles {
		if current.profile.Role == "explorer" {
			return slot, nil
		}
	}
	return manager.freeSlot("explorer")
}

func (manager *Manager) freeSlot(role string) (int, error) {
	total := manager.config.WarmProfiles + manager.config.ExplorerProfiles
	start := 0
	if role == "explorer" {
		start = manager.config.WarmProfiles
	}
	for offset := 0; offset < total; offset++ {
		slot := (start + offset) % total
		if _, exists := manager.profiles[slot]; !exists {
			return slot, nil
		}
	}
	return 0, errors.New("no Tor profile slot is available")
}

func (manager *Manager) profileList() []Profile {
	result := make([]Profile, 0, len(manager.profiles))
	for _, profile := range manager.profiles {
		if profile.process.Exited() {
			continue
		}
		result = append(result, profile.profile)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Slot < result[j].Slot })
	return result
}

type ExecRunner struct {
	GracePeriod time.Duration
	KillWait    time.Duration
}

func (runner ExecRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	gracePeriod := runner.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 2 * time.Second
	}
	killWait := runner.KillWait
	if killWait <= 0 {
		killWait = 2 * time.Second
	}
	process := &execProcess{
		command: command, done: make(chan struct{}),
		gracePeriod: gracePeriod, killWait: killWait, processGroup: true,
	}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	return process, nil
}

type execProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	gracePeriod  time.Duration
	killWait     time.Duration
	processGroup bool
	stopMu       sync.Mutex
}

func (process *execProcess) Exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *execProcess) Stop() error {
	process.stopMu.Lock()
	defer process.stopMu.Unlock()
	if process.command.Process == nil {
		return nil
	}
	if process.Exited() {
		return nil
	}
	if err := process.signal(syscall.SIGTERM); err != nil {
		if process.Exited() {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	gracePeriod := process.gracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 2 * time.Second
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(gracePeriod):
	}
	if err := process.signal(syscall.SIGKILL); err != nil {
		if process.Exited() {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	killWait := process.killWait
	if killWait <= 0 {
		killWait = 2 * time.Second
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(killWait):
		return errors.New("timed out waiting for forced Tor process exit")
	}
}

func (process *execProcess) signal(signal syscall.Signal) error {
	if process.processGroup {
		return syscall.Kill(-process.command.Process.Pid, signal)
	}
	return process.command.Process.Signal(signal)
}
