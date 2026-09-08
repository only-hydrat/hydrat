package proberuntime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// UnlimitedProbes disables only count-based recycling. Resource, cleanup,
	// child-exit and readiness failures still recycle the managed process.
	UnlimitedProbes = ^uint64(0)

	defaultMaxProbes        = uint64(250)
	defaultMaxRSSBytes      = int64(256 * 1024 * 1024)
	defaultMaxFDs           = 512
	defaultDrainTimeout     = 25 * time.Second
	defaultStopTimeout      = 5 * time.Second
	defaultReadinessTimeout = 60 * time.Second

	reasonCleanupFailure   = "cleanup_failure"
	reasonChildExit        = "child_exit"
	reasonReadinessFailure = "readiness_failure"
	reasonRSSLimit         = "rss_limit"
	reasonFDLimit          = "fd_limit"
	reasonProbeLimit       = "probe_limit"
)

var (
	ErrClosed             = errors.New("probe runtime is closed")
	ErrNotStarted         = errors.New("probe runtime is not started")
	ErrMetricsUnsupported = errors.New("probe process metrics are unsupported")
)

type Config struct {
	Binary           string
	ConfigPath       string
	APIAddress       string
	MaxProbes        uint64
	MaxRSSBytes      int64
	MaxFDs           int
	DrainTimeout     time.Duration
	StopTimeout      time.Duration
	ReadinessTimeout time.Duration
}

type Snapshot struct {
	Status            string `json:"status"`
	Epoch             uint64 `json:"epoch"`
	RSSBytes          int64  `json:"rss_bytes"`
	FDCount           int    `json:"fd_count"`
	CompletedProbes   uint64 `json:"completed_probes"`
	RecycleCount      uint64 `json:"recycle_count"`
	LastRecycleReason string `json:"last_recycle_reason,omitempty"`
}

type Lease struct {
	Epoch   uint64
	Context context.Context

	manager *Manager
	cancel  context.CancelFunc
	active  bool
}

type resetter interface {
	Reset(uint64)
}

type ownedProcess interface {
	PID() int
	Done() <-chan struct{}
	BeginStop() bool
	Stop(time.Duration) error
}

type processStarter interface {
	Start(context.Context, Config) (ownedProcess, error)
}

type processStarterFunc func(context.Context, Config) (ownedProcess, error)

func (function processStarterFunc) Start(ctx context.Context, config Config) (ownedProcess, error) {
	return function(ctx, config)
}

type readinessCheck func(context.Context, ownedProcess, string) error

type processMetrics struct {
	rssBytes int64
	fdCount  int
}

type metricsReader interface {
	Read(int) (processMetrics, error)
}

type metricsReaderFunc func(int) (processMetrics, error)

func (function metricsReaderFunc) Read(pid int) (processMetrics, error) {
	return function(pid)
}

type dependencies struct {
	starter   processStarter
	readiness readinessCheck
	metrics   metricsReader
}

type Option func(*dependencies)

func withProcessStarter(starter processStarter) Option {
	return func(dependencies *dependencies) {
		if starter != nil {
			dependencies.starter = starter
		}
	}
}

func withReadinessCheck(check readinessCheck) Option {
	return func(dependencies *dependencies) {
		if check != nil {
			dependencies.readiness = check
		}
	}
}

func withMetricsReader(reader metricsReader) Option {
	return func(dependencies *dependencies) {
		if reader != nil {
			dependencies.metrics = reader
		}
	}
}

type Manager struct {
	config   Config
	resetter resetter
	starter  processStarter
	check    readinessCheck
	metrics  metricsReader

	mu   sync.Mutex
	cond *sync.Cond

	startCalled bool
	starting    bool
	ready       bool
	draining    bool
	degraded    bool
	closed      bool
	resetting   bool

	process           ownedProcess
	processGeneration uint64
	intentionalStop   uint64
	active            map[*Lease]struct{}
	epoch             uint64
	rssBytes          int64
	fdCount           int
	completedProbes   uint64
	recycleCount      uint64
	lastRecycleReason string
	metricErrorLogged bool

	recycleRequests chan struct{}
	lifetimeCtx     context.Context
	lifetimeCancel  context.CancelFunc
	workerStarted   bool
	workerDone      chan struct{}
	startDone       chan struct{}
	watchers        sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

func New(config Config, resetter interface{ Reset(uint64) }, options ...Option) (*Manager, error) {
	if resetter == nil {
		return nil, errors.New("probe runtime resetter is required")
	}
	config = withRuntimeDefaults(config)
	if strings.TrimSpace(config.Binary) == "" {
		return nil, errors.New("probe runtime binary is required")
	}
	if strings.TrimSpace(config.ConfigPath) == "" {
		return nil, errors.New("probe runtime config path is required")
	}
	if strings.TrimSpace(config.APIAddress) == "" {
		return nil, errors.New("probe runtime API address is required")
	}
	if config.MaxProbes == 0 {
		return nil, errors.New("probe runtime max probes must be positive")
	}
	if config.MaxRSSBytes <= 0 {
		return nil, errors.New("probe runtime max RSS must be positive")
	}
	if config.MaxFDs <= 0 {
		return nil, errors.New("probe runtime max FDs must be positive")
	}
	if config.DrainTimeout <= 0 {
		return nil, errors.New("probe runtime drain timeout must be positive")
	}
	if config.StopTimeout <= 0 {
		return nil, errors.New("probe runtime stop timeout must be positive")
	}
	if config.ReadinessTimeout <= 0 {
		return nil, errors.New("probe runtime readiness timeout must be positive")
	}

	deps := dependencies{
		starter:   execProcessStarter{},
		readiness: checkAPIReadiness,
		metrics:   procMetricsReader{},
	}
	for _, option := range options {
		if option != nil {
			option(&deps)
		}
	}
	manager := &Manager{
		config:          config,
		resetter:        resetter,
		starter:         deps.starter,
		check:           deps.readiness,
		metrics:         deps.metrics,
		active:          make(map[*Lease]struct{}),
		recycleRequests: make(chan struct{}, 1),
		workerDone:      make(chan struct{}),
		startDone:       make(chan struct{}),
	}
	manager.cond = sync.NewCond(&manager.mu)
	return manager, nil
}

func withRuntimeDefaults(config Config) Config {
	if config.MaxProbes == 0 {
		config.MaxProbes = defaultMaxProbes
	}
	if config.MaxRSSBytes == 0 {
		config.MaxRSSBytes = defaultMaxRSSBytes
	}
	if config.MaxFDs == 0 {
		config.MaxFDs = defaultMaxFDs
	}
	if config.DrainTimeout == 0 {
		config.DrainTimeout = defaultDrainTimeout
	}
	if config.StopTimeout == 0 {
		config.StopTimeout = defaultStopTimeout
	}
	if config.ReadinessTimeout == 0 {
		config.ReadinessTimeout = defaultReadinessTimeout
	}
	return config
}

func (manager *Manager) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return ErrClosed
	}
	if manager.startCalled {
		manager.mu.Unlock()
		return errors.New("probe runtime was already started")
	}
	manager.startCalled = true
	manager.starting = true
	manager.lifetimeCtx, manager.lifetimeCancel = context.WithCancel(ctx)
	lifetimeCtx := manager.lifetimeCtx
	manager.cond.Broadcast()
	manager.mu.Unlock()
	defer close(manager.startDone)

	process, err := manager.starter.Start(lifetimeCtx, manager.config)
	if err != nil {
		manager.markInitialStartFailure()
		return fmt.Errorf("start probe Xray: %w", err)
	}
	if err := manager.awaitReadiness(lifetimeCtx, process); err != nil {
		stopErr := process.Stop(manager.config.StopTimeout)
		if stopErr != nil {
			manager.retainProcess(process)
		}
		manager.markInitialStartFailure()
		if stopErr != nil {
			return errors.Join(fmt.Errorf("wait for probe Xray readiness: %w", err), stopErr)
		}
		return fmt.Errorf("wait for probe Xray readiness: %w", err)
	}

	manager.mu.Lock()
	if manager.closed || lifetimeCtx.Err() != nil {
		manager.mu.Unlock()
		stopErr := process.Stop(manager.config.StopTimeout)
		if stopErr != nil {
			manager.retainProcess(process)
		}
		manager.markInitialStartFailure()
		return errors.Join(ErrClosed, stopErr)
	}
	manager.process = process
	manager.processGeneration++
	generation := manager.processGeneration
	manager.epoch = 1
	manager.resetting = true
	manager.mu.Unlock()

	manager.resetter.Reset(1)

	manager.mu.Lock()
	manager.resetting = false
	if manager.closed || lifetimeCtx.Err() != nil ||
		manager.process != process || manager.processGeneration != generation ||
		manager.epoch != 1 {
		cleanup := !manager.closed && manager.process == process
		manager.cond.Broadcast()
		manager.mu.Unlock()
		if cleanup {
			stopErr := process.Stop(manager.config.StopTimeout)
			manager.mu.Lock()
			if stopErr == nil && manager.process == process {
				manager.process = nil
				manager.processGeneration++
			}
			manager.mu.Unlock()
			if stopErr != nil {
				manager.retainProcess(process)
			}
			manager.markInitialStartFailure()
			return errors.Join(ErrClosed, stopErr)
		}
		return ErrClosed
	}
	if channelClosed(process.Done()) {
		manager.process = nil
		manager.processGeneration++
		manager.starting = false
		manager.degraded = true
		if manager.lifetimeCancel != nil {
			manager.lifetimeCancel()
		}
		manager.cond.Broadcast()
		manager.mu.Unlock()
		return errors.New("probe Xray exited during control reset")
	}
	manager.starting = false
	manager.ready = true
	manager.degraded = false
	manager.workerStarted = true
	manager.cond.Broadcast()
	manager.mu.Unlock()

	manager.watchProcess(process, generation)
	go manager.run()
	return nil
}

func (manager *Manager) Acquire(ctx context.Context) (*Lease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stopWake := context.AfterFunc(ctx, func() {
		manager.mu.Lock()
		manager.cond.Broadcast()
		manager.mu.Unlock()
	})
	defer stopWake()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	for {
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case manager.closed:
			return nil, ErrClosed
		case !manager.startCalled:
			return nil, ErrNotStarted
		case manager.ready && !manager.draining:
			leaseCtx, cancel := context.WithCancel(ctx)
			lease := &Lease{
				Epoch: manager.epoch, Context: leaseCtx,
				manager: manager, cancel: cancel, active: true,
			}
			manager.active[lease] = struct{}{}
			return lease, nil
		default:
			manager.cond.Wait()
		}
	}
}

func (manager *Manager) Release(lease *Lease, cleanupErr error) {
	if lease == nil || lease.manager != manager {
		return
	}

	manager.mu.Lock()
	if !lease.active {
		manager.mu.Unlock()
		return
	}
	lease.active = false
	process := manager.process
	epoch := lease.Epoch
	if epoch == manager.epoch && !manager.closed {
		manager.completedProbes++
	}
	completed := manager.completedProbes
	lifetimeCtx := manager.lifetimeCtx
	manager.mu.Unlock()

	var (
		readinessErr error
		metrics      processMetrics
		metricsErr   error
	)
	exited := process == nil || channelClosed(process.Done())
	if process != nil && !exited {
		checkTimeout := manager.config.ReadinessTimeout
		if checkTimeout > time.Second {
			checkTimeout = time.Second
		}
		checkCtx, cancel := context.WithTimeout(lifetimeCtx, checkTimeout)
		readinessErr = manager.check(checkCtx, process, manager.config.APIAddress)
		cancel()
		metrics, metricsErr = manager.metrics.Read(process.PID())
		exited = channelClosed(process.Done())
	}

	manager.mu.Lock()
	_, tracked := manager.active[lease]
	delete(manager.active, lease)
	lease.cancel()
	logMetricError := false
	if tracked && epoch == manager.epoch && !manager.closed {
		if metricsErr == nil && process != nil {
			manager.rssBytes = metrics.rssBytes
			manager.fdCount = metrics.fdCount
		} else if metricsErr != nil && !manager.metricErrorLogged {
			manager.metricErrorLogged = true
			logMetricError = true
		}
		reason := ""
		switch {
		case cleanupErr != nil:
			reason = reasonCleanupFailure
		case exited:
			reason = reasonChildExit
		case readinessErr != nil:
			reason = reasonReadinessFailure
		case metricsErr == nil && metrics.rssBytes >= manager.config.MaxRSSBytes:
			reason = reasonRSSLimit
		case metricsErr == nil && metrics.fdCount >= manager.config.MaxFDs:
			reason = reasonFDLimit
		case manager.config.MaxProbes != UnlimitedProbes && completed >= manager.config.MaxProbes:
			reason = reasonProbeLimit
		}
		if reason != "" {
			manager.requestRecycleLocked(reason)
		}
	}
	manager.cond.Broadcast()
	manager.mu.Unlock()
	if logMetricError {
		log.Printf("probe runtime: read metrics for pid %d: %v", process.PID(), metricsErr)
	}
}

func (manager *Manager) Snapshot() Snapshot {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return Snapshot{
		Status:            manager.statusLocked(),
		Epoch:             manager.epoch,
		RSSBytes:          manager.rssBytes,
		FDCount:           manager.fdCount,
		CompletedProbes:   manager.completedProbes,
		RecycleCount:      manager.recycleCount,
		LastRecycleReason: manager.lastRecycleReason,
	}
}

func (manager *Manager) Close() error {
	manager.closeOnce.Do(func() {
		manager.mu.Lock()
		manager.closed = true
		manager.ready = false
		manager.draining = true
		for lease := range manager.active {
			lease.active = false
			lease.cancel()
			delete(manager.active, lease)
		}
		if manager.lifetimeCancel != nil {
			manager.lifetimeCancel()
		}
		startCalled := manager.startCalled
		starting := manager.starting
		resetting := manager.resetting
		process := manager.process
		manager.cond.Broadcast()
		manager.mu.Unlock()

		if resetting {
			var stopErr error
			if process != nil {
				stopErr = process.Stop(manager.config.StopTimeout)
			}
			manager.mu.Lock()
			manager.closeErr = errors.Join(manager.closeErr, stopErr)
			if stopErr == nil && manager.process == process {
				manager.process = nil
				manager.processGeneration++
			}
			manager.mu.Unlock()
			manager.watchers.Wait()
			return
		}
		if startCalled && starting {
			<-manager.startDone
		}
		manager.mu.Lock()
		workerStarted := manager.workerStarted
		process = manager.process
		manager.mu.Unlock()
		if workerStarted {
			<-manager.workerDone
		} else if process != nil {
			manager.recordCloseError(process.Stop(manager.config.StopTimeout))
		}
		manager.watchers.Wait()
	})
	return manager.closeError()
}

func (manager *Manager) run() {
	defer close(manager.workerDone)
	for {
		select {
		case <-manager.lifetimeCtx.Done():
			manager.shutdown()
			return
		case <-manager.recycleRequests:
			manager.recycle()
		}
	}
}

func (manager *Manager) recycle() {
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return
	}
	manager.recycleCount++
	manager.mu.Unlock()

	if !manager.waitForDrain() {
		return
	}

	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return
	}
	process := manager.process
	stoppingGeneration := manager.processGeneration
	if process != nil {
		if process.BeginStop() {
			manager.intentionalStop = stoppingGeneration
		} else {
			manager.requestRecycleLocked(reasonChildExit)
		}
	}
	manager.starting = true
	manager.ready = false
	manager.cond.Broadcast()
	manager.mu.Unlock()

	if process != nil {
		if err := process.Stop(manager.config.StopTimeout); err != nil {
			manager.mu.Lock()
			manager.clearIntentionalStopLocked(stoppingGeneration)
			manager.closeErr = errors.Join(manager.closeErr, err)
			manager.starting = false
			manager.draining = false
			manager.degraded = true
			manager.cond.Broadcast()
			manager.mu.Unlock()
			return
		}
	}

	manager.mu.Lock()
	manager.clearIntentionalStopLocked(stoppingGeneration)
	if manager.process == process {
		manager.process = nil
		manager.processGeneration++
	}
	manager.mu.Unlock()

	replacement, err := manager.starter.Start(manager.lifetimeCtx, manager.config)
	if err == nil {
		err = manager.awaitReadiness(manager.lifetimeCtx, replacement)
	}
	if err != nil {
		var stopErr error
		if replacement != nil {
			stopErr = replacement.Stop(manager.config.StopTimeout)
		}
		manager.mu.Lock()
		if stopErr != nil {
			if manager.process == nil {
				manager.process = replacement
				manager.processGeneration++
			}
			manager.closeErr = errors.Join(manager.closeErr, stopErr)
		}
		manager.starting = false
		manager.draining = false
		manager.degraded = true
		manager.cond.Broadcast()
		manager.mu.Unlock()
		return
	}

	manager.mu.Lock()
	if manager.closed || manager.lifetimeCtx.Err() != nil {
		manager.mu.Unlock()
		stopErr := replacement.Stop(manager.config.StopTimeout)
		if stopErr != nil {
			manager.retainProcessError(replacement, stopErr)
		}
		return
	}
	manager.process = replacement
	manager.processGeneration++
	generation := manager.processGeneration
	manager.epoch++
	epoch := manager.epoch
	manager.completedProbes = 0
	manager.rssBytes = 0
	manager.fdCount = 0
	manager.metricErrorLogged = false
	manager.resetting = true
	manager.mu.Unlock()

	manager.resetter.Reset(epoch)

	manager.mu.Lock()
	manager.resetting = false
	if manager.closed || manager.lifetimeCtx.Err() != nil ||
		manager.process != replacement || manager.processGeneration != generation ||
		manager.epoch != epoch {
		cleanup := !manager.closed && manager.process == replacement
		manager.cond.Broadcast()
		manager.mu.Unlock()
		if cleanup {
			stopErr := replacement.Stop(manager.config.StopTimeout)
			if stopErr != nil {
				manager.retainProcessError(replacement, stopErr)
			} else {
				manager.mu.Lock()
				if manager.process == replacement {
					manager.process = nil
					manager.processGeneration++
				}
				manager.mu.Unlock()
			}
		}
		return
	}
	if channelClosed(replacement.Done()) {
		manager.lastRecycleReason = reasonChildExit
		manager.process = nil
		manager.processGeneration++
		manager.starting = false
		manager.ready = false
		manager.draining = false
		manager.degraded = true
		manager.cond.Broadcast()
		manager.mu.Unlock()
		return
	}
	manager.starting = false
	manager.draining = false
	manager.degraded = false
	manager.ready = true
	manager.cond.Broadcast()
	manager.mu.Unlock()
	manager.watchProcess(replacement, generation)
}

func (manager *Manager) waitForDrain() bool {
	deadline := time.Now().Add(manager.config.DrainTimeout)
	timeoutWake := time.AfterFunc(manager.config.DrainTimeout, func() {
		manager.mu.Lock()
		manager.cond.Broadcast()
		manager.mu.Unlock()
	})
	cancelWake := context.AfterFunc(manager.lifetimeCtx, func() {
		manager.mu.Lock()
		manager.cond.Broadcast()
		manager.mu.Unlock()
	})
	defer timeoutWake.Stop()
	defer cancelWake()

	manager.mu.Lock()
	for len(manager.active) > 0 && !manager.closed &&
		manager.lifetimeCtx.Err() == nil && time.Now().Before(deadline) {
		manager.cond.Wait()
	}
	if manager.closed || manager.lifetimeCtx.Err() != nil {
		manager.mu.Unlock()
		return false
	}
	if len(manager.active) > 0 {
		for lease := range manager.active {
			lease.active = false
			lease.cancel()
			delete(manager.active, lease)
		}
		manager.cond.Broadcast()
	}
	manager.mu.Unlock()
	return true
}

func (manager *Manager) shutdown() {
	manager.mu.Lock()
	manager.closed = true
	manager.ready = false
	manager.draining = true
	for lease := range manager.active {
		lease.active = false
		lease.cancel()
		delete(manager.active, lease)
	}
	process := manager.process
	manager.cond.Broadcast()
	manager.mu.Unlock()
	if process != nil {
		manager.recordCloseError(process.Stop(manager.config.StopTimeout))
	}
}

func (manager *Manager) awaitReadiness(parent context.Context, process ownedProcess) error {
	ctx, cancel := context.WithTimeout(parent, manager.config.ReadinessTimeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if channelClosed(process.Done()) {
			return errors.New("probe Xray exited before readiness")
		}
		if err := manager.check(ctx, process, manager.config.APIAddress); err == nil {
			if channelClosed(process.Done()) {
				return errors.New("probe Xray exited before readiness")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-process.Done():
			return errors.New("probe Xray exited before readiness")
		case <-ticker.C:
		}
	}
}

func (manager *Manager) watchProcess(process ownedProcess, generation uint64) {
	manager.watchers.Add(1)
	go func() {
		defer manager.watchers.Done()
		select {
		case <-manager.lifetimeCtx.Done():
			return
		case <-process.Done():
		}
		manager.mu.Lock()
		if !manager.closed && manager.processGeneration == generation &&
			manager.intentionalStop != generation {
			manager.requestRecycleLocked(reasonChildExit)
		}
		manager.mu.Unlock()
	}()
}

func (manager *Manager) requestRecycleLocked(reason string) {
	if manager.closed {
		return
	}
	if manager.draining {
		if recycleReasonPriority(reason) < recycleReasonPriority(manager.lastRecycleReason) {
			manager.lastRecycleReason = reason
		}
		return
	}
	if !manager.ready {
		return
	}
	manager.draining = true
	manager.lastRecycleReason = reason
	manager.cond.Broadcast()
	select {
	case manager.recycleRequests <- struct{}{}:
	default:
	}
}

func (manager *Manager) clearIntentionalStopLocked(generation uint64) {
	if manager.intentionalStop == generation {
		manager.intentionalStop = 0
	}
}

func (manager *Manager) statusLocked() string {
	switch {
	case manager.closed:
		return "closed"
	case manager.starting:
		return "starting"
	case manager.degraded:
		return "degraded"
	case manager.draining:
		return "draining"
	case manager.ready:
		return "ready"
	default:
		return "stopped"
	}
}

func (manager *Manager) markInitialStartFailure() {
	manager.mu.Lock()
	manager.starting = false
	manager.degraded = true
	if manager.lifetimeCancel != nil {
		manager.lifetimeCancel()
	}
	manager.cond.Broadcast()
	manager.mu.Unlock()
}

func (manager *Manager) retainProcess(process ownedProcess) {
	manager.mu.Lock()
	if process != nil && manager.process == nil {
		manager.process = process
		manager.processGeneration++
	}
	manager.mu.Unlock()
}

func (manager *Manager) retainProcessError(process ownedProcess, err error) {
	manager.mu.Lock()
	if process != nil && manager.process == nil {
		manager.process = process
		manager.processGeneration++
	}
	manager.closeErr = errors.Join(manager.closeErr, err)
	manager.mu.Unlock()
}

func (manager *Manager) recordCloseError(err error) {
	manager.mu.Lock()
	manager.closeErr = errors.Join(manager.closeErr, err)
	manager.mu.Unlock()
}

func (manager *Manager) closeError() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.closeErr
}

func recycleReasonPriority(reason string) int {
	switch reason {
	case reasonCleanupFailure:
		return 0
	case reasonChildExit:
		return 1
	case reasonReadinessFailure:
		return 2
	case reasonRSSLimit:
		return 3
	case reasonFDLimit:
		return 4
	case reasonProbeLimit:
		return 5
	default:
		return 6
	}
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func checkAPIReadiness(ctx context.Context, _ ownedProcess, address string) error {
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return connection.Close()
}
