package torpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	isolatedProbeRetryInterval    = time.Second
	isolatedProbeMaxRetryInterval = 30 * time.Second
)

type IsolatedProfileManagerOption func(*IsolatedProfileManager)

func WithProbeMirrorErrorReporter(report func(error)) IsolatedProfileManagerOption {
	return func(manager *IsolatedProfileManager) {
		manager.reportProbeError = report
	}
}

type profileRuntime interface {
	Reconcile(context.Context, []Candidate) ([]Profile, error)
	Profiles() []Profile
	ExploreNext(context.Context) ([]Profile, error)
}

// IsolatedProfileManager keeps the serving Tor runtime authoritative and
// mirrors its candidate set into the probe runtime asynchronously. A broken or
// slow probe process can therefore reduce observability, but cannot block a
// serving promotion, retirement, or repair.
type IsolatedProfileManager struct {
	serving profileRuntime
	probing profileRuntime

	ctx    context.Context
	cancel context.CancelFunc
	wait   sync.WaitGroup

	mu               sync.Mutex
	pending          []Candidate
	pendingVersion   uint64
	appliedVersion   uint64
	retryRunning     bool
	closed           bool
	lastAttemptAt    time.Time
	lastSuccessAt    time.Time
	lastProbeError   error
	reportProbeError func(error)
}

func NewIsolatedProfileManager(
	serving profileRuntime,
	probing profileRuntime,
	options ...IsolatedProfileManagerOption,
) (*IsolatedProfileManager, error) {
	if serving == nil || probing == nil {
		return nil, errors.New("serving and probe Tor profile runtimes are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := &IsolatedProfileManager{
		serving: serving, probing: probing, ctx: ctx, cancel: cancel,
	}
	for _, option := range options {
		option(manager)
	}
	return manager, nil
}

// ProbeMirrorHealth reports a persistent failure of the isolated Tor probe
// plane without making it a dependency of serving Reconcile.
func (manager *IsolatedProfileManager) ProbeMirrorHealth() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.lastProbeError != nil && manager.appliedVersion < manager.pendingVersion {
		return fmt.Errorf(
			"Tor probe mirror generation %d failed at %s: %w",
			manager.pendingVersion, manager.lastAttemptAt.UTC().Format(time.RFC3339),
			manager.lastProbeError,
		)
	}
	return nil
}

func (manager *IsolatedProfileManager) Reconcile(
	ctx context.Context,
	candidates []Candidate,
) ([]Profile, error) {
	profiles, err := manager.serving.Reconcile(ctx, candidates)
	if err != nil {
		return nil, err
	}
	manager.queueProbeReconcile(candidates)
	return profiles, nil
}

func (manager *IsolatedProfileManager) Profiles() []Profile {
	return manager.serving.Profiles()
}

func (manager *IsolatedProfileManager) ExploreNext(ctx context.Context) ([]Profile, error) {
	// Background qualification probes explicitly place their requested bridge
	// in the isolated explorer slot, so rotating the serving explorer must not
	// wait for or synchronously mutate the probe runtime.
	return manager.serving.ExploreNext(ctx)
}

func (manager *IsolatedProfileManager) Close() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return
	}
	manager.closed = true
	manager.mu.Unlock()
	manager.cancel()
	manager.wait.Wait()
}

func (manager *IsolatedProfileManager) queueProbeReconcile(candidates []Candidate) {
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return
	}
	manager.pending = append([]Candidate(nil), candidates...)
	manager.pendingVersion++
	if manager.retryRunning {
		manager.mu.Unlock()
		return
	}
	manager.retryRunning = true
	manager.wait.Add(1)
	manager.mu.Unlock()
	go manager.retryProbeReconcile()
}

func (manager *IsolatedProfileManager) retryProbeReconcile() {
	defer manager.wait.Done()
	retryInterval := isolatedProbeRetryInterval
	for {
		manager.mu.Lock()
		candidates := append([]Candidate(nil), manager.pending...)
		version := manager.pendingVersion
		manager.mu.Unlock()

		_, err := manager.probing.Reconcile(manager.ctx, candidates)
		attemptedAt := time.Now()
		if err != nil {
			if manager.ctx.Err() != nil {
				manager.finishProbeRetry()
				return
			}
			manager.mu.Lock()
			manager.lastAttemptAt = attemptedAt
			manager.lastProbeError = err
			reporter := manager.reportProbeError
			manager.mu.Unlock()
			if reporter != nil {
				reporter(err)
			}
			timer := time.NewTimer(retryInterval)
			select {
			case <-timer.C:
				if retryInterval < isolatedProbeMaxRetryInterval {
					retryInterval *= 2
					if retryInterval > isolatedProbeMaxRetryInterval {
						retryInterval = isolatedProbeMaxRetryInterval
					}
				}
				continue
			case <-manager.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				manager.finishProbeRetry()
				return
			}
		}

		manager.mu.Lock()
		manager.lastAttemptAt = attemptedAt
		manager.lastSuccessAt = attemptedAt
		manager.lastProbeError = nil
		manager.appliedVersion = version
		if version == manager.pendingVersion {
			manager.pending = nil
			manager.retryRunning = false
			manager.mu.Unlock()
			return
		}
		manager.mu.Unlock()
	}
}

func (manager *IsolatedProfileManager) finishProbeRetry() {
	manager.mu.Lock()
	manager.retryRunning = false
	manager.mu.Unlock()
}
