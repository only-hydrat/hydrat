package proberuntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const testMiB = int64(1024 * 1024)

func TestManagerStartsAtEpochOneOnlyAfterReadiness(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ready := fixture.blockReadiness(1)
	manager := fixture.manager(Config{})

	started := make(chan error, 1)
	go func() { started <- manager.Start(fixture.ctx) }()
	fixture.waitForStarts(1)

	if got := fixture.resetEpochs(); len(got) != 0 {
		t.Fatalf("Reset called before readiness: %v", got)
	}
	snapshot := manager.Snapshot()
	if snapshot.Status != "starting" || snapshot.Epoch != 0 {
		t.Fatalf("snapshot before readiness=%+v", snapshot)
	}

	close(ready)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if got := fixture.resetEpochs(); !reflect.DeepEqual(got, []uint64{1}) {
		t.Fatalf("reset epochs=%v, want [1]", got)
	}
	if snapshot := manager.Snapshot(); snapshot.Status != "ready" || snapshot.Epoch != 1 {
		t.Fatalf("started snapshot=%+v", snapshot)
	}
}

func TestManagerRetainsInitialChildWhenReadinessCleanupStopFails(t *testing.T) {
	fixture := newRuntimeFixture(t)
	stopErr := errors.New("initial child did not stop")
	fixture.failReadinessAfter(1, 0, errors.New("initial child never ready"))
	fixture.setStopErrors(1, stopErr, nil)
	manager := fixture.manager(Config{ReadinessTimeout: 30 * time.Millisecond})

	err := manager.Start(fixture.ctx)
	if !errors.Is(err, stopErr) {
		t.Fatalf("Start error=%v, want retained-child Stop error", err)
	}
	process := fixture.process(1)
	if got := process.stopCalls.Load(); got != 1 {
		t.Fatalf("initial cleanup stop calls=%d, want 1", got)
	}
	if snapshot := manager.Snapshot(); snapshot.Status != "degraded" || snapshot.Epoch != 0 {
		t.Fatalf("snapshot after initial cleanup failure=%+v", snapshot)
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("Close retry error=%v", err)
	}
	if got := process.stopCalls.Load(); got != 2 {
		t.Fatalf("Close stop calls=%d, want retry of same handle", got)
	}
	if !channelClosed(process.Done()) {
		t.Fatal("retained initial child is still running after Close retry")
	}
	if got := fixture.starts.Load(); got != 1 {
		t.Fatalf("starts=%d, want no extra child", got)
	}
}

func TestManagerRecyclesOnceAfterConcurrentProbeLimitCrossings(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 4})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	leases := make([]*Lease, 12)
	for index := range leases {
		lease, err := manager.Acquire(fixture.ctx)
		if err != nil {
			t.Fatal(err)
		}
		leases[index] = lease
	}
	var releases sync.WaitGroup
	releases.Add(len(leases))
	for _, lease := range leases {
		lease := lease
		go func() {
			defer releases.Done()
			manager.Release(lease, nil)
		}()
	}
	releases.Wait()

	fixture.waitForEpoch(manager, 2)
	time.Sleep(10 * time.Millisecond)
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want exactly 2", got)
	}
	if got := manager.Snapshot().RecycleCount; got != 1 {
		t.Fatalf("recycle count=%d, want 1", got)
	}
	if got := fixture.resetEpochs(); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("reset epochs=%v, want [1 2]", got)
	}
}

func TestManagerConcurrentReleaseOfSameLeaseCountsOnce(t *testing.T) {
	fixture := newRuntimeFixture(t)
	firstMetricRead := make(chan struct{})
	allowFirstMetricRead := make(chan struct{})
	var metricReads atomic.Int64
	fixture.metrics = func(int) (processMetrics, error) {
		if metricReads.Add(1) == 1 {
			close(firstMetricRead)
			<-allowFirstMetricRead
		}
		return processMetrics{rssBytes: testMiB, fdCount: 8}, nil
	}
	manager := fixture.manager(Config{MaxProbes: 2})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	guard := fixture.acquire(manager)
	defer manager.Release(guard, nil)
	lease := fixture.acquire(manager)

	firstDone := make(chan struct{})
	go func() {
		manager.Release(lease, nil)
		close(firstDone)
	}()
	<-firstMetricRead

	secondDone := make(chan struct{})
	go func() {
		manager.Release(lease, nil)
		close(secondDone)
	}()
	<-secondDone
	close(allowFirstMetricRead)
	<-firstDone

	snapshot := manager.Snapshot()
	if snapshot.CompletedProbes != 1 {
		t.Fatalf("same lease completed probes=%d, want 1", snapshot.CompletedProbes)
	}
	if snapshot.Status != "ready" || fixture.starts.Load() != 1 {
		t.Fatalf("same lease triggered recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
	}

	manager.Release(guard, nil)
	fixture.waitForEpoch(manager, 2)
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want one replacement", got)
	}
}

func TestManagerClosesAdmissionAndDrainsBeforeStopping(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1, DrainTimeout: 250 * time.Millisecond})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	held := fixture.acquire(manager)
	trigger := fixture.acquire(manager)
	firstProcess := fixture.process(1)

	manager.Release(trigger, nil)
	fixture.waitForStatus(manager, "draining")
	select {
	case <-firstProcess.stopped:
		t.Fatal("process stopped before active lease drained")
	default:
	}

	acquireCtx, cancel := context.WithTimeout(fixture.ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := manager.Acquire(acquireCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire during drain error=%v, want deadline exceeded", err)
	}
	select {
	case <-firstProcess.stopped:
		t.Fatal("process stopped while active lease was still admitted")
	default:
	}

	manager.Release(held, nil)
	fixture.waitForEpoch(manager, 2)
	select {
	case <-firstProcess.stopped:
	default:
		t.Fatal("old process was not stopped after leases drained")
	}
}

func TestManagerAcquireRejectsPreCancelledContext(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lease, err := manager.Acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire error=%v, want context.Canceled", err)
	}
	if lease != nil {
		t.Fatalf("Acquire returned lease=%+v for canceled context", lease)
	}
	manager.mu.Lock()
	active := len(manager.active)
	manager.mu.Unlock()
	if active != 0 {
		t.Fatalf("active leases=%d, want 0", active)
	}
	if completed := manager.Snapshot().CompletedProbes; completed != 0 {
		t.Fatalf("completed probes=%d, want 0", completed)
	}
}

func TestManagerCancelsRemainingLeasesAfterDrainTimeout(t *testing.T) {
	fixture := newRuntimeFixture(t)
	const drainTimeout = 40 * time.Millisecond
	manager := fixture.manager(Config{MaxProbes: 1, DrainTimeout: drainTimeout})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	held := fixture.acquire(manager)
	trigger := fixture.acquire(manager)

	started := time.Now()
	manager.Release(trigger, nil)
	select {
	case <-held.Context.Done():
		t.Fatal("lease canceled before drain timeout")
	case <-time.After(drainTimeout / 4):
	}
	select {
	case <-held.Context.Done():
	case <-time.After(10 * drainTimeout):
		t.Fatal("lease was not canceled after drain timeout")
	}
	if elapsed := time.Since(started); elapsed < drainTimeout {
		t.Fatalf("lease canceled after %s, before %s drain timeout", elapsed, drainTimeout)
	}
	fixture.waitForEpoch(manager, 2)
	manager.Release(held, nil)
}

func TestManagerRecoversUnexpectedChildExit(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	fixture.process(1).exit()
	fixture.waitForEpoch(manager, 2)

	snapshot := manager.Snapshot()
	if snapshot.LastRecycleReason != reasonChildExit || snapshot.RecycleCount != 1 {
		t.Fatalf("snapshot after child recovery=%+v", snapshot)
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want 2", got)
	}
}

func TestManagerChildExitUpgradesReasonDuringDrainWithoutSecondRecycle(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1, DrainTimeout: 250 * time.Millisecond})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	held := fixture.acquire(manager)
	defer manager.Release(held, nil)

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForStatus(manager, "draining")
	fixture.process(1).exit()
	fixture.eventually(func() bool {
		return manager.Snapshot().LastRecycleReason == reasonChildExit
	}, "child-exit priority upgrade")

	manager.Release(held, nil)
	fixture.waitForEpoch(manager, 2)
	snapshot := manager.Snapshot()
	if snapshot.LastRecycleReason != reasonChildExit {
		t.Fatalf("reason=%q, want %q", snapshot.LastRecycleReason, reasonChildExit)
	}
	if snapshot.RecycleCount != 1 || fixture.starts.Load() != 2 {
		t.Fatalf("child exit started another recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
	}
}

func TestManagerChildExitAtDrainCompletionBeatsIntentionalStop(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1, DrainTimeout: time.Second})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	held := fixture.acquire(manager)
	manager.Release(fixture.acquire(manager), nil)
	fixture.eventually(func() bool {
		return manager.Snapshot().RecycleCount == 1
	}, "recycle worker drain")

	// Complete the drain while holding the state lock. Wake and queue the
	// recycler first, then close Done and queue the watcher behind it.
	manager.mu.Lock()
	held.active = false
	delete(manager.active, held)
	held.cancel()
	manager.cond.Broadcast()
	time.Sleep(20 * time.Millisecond)
	fixture.process(1).exit()
	time.Sleep(20 * time.Millisecond)
	manager.mu.Unlock()

	fixture.waitForEpoch(manager, 2)
	snapshot := manager.Snapshot()
	if snapshot.LastRecycleReason != reasonChildExit {
		t.Fatalf("reason=%q, want %q", snapshot.LastRecycleReason, reasonChildExit)
	}
	if snapshot.RecycleCount != 1 || fixture.starts.Load() != 2 {
		t.Fatalf("drain-completion exit started extra recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
	}
}

func TestManagerProcessStopArbitrationControlsRecycleReason(t *testing.T) {
	t.Run("natural exit wins before managed stop intent", func(t *testing.T) {
		fixture := newRuntimeFixture(t)
		gate := fixture.blockBeginStop(1)
		defer gate.release()
		manager := fixture.manager(Config{MaxProbes: 1})
		if err := manager.Start(fixture.ctx); err != nil {
			t.Fatal(err)
		}

		manager.Release(fixture.acquire(manager), nil)
		select {
		case <-gate.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("recycler did not reach process stop arbitration")
		}
		fixture.process(1).exit()
		gate.release()

		fixture.waitForEpoch(manager, 2)
		snapshot := manager.Snapshot()
		if snapshot.LastRecycleReason != reasonChildExit {
			t.Fatalf("reason=%q, want %q", snapshot.LastRecycleReason, reasonChildExit)
		}
		if snapshot.RecycleCount != 1 || fixture.starts.Load() != 2 {
			t.Fatalf("exit-first arbitration started extra recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
		}
	})

	t.Run("managed stop intent wins before child exit", func(t *testing.T) {
		fixture := newRuntimeFixture(t)
		manager := fixture.manager(Config{MaxProbes: 1})
		if err := manager.Start(fixture.ctx); err != nil {
			t.Fatal(err)
		}

		manager.Release(fixture.acquire(manager), nil)
		fixture.waitForEpoch(manager, 2)
		snapshot := manager.Snapshot()
		if snapshot.LastRecycleReason != reasonProbeLimit {
			t.Fatalf("reason=%q, want %q", snapshot.LastRecycleReason, reasonProbeLimit)
		}
		if snapshot.RecycleCount != 1 || fixture.starts.Load() != 2 {
			t.Fatalf("stop-first arbitration started extra recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
		}
	})
}

func TestManagerIntentionalStopDoesNotBecomeChildExit(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForEpoch(manager, 2)
	snapshot := manager.Snapshot()
	if snapshot.LastRecycleReason != reasonProbeLimit {
		t.Fatalf("intentional Stop reason=%q, want %q", snapshot.LastRecycleReason, reasonProbeLimit)
	}
	if snapshot.RecycleCount != 1 || fixture.starts.Load() != 2 {
		t.Fatalf("intentional Stop started extra recycle: starts=%d snapshot=%+v", fixture.starts.Load(), snapshot)
	}
}

func TestManagerRecycleThresholdPriorityAndMetricFallback(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		metrics    func(int) (processMetrics, error)
		wantReason string
	}{
		{
			name: "RSS before FDs and count",
			config: Config{
				MaxProbes: 1, MaxRSSBytes: 10 * testMiB, MaxFDs: 10,
			},
			metrics: func(int) (processMetrics, error) {
				return processMetrics{rssBytes: 10 * testMiB, fdCount: 10}, nil
			},
			wantReason: reasonRSSLimit,
		},
		{
			name: "FDs before count",
			config: Config{
				MaxProbes: 1, MaxRSSBytes: 10 * testMiB, MaxFDs: 10,
			},
			metrics: func(int) (processMetrics, error) {
				return processMetrics{rssBytes: testMiB, fdCount: 10}, nil
			},
			wantReason: reasonFDLimit,
		},
		{
			name: "FDs below threshold do not preempt count",
			config: Config{
				MaxProbes: 1, MaxRSSBytes: 10 * testMiB, MaxFDs: 10,
			},
			metrics: func(int) (processMetrics, error) {
				return processMetrics{rssBytes: testMiB, fdCount: 9}, nil
			},
			wantReason: reasonProbeLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeFixture(t)
			fixture.metrics = test.metrics
			manager := fixture.manager(test.config)
			if err := manager.Start(fixture.ctx); err != nil {
				t.Fatal(err)
			}

			manager.Release(fixture.acquire(manager), nil)
			fixture.waitForEpoch(manager, 2)

			snapshot := manager.Snapshot()
			if snapshot.LastRecycleReason != test.wantReason {
				t.Fatalf("reason=%q, want %q; snapshot=%+v", snapshot.LastRecycleReason, test.wantReason, snapshot)
			}
		})
	}
}

func TestManagerMetricFailureFallsBackToProductionProbeCount(t *testing.T) {
	fixture := newRuntimeFixture(t)
	fixture.metrics = func(int) (processMetrics, error) {
		return processMetrics{}, errors.New("proc unavailable")
	}
	manager := fixture.manager(Config{})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	for completed := uint64(1); completed < defaultMaxProbes; completed++ {
		manager.Release(fixture.acquire(manager), nil)
	}
	if snapshot := manager.Snapshot(); snapshot.Epoch != 1 ||
		snapshot.CompletedProbes != defaultMaxProbes-1 {
		t.Fatalf("snapshot before count backstop=%+v", snapshot)
	}
	if got := fixture.starts.Load(); got != 1 {
		t.Fatalf("metric failures recycled early; starts=%d", got)
	}

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForEpoch(manager, 2)
	if got := manager.Snapshot().LastRecycleReason; got != reasonProbeLimit {
		t.Fatalf("reason=%q, want %q", got, reasonProbeLimit)
	}
}

func TestManagerUnlimitedProbeSentinelNeverRequestsCountRecycle(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: UnlimitedProbes})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.mu.Lock()
	manager.completedProbes = UnlimitedProbes - 1
	manager.mu.Unlock()
	manager.Release(fixture.acquire(manager), nil)
	time.Sleep(10 * time.Millisecond)

	snapshot := manager.Snapshot()
	if snapshot.Epoch != 1 || snapshot.RecycleCount != 0 ||
		snapshot.LastRecycleReason == reasonProbeLimit {
		t.Fatalf("unlimited runtime requested count recycle: %+v", snapshot)
	}
}

func TestManagerReadinessFailureAfterStartupRequestsRecycle(t *testing.T) {
	fixture := newRuntimeFixture(t)
	fixture.failReadinessAfter(1, 1, errors.New("api unavailable"))
	manager := fixture.manager(Config{})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForEpoch(manager, 2)
	if got := manager.Snapshot().LastRecycleReason; got != reasonReadinessFailure {
		t.Fatalf("reason=%q, want %q", got, reasonReadinessFailure)
	}
}

func TestManagerCleanupFailureHasPriorityAndFailedReplacementStaysDegraded(t *testing.T) {
	fixture := newRuntimeFixture(t)
	fixture.metrics = func(int) (processMetrics, error) {
		return processMetrics{rssBytes: 512 * testMiB, fdCount: 1024}, nil
	}
	fixture.failReadinessAfter(2, 0, errors.New("replacement never ready"))
	manager := fixture.manager(Config{
		MaxProbes: 1, ReadinessTimeout: 30 * time.Millisecond,
	})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), errors.New("slot cleanup failed"))
	fixture.waitForStatus(manager, "degraded")

	snapshot := manager.Snapshot()
	if snapshot.Epoch != 1 || snapshot.LastRecycleReason != reasonCleanupFailure {
		t.Fatalf("degraded snapshot=%+v", snapshot)
	}
	if got := fixture.resetEpochs(); !reflect.DeepEqual(got, []uint64{1}) {
		t.Fatalf("Reset called for unready child: %v", got)
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want 2", got)
	}
	select {
	case <-fixture.process(2).stopped:
	default:
		t.Fatal("unready replacement process was not stopped")
	}
}

func TestManagerRetainsReplacementWhenReadinessCleanupStopFails(t *testing.T) {
	fixture := newRuntimeFixture(t)
	stopErr := errors.New("replacement child did not stop")
	fixture.failReadinessAfter(2, 0, errors.New("replacement never ready"))
	fixture.setStopErrors(2, stopErr, nil)
	manager := fixture.manager(Config{
		MaxProbes: 1, ReadinessTimeout: 30 * time.Millisecond,
	})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForStatus(manager, "degraded")
	replacement := fixture.process(2)
	if got := replacement.stopCalls.Load(); got != 1 {
		t.Fatalf("replacement cleanup stop calls=%d, want 1", got)
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want initial plus one replacement", got)
	}

	if err := manager.Close(); !errors.Is(err, stopErr) {
		t.Fatalf("Close error=%v, want recorded replacement Stop error", err)
	}
	if got := replacement.stopCalls.Load(); got != 2 {
		t.Fatalf("Close stop calls=%d, want retry of same replacement handle", got)
	}
	if !channelClosed(replacement.Done()) {
		t.Fatal("retained replacement is still running after Close retry")
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("Close started extra process; starts=%d", got)
	}
}

func TestManagerCloseStopsReplacementWhileResetIsBlocked(t *testing.T) {
	fixture := newRuntimeFixture(t)
	resetter := newBlockingResetter(2)
	defer resetter.release()
	manager, err := New(fixture.config(Config{MaxProbes: 1}), resetter, fixture.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), nil)
	select {
	case <-resetter.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("replacement Reset did not block")
	}
	replacement := fixture.process(2)
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close error=%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Close blocked while Reset held manager state")
	}
	if got := replacement.stopCalls.Load(); got != 1 {
		t.Fatalf("replacement stop calls=%d, want 1", got)
	}
	if !channelClosed(replacement.Done()) {
		t.Fatal("replacement remained live while Reset was blocked")
	}

	resetter.release()
	select {
	case <-manager.workerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("recycle worker did not exit after Reset returned")
	}
	if snapshot := manager.Snapshot(); snapshot.Status != "closed" {
		t.Fatalf("blocked Reset resurrected manager: %+v", snapshot)
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want initial plus one replacement", got)
	}
}

func TestManagerInitialChildExitDuringResetNeverOpensAdmission(t *testing.T) {
	fixture := newRuntimeFixture(t)
	resetter := newBlockingResetter(1)
	defer resetter.release()
	manager, err := New(fixture.config(Config{}), resetter, fixture.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	startResult := make(chan error, 1)
	go func() { startResult <- manager.Start(fixture.ctx) }()
	select {
	case <-resetter.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("initial Reset did not block")
	}
	process := fixture.process(1)
	process.exit()

	type acquireResult struct {
		lease *Lease
		err   error
	}
	acquireCtx, cancelAcquire := context.WithCancel(context.Background())
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, acquireErr := manager.Acquire(acquireCtx)
		acquired <- acquireResult{lease: lease, err: acquireErr}
	}()

	resetter.release()
	var startErr error
	select {
	case startErr = <-startResult:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after initial Reset")
	}
	cancelAcquire()
	acquire := <-acquired
	if acquire.lease != nil {
		manager.Release(acquire.lease, nil)
		t.Fatalf("Acquire admitted dead initial child at epoch %d", acquire.lease.Epoch)
	}
	if !errors.Is(acquire.err, context.Canceled) {
		t.Fatalf("blocked Acquire error=%v, want context.Canceled", acquire.err)
	}
	if startErr == nil || !strings.Contains(startErr.Error(), "exited during control reset") {
		t.Fatalf("Start error=%v, want reset-time child-exit error", startErr)
	}
	if snapshot := manager.Snapshot(); snapshot.Status != "degraded" || snapshot.Epoch != 1 {
		t.Fatalf("initial reset-time exit snapshot=%+v", snapshot)
	}
	manager.mu.Lock()
	owned := manager.process
	manager.mu.Unlock()
	if owned != nil {
		t.Fatal("manager retained dead initial process")
	}
	if got := fixture.starts.Load(); got != 1 {
		t.Fatalf("starts=%d, want no replacement", got)
	}
	requireManagerCloseTwiceWithin(t, manager, nil)
}

func TestManagerReplacementChildExitDuringResetNeverOpensAdmission(t *testing.T) {
	fixture := newRuntimeFixture(t)
	resetter := newBlockingResetter(2)
	defer resetter.release()
	manager, err := New(fixture.config(Config{}), resetter, fixture.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}

	manager.Release(fixture.acquire(manager), errors.New("slot cleanup failed"))
	select {
	case <-resetter.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("replacement Reset did not block")
	}
	replacement := fixture.process(2)
	replacement.exit()

	type acquireResult struct {
		lease *Lease
		err   error
	}
	acquireCtx, cancelAcquire := context.WithCancel(context.Background())
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, acquireErr := manager.Acquire(acquireCtx)
		acquired <- acquireResult{lease: lease, err: acquireErr}
	}()

	resetter.release()
	fixture.eventually(func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return !manager.resetting
	}, "replacement Reset completion")
	cancelAcquire()
	acquire := <-acquired
	if acquire.lease != nil {
		manager.Release(acquire.lease, nil)
		t.Fatalf(
			"Acquire admitted epoch %d during replacement reset-time child-exit failure",
			acquire.lease.Epoch,
		)
	}
	if !errors.Is(acquire.err, context.Canceled) {
		t.Fatalf("blocked Acquire error=%v, want context.Canceled", acquire.err)
	}

	snapshot := manager.Snapshot()
	if snapshot.Status != "degraded" || snapshot.Epoch != 2 ||
		snapshot.LastRecycleReason != reasonChildExit || snapshot.RecycleCount != 1 {
		t.Fatalf("replacement reset-time exit snapshot=%+v", snapshot)
	}
	manager.mu.Lock()
	owned := manager.process
	manager.mu.Unlock()
	if owned != nil {
		t.Fatal("manager retained dead replacement process")
	}
	if got := fixture.starts.Load(); got != 2 {
		t.Fatalf("starts=%d, want initial plus one replacement", got)
	}
	requireManagerCloseTwiceWithin(t, manager, nil)
}

func TestManagerDoesNotResetReplacementUntilItIsReady(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	replacementReady := fixture.blockReadiness(2)

	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForStarts(2)
	if got := fixture.resetEpochs(); !reflect.DeepEqual(got, []uint64{1}) {
		t.Fatalf("Reset called before replacement readiness: %v", got)
	}
	if snapshot := manager.Snapshot(); snapshot.Epoch != 1 || snapshot.Status != "starting" {
		t.Fatalf("snapshot while replacement starts=%+v", snapshot)
	}

	close(replacementReady)
	fixture.waitForEpoch(manager, 2)
	if got := fixture.resetEpochs(); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("reset epochs=%v, want [1 2]", got)
	}
}

func TestManagerCloseIsIdempotentAndReleasesAllWaiters(t *testing.T) {
	fixture := newRuntimeFixture(t)
	manager := fixture.manager(Config{MaxProbes: 1, DrainTimeout: time.Second})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	held := fixture.acquire(manager)
	manager.Release(fixture.acquire(manager), nil)
	fixture.waitForStatus(manager, "draining")

	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background())
		acquireResult <- err
	}()

	const callers = 8
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() { results <- manager.Close() }()
	}
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("Close error=%v", err)
		}
	}
	if err := <-acquireResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked Acquire error=%v, want ErrClosed", err)
	}
	select {
	case <-held.Context.Done():
	default:
		t.Fatal("Close did not cancel active lease")
	}
	if got := fixture.process(1).stopCalls.Load(); got != 1 {
		t.Fatalf("process stop calls=%d, want 1", got)
	}
	if snapshot := manager.Snapshot(); snapshot.Status != "closed" {
		t.Fatalf("closed snapshot=%+v", snapshot)
	}
	manager.Release(held, nil)
}

func TestManagerCloseReturnsStopErrorWhenChildDoneStaysOpen(t *testing.T) {
	fixture := newRuntimeFixture(t)
	stopErr := errors.New("probe child did not stop")
	fixture.setStopErrors(1, stopErr)
	manager := fixture.manager(Config{})
	if err := manager.Start(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	process := fixture.process(1)

	closeResult := make(chan error, 1)
	go func() { closeResult <- manager.Close() }()
	select {
	case err := <-closeResult:
		if !errors.Is(err, stopErr) {
			t.Fatalf("Close error=%v, want %v", err, stopErr)
		}
	case <-time.After(100 * time.Millisecond):
		process.exit()
		select {
		case err := <-closeResult:
			t.Fatalf("Close waited for child Done after Stop error; eventual error=%v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("Close remained blocked after forced test cleanup")
		}
	}

	watchersDone := make(chan struct{})
	go func() {
		manager.watchers.Wait()
		close(watchersDone)
	}()
	select {
	case <-watchersDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("process watcher did not retire during Close")
	}
	if channelClosed(process.Done()) {
		t.Fatal("test child exited despite permanent Stop error")
	}
	if got := process.stopCalls.Load(); got != 1 {
		t.Fatalf("Stop calls=%d, want 1", got)
	}
	if snapshot := manager.Snapshot(); snapshot.RecycleCount != 0 ||
		snapshot.LastRecycleReason != "" || snapshot.Status != "closed" {
		t.Fatalf("Close requested recycle after shutdown won: %+v", snapshot)
	}
	if got := fixture.starts.Load(); got != 1 {
		t.Fatalf("Close started replacement process; starts=%d", got)
	}

	repeatedResult := make(chan error, 1)
	go func() { repeatedResult <- manager.Close() }()
	select {
	case err := <-repeatedResult:
		if !errors.Is(err, stopErr) {
			t.Fatalf("repeated Close error=%v, want %v", err, stopErr)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("repeated Close blocked")
	}
	if got := process.stopCalls.Load(); got != 1 {
		t.Fatalf("repeated Close retried Stop: calls=%d", got)
	}
}

func TestNewRejectsInvalidRuntimeDependenciesAndBounds(t *testing.T) {
	fixture := newRuntimeFixture(t)
	config := fixture.config(Config{})

	if _, err := New(config, nil, fixture.options()...); err == nil {
		t.Fatal("New accepted nil resetter")
	}
	for name, mutate := range map[string]func(*Config){
		"binary":             func(config *Config) { config.Binary = "" },
		"config path":        func(config *Config) { config.ConfigPath = "" },
		"API address":        func(config *Config) { config.APIAddress = "" },
		"negative RSS":       func(config *Config) { config.MaxRSSBytes = -1 },
		"negative FDs":       func(config *Config) { config.MaxFDs = -1 },
		"negative drain":     func(config *Config) { config.DrainTimeout = -1 },
		"negative stop":      func(config *Config) { config.StopTimeout = -1 },
		"negative readiness": func(config *Config) { config.ReadinessTimeout = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := config
			mutate(&invalid)
			if _, err := New(invalid, fixture, fixture.options()...); err == nil {
				t.Fatal("New accepted invalid config")
			}
		})
	}
}

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

func TestExecProcessBeginStopArbitratesWithExit(t *testing.T) {
	t.Run("natural exit wins", func(t *testing.T) {
		process := &execProcess{done: make(chan struct{})}
		process.publishExit()

		if process.BeginStop() {
			t.Fatal("BeginStop acquired ownership after natural exit")
		}
		if !channelClosed(process.Done()) {
			t.Fatal("natural exit was not published")
		}
	})

	t.Run("managed stop wins", func(t *testing.T) {
		process := &execProcess{done: make(chan struct{})}
		if !process.BeginStop() {
			t.Fatal("BeginStop did not acquire ownership before exit")
		}
		process.publishExit()

		if !process.BeginStop() {
			t.Fatal("managed stop ownership was lost after exit publication")
		}
		if !channelClosed(process.Done()) {
			t.Fatal("managed exit was not published")
		}
	})
}

func TestProcMetricsReaderReadsCurrentProcessOrReportsUnsupported(t *testing.T) {
	metrics, err := (procMetricsReader{}).Read(os.Getpid())
	if errors.Is(err, ErrMetricsUnsupported) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if metrics.rssBytes <= 0 || metrics.fdCount <= 0 {
		t.Fatalf("current process metrics=%+v", metrics)
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

type runtimeFixture struct {
	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc

	starts atomic.Int64

	mu                 sync.Mutex
	processes          []*fakeProcess
	resets             []uint64
	readinessGates     map[int]chan struct{}
	readinessChecks    map[int]int
	readinessFailAfter map[int]int
	readinessErrors    map[int]error
	beginStopGates     map[int]*fakeBeginStopGate
	stopErrors         map[int][]error
	metrics            func(int) (processMetrics, error)
}

type fakeBeginStopGate struct {
	entered     chan struct{}
	allow       chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newFakeBeginStopGate() *fakeBeginStopGate {
	return &fakeBeginStopGate{
		entered: make(chan struct{}),
		allow:   make(chan struct{}),
	}
}

func (gate *fakeBeginStopGate) wait() {
	gate.enterOnce.Do(func() { close(gate.entered) })
	<-gate.allow
}

func (gate *fakeBeginStopGate) release() {
	gate.releaseOnce.Do(func() { close(gate.allow) })
}

type blockingResetter struct {
	blockEpoch  uint64
	entered     chan struct{}
	unblock     chan struct{}
	enterOnce   sync.Once
	unblockOnce sync.Once

	mu     sync.Mutex
	epochs []uint64
}

func newBlockingResetter(blockEpoch uint64) *blockingResetter {
	return &blockingResetter{
		blockEpoch: blockEpoch,
		entered:    make(chan struct{}),
		unblock:    make(chan struct{}),
	}
}

func (resetter *blockingResetter) Reset(epoch uint64) {
	resetter.mu.Lock()
	resetter.epochs = append(resetter.epochs, epoch)
	resetter.mu.Unlock()
	if epoch == resetter.blockEpoch {
		resetter.enterOnce.Do(func() { close(resetter.entered) })
		<-resetter.unblock
	}
}

func (resetter *blockingResetter) release() {
	resetter.unblockOnce.Do(func() { close(resetter.unblock) })
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture := &runtimeFixture{
		t:                  t,
		ctx:                ctx,
		cancel:             cancel,
		readinessGates:     make(map[int]chan struct{}),
		readinessChecks:    make(map[int]int),
		readinessFailAfter: make(map[int]int),
		readinessErrors:    make(map[int]error),
		beginStopGates:     make(map[int]*fakeBeginStopGate),
		stopErrors:         make(map[int][]error),
		metrics: func(int) (processMetrics, error) {
			return processMetrics{rssBytes: testMiB, fdCount: 8}, nil
		},
	}
	t.Cleanup(func() {
		cancel()
		fixture.mu.Lock()
		processes := append([]*fakeProcess(nil), fixture.processes...)
		fixture.mu.Unlock()
		for _, process := range processes {
			process.exit()
		}
	})
	return fixture
}

func (fixture *runtimeFixture) Reset(epoch uint64) {
	fixture.mu.Lock()
	fixture.resets = append(fixture.resets, epoch)
	fixture.mu.Unlock()
}

func (fixture *runtimeFixture) config(overrides Config) Config {
	config := Config{
		Binary:           "xray",
		ConfigPath:       "/etc/hydrat/xray-probe.json",
		APIAddress:       "127.0.0.1:10086",
		MaxProbes:        250,
		MaxRSSBytes:      256 * testMiB,
		MaxFDs:           512,
		DrainTimeout:     100 * time.Millisecond,
		StopTimeout:      100 * time.Millisecond,
		ReadinessTimeout: 100 * time.Millisecond,
	}
	if overrides.Binary != "" {
		config.Binary = overrides.Binary
	}
	if overrides.ConfigPath != "" {
		config.ConfigPath = overrides.ConfigPath
	}
	if overrides.APIAddress != "" {
		config.APIAddress = overrides.APIAddress
	}
	if overrides.MaxProbes != 0 {
		config.MaxProbes = overrides.MaxProbes
	}
	if overrides.MaxRSSBytes != 0 {
		config.MaxRSSBytes = overrides.MaxRSSBytes
	}
	if overrides.MaxFDs != 0 {
		config.MaxFDs = overrides.MaxFDs
	}
	if overrides.DrainTimeout != 0 {
		config.DrainTimeout = overrides.DrainTimeout
	}
	if overrides.StopTimeout != 0 {
		config.StopTimeout = overrides.StopTimeout
	}
	if overrides.ReadinessTimeout != 0 {
		config.ReadinessTimeout = overrides.ReadinessTimeout
	}
	return config
}

func (fixture *runtimeFixture) manager(overrides Config) *Manager {
	fixture.t.Helper()
	manager, err := New(fixture.config(overrides), fixture, fixture.options()...)
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func (fixture *runtimeFixture) options() []Option {
	return []Option{
		withProcessStarter(processStarterFunc(fixture.startProcess)),
		withReadinessCheck(fixture.checkReadiness),
		withMetricsReader(metricsReaderFunc(func(pid int) (processMetrics, error) {
			return fixture.metrics(pid)
		})),
	}
}

func (fixture *runtimeFixture) startProcess(context.Context, Config) (ownedProcess, error) {
	index := int(fixture.starts.Add(1))
	fixture.mu.Lock()
	stopErrors := append([]error(nil), fixture.stopErrors[index]...)
	process := &fakeProcess{
		pid:           10_000 + index,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
		beginStopGate: fixture.beginStopGates[index],
		stopErrors:    stopErrors,
	}
	fixture.processes = append(fixture.processes, process)
	fixture.mu.Unlock()
	return process, nil
}

func (fixture *runtimeFixture) checkReadiness(ctx context.Context, process ownedProcess, _ string) error {
	index := process.PID() - 10_000
	fixture.mu.Lock()
	fixture.readinessChecks[index]++
	check := fixture.readinessChecks[index]
	gate := fixture.readinessGates[index]
	failAfter, hasFailure := fixture.readinessFailAfter[index]
	readinessErr := fixture.readinessErrors[index]
	fixture.mu.Unlock()
	if gate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-gate:
		}
	}
	if hasFailure && check > failAfter {
		return readinessErr
	}
	return nil
}

func (fixture *runtimeFixture) blockReadiness(processIndex int) chan struct{} {
	fixture.t.Helper()
	gate := make(chan struct{})
	fixture.mu.Lock()
	fixture.readinessGates[processIndex] = gate
	fixture.mu.Unlock()
	return gate
}

func (fixture *runtimeFixture) failReadinessAfter(processIndex, successfulChecks int, err error) {
	fixture.t.Helper()
	fixture.mu.Lock()
	fixture.readinessFailAfter[processIndex] = successfulChecks
	fixture.readinessErrors[processIndex] = err
	fixture.mu.Unlock()
}

func (fixture *runtimeFixture) blockBeginStop(processIndex int) *fakeBeginStopGate {
	fixture.t.Helper()
	gate := newFakeBeginStopGate()
	fixture.mu.Lock()
	fixture.beginStopGates[processIndex] = gate
	fixture.mu.Unlock()
	return gate
}

func (fixture *runtimeFixture) setStopErrors(processIndex int, stopErrors ...error) {
	fixture.t.Helper()
	fixture.mu.Lock()
	fixture.stopErrors[processIndex] = append([]error(nil), stopErrors...)
	fixture.mu.Unlock()
}

func (fixture *runtimeFixture) acquire(manager *Manager) *Lease {
	fixture.t.Helper()
	lease, err := manager.Acquire(fixture.ctx)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return lease
}

func (fixture *runtimeFixture) process(index int) *fakeProcess {
	fixture.t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.processes) < index {
		fixture.t.Fatalf("process %d does not exist; starts=%d", index, len(fixture.processes))
	}
	return fixture.processes[index-1]
}

func (fixture *runtimeFixture) resetEpochs() []uint64 {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]uint64(nil), fixture.resets...)
}

func (fixture *runtimeFixture) waitForStarts(want int64) {
	fixture.t.Helper()
	fixture.eventually(func() bool { return fixture.starts.Load() >= want }, "starts")
}

func (fixture *runtimeFixture) waitForEpoch(manager *Manager, want uint64) {
	fixture.t.Helper()
	fixture.eventually(func() bool { return manager.Snapshot().Epoch == want }, "epoch")
}

func (fixture *runtimeFixture) waitForStatus(manager *Manager, want string) {
	fixture.t.Helper()
	fixture.eventually(func() bool { return manager.Snapshot().Status == want }, "status "+want)
}

func (fixture *runtimeFixture) eventually(check func() bool, description string) {
	fixture.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	fixture.t.Fatalf("timed out waiting for %s", description)
}

func requireManagerCloseTwiceWithin(t *testing.T, manager *Manager, wantErr error) {
	t.Helper()
	for call := 1; call <= 2; call++ {
		result := make(chan error, 1)
		go func() { result <- manager.Close() }()
		select {
		case err := <-result:
			if wantErr == nil && err != nil {
				t.Fatalf("Close call %d error=%v", call, err)
			}
			if wantErr != nil && !errors.Is(err, wantErr) {
				t.Fatalf("Close call %d error=%v, want %v", call, err, wantErr)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Close call %d blocked", call)
		}
	}
}

type fakeProcess struct {
	pid           int
	done          chan struct{}
	stopped       chan struct{}
	beginStopGate *fakeBeginStopGate
	stopCalls     atomic.Int64
	stopMu        sync.Mutex
	stopErrors    []error
	stateMu       sync.Mutex
	exited        bool
	stopIntent    bool
	stoppedOnce   sync.Once
}

func (process *fakeProcess) PID() int              { return process.pid }
func (process *fakeProcess) Done() <-chan struct{} { return process.done }
func (process *fakeProcess) BeginStop() bool {
	if process.beginStopGate != nil {
		process.beginStopGate.wait()
	}
	process.stateMu.Lock()
	defer process.stateMu.Unlock()
	if process.stopIntent {
		return true
	}
	if process.exited {
		return false
	}
	process.stopIntent = true
	return true
}
func (process *fakeProcess) Stop(time.Duration) error {
	process.stopCalls.Add(1)
	if !process.BeginStop() {
		return nil
	}
	process.stopMu.Lock()
	var stopErr error
	if len(process.stopErrors) > 0 {
		stopErr = process.stopErrors[0]
		process.stopErrors = process.stopErrors[1:]
	}
	process.stopMu.Unlock()
	if stopErr != nil {
		return stopErr
	}
	process.publishExit()
	process.stoppedOnce.Do(func() { close(process.stopped) })
	return nil
}
func (process *fakeProcess) exit() {
	process.publishExit()
}
func (process *fakeProcess) publishExit() {
	process.stateMu.Lock()
	defer process.stateMu.Unlock()
	if process.exited {
		return
	}
	process.exited = true
	close(process.done)
}
