package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/wireguard"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

func TestRuntimeClientLifecycleEnqueuesPlacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ordinaryGate := make(chan struct{})
	close(ordinaryGate)
	clientChanges := make(chan struct{}, 1)
	enqueued := make(chan PlacementReason, 1)
	runtime := Runtime{
		ClientChanges:         clientChanges,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	go runtime.watchEvents(
		ctx, ordinaryGate, make(chan struct{}, 1), make(chan struct{}, 1),
		make(chan struct{}, 1), func(reason PlacementReason) { enqueued <- reason },
	)
	clientChanges <- struct{}{}
	select {
	case reason := <-enqueued:
		if reason != PlacementClientLifecycle {
			t.Fatalf("placement reason=%q, want %q", reason, PlacementClientLifecycle)
		}
	case <-time.After(time.Second):
		t.Fatal("client lifecycle change did not enqueue placement")
	}
}

func TestRuntimeRepairsProfilesBeforeStartupAndOnInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	startupInspected := false
	runtime := Runtime{
		ProfileRepair: func(context.Context, time.Time) (bool, error) {
			call := calls.Add(1)
			if call == 2 {
				cancel()
			}
			return call == 2, nil
		},
		ProfileRepairInterval: time.Millisecond,
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			startupInspected = true
			if calls.Load() != 1 {
				t.Fatalf("startup inspection ran before profile repair: calls=%d", calls.Load())
			}
			return false, nil
		},
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !startupInspected || calls.Load() < 2 {
		t.Fatalf("startup_inspected=%t repair_calls=%d", startupInspected, calls.Load())
	}
}

func TestRuntimeSuppressesPromotionForUnstableInventoryButKeepsHardFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hardFailures := make(chan struct{}, 1)
	qualificationDone := make(chan struct{})
	placed := make(chan PlacementReason, 2)
	runtime := Runtime{
		Refresh: func(context.Context) error { return nil },
		Qualify: func(context.Context, time.Time) error {
			select {
			case <-qualificationDone:
			default:
				close(qualificationDone)
			}
			return store.ErrCandidateInventoryChanged
		},
		Place: func(
			_ context.Context,
			_ time.Time,
			reason PlacementReason,
		) error {
			placed <- reason
			return nil
		},
		HardFailures: hardFailures,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case <-qualificationDone:
	case <-time.After(time.Second):
		t.Fatal("qualification did not run")
	}
	select {
	case reason := <-placed:
		t.Fatalf("unstable inventory enqueued placement %s", reason)
	case <-time.After(100 * time.Millisecond):
	}
	hardFailures <- struct{}{}
	select {
	case reason := <-placed:
		if reason != PlacementHardFailure {
			t.Fatalf("reason=%s want hard failure", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("hard-failure placement was suppressed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestRuntimeSpacesStartupAndExternalActiveStarts(t *testing.T) {
	const interval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	starts := make(chan time.Time, 2)
	sourceChanges := make(chan struct{}, 1)
	runtime := Runtime{
		RecoveryReady: func(context.Context, time.Time) error {
			return errors.New("normalization required")
		},
		Refresh: func(context.Context) error { return nil },
		Active: func(context.Context, time.Time) error {
			starts <- time.Now()
			return nil
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization {
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
		ActiveOverlap:         2,
		ActiveInterval:        interval,
		SourceChanges:         sourceChanges,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	var first time.Time
	select {
	case first = <-starts:
	case <-time.After(time.Second):
		t.Fatal("startup active run did not start")
	}
	sourceChanges <- struct{}{}
	var second time.Time
	select {
	case second = <-starts:
	case <-time.After(time.Second):
		t.Fatal("external active run did not start")
	}
	if spacing := second.Sub(first); spacing < interval-5*time.Millisecond {
		cancel()
		<-done
		t.Fatalf("active starts were not serialized: spacing=%s", spacing)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeDurablyRetriesHardFailureAfterRecoveringErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	attempted := make(chan time.Time, 3)
	attempts := 0
	runtime := Runtime{
		Place: func(
			_ context.Context,
			at time.Time,
			reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			attempted <- at
			switch attempts {
			case 1:
				return dataplane.ErrRuntimeRecovering
			case 2:
				return store.ErrCandidateInventoryChanged
			default:
				cancel()
				return nil
			}
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatalf("hard failure was dropped after %d attempts", attempts)
	}
	if attempts != 3 || len(attempted) != 3 {
		t.Fatalf("hard retry attempts=%d timestamps=%d", attempts, len(attempted))
	}
}

func TestRuntimeHardFailurePreemptsContextAwareLowerPlacementWithoutOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manual := make(chan struct{}, 1)
	hard := NewHardFailureMailbox()
	lowerStarted := make(chan struct{})
	hardDone := make(chan struct{})
	recomputed := make(chan struct{})
	var lock sync.Mutex
	inFlight := 0
	maximum := 0
	manualCalls := 0
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			lock.Lock()
			inFlight++
			if inFlight > maximum {
				maximum = inFlight
			}
			if reason == PlacementManual {
				manualCalls++
			}
			lock.Unlock()
			defer func() {
				lock.Lock()
				inFlight--
				lock.Unlock()
			}()
			switch reason {
			case PlacementManual:
				if manualCalls == 1 {
					close(lowerStarted)
					<-ctx.Done()
					return ctx.Err()
				}
				close(recomputed)
				return nil
			case PlacementHardFailure:
				close(hardDone)
				return nil
			default:
				return nil
			}
		},
		ManualReassigns: manual, HardFailureEvents: hard,
		PlacementPreemptTimeout: 100 * time.Millisecond,
		SourceRefreshInterval:   time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	manual <- struct{}{}
	<-lowerStarted
	started := time.Now()
	deadline := started.Add(time.Second)
	hard.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: started,
		DetectedAt: started, Deadline: deadline,
	})
	select {
	case <-hardDone:
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("hard placement admission=%s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("hard placement did not preempt lower work")
	}
	select {
	case <-recomputed:
	case <-time.After(time.Second):
		t.Fatal("canceled lower reason was not recomputed after hard placement")
	}
	lock.Lock()
	gotMaximum := maximum
	lock.Unlock()
	if gotMaximum != 1 {
		t.Fatalf("placement overlap=%d", gotMaximum)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestRuntimeNonCooperativePreemptionLatchesUnreadyWithoutHardOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manual := make(chan struct{}, 1)
	hard := NewHardFailureMailbox()
	lowerStarted := make(chan struct{})
	releaseLower := make(chan struct{})
	unready := make(chan error, 1)
	hardCalls := 0
	runtime := Runtime{
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				hardCalls++
				return nil
			}
			close(lowerStarted)
			<-releaseLower
			return nil
		},
		ManualReassigns: manual, HardFailureEvents: hard,
		PlacementPreemptTimeout: 25 * time.Millisecond,
		Unready:                 func(err error) { unready <- err },
		SourceRefreshInterval:   time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	manual <- struct{}{}
	<-lowerStarted
	now := time.Now()
	hard.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(time.Second),
	})
	select {
	case err := <-unready:
		if !errors.Is(err, ErrPlacementPreemptionTimeout) {
			t.Fatalf("unready error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("non-cooperative placement did not latch unready")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPlacementPreemptionTimeout) {
			t.Fatalf("runtime error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not return fatal preemption error")
	}
	if hardCalls != 0 {
		t.Fatalf("hard placement overlapped ignored lower call: calls=%d", hardCalls)
	}
	close(releaseLower)
}

func TestRuntimePreemptionTimerUsesRemainingHardDeadline(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	clock := newManualRuntimeClock(base)
	manual := make(chan struct{}, 1)
	hard := NewHardFailureMailbox()
	lowerStarted := make(chan struct{})
	releaseLower := make(chan struct{})
	unready := make(chan error, 1)
	var hardCalls atomic.Int32
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				hardCalls.Add(1)
				return nil
			}
			close(lowerStarted)
			<-releaseLower
			return nil
		},
		HardFailureEvents:       hard,
		ManualReassigns:         manual,
		Unready:                 func(err error) { unready <- err },
		clock:                   clock,
		PlacementPreemptTimeout: 100 * time.Millisecond,
		SourceRefreshInterval:   time.Hour,
		QualificationInterval:   time.Hour,
		PlacementInterval:       time.Hour,
		ActiveInterval:          time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(context.Background()) }()
	manual <- struct{}{}
	select {
	case <-lowerStarted:
	case <-time.After(time.Second):
		close(releaseLower)
		t.Fatal("lower placement did not start")
	}
	started := time.Now()
	hard.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: base,
		DetectedAt: base, Deadline: base.Add(30 * time.Millisecond),
	})
	select {
	case err := <-unready:
		if !errors.Is(err, ErrHardFailoverDeadlineExceeded) {
			close(releaseLower)
			t.Fatalf("unready error=%v", err)
		}
		if elapsed := time.Since(started); elapsed > 75*time.Millisecond {
			close(releaseLower)
			t.Fatalf("hard deadline fatal elapsed=%s", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		close(releaseLower)
		t.Fatal("preemption timer ignored remaining hard deadline")
	}
	if err := <-done; !errors.Is(err, ErrHardFailoverDeadlineExceeded) {
		close(releaseLower)
		t.Fatalf("runtime error=%v", err)
	}
	if calls := hardCalls.Load(); calls != 0 {
		close(releaseLower)
		t.Fatalf("hard placement overlapped non-cooperative lower: calls=%d", calls)
	}
	close(releaseLower)
}

func TestRuntimeActiveCriticalCoverageFailureLatchesUnreadyWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unready := make(chan error, 1)
	runtime := Runtime{
		Active: func(context.Context, time.Time) error {
			return ErrActiveCriticalCoverageExceeded
		},
		Unready:               func(err error) { unready <- err },
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Millisecond,
		ActiveDeadline:        625 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatalf("unready error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("critical coverage failure did not latch unready")
	}
	select {
	case err := <-done:
		t.Fatalf("critical coverage failure restarted runtime: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHardDeadlineExpiryLatchesUnreadyWithoutRestart(t *testing.T) {
	hardFailures := NewHardFailureMailbox()
	unready := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := Runtime{
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		},
		HardFailureEvents:     hardFailures,
		Unready:               func(err error) { unready <- err },
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	now := time.Now()
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(25 * time.Millisecond),
	})
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrHardFailoverDeadlineExceeded) {
			t.Fatalf("unready error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hard deadline expiry did not latch unready")
	}
	select {
	case err := <-done:
		t.Fatalf("hard deadline expiry restarted runtime: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeDynamicPermanentHardFailureLatchesUnreadyAndReturnsFatal(t *testing.T) {
	hardFailures := NewHardFailureMailbox()
	unready := make(chan error, 1)
	permanent := errors.New("permanent hard apply failure")
	var hardCalls atomic.Int32
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				return nil
			}
			hardCalls.Add(1)
			return permanent
		},
		HardFailureEvents:     hardFailures,
		Unready:               func(err error) { unready <- err },
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(context.Background()) }()
	now := time.Now()
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(time.Second),
	})
	select {
	case err := <-unready:
		if !errors.Is(err, permanent) {
			t.Fatalf("unready error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent dynamic hard failure did not latch unready")
	}
	select {
	case err := <-done:
		if !errors.Is(err, permanent) {
			t.Fatalf("runtime error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent dynamic hard failure did not stop runtime")
	}
	if calls := hardCalls.Load(); calls != 1 {
		t.Fatalf("permanent hard event attempts=%d", calls)
	}
}

func TestRuntimeDynamicCapacityLossRecoversWithoutRestartAndHardCannotClearIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	promotions := make(chan struct{}, 4)
	capacityChanges := make(chan struct{}, 1)
	hardFailures := make(chan struct{}, 1)
	var capacityLost atomic.Bool
	var ready atomic.Bool
	readyEvents := make(chan bool, 8)
	placed := make(chan PlacementReason, 8)
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:udp:reserve"}, SearchExhausted: true,
	}
	runtime := Runtime{
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			placed <- reason
			if reason != PlacementHardFailure && capacityLost.Load() {
				return coverageErr
			}
			return nil
		},
		CapacityReady: func(context.Context, time.Time) error {
			if capacityLost.Load() {
				return coverageErr
			}
			return nil
		},
		Refresh:    func(context.Context) error { return nil },
		Qualify:    func(context.Context, time.Time) error { return nil },
		Unready:    func(error) { ready.Store(false); readyEvents <- false },
		Ready:      func() { ready.Store(true); readyEvents <- true },
		Promotions: promotions, HardFailures: hardFailures,
		CapacityChanges:    capacityChanges,
		PlacementRetryBase: time.Hour, PlacementRetryMax: time.Hour,
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case state := <-readyEvents:
		if !state {
			t.Fatal("runtime did not become initially ready")
		}
	case <-time.After(time.Second):
		t.Fatal("initial readiness was not reported")
	}
	capacityLost.Store(true)
	promotions <- struct{}{}
	select {
	case state := <-readyEvents:
		if state {
			t.Fatal("capacity loss reported ready")
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary capacity loss did not report unready")
	}
	select {
	case err := <-done:
		t.Fatalf("capacity degradation restarted runtime: %v", err)
	default:
	}
	hardFailures <- struct{}{}
	hardObserved := false
	deadline := time.After(3 * time.Second)
	for !hardObserved {
		select {
		case reason := <-placed:
			hardObserved = reason == PlacementHardFailure
		case <-deadline:
			t.Fatal("hard placement did not run while capacity degraded")
		}
	}
	time.Sleep(20 * time.Millisecond)
	if ready.Load() {
		t.Fatal("hard success cleared capacity degradation")
	}
	capacityLost.Store(false)
	capacityChanges <- struct{}{}
	select {
	case state := <-readyEvents:
		if !state {
			t.Fatal("ordinary recovery did not restore ready")
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary capacity recovery did not report ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRecoveryGateDefersOrdinaryInputsButAdmitsHard(t *testing.T) {
	manual := make(chan struct{}, 1)
	qoe := make(chan struct{}, 1)
	hard := NewHardFailureMailbox()
	capacityChanges := make(chan struct{}, 1)
	placed := make(chan PlacementReason, 16)
	ready := make(chan struct{}, 2)
	recoveryStarted := make(chan struct{})
	var converged atomic.Bool
	var directStartupCalls atomic.Int32
	var recoveryCalls atomic.Int32
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:tcp:reserve"},
		SearchExhausted: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error {
			directStartupCalls.Add(1)
			if !converged.Load() {
				return coverageErr
			}
			return nil
		},
		CapacityReady: func(context.Context, time.Time) error {
			if !converged.Load() {
				return coverageErr
			}
			return nil
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			switch reason {
			case PlacementStartupNormalization:
				if recoveryCalls.Add(1) == 1 {
					close(recoveryStarted)
					<-ctx.Done()
					return ctx.Err()
				}
			case PlacementPeriodic, PlacementManual, PlacementQoEDegraded,
				PlacementHardFailure:
				placed <- reason
			}
			return nil
		},
		ManualReassigns: manual, QoEDegradations: qoe,
		HardFailureEvents: hard, CapacityChanges: capacityChanges,
		Ready:                      func() { ready <- struct{}{} },
		NormalizationRetryInterval: time.Hour,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          10 * time.Millisecond,
		ActiveInterval:             time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-recoveryStarted:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("startup recovery placement did not start")
	}
	manual <- struct{}{}
	qoe <- struct{}{}
	probeStartedAt := time.Now()
	event, err := NewHardFailureEvent(
		"critical", probeStartedAt, probeStartedAt, time.Minute,
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	hard.Publish(event)
	select {
	case reason := <-placed:
		if reason != PlacementHardFailure {
			cancel()
			t.Fatalf("ordinary reason escaped recovery gate: %s", reason)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("hard event did not cross recovery gate")
	}
	select {
	case reason := <-placed:
		cancel()
		t.Fatalf("ordinary reason escaped before readiness: %s", reason)
	case <-time.After(40 * time.Millisecond):
	}
	converged.Store(true)
	capacityChanges <- struct{}{}
	select {
	case <-ready:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("ordinary gate did not open after capacity convergence")
	}
	want := map[PlacementReason]bool{
		PlacementPeriodic:    false,
		PlacementManual:      false,
		PlacementQoEDegraded: false,
	}
	deadline := time.After(time.Second)
	for {
		complete := true
		for _, seen := range want {
			complete = complete && seen
		}
		if complete {
			break
		}
		select {
		case reason := <-placed:
			if _, expected := want[reason]; expected {
				want[reason] = true
			}
		case <-deadline:
			cancel()
			t.Fatalf("ordinary reasons not released after readiness: %+v", want)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
		t.Fatal("ordinary workers released more than once")
	default:
	}
	if calls := directStartupCalls.Load(); calls != 1 {
		t.Fatalf("direct StartupNormalize calls after recovery start=%d", calls)
	}
}

func TestRuntimeHardRetryWakePreemptsLowerThroughSameNoOverlapPath(t *testing.T) {
	hardFailures := NewHardFailureMailbox()
	manual := make(chan struct{}, 1)
	firstHardFailed := make(chan struct{})
	manualStarted := make(chan struct{})
	secondHardDone := make(chan struct{})
	var mu sync.Mutex
	inFlight := 0
	maximum := 0
	hardCalls := 0
	var manualStartedOnce sync.Once
	reasons := make([]PlacementReason, 0, 3)
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			mu.Lock()
			inFlight++
			if inFlight > maximum {
				maximum = inFlight
			}
			reasons = append(reasons, reason)
			if reason == PlacementHardFailure {
				hardCalls++
			}
			call := hardCalls
			mu.Unlock()
			defer func() {
				mu.Lock()
				inFlight--
				mu.Unlock()
			}()
			switch {
			case reason == PlacementHardFailure && call == 1:
				close(firstHardFailed)
				return dataplane.MarkTemporary(errors.New("temporary hard apply"))
			case reason == PlacementHardFailure:
				close(secondHardDone)
				return nil
			case reason == PlacementManual:
				manualStartedOnce.Do(func() { close(manualStarted) })
				<-ctx.Done()
				return ctx.Err()
			default:
				return nil
			}
		},
		HardFailureEvents:       hardFailures,
		ManualReassigns:         manual,
		PlacementRetryBase:      100 * time.Millisecond,
		PlacementRetryMax:       100 * time.Millisecond,
		PlacementPreemptTimeout: 100 * time.Millisecond,
		SourceRefreshInterval:   time.Hour,
		QualificationInterval:   time.Hour,
		PlacementInterval:       time.Hour,
		ActiveInterval:          time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	now := time.Now()
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(time.Second),
	})
	select {
	case <-firstHardFailed:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("first hard attempt did not fail")
	}
	manual <- struct{}{}
	select {
	case <-manualStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("lower placement did not start during hard backoff")
	}
	select {
	case <-secondHardDone:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("hard retry wake did not preempt lower placement")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if maximum != 1 || !reflect.DeepEqual(reasons[:3], []PlacementReason{
		PlacementHardFailure, PlacementManual, PlacementHardFailure,
	}) {
		t.Fatalf("retry overlap/reasons=%d/%v", maximum, reasons)
	}
}

func TestRuntimeNewMailboxHardMergesOlderRetryDeadline(t *testing.T) {
	hardFailures := NewHardFailureMailbox()
	manual := make(chan struct{}, 1)
	firstHardFailed := make(chan struct{})
	manualStarted := make(chan struct{})
	secondHardDeadline := make(chan time.Time, 1)
	var manualStartedOnce sync.Once
	var hardCalls atomic.Int32
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			switch reason {
			case PlacementHardFailure:
				call := hardCalls.Add(1)
				if call == 1 {
					close(firstHardFailed)
					return dataplane.MarkTemporary(errors.New("temporary hard apply"))
				}
				deadline, ok := ctx.Deadline()
				if !ok {
					deadline = time.Time{}
				}
				secondHardDeadline <- deadline
				return nil
			case PlacementManual:
				manualStartedOnce.Do(func() { close(manualStarted) })
				<-ctx.Done()
				return ctx.Err()
			default:
				return nil
			}
		},
		HardFailureEvents:       hardFailures,
		ManualReassigns:         manual,
		PlacementRetryBase:      100 * time.Millisecond,
		PlacementRetryMax:       100 * time.Millisecond,
		PlacementPreemptTimeout: 100 * time.Millisecond,
		SourceRefreshInterval:   time.Hour,
		QualificationInterval:   time.Hour,
		PlacementInterval:       time.Hour,
		ActiveInterval:          time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	now := time.Now()
	oldDeadline := now.Add(500 * time.Millisecond)
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "old", ProbeStartedAt: now,
		DetectedAt: now, Deadline: oldDeadline,
	})
	select {
	case <-firstHardFailed:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("old hard attempt did not enter retry")
	}
	time.Sleep(10 * time.Millisecond)
	manual <- struct{}{}
	select {
	case <-manualStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("lower placement did not start during old hard backoff")
	}
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "new", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(2 * time.Second),
	})
	select {
	case deadline := <-secondHardDeadline:
		if !deadline.Equal(oldDeadline) {
			cancel()
			t.Fatalf("merged hard deadline=%s want old retry=%s", deadline, oldDeadline)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("new mailbox hard did not preempt lower placement")
	}
	time.Sleep(150 * time.Millisecond)
	if calls := hardCalls.Load(); calls != 2 {
		cancel()
		t.Fatalf("stale retry survived covered hard success: calls=%d", calls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHardRetryDeadlineExpiresUnreadyWithoutRestartOrReplay(t *testing.T) {
	hardFailures := NewHardFailureMailbox()
	unready := make(chan error, 1)
	hardCalls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := Runtime{
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				hardCalls++
			}
			return dataplane.MarkTemporary(errors.New("temporary hard apply"))
		},
		HardFailureEvents:     hardFailures,
		PlacementRetryBase:    time.Second,
		PlacementRetryMax:     time.Second,
		Unready:               func(err error) { unready <- err },
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	now := time.Now()
	hardFailures.Publish(HardFailureEvent{
		CandidateID: "candidate", ProbeStartedAt: now,
		DetectedAt: now, Deadline: now.Add(40 * time.Millisecond),
	})
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrHardFailoverDeadlineExceeded) {
			t.Fatalf("unready error=%v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("hard retry waited past original deadline")
	}
	select {
	case err := <-done:
		t.Fatalf("expired hard retry restarted runtime: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	if hardCalls != 1 {
		t.Fatalf("expired hard retry calls=%d", hardCalls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRetriesTemporaryPromotionWithOriginalReason(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	promotions := make(chan struct{}, 1)
	reasons := make(chan PlacementReason, 2)
	attempts := 0
	runtime := Runtime{
		Place: func(
			_ context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementPromotion {
				return nil
			}
			attempts++
			reasons <- reason
			if attempts == 1 {
				return dataplane.MarkTemporary(errors.New("agent unavailable"))
			}
			cancel()
			return nil
		},
		Promotions:            promotions,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	promotions <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatalf("temporary promotion was dropped after %d attempts", attempts)
	}
	if attempts != 2 || len(reasons) != 2 {
		t.Fatalf("promotion attempts=%d reasons=%d", attempts, len(reasons))
	}
	for len(reasons) > 0 {
		if reason := <-reasons; reason != PlacementPromotion {
			t.Fatalf("retried reason=%s want=%s", reason, PlacementPromotion)
		}
	}
}

func TestRuntimeActiveWorkerDoesNotBlockHardFailureEventsAndNeverOverlaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hardFailures := make(chan struct{}, 1)
	activeStarted := make(chan struct{})
	releaseActive := make(chan struct{})
	placed := make(chan PlacementReason, 1)
	var lock sync.Mutex
	running, maximum := 0, 0
	var once sync.Once
	runtime := Runtime{
		Active: func(context.Context, time.Time) error {
			lock.Lock()
			running++
			if running > maximum {
				maximum = running
			}
			lock.Unlock()
			once.Do(func() { close(activeStarted) })
			<-releaseActive
			lock.Lock()
			running--
			lock.Unlock()
			return nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				placed <- reason
			}
			return nil
		},
		HardFailures:          hardFailures,
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: 5 * time.Millisecond,
		ActiveDeadline: time.Second,
	}
	done := make(chan struct{})
	go func() { runtime.Start(ctx); close(done) }()
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("active worker did not start")
	}
	hardFailures <- struct{}{}
	select {
	case reason := <-placed:
		if reason != PlacementHardFailure {
			t.Fatalf("reason=%s", reason)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("blocked active probe stalled hard-failure watcher")
	}
	time.Sleep(30 * time.Millisecond)
	lock.Lock()
	if maximum != 1 {
		lock.Unlock()
		t.Fatalf("active max overlap=%d", maximum)
	}
	lock.Unlock()
	close(releaseActive)
	cancel()
	waitRuntimeDone(t, done)
}

func TestRuntimeCapsOverlappingActiveGenerationsAtConfiguredThree(t *testing.T) {
	var mu sync.Mutex
	current := 0
	maximum := 0
	threeStarted := make(chan struct{})
	var threeOnce sync.Once
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Active: func(ctx context.Context, _ time.Time) error {
			mu.Lock()
			current++
			if current > maximum {
				maximum = current
			}
			if current == 3 {
				threeOnce.Do(func() { close(threeStarted) })
			}
			mu.Unlock()
			<-ctx.Done()
			mu.Lock()
			current--
			mu.Unlock()
			return ctx.Err()
		},
		ActiveOverlap:         3,
		ActiveInterval:        10 * time.Millisecond,
		ActiveDeadline:        time.Second,
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-threeStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("three active generations did not start")
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if maximum != 3 {
		t.Fatalf("active generation max=%d", maximum)
	}
}

func TestRuntimeRetriesTemporaryHTTPApplyAndRetainsHardReason(t *testing.T) {
	runner := &temporaryRouteRunner{failRoutes: 1}
	adapter := xrayapi.NewAdapter(
		"xray", "127.0.0.1:10085", "9.9.9.9", runner,
	)
	reconciler, err := dataplane.NewReconciler(
		adapter, t.TempDir()+"/applied.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	client := agentapi.NewClient(serveRuntimeAgent(
		t, agentapi.NewServer(reconciler, 64*1024),
	))
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{{
			ID: "primary", Protocol: dataplane.ProtocolVLESS,
			Config: []byte(`{"protocol":"vless"}`),
		}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "primary", UDPOutbound: "primary",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	attempts := 0
	runtime := Runtime{
		Place: func(
			ctx context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			err := client.Apply(ctx, plan)
			if err == nil {
				cancel()
			}
			return err
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("temporary HTTP apply was not retried")
	}
	if attempts != 2 || runner.RouteCalls() != 2 {
		t.Fatalf("hard attempts=%d xray route calls=%d want 2/2",
			attempts, runner.RouteCalls())
	}
}

func TestRuntimeUnixHTTPHardFailurePreemptsStartupNormalizationWithinEnvelope(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
		{name: "replacement", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "domain-c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	applier := newWallClockHTTPApplier()
	agent := agentapi.NewClient(serveRuntimeAgent(t, agentapi.NewServer(
		applier, 64*1024, agentapi.WithActivityProvider(emptyActivityProvider{}),
	)))
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("1.1.1.1"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	engine.dnsResolvers = []string{"9.9.9.9"}

	hardFailures := NewHardFailureMailbox()
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	reasons := make(chan PlacementReason, 16)
	var writerMu sync.Mutex
	writers, maximumWriters := 0, 0
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"startup:normalization"},
		SearchExhausted: true,
	}
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return coverageErr },
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(ctx context.Context, at time.Time, reason PlacementReason) error {
			writerMu.Lock()
			writers++
			if writers > maximumWriters {
				maximumWriters = writers
			}
			writerMu.Unlock()
			defer func() {
				writerMu.Lock()
				writers--
				writerMu.Unlock()
			}()
			reasons <- reason
			return engine.CycleForReason(ctx, at, reason)
		},
		HardFailureEvents:          hardFailures,
		Unready:                    func(err error) { unready <- err },
		Ready:                      func() { ready <- struct{}{} },
		PlacementPreemptTimeout:    100 * time.Millisecond,
		NormalizationRetryInterval: time.Hour,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runtimeCtx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			cancelRuntime()
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup normalization did not keep readiness red")
	}
	select {
	case <-applier.lowerStarted:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup-normalization HTTP apply did not block")
	}
	assignment := engineQoEAssignment(t, database, "alice")
	failed := engineCandidateByID(t, candidates, assignment.TCPOutbound)
	probeStartedAt := time.Now()
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		cancelRuntime()
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, time.Now(),
	); err != nil || !commit.Accepted {
		cancelRuntime()
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	detectedAt := time.Now()
	event, err := NewHardFailureEvent(
		failed.ID, probeStartedAt, detectedAt, 950*time.Millisecond,
	)
	if err != nil {
		cancelRuntime()
		t.Fatal(err)
	}
	hardFailures.Publish(event)
	select {
	case <-applier.hardDone:
	case <-time.After(950 * time.Millisecond):
		cancelRuntime()
		t.Fatal("hard HTTP apply exceeded its 950ms budget")
	}
	hardElapsed := time.Since(probeStartedAt)
	select {
	case <-ready:
		cancelRuntime()
		t.Fatal("hard success alone turned readiness green")
	default:
	}
	select {
	case <-applier.recomputeDone:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup normalization was not recomputed after hard apply")
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("fresh startup normalization did not restore readiness")
	}
	var state store.PlanState
	settleDeadline := time.Now().Add(500 * time.Millisecond)
	for {
		state, err = database.LoadPlanState(ctx)
		if err != nil {
			cancelRuntime()
			t.Fatal(err)
		}
		if state.AppliedGeneration == 4 {
			break
		}
		if time.Now().After(settleDeadline) {
			cancelRuntime()
			t.Fatalf("recomputed generation did not settle: desired=%d applied=%d reason=%s",
				state.DesiredGeneration, state.AppliedGeneration, state.DesiredReason)
		}
		time.Sleep(time.Millisecond)
	}
	totalElapsed := time.Since(probeStartedAt)
	cancelRuntime()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if hardElapsed >= 950*time.Millisecond || totalElapsed >= 2*time.Second {
		t.Fatalf("wall envelope hard=%s total=%s", hardElapsed, totalElapsed)
	}
	preemptionGap := applier.PreemptionGap()
	if preemptionGap < 0 || preemptionGap > 100*time.Millisecond {
		t.Fatalf("normalization cancellation to hard Apply gap=%s", preemptionGap)
	}
	if maximum := applier.MaximumConcurrency(); maximum != 1 {
		t.Fatalf("HTTP apply max concurrency=%d", maximum)
	}
	writerMu.Lock()
	gotMaximumWriters := maximumWriters
	writerMu.Unlock()
	if gotMaximumWriters != 1 {
		t.Fatalf("Engine writer max concurrency=%d", gotMaximumWriters)
	}
	if generations := applier.Generations(); !reflect.DeepEqual(
		generations, []int64{1, 2, 3, 4},
	) {
		t.Fatalf("HTTP apply generations=%v", generations)
	}
	if state.DesiredGeneration != 4 || state.AppliedGeneration != 4 ||
		state.DesiredReason != string(PlacementStartupNormalization) {
		t.Fatalf("final plan state=%+v", state)
	}
	seen := make([]PlacementReason, 0, len(reasons))
	for len(reasons) > 0 {
		seen = append(seen, <-reasons)
	}
	if len(seen) != 3 || seen[0] != PlacementStartupNormalization ||
		seen[1] != PlacementHardFailure || seen[2] != PlacementStartupNormalization {
		t.Fatalf("placement reasons=%v", seen)
	}
	t.Logf(
		"wall-clock cancel-to-hard=%s hard=%s total-through-recompute=%s",
		preemptionGap, hardElapsed, totalElapsed,
	)
}

func TestRuntimeSilentDropDualLivenessTriggersHardFailoverWithinProductionEnvelope(t *testing.T) {
	var requests atomic.Int32
	var timingLock sync.Mutex
	var requestTimes []time.Time
	bothStarted := make(chan struct{})
	silent := httptest.NewTLSServer(http.HandlerFunc(func(
		_ http.ResponseWriter,
		request *http.Request,
	) {
		timingLock.Lock()
		requestTimes = append(requestTimes, time.Now())
		timingLock.Unlock()
		if requests.Add(1) == 2 {
			close(bothStarted)
		}
		<-request.Context().Done()
	}))
	defer silent.Close()
	targetAddress := silent.Listener.Addr().String()
	baseTransport := silent.Client().Transport.(*http.Transport)
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		transport := baseTransport.Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test endpoint
		transport.DialContext = func(
			ctx context.Context, _, _ string,
		) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", targetAddress)
		}
		return &http.Client{Transport: transport}
	}}
	hardFailures := NewHardFailureMailbox()
	probeTiming := make(chan [2]time.Time, 1)
	hardDone := make(chan time.Time, 1)
	var probed atomic.Bool
	runtime := Runtime{
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Active: func(ctx context.Context, _ time.Time) error {
			if !probed.CompareAndSwap(false, true) {
				return nil
			}
			started := time.Now()
			observation := liveness.Observe(ctx, "unused")
			detected := time.Now()
			if observation.PrimaryOK || observation.ConfirmationOK {
				return errors.New("silent endpoints unexpectedly passed liveness")
			}
			event, err := NewHardFailureEvent(
				"candidate", started, detected, 1575*time.Millisecond,
			)
			if err != nil {
				return err
			}
			select {
			case probeTiming <- [2]time.Time{started, detected}:
			default:
			}
			hardFailures.Publish(event)
			return nil
		},
		Place: func(ctx context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				return nil
			}
			timer := time.NewTimer(50 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case completed := <-timer.C:
				hardDone <- completed
				return nil
			}
		},
		HardFailureEvents:       hardFailures,
		PlacementPreemptTimeout: 100 * time.Millisecond,
		SourceRefreshInterval:   time.Hour,
		QualificationInterval:   time.Hour,
		PlacementInterval:       time.Hour,
		ActiveInterval:          time.Millisecond,
		ActiveDeadline:          625 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-bothStarted:
	case <-time.After(200 * time.Millisecond):
		cancel()
		t.Fatal("two silent liveness endpoints were not started concurrently")
	}
	var timing [2]time.Time
	select {
	case timing = <-probeTiming:
	case <-time.After(700 * time.Millisecond):
		cancel()
		t.Fatal("silent liveness did not publish hard failure by active envelope")
	}
	var completed time.Time
	select {
	case completed = <-hardDone:
	case <-time.After(950 * time.Millisecond):
		cancel()
		t.Fatal("silent liveness hard failover exceeded budget")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	detectionElapsed := timing[1].Sub(timing[0])
	totalElapsed := completed.Sub(timing[0])
	if detectionElapsed < 400*time.Millisecond || detectionElapsed > 625*time.Millisecond {
		t.Fatalf("silent liveness detection=%s outside production deadline envelope", detectionElapsed)
	}
	if totalElapsed >= 2*time.Second {
		t.Fatalf("silent liveness combined failover=%s", totalElapsed)
	}
	timingLock.Lock()
	times := append([]time.Time(nil), requestTimes...)
	timingLock.Unlock()
	if len(times) != 2 {
		t.Fatalf("silent endpoint requests=%d", len(times))
	}
	spread := times[1].Sub(times[0])
	if spread < 0 {
		spread = -spread
	}
	if spread > 50*time.Millisecond {
		t.Fatalf("silent endpoint start spread=%s", spread)
	}
	t.Logf("silent-drop detection=%s endpoint-spread=%s combined-failover=%s",
		detectionElapsed, spread, totalElapsed)
}

func TestRuntimeDoesNotRetryPermanentHTTPValidationFailure(t *testing.T) {
	runner := &temporaryRouteRunner{}
	adapter := xrayapi.NewAdapter(
		"xray", "127.0.0.1:10085", "9.9.9.9", runner,
	)
	reconciler, err := dataplane.NewReconciler(
		adapter, t.TempDir()+"/applied.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	client := agentapi.NewClient(serveRuntimeAgent(
		t, agentapi.NewServer(reconciler, 64*1024),
	))
	invalid := dataplane.DesiredPlan{
		Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	firstAttempt := make(chan struct{})
	attempts := 0
	runtime := Runtime{
		Place: func(
			ctx context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			if attempts == 1 {
				close(firstAttempt)
			}
			return client.Apply(ctx, invalid)
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("permanent validation failure was not attempted")
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	waitRuntimeDone(t, done)
	if attempts != 1 || runner.RouteCalls() != 0 {
		t.Fatalf("permanent failure attempts=%d xray route calls=%d",
			attempts, runner.RouteCalls())
	}
}

func TestRuntimeHandlesPersistedHardFailureBeforeStartupPromotion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	placed := make(chan PlacementReason, 2)
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return true, nil
		},
		Refresh: func(context.Context) error { return nil },
		Qualify: func(context.Context, time.Time) error { return nil },
		Place: func(
			_ context.Context, _ time.Time, reason PlacementReason,
		) error {
			placed <- reason
			if reason == PlacementHardFailure {
				cancel()
			}
			return nil
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case first := <-placed:
		if first != PlacementHardFailure {
			t.Fatalf("startup first placement=%s want hard failure", first)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("persisted hard failure was not placed at startup")
	}
	waitRuntimeDone(t, done)
}

func TestRuntimeNormalizesAfterPersistedHardBeforeMaintenanceAndActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lock sync.Mutex
	order := make([]string, 0, 4)
	record := func(value string) {
		lock.Lock()
		order = append(order, value)
		lock.Unlock()
	}
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return true, nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				record("hard")
			}
			return nil
		},
		StartupNormalize: func(context.Context, time.Time) error {
			record("normalize")
			return nil
		},
		Maintenance: func(context.Context, time.Time) error {
			record("maintenance")
			return nil
		},
		Active: func(context.Context, time.Time) error {
			record("active")
			cancel()
			return nil
		},
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	got := append([]string(nil), order...)
	lock.Unlock()
	if !reflect.DeepEqual(got, []string{"hard", "normalize", "maintenance", "active"}) {
		t.Fatalf("startup order=%v", got)
	}
}

func TestRuntimeReportsReadyBeforeStartingOrdinaryWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ready atomic.Bool
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return nil },
		Ready:            func() { ready.Store(true) },
		Active: func(context.Context, time.Time) error {
			if !ready.Load() {
				t.Error("Active started while controller readiness was red")
			}
			cancel()
			return nil
		},
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !ready.Load() {
		t.Fatal("successful startup never reported controller ready")
	}
}

func TestRuntimeStartupFatalErrorReportsExactUnreadyCause(t *testing.T) {
	want := errors.New("startup hard-failure inspection failed")
	var unready error
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return false, want
		},
		Unready: func(err error) { unready = err },
	}
	if err := runtime.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start=%v want %v", err, want)
	}
	if !errors.Is(unready, want) {
		t.Fatalf("unready=%v want exact startup failure", unready)
	}
}

func TestRuntimeStartupNormalizationRetriesThreeTimesThenUnready(t *testing.T) {
	want := dataplane.MarkTemporary(errors.New("normalization busy"))
	attempts := 0
	ordinary := 0
	var unready error
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error {
			attempts++
			return want
		},
		Maintenance:        func(context.Context, time.Time) error { ordinary++; return nil },
		Active:             func(context.Context, time.Time) error { ordinary++; return nil },
		Unready:            func(err error) { unready = err },
		PlacementRetryBase: time.Millisecond,
		PlacementRetryMax:  time.Millisecond,
	}
	err := runtime.Start(context.Background())
	if !errors.Is(err, want) || !errors.Is(unready, want) {
		t.Fatalf("Start=%v unready=%v want=%v", err, unready, want)
	}
	if attempts != 3 || ordinary != 0 {
		t.Fatalf("attempts=%d ordinary=%d", attempts, ordinary)
	}
}

func TestRuntimePermanentStartupNormalizationFailsUnreadyWithoutRetry(t *testing.T) {
	want := errors.New("active critical cover impossible")
	attempts := 0
	var unready error
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error {
			attempts++
			return want
		},
		Unready: func(err error) { unready = err },
	}
	err := runtime.Start(context.Background())
	if !errors.Is(err, want) || !errors.Is(unready, want) || attempts != 1 {
		t.Fatalf("Start=%v unready=%v attempts=%d", err, unready, attempts)
	}
}

func TestRuntimeLegacyActiveCriticalPlanNormalizesBeforeActive(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupHardFailure: engine.HasFreshAssignedHardFailure,
		StartupNormalize:   engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:      engine.ActiveCardinalityReady,
		CapacityReady:      engine.CapacityReady,
		Active: func(context.Context, time.Time) error {
			if len(agent.plans) != 1 ||
				enginePlanCriticalCandidateCount(agent.plans[0]) > 16 {
				t.Fatalf("Active before normalization plans=%d", len(agent.plans))
			}
			cancel()
			return nil
		},
		clock:                 newManualRuntimeClock(now.Add(time.Second)),
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStaleAppliedReserveProofsRefreshBeforeRealCapacityReady(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 2)
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, 1)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	staleNow := now.Add(3 * time.Minute)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	capacityChanges := make(chan struct{}, 1)
	var probes atomic.Int32
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		CapacityChanges: capacityChanges,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probes.Add(1)
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: staleNow},
	}
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place:            engine.CycleForReason,
		Active:           monitor.Run,
		CapacityChanges:  capacityChanges,
		Unready:          func(err error) { unready <- err },
		Ready: func() {
			ready <- struct{}{}
			cancel()
		},
		NormalizationRetryInterval: time.Hour,
		clock:                      newManualRuntimeClock(staleNow),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("stale applied proofs did not keep readiness red")
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("active proof refresh did not restore real capacity readiness")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if probes.Load() < 2 {
		t.Fatalf("active proof refreshes=%d want both primary and reserve", probes.Load())
	}
	if err := engine.CapacityReady(context.Background(), staleNow); err != nil {
		t.Fatalf("final capacity readiness=%v", err)
	}
}

func TestRuntimeBlockedAssignmentsBootstrapProofsAndRecoverReadiness(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	fingerprints := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		for success := 0; success < 2; success++ {
			if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 100, At: now.Add(time.Duration(success) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
		fingerprints = append(fingerprints, candidate.Fingerprint)
	}
	if err := database.ReplaceWorkingPool(ctx, fingerprints, nil); err != nil {
		t.Fatal(err)
	}
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false, "", "",
	)
	recoveryAt := now.Add(2 * time.Second)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
		WithActiveProofFreshness(5*time.Second), WithActiveCriticalRouteLimit(16),
	)
	capacityChanges := make(chan struct{}, 1)
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		ProofFreshness: 5 * time.Second, CapacityChanges: capacityChanges,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: recoveryAt},
	}
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	runCtx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place:            engine.CycleForReason,
		Active:           monitor.Run,
		CapacityChanges:  capacityChanges,
		Unready:          func(err error) { unready <- err },
		Ready: func() {
			ready <- struct{}{}
			cancel()
		},
		NormalizationRetryInterval: time.Hour,
		clock:                      newManualRuntimeClock(recoveryAt),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runCtx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatalf("blocked startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("blocked startup did not keep readiness red")
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("prospective bootstrap did not recover blocked assignments")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("recovery plans=%d", len(agent.plans))
	}
	route := agent.plans[0].Clients[0]
	if route.BlockTCP || route.BlockUDP || route.TCPOutbound == "" ||
		route.UDPOutbound == "" || route.TCPReserveOutbound == "" ||
		route.UDPReserveOutbound == "" {
		t.Fatalf("blocked assignment did not recover full failover route: %+v", route)
	}
}

func TestRuntimeLegacyOverlimitStaleProofBootstrapConvergesWithinCap(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	staleNow := now.Add(3 * time.Minute)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	bootstrap, err := engine.ActiveTargets(context.Background(), staleNow)
	if err != nil || len(bootstrap) == 0 || len(bootstrap) > 16 {
		t.Fatalf("bootstrap targets=%d err=%v", len(bootstrap), err)
	}
	allStarted := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	var probeMu sync.Mutex
	current, maximum := 0, 0
	observed := make(map[string]bool)
	capacityChanges := make(chan struct{}, 1)
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 48, CriticalLimit: 16,
		CapacityChanges: capacityChanges,
		Agent: activeProbeAgentFunc(func(
			ctx context.Context, request agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probeMu.Lock()
			current++
			if current > maximum {
				maximum = current
			}
			observed[request.CandidateID] = true
			if len(observed) == len(bootstrap) {
				startOnce.Do(func() { close(allStarted) })
			}
			probeMu.Unlock()
			select {
			case <-release:
			case <-ctx.Done():
				return agentapi.ProbeResponse{}, ctx.Err()
			}
			probeMu.Lock()
			current--
			probeMu.Unlock()
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: staleNow},
	}
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place:            engine.CycleForReason,
		Active:           monitor.Run,
		CapacityChanges:  capacityChanges,
		Unready:          func(err error) { unready <- err },
		Ready: func() {
			ready <- struct{}{}
			cancel()
		},
		NormalizationRetryInterval: time.Hour,
		clock:                      newManualRuntimeClock(staleNow),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	bootstrapStarted := time.Now()
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			cancel()
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("legacy overlimit did not keep readiness red")
	}
	select {
	case <-allStarted:
		close(release)
	case <-time.After(2 * time.Second):
		cancel()
		close(release)
		t.Fatal("bounded bootstrap probes did not start concurrently")
	}
	select {
	case <-ready:
	case <-time.After(4 * time.Second):
		cancel()
		t.Fatal("bootstrap proofs did not unblock capped normalization")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	probeMu.Lock()
	observedCount, maxConcurrent := len(observed), maximum
	probeMu.Unlock()
	if observedCount != len(bootstrap) || observedCount > 16 ||
		maxConcurrent != observedCount || maxConcurrent > 48 {
		t.Fatalf("bootstrap observed=%d max=%d targets=%d", observedCount, maxConcurrent, len(bootstrap))
	}
	if len(agent.plans) != 1 || enginePlanCriticalCandidateCount(agent.plans[0]) > 16 {
		t.Fatalf("normalized plans=%d critical=%d", len(agent.plans),
			enginePlanCriticalCandidateCount(agent.plans[0]))
	}
	if err := engine.ActiveCardinalityReady(context.Background(), staleNow); err != nil {
		t.Fatalf("final cardinality=%v", err)
	}
	if err := engine.CapacityReady(context.Background(), staleNow); err != nil {
		t.Fatalf("final capacity=%v", err)
	}
	engine.bootstrapCoverageMu.Lock()
	bootstrapCache := engine.bootstrapCoverageSearch
	engine.bootstrapCoverageMu.Unlock()
	if bootstrapCache != nil {
		t.Fatal("normalized plan retained completed bootstrap cover cache")
	}
	t.Logf("legacy bootstrap targets=%d max_concurrent=%d convergence=%s",
		observedCount, maxConcurrent, time.Since(bootstrapStarted))
}

func TestRuntimeImpossibleLegacyBootstrapStaysLiveAndUnready(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 17)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	for clientIndex := 0; clientIndex < 17; clientIndex++ {
		clientID := fmt.Sprintf("client-%02d", clientIndex)
		for candidateIndex := 0; candidateIndex < 17; candidateIndex++ {
			if candidateIndex != clientIndex {
				placement.Exclude(
					clientID, candidates[fmt.Sprintf("route-%02d", candidateIndex)].ID,
					now.Add(time.Hour),
				)
			}
		}
	}
	staleNow := now.Add(3 * time.Minute)
	engine := NewEngine(
		database, &engineAgent{}, nil, placement, []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	var probes atomic.Int32
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 48, CriticalLimit: 16,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probes.Add(1)
			return agentapi.ProbeResponse{}, nil
		}),
		Clock: fixedActiveMonitorClock{now: staleNow},
	}
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place:            engine.CycleForReason,
		Active:           monitor.Run,
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Unready:                    func(err error) { unready <- err },
		Ready:                      func() { ready <- struct{}{} },
		NormalizationRetryInterval: time.Hour,
		clock:                      newManualRuntimeClock(staleNow),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			cancel()
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("impossible bootstrap did not latch readiness red")
	}
	select {
	case <-ready:
		cancel()
		t.Fatal("impossible bootstrap became ready")
	case err := <-done:
		t.Fatalf("impossible bootstrap stopped runtime: %v", err)
	case <-time.After(750 * time.Millisecond):
	}
	if probes.Load() != 0 {
		cancel()
		t.Fatalf("impossible bootstrap probed %d unsafe targets", probes.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProductionActiveCadenceDoesNotSpinUnchangedNormalization(t *testing.T) {
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:tcp:reserve"},
		SearchExhausted: true,
	}
	var normalizationAttempts atomic.Int32
	var activeAttempts atomic.Int32
	latch := NewReadinessLatch()
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error {
			normalizationAttempts.Add(1)
			return coverageErr
		},
		RecoveryReady: func(context.Context, time.Time) error { return coverageErr },
		CapacityReady: func(context.Context, time.Time) error { return coverageErr },
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization {
				normalizationAttempts.Add(1)
				return coverageErr
			}
			return nil
		},
		Active: func(context.Context, time.Time) error {
			activeAttempts.Add(1)
			return ErrActiveCriticalCoverageExceeded
		},
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Unready:                    latch.Unready,
		Ready:                      latch.Ready,
		NormalizationRetryInterval: 5 * time.Second,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             250 * time.Millisecond,
		ActiveDeadline:             625 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	deadline := time.After(2 * time.Second)
	for activeAttempts.Load() < 4 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("production-cadence active lane did not remain live")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if attempts := normalizationAttempts.Load(); attempts > 2 {
		cancel()
		t.Fatalf("unchanged capacity normalization attempts=%d want<=2 before 5s retry", attempts)
	}
	if err := latch.Health(context.Background()); err == nil {
		cancel()
		t.Fatal("unchanged impossible capacity became ready")
	}
	select {
	case err := <-done:
		t.Fatalf("unchanged impossible capacity stopped liveness: %v", err)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFreshnessRecheckTurnsReadyRedThenAcceptedProofRecovers(t *testing.T) {
	now := time.Now()
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	for _, candidate := range candidates {
		setEngineActiveObservationAt(t, database, candidate, now)
	}
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(250*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	freshAt := time.Now()
	for _, candidate := range candidates {
		setEngineActiveObservationAt(t, database, candidate, freshAt)
	}
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(250*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	capacityChanges := make(chan struct{}, 1)
	var healthy atomic.Bool
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		PlanningDeadline: 450 * time.Millisecond,
		ProbeDeadline:    625 * time.Millisecond,
		ProofFreshness:   500 * time.Millisecond,
		CapacityChanges:  capacityChanges,
		Agent: activeProbeAgentFunc(func(
			context.Context, agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			if !healthy.Load() {
				return agentapi.ProbeResponse{
					FailureClass: agentapi.FailureInfrastructure,
				}, errors.New("probe infrastructure unavailable")
			}
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
	}
	latch := NewReadinessLatch()
	ready := make(chan struct{}, 2)
	unready := make(chan error, 1)
	var recoveryWakes atomic.Int32
	runCtx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place: func(ctx context.Context, at time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization {
				recoveryWakes.Add(1)
			}
			return engine.CycleForReason(ctx, at, reason)
		},
		Active:                     monitor.Run,
		CapacityChanges:            capacityChanges,
		ActiveInterval:             250 * time.Millisecond,
		ActiveDeadline:             625 * time.Millisecond,
		ActivePlanningDeadline:     450 * time.Millisecond,
		NormalizationRetryInterval: 5 * time.Second,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		Unready: func(err error) {
			latch.Unready(err)
			select {
			case unready <- err:
			default:
			}
		},
		Ready: func() {
			latch.Ready()
			select {
			case ready <- struct{}{}:
			default:
			}
		},
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runCtx) }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("fresh proof did not start ready")
	}
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			cancel()
			t.Fatalf("freshness recheck error=%v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("aged proof did not turn readiness red")
	}
	deadline := time.Now().Add(time.Second)
	for recoveryWakes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if wakes := recoveryWakes.Load(); wakes != 1 {
		cancel()
		t.Fatalf("aged unchanged proof recovery wakes=%d want=1", wakes)
	}
	if err := latch.Health(context.Background()); err == nil {
		cancel()
		t.Fatal("aged proof remained ready")
	}
	for _, row := range mustCandidateHealth(t, database) {
		if row.ActiveObservedAt.After(freshAt) {
			cancel()
			t.Fatalf("infrastructure failure mutated active proof: %+v", row)
		}
	}
	healthy.Store(true)
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("accepted renewed proof did not restore readiness")
	}
	if err := latch.Health(context.Background()); err != nil {
		cancel()
		t.Fatalf("renewed proof readiness=%v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHardFailoverDuringDegradedRecoveryStaysRedUntilConvergence(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 3)
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, 1)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	runtimeNow := now.Add(3 * time.Minute)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	capacityChanges := make(chan struct{}, 1)
	var probed sync.Map
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		CapacityChanges: capacityChanges,
		Agent: activeProbeAgentFunc(func(
			_ context.Context, request agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probed.Store(request.CandidateID, true)
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: runtimeNow},
	}
	normalizationBlocked := make(chan struct{})
	allowNormalization := make(chan struct{})
	var blockedOnce sync.Once
	hardFailures := NewHardFailureMailbox()
	hardApplied := make(chan struct{}, 1)
	activeCompleted := make(chan struct{})
	var activeOnce sync.Once
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Active: func(ctx context.Context, at time.Time) error {
			err := monitor.Run(ctx, at)
			activeOnce.Do(func() { close(activeCompleted) })
			return err
		},
		Place: func(ctx context.Context, at time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization {
				blockedOnce.Do(func() { close(normalizationBlocked) })
				select {
				case <-allowNormalization:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			err := engine.CycleForReason(ctx, at, reason)
			if reason == PlacementHardFailure && err == nil {
				select {
				case hardApplied <- struct{}{}:
				default:
				}
			}
			return err
		},
		HardFailureEvents: hardFailures, CapacityChanges: capacityChanges,
		Unready: func(err error) { unready <- err },
		Ready: func() {
			ready <- struct{}{}
			cancel()
		},
		NormalizationRetryInterval: 25 * time.Millisecond,
		clock:                      newManualRuntimeClock(runtimeNow),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: 20 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("degraded recovery did not latch readiness red")
	}
	select {
	case <-activeCompleted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("recovery Active monitor did not run")
	}
	select {
	case <-normalizationBlocked:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("ordinary convergence did not reach controlled gate")
	}
	assignments, err := database.ListAssignments(context.Background())
	if err != nil || len(assignments) != 1 {
		cancel()
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
	_, mappings, err := database.ListAppliedReserveMappings(context.Background())
	if err != nil || len(mappings) != 1 {
		cancel()
		t.Fatalf("reserve mappings=%+v err=%v", mappings, err)
	}
	failed := engineCandidateByID(t, candidates, assignments[0].TCPOutbound)
	existingReserve := mappings[0].TCPReserveCandidateID
	var thirdID string
	for _, candidate := range candidates {
		if candidate.ID != failed.ID && candidate.ID != existingReserve {
			thirdID = candidate.ID
			break
		}
	}
	if thirdID == "" {
		cancel()
		t.Fatal("replacement reserve candidate not found")
	}
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), failed, store.ObservationActive,
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		context.Background(), failed, reservation, runtimeNow,
	); err != nil || !commit.Accepted {
		cancel()
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	hardStarted := time.Now()
	hardFailures.Publish(HardFailureEvent{
		CandidateID: failed.ID, ProbeStartedAt: runtimeNow,
		DetectedAt: runtimeNow, Deadline: runtimeNow.Add(2 * time.Second),
	})
	select {
	case <-hardApplied:
		if elapsed := time.Since(hardStarted); elapsed > 500*time.Millisecond {
			cancel()
			t.Fatalf("hard failover during recovery took %s", elapsed)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("hard failover was not applied during degraded recovery")
	}
	select {
	case <-ready:
		cancel()
		t.Fatal("hard success alone turned readiness green")
	default:
	}
	proofDeadline := time.Now().Add(time.Second)
	for {
		if _, ok := probed.Load(thirdID); ok {
			break
		}
		if time.Now().After(proofDeadline) {
			cancel()
			t.Fatalf("replacement reserve %s was not actively proved", thirdID)
		}
		time.Sleep(time.Millisecond)
	}
	// The probe callback runs before ActiveMonitor commits its observation.
	// Wait for the durable proof rather than racing normalization against an
	// in-flight store write; merely observing the callback is not convergence.
	proofCommitDeadline := time.Now().Add(5 * time.Second)
	for {
		healthRows, err := database.ListCandidateHealth(context.Background())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		committed := false
		for _, healthRow := range healthRows {
			if healthRow.CandidateID == thirdID &&
				!healthRow.ActiveObservedAt.Before(runtimeNow) {
				committed = true
				break
			}
		}
		if committed {
			break
		}
		if time.Now().After(proofCommitDeadline) {
			cancel()
			t.Fatalf("replacement reserve %s proof was not committed", thirdID)
		}
		time.Sleep(time.Millisecond)
	}
	close(allowNormalization)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		healthRows, healthErr := database.ListCandidateHealth(context.Background())
		assignments, assignmentErr := database.ListAssignments(context.Background())
		_, mappings, mappingErr := database.ListAppliedReserveMappings(context.Background())
		readinessErr := engine.CapacityReady(context.Background(), runtimeNow)
		t.Fatalf(
			"ordinary convergence did not restore readiness after hard failover: readiness=%v health=%+v health_err=%v assignments=%+v assignment_err=%v mappings=%+v mapping_err=%v",
			readinessErr, healthRows, healthErr, assignments, assignmentErr, mappings, mappingErr,
		)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := engine.CapacityReady(context.Background(), runtimeNow); err != nil {
		t.Fatalf("final capacity readiness=%v", err)
	}
}

func TestRuntimeMissingReservesProbeProspectiveThenStartupNormalize(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 2)
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, 1)
	seedNow := now.Add(3 * time.Minute)
	setEngineActiveObservationAt(t, database, candidates["route-00"], seedNow)
	seedAgent := &engineAgent{}
	seed := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), seedNow); err != nil {
		t.Fatal(err)
	}
	if len(seedAgent.plans) != 1 ||
		seedAgent.plans[0].Clients[0].TCPReserveOutbound != "" ||
		seedAgent.plans[0].Clients[0].UDPReserveOutbound != "" {
		t.Fatalf("seed plan unexpectedly had reserves: %+v", seedAgent.plans)
	}
	runtimeNow := seedNow.Add(time.Second)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	capacityChanges := make(chan struct{}, 1)
	var probed sync.Map
	monitor := &ActiveMonitor{
		Store: database, Targets: engine, Slots: 16, CriticalLimit: 16,
		CapacityChanges: capacityChanges,
		Agent: activeProbeAgentFunc(func(
			_ context.Context, request agentapi.ProbeRequest,
		) (agentapi.ProbeResponse, error) {
			probed.Store(request.CandidateID, true)
			return agentapi.ProbeResponse{Observation: health.Observation{
				PrimaryOK: true, ConfirmationOK: true,
			}}, nil
		}),
		Clock: fixedActiveMonitorClock{now: runtimeNow},
	}
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Place:            engine.CycleForReason,
		Active:           monitor.Run,
		CapacityChanges:  capacityChanges,
		Unready:          func(err error) { unready <- err },
		Ready: func() {
			ready <- struct{}{}
			cancel()
		},
		NormalizationRetryInterval: time.Hour,
		clock:                      newManualRuntimeClock(runtimeNow),
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("missing reserves did not keep readiness red")
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("prospective proof did not unblock startup normalization")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	prospective := candidates["route-01"].ID
	if _, ok := probed.Load(prospective); !ok {
		t.Fatalf("prospective candidate %s was not actively proved", prospective)
	}
	if len(agent.plans) != 1 ||
		agent.plans[0].Clients[0].TCPReserveOutbound == "" ||
		agent.plans[0].Clients[0].UDPReserveOutbound == "" {
		t.Fatalf("startup normalization did not apply complete reserves: %+v", agent.plans)
	}
	if err := engine.CapacityReady(context.Background(), runtimeNow); err != nil {
		t.Fatalf("final capacity readiness=%v", err)
	}
}

func TestRuntimeLegacyHardFailoverAppliesBeforeNormalizationAndActive(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seedAgent := &engineAgent{}
	seed := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	assignments, err := database.ListAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	failed := engineCandidateByID(t, candidates, assignments[0].TCPOutbound)
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		context.Background(), failed, reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupHardFailure: engine.HasFreshAssignedHardFailure,
		Place:              engine.CycleForReason,
		StartupNormalize:   engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:      engine.ActiveCardinalityReady,
		CapacityReady:      engine.CapacityReady,
		Active: func(context.Context, time.Time) error {
			if len(agent.plans) != 2 {
				t.Fatalf("Apply order plans=%d want hard+normalization", len(agent.plans))
			}
			legacy := enginePlanCriticalCandidateCount(seedAgent.plans[0])
			hard := enginePlanCriticalCandidateCount(agent.plans[0])
			normalized := enginePlanCriticalCandidateCount(agent.plans[1])
			if hard > legacy || normalized > 16 {
				t.Fatalf("capacity legacy=%d hard=%d normalized=%d", legacy, hard, normalized)
			}
			cancel()
			return nil
		},
		clock:                 newManualRuntimeClock(now.Add(2 * time.Second)),
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePendingHardGenerationAppliesBeforeNormalizeWhenHealthIsStale(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	seedAgent := &engineAgent{}
	seed := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	failed := engineCandidateByID(
		t, candidates,
		candidateIDFromHandler(seedAgent.plans[0].Clients[0].TCPOutbound, "alice"),
	)
	reservation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard commit=%+v err=%v", commit, err)
	}
	seedAgent.applyErr = errors.New("lost hard apply response")
	if err := seed.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err == nil {
		t.Fatal("hard generation did not remain pending")
	}
	pending, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.DesiredGeneration != 2 || pending.AppliedGeneration != 1 ||
		pending.DesiredReason != string(PlacementHardFailure) {
		t.Fatalf("pending state=%+v", pending)
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	staleNow := now.Add(time.Hour)
	runCtx, cancel := context.WithCancel(context.Background())
	order := make([]string, 0, 3)
	runtime := Runtime{
		StartupHardFailure: engine.HasStartupHardFailure,
		Place:              engine.CycleForReason,
		StartupNormalize: func(context.Context, time.Time) error {
			order = append(order, "normalize")
			return nil
		},
		Active: func(context.Context, time.Time) error {
			order = append(order, "active")
			cancel()
			return errors.New("active backend unavailable")
		},
		clock:                 newManualRuntimeClock(staleNow),
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(runCtx); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || agent.plans[0].Generation != 2 ||
		!reflect.DeepEqual(order, []string{"normalize", "active"}) {
		t.Fatalf("pending hard order plans=%v order=%v",
			enginePlanGenerations(agent.plans), order)
	}
}

func TestRuntimeImpossibleLegacyNormalizationFailsUnreadyWithoutApplyCorruption(
	t *testing.T,
) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 17)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	placement := scheduler.New(scheduler.PolicyDefaults())
	for clientIndex := 0; clientIndex < 17; clientIndex++ {
		clientID := fmt.Sprintf("client-%02d", clientIndex)
		for candidateIndex := 0; candidateIndex < 17; candidateIndex++ {
			if candidateIndex == clientIndex {
				continue
			}
			placement.Exclude(
				clientID, candidates[fmt.Sprintf("route-%02d", candidateIndex)].ID,
				now.Add(time.Hour),
			)
		}
	}
	seed := NewEngine(
		database, &engineAgent{}, nil, placement, []byte("secret"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	before, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	impossibleEngine := NewEngine(
		database, agent, nil, placement, []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	recoveryEngine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	var feasible atomic.Bool
	var normalizationAttempts atomic.Int32
	sourceChanges := make(chan struct{}, 1)
	capacityChanges := make(chan struct{}, 1)
	unready := make(chan error, 4)
	ready := make(chan struct{}, 1)
	active := make(chan struct{}, 2)
	var refreshes atomic.Int32
	var qualifications atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: func(ctx context.Context, at time.Time) error {
			normalizationAttempts.Add(1)
			if feasible.Load() {
				return recoveryEngine.NormalizeActiveCriticalRoutes(ctx, at)
			}
			return impossibleEngine.NormalizeActiveCriticalRoutes(ctx, at)
		},
		Place: func(ctx context.Context, at time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization {
				normalizationAttempts.Add(1)
				if feasible.Load() {
					return recoveryEngine.CycleForReason(ctx, at, reason)
				}
				return impossibleEngine.CycleForReason(ctx, at, reason)
			}
			return nil
		},
		RecoveryReady: impossibleEngine.ActiveCardinalityReady,
		CapacityReady: func(ctx context.Context, at time.Time) error {
			if feasible.Load() {
				return recoveryEngine.CapacityReady(ctx, at)
			}
			return impossibleEngine.CapacityReady(ctx, at)
		},
		Refresh: func(context.Context) error {
			refreshes.Add(1)
			return nil
		},
		Qualify: func(context.Context, time.Time) error {
			qualifications.Add(1)
			return nil
		},
		Active: func(context.Context, time.Time) error {
			select {
			case active <- struct{}{}:
			default:
			}
			return nil
		},
		SourceChanges: sourceChanges, CapacityChanges: capacityChanges,
		Unready:                    func(err error) { unready <- err },
		Ready:                      func() { ready <- struct{}{} },
		NormalizationRetryInterval: 10 * time.Millisecond,
		clock:                      newManualRuntimeClock(now.Add(time.Second)),
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	var degraded error
	select {
	case degraded = <-unready:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("capacity failure did not latch readiness red")
	}
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(degraded, &coverErr) {
		t.Fatalf("unready=%v", degraded)
	}
	after, loadErr := database.LoadPlanState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(after, before) || len(agent.plans) != 0 {
		t.Fatalf("failed normalization mutated state before=%+v after=%+v plans=%d",
			before, after, len(agent.plans))
	}
	select {
	case err := <-done:
		t.Fatalf("degraded runtime exited early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-active:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("bootstrap Active lane did not start while capacity was red")
	}
	if refreshes.Load() == 0 || qualifications.Load() == 0 {
		t.Fatalf("degraded recovery workers refresh=%d qualify=%d",
			refreshes.Load(), qualifications.Load())
	}
	feasible.Store(true)
	sourceChanges <- struct{}{}
	capacityChanges <- struct{}{}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatalf("capacity recovery did not restore readiness after %d normalization attempts",
			normalizationAttempts.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || enginePlanCriticalCandidateCount(agent.plans[0]) > 16 {
		t.Fatalf("recovery plans=%d", len(agent.plans))
	}
}

func TestRuntimeCompletesPersistedHardPlacementBeforeBlockingStartupMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	maintenanceEntered := make(chan struct{})
	releaseMaintenance := make(chan struct{})
	var lock sync.Mutex
	var order []string
	record := func(value string) {
		lock.Lock()
		order = append(order, value)
		lock.Unlock()
	}
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return true, nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				t.Fatalf("startup placement=%s want hard failure", reason)
			}
			record("hard-start")
			record("hard-complete")
			return nil
		},
		Maintenance: func(ctx context.Context, _ time.Time) error {
			record("maintenance")
			close(maintenanceEntered)
			select {
			case <-releaseMaintenance:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-maintenanceEntered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("startup maintenance did not run")
	}
	lock.Lock()
	got := append([]string(nil), order...)
	lock.Unlock()
	if !reflect.DeepEqual(got, []string{"hard-start", "hard-complete", "maintenance"}) {
		t.Fatalf("startup order=%v", got)
	}
	cancel()
	close(releaseMaintenance)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRetriesTemporaryPersistedHardPlacementBeforeStartupMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	maintenanceEntered := make(chan struct{})
	var lock sync.Mutex
	var order []string
	attempts := 0
	record := func(value string) {
		lock.Lock()
		order = append(order, value)
		lock.Unlock()
	}
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return true, nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				t.Fatalf("startup placement=%s want hard failure", reason)
			}
			attempts++
			record(fmt.Sprintf("hard-%d", attempts))
			if attempts < 3 {
				return dataplane.MarkTemporary(errors.New("dataplane busy"))
			}
			return nil
		},
		Maintenance: func(context.Context, time.Time) error {
			record("maintenance")
			close(maintenanceEntered)
			cancel()
			return nil
		},
		PlacementRetryBase: 5 * time.Millisecond,
		PlacementRetryMax:  10 * time.Millisecond,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-maintenanceEntered:
	default:
		t.Fatal("startup maintenance did not run after hard placement success")
	}
	lock.Lock()
	got := append([]string(nil), order...)
	lock.Unlock()
	want := []string{"hard-1", "hard-2", "hard-3", "maintenance"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("startup retry order=%v want=%v", got, want)
	}
}

func TestRuntimePermanentPersistedHardPlacementErrorStartsNoOrdinaryWork(t *testing.T) {
	want := errors.New("invalid persisted hard plan")
	ordinaryCalls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return true, nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason != PlacementHardFailure {
				ordinaryCalls++
			}
			return want
		},
		Maintenance: func(context.Context, time.Time) error { ordinaryCalls++; return nil },
		Refresh:     func(context.Context) error { ordinaryCalls++; return nil },
		Qualify:     func(context.Context, time.Time) error { ordinaryCalls++; return nil },
		Active:      func(context.Context, time.Time) error { ordinaryCalls++; return nil },
	}
	err := runtime.Start(ctx)
	if !errors.Is(err, want) {
		t.Fatalf("Start error=%v want=%v", err, want)
	}
	if ordinaryCalls != 0 {
		t.Fatalf("ordinary work started after permanent hard placement error: %d", ordinaryCalls)
	}
}

func TestRuntimeRetriesTemporaryStartupInspectionBeforeOrdinaryWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lock sync.Mutex
	var order []string
	attempts := 0
	record := func(value string) {
		lock.Lock()
		order = append(order, value)
		lock.Unlock()
	}
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			attempts++
			record("inspect")
			if attempts < 3 {
				return false, dataplane.MarkTemporary(errors.New("database busy"))
			}
			return true, nil
		},
		Maintenance: func(context.Context, time.Time) error { record("maintenance"); return nil },
		Refresh:     func(context.Context) error { record("refresh"); return nil },
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementHardFailure {
				record("hard")
				cancel()
			}
			return nil
		},
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	defer lock.Unlock()
	if len(order) < 4 || !reflect.DeepEqual(order[:3], []string{"inspect", "inspect", "inspect"}) {
		t.Fatalf("startup order=%v", order)
	}
	for _, item := range order[:3] {
		if item != "inspect" {
			t.Fatalf("ordinary work ran before startup gate: %v", order)
		}
	}
}

func TestRuntimeReturnsPermanentStartupInspectionErrorWithoutStartingWorkers(t *testing.T) {
	want := errors.New("corrupt startup state")
	ordinaryCalls := 0
	runtime := Runtime{
		StartupHardFailure: func(context.Context, time.Time) (bool, error) {
			return false, want
		},
		Maintenance: func(context.Context, time.Time) error { ordinaryCalls++; return nil },
		Refresh:     func(context.Context) error { ordinaryCalls++; return nil },
		Place:       func(context.Context, time.Time, PlacementReason) error { ordinaryCalls++; return nil },
	}
	err := runtime.Start(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("Start error=%v want=%v", err, want)
	}
	if ordinaryCalls != 0 {
		t.Fatalf("ordinary workers started after permanent startup failure: %d", ordinaryCalls)
	}
}

func TestRuntimeCancelsPendingHardFailureBackoffOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	firstAttempt := make(chan struct{})
	attempts := 0
	runtime := Runtime{
		Place: func(
			_ context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			if attempts == 1 {
				close(firstAttempt)
			}
			return dataplane.ErrRuntimeRecovering
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    250 * time.Millisecond,
		PlacementRetryMax:     250 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("initial hard placement did not run")
	}
	cancel()
	waitRuntimeDone(t, done)
	time.Sleep(300 * time.Millisecond)
	if attempts != 1 {
		t.Fatalf("hard placement retried after shutdown: attempts=%d", attempts)
	}
}

func TestRuntimeFailoverIsNotStarvedByBlockedQualification(t *testing.T) {
	qualificationStarted := make(chan struct{})
	releaseQualification := make(chan struct{})
	hardFailure := make(chan struct{}, 1)
	placed := make(chan PlacementReason, 4)
	runtime := Runtime{
		Qualify: func(ctx context.Context, _ time.Time) error {
			close(qualificationStarted)
			select {
			case <-releaseQualification:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			placed <- reason
			return nil
		},
		HardFailures:          hardFailure,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.Start(ctx)
	select {
	case <-qualificationStarted:
	case <-time.After(time.Second):
		t.Fatal("qualification did not start")
	}
	hardFailure <- struct{}{}
	select {
	case reason := <-placed:
		if reason != PlacementHardFailure {
			t.Fatalf("reason=%s", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hard failure placement was starved by qualification")
	}
	close(releaseQualification)
}

func TestRuntimeRunsMaintenanceBeforeInitialSourceRefresh(t *testing.T) {
	clock := newManualRuntimeClock(time.Unix(1_800_000_000, 0))
	order := make(chan string, 2)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		Maintenance: func(context.Context, time.Time) error {
			order <- "maintenance"
			return nil
		},
		Refresh: func(context.Context) error {
			order <- "refresh"
			cancel()
			return nil
		},
		clock:                 clock,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()

	for _, want := range []string{"maintenance", "refresh"} {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("startup order got=%q want=%q", got, want)
			}
		case <-time.After(time.Second):
			cancel()
			waitRuntimeDone(t, done)
			t.Fatalf("startup did not run %s", want)
		}
	}
	waitRuntimeDone(t, done)
	if clock.interval != time.Minute {
		t.Fatalf("maintenance interval=%s want=1m", clock.interval)
	}
}

func TestRuntimeRetriesMaintenanceOnNextMinuteAfterError(t *testing.T) {
	clock := newManualRuntimeClock(time.Unix(1_800_000_000, 0))
	calls := make(chan time.Time, 2)
	ctx, cancel := context.WithCancel(context.Background())
	var count int
	runtime := Runtime{
		Maintenance: func(_ context.Context, at time.Time) error {
			count++
			calls <- at
			if count == 1 {
				return errors.New("temporary store failure")
			}
			cancel()
			return nil
		},
		clock:                 clock,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case at := <-calls:
		if !at.Equal(clock.now) {
			t.Fatalf("startup maintenance at=%s want=%s", at, clock.now)
		}
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("startup maintenance did not run")
	}

	next := clock.now.Add(time.Minute)
	clock.now = next
	clock.ticker.ticks <- next
	select {
	case at := <-calls:
		if !at.Equal(next) {
			t.Fatalf("retry maintenance at=%s want=%s", at, next)
		}
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("maintenance was not retried")
	}
	waitRuntimeDone(t, done)
}

func TestRuntimeMaintenanceStopsPromptlyOnCancellation(t *testing.T) {
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		Maintenance: func(ctx context.Context, _ time.Time) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
		clock: newManualRuntimeClock(time.Unix(1_800_000_000, 0)),
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not start")
	}
	cancel()
	waitRuntimeDone(t, done)
}

func TestRuntimePlacesPromotionWhileQualificationContinues(t *testing.T) {
	promotions := make(chan struct{}, 1)
	qualificationStarted := make(chan struct{})
	releaseQualification := make(chan struct{})
	placed := make(chan PlacementReason, 1)
	runtime := Runtime{
		Qualify: func(ctx context.Context, _ time.Time) error {
			close(qualificationStarted)
			select {
			case <-releaseQualification:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			placed <- reason
			return nil
		},
		Promotions:            promotions,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.Start(ctx)
	<-qualificationStarted
	promotions <- struct{}{}
	select {
	case reason := <-placed:
		if reason != PlacementPromotion {
			t.Fatalf("reason=%s", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("promotion placement waited for qualification completion")
	}
	close(releaseQualification)
}

func TestRuntimeQoEDoesNotStarveOtherControlLoopsAndStopsOnCancellation(t *testing.T) {
	qoeStarted := make(chan struct{})
	qoeExited := make(chan struct{})
	allowRefresh := make(chan struct{})
	refreshed := make(chan struct{}, 1)
	qualified := make(chan struct{}, 1)
	active := make(chan struct{}, 1)
	placed := make(chan PlacementReason, 4)
	qoeDegraded := make(chan struct{}, 1)
	var qoeOnce sync.Once

	runtime := Runtime{
		Refresh: func(ctx context.Context) error {
			select {
			case <-allowRefresh:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case refreshed <- struct{}{}:
			default:
			}
			return nil
		},
		Qualify: func(context.Context, time.Time) error {
			select {
			case qualified <- struct{}{}:
			default:
			}
			return nil
		},
		Active: func(context.Context, time.Time) error {
			select {
			case active <- struct{}{}:
			default:
			}
			return nil
		},
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			placed <- reason
			return nil
		},
		QoE: func(ctx context.Context, _ time.Time) error {
			qoeOnce.Do(func() { close(qoeStarted) })
			<-ctx.Done()
			close(qoeExited)
			return ctx.Err()
		},
		QoEDegradations:       qoeDegraded,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Second,
		QoEInterval:           5 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()

	select {
	case <-qoeStarted:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("QoE cycle did not start")
	}
	close(allowRefresh)
	qoeDegraded <- struct{}{}

	for _, check := range []struct {
		name    string
		signal  <-chan struct{}
		timeout time.Duration
	}{
		{name: "source refresh", signal: refreshed, timeout: time.Second},
		{name: "qualification", signal: qualified, timeout: time.Second},
		{name: "active liveness", signal: active, timeout: 3 * time.Second},
	} {
		select {
		case <-check.signal:
		case <-time.After(check.timeout):
			cancel()
			waitRuntimeDone(t, done)
			t.Fatalf("%s was starved by QoE", check.name)
		}
	}
	placementDeadline := time.After(time.Second)

placementLoop:
	for {
		select {
		case reason := <-placed:
			if reason == PlacementQoEDegraded {
				break placementLoop
			}
		case <-placementDeadline:
			cancel()
			waitRuntimeDone(t, done)
			t.Fatal("QoE placement was starved by QoE measurement")
		}
	}

	cancel()
	select {
	case <-qoeExited:
	case <-time.After(time.Second):
		t.Fatal("QoE worker ignored runtime cancellation")
	}
	waitRuntimeDone(t, done)
}

func TestRuntimeQoERunsWhileCapacityRecoveryIsPending(t *testing.T) {
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:udp:reserve"}, SearchExhausted: true,
	}
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return coverageErr },
		RecoveryReady:    func(context.Context, time.Time) error { return coverageErr },
		CapacityReady:    func(context.Context, time.Time) error { return coverageErr },
		QoE: func(context.Context, time.Time) error {
			close(started)
			return nil
		},
		QoEInterval:                5 * time.Millisecond,
		NormalizationRetryInterval: time.Hour,
		SourceRefreshInterval:      time.Hour, QualificationInterval: time.Hour,
		PlacementInterval: time.Hour, ActiveInterval: time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("QoE recovery waited for capacity readiness")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeQoESkipsOverdueTickAndUsesFreshTimestamp(t *testing.T) {
	const interval = 40 * time.Millisecond
	type invocation struct {
		at       time.Time
		observed time.Time
	}
	invocations := make(chan invocation, 3)
	releaseFirst := make(chan struct{})
	var calls int
	runtime := Runtime{
		QoE: func(ctx context.Context, at time.Time) error {
			calls++
			invocations <- invocation{at: at, observed: time.Now()}
			if calls != 1 {
				return nil
			}
			select {
			case <-releaseFirst:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
		QoEInterval:           interval,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()

	select {
	case <-invocations:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("first QoE cycle did not start")
	}
	time.Sleep(2 * interval)
	releasedAt := time.Now()
	close(releaseFirst)

	var second invocation
	select {
	case second = <-invocations:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("second QoE cycle did not start after the next interval")
	}
	if delay := second.observed.Sub(releasedAt); delay < interval/2 {
		t.Errorf("overdue QoE tick replayed after %s, want a new interval", delay)
	}
	if second.at.Before(releasedAt) {
		t.Errorf("second QoE timestamp=%s predates first completion=%s", second.at, releasedAt)
	}
	if age := second.observed.Sub(second.at); age > interval/2 {
		t.Errorf("second QoE timestamp age=%s, want a fresh timestamp", age)
	}

	cancel()
	waitRuntimeDone(t, done)
}

func TestPlacementQueuePrioritizesManualAndCoalescesPeriodic(t *testing.T) {
	queue := NewPlacementQueue()
	queue.Enqueue(PlacementPeriodic)
	queue.Enqueue(PlacementPeriodic)
	queue.Enqueue(PlacementPromotion)
	queue.Enqueue(PlacementManual)
	if queue.Len() != 3 {
		t.Fatalf("len=%d", queue.Len())
	}
	if reason, _ := queue.Pop(); reason != PlacementManual {
		t.Fatalf("first=%s", reason)
	}
}

func TestRuntimeDoesNotRunPlacementConcurrently(t *testing.T) {
	trigger := make(chan struct{}, 16)
	var mu sync.Mutex
	running := 0
	maxRunning := 0
	runtime := Runtime{
		Place: func(context.Context, time.Time, PlacementReason) error {
			mu.Lock()
			running++
			if running > maxRunning {
				maxRunning = running
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
			return nil
		},
		ManualReassigns:       trigger,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.Start(ctx)
	}()
	for index := 0; index < 10; index++ {
		trigger <- struct{}{}
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if maxRunning != 1 {
		t.Fatalf("max concurrent placements=%d", maxRunning)
	}
}

func TestRuntimeActiveProbeAllowsResponseAfterServerDeadline(t *testing.T) {
	const serverDeadline = 5 * time.Millisecond
	socketPath := serveRuntimeAgent(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/probes/active" {
			t.Errorf("unexpected request path %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(serverDeadline + 5*time.Millisecond)
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"candidate_id":"active","success":true}`)
	}))
	agent := agentapi.NewClient(
		socketPath,
		agentapi.WithClientProbeDeadlines(
			time.Second,
			time.Second,
			serverDeadline,
			time.Second,
			time.Second,
		),
	)
	activeResult := make(chan error, 1)
	var resultOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := Runtime{
		Active: func(ctx context.Context, _ time.Time) error {
			_, err := agent.ProbeActive(ctx, agentapi.ProbeRequest{
				CandidateID: "active", Kind: "vless", Payload: "payload",
			})
			resultOnce.Do(func() {
				activeResult <- err
				cancel()
			})
			return err
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        20 * time.Millisecond,
		ActiveDeadline:        agentapi.ProbeRequestTimeout(serverDeadline),
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()

	select {
	case err := <-activeResult:
		waitRuntimeDone(t, done)
		if err != nil {
			t.Fatalf("active response inside controller slack was canceled: %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("active probe did not finish")
	}
}

func TestRuntimeActiveProbeHonorsExternalCancellation(t *testing.T) {
	started := make(chan struct{})
	socketPath := serveRuntimeAgent(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	agent := agentapi.NewClient(
		socketPath,
		agentapi.WithClientProbeDeadlines(
			time.Second,
			time.Second,
			500*time.Millisecond,
			time.Second,
			time.Second,
		),
	)
	activeResult := make(chan error, 1)
	var resultOnce sync.Once
	runtime := Runtime{
		Active: func(ctx context.Context, _ time.Time) error {
			_, err := agent.ProbeActive(ctx, agentapi.ProbeRequest{
				CandidateID: "active", Kind: "vless", Payload: "payload",
			})
			resultOnce.Do(func() {
				activeResult <- err
			})
			return err
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        20 * time.Millisecond,
		ActiveDeadline:        agentapi.ProbeRequestTimeout(500 * time.Millisecond),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("active probe did not start")
	}

	start := time.Now()
	cancel()
	select {
	case err := <-activeResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active probe error=%v, want external cancellation", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("external cancellation took %s", elapsed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("active probe ignored external cancellation")
	}
	waitRuntimeDone(t, done)
}

func waitRuntimeDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop")
	}
}

type manualRuntimeTicker struct {
	ticks chan time.Time
}

func (ticker *manualRuntimeTicker) Chan() <-chan time.Time {
	return ticker.ticks
}

func (*manualRuntimeTicker) Stop() {}

type manualRuntimeClock struct {
	now      time.Time
	interval time.Duration
	ticker   *manualRuntimeTicker
}

func newManualRuntimeClock(now time.Time) *manualRuntimeClock {
	return &manualRuntimeClock{
		now: now, ticker: &manualRuntimeTicker{ticks: make(chan time.Time, 1)},
	}
}

func (clock *manualRuntimeClock) Now() time.Time {
	return clock.now
}

func (clock *manualRuntimeClock) NewTicker(
	interval time.Duration,
) runtimeTicker {
	clock.interval = interval
	return clock.ticker
}

func serveRuntimeAgent(t *testing.T, handler http.Handler) string {
	t.Helper()
	socketFile, err := os.CreateTemp("", "hydrat-agent-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socketPath := socketFile.Name()
	if err := socketFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(socketPath)
	})
	return socketPath
}

type emptyActivityProvider struct{}

func (emptyActivityProvider) Snapshot(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

type wallClockHTTPApplier struct {
	mu               sync.Mutex
	generations      []int64
	inFlight         int
	maximum          int
	lowerCanceledAt  time.Time
	hardStartedAt    time.Time
	lowerStarted     chan struct{}
	hardDone         chan struct{}
	recomputeDone    chan struct{}
	lowerStartedOnce sync.Once
	hardDoneOnce     sync.Once
	recomputeOnce    sync.Once
}

func newWallClockHTTPApplier() *wallClockHTTPApplier {
	return &wallClockHTTPApplier{
		lowerStarted: make(chan struct{}), hardDone: make(chan struct{}),
		recomputeDone: make(chan struct{}),
	}
}

func (applier *wallClockHTTPApplier) Apply(
	ctx context.Context,
	plan dataplane.DesiredPlan,
) error {
	applier.mu.Lock()
	applier.generations = append(applier.generations, plan.Generation)
	applier.inFlight++
	if applier.inFlight > applier.maximum {
		applier.maximum = applier.inFlight
	}
	applier.mu.Unlock()
	defer func() {
		applier.mu.Lock()
		applier.inFlight--
		applier.mu.Unlock()
	}()
	switch plan.Generation {
	case 2:
		applier.lowerStartedOnce.Do(func() { close(applier.lowerStarted) })
		<-ctx.Done()
		applier.mu.Lock()
		applier.lowerCanceledAt = time.Now()
		applier.mu.Unlock()
		return ctx.Err()
	case 3:
		applier.mu.Lock()
		applier.hardStartedAt = time.Now()
		applier.mu.Unlock()
		timer := time.NewTimer(50 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			applier.hardDoneOnce.Do(func() { close(applier.hardDone) })
		}
	case 4:
		applier.recomputeOnce.Do(func() { close(applier.recomputeDone) })
	}
	return nil
}

func (applier *wallClockHTTPApplier) MaximumConcurrency() int {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	return applier.maximum
}

func (applier *wallClockHTTPApplier) PreemptionGap() time.Duration {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	if applier.lowerCanceledAt.IsZero() || applier.hardStartedAt.IsZero() {
		return -1
	}
	return applier.hardStartedAt.Sub(applier.lowerCanceledAt)
}

func (applier *wallClockHTTPApplier) Generations() []int64 {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	return append([]int64(nil), applier.generations...)
}

func TestActiveCoverageRetryDistinguishesImpossibleFromExhaustedSearch(t *testing.T) {
	impossible := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:tcp:reserve"},
	}
	if retryActiveCriticalCoverage(impossible) {
		t.Fatal("impossible cover scheduled a timer retry")
	}
	exhaustedBeforeEvaluation := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:tcp:reserve"},
		SearchExhausted: true, Evaluations: 0,
	}
	if !retryActiveCriticalCoverage(exhaustedBeforeEvaluation) {
		t.Fatal("bounded search that exhausted before evaluation lost its retry")
	}
}

func TestRuntimeRetriesCoverageExhaustedBeforeFirstEvaluation(t *testing.T) {
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"alice:tcp:reserve"},
		SearchExhausted: true, Evaluations: 0,
	}
	var attempts atomic.Int32
	ready := make(chan struct{}, 1)
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return coverageErr },
		Place: func(_ context.Context, _ time.Time, reason PlacementReason) error {
			if reason == PlacementStartupNormalization && attempts.Add(1) == 1 {
				return coverageErr
			}
			return nil
		},
		CapacityReady: func(context.Context, time.Time) error {
			if attempts.Load() < 2 {
				return coverageErr
			}
			return nil
		},
		Ready:                      func() { ready <- struct{}{} },
		NormalizationRetryInterval: 5 * time.Millisecond,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Start(ctx) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("zero-evaluation bounded search was not retried")
	}
	if got := attempts.Load(); got != 2 {
		cancel()
		t.Fatalf("normalization attempts=%d want=2", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type temporaryRouteRunner struct {
	mu         sync.Mutex
	failRoutes int
	routeCalls int
}

func (runner *temporaryRouteRunner) Run(
	ctx context.Context,
	_ string,
	_ string,
	args ...string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) < 2 || args[0] != "api" || args[1] != "adrules" {
		return nil
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.routeCalls++
	if runner.routeCalls <= runner.failRoutes {
		return errors.New("xray route API unavailable")
	}
	return nil
}

func (runner *temporaryRouteRunner) RouteCalls() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.routeCalls
}
