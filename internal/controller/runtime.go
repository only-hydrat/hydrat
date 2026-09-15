package controller

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/only-hydrat/hydrat/internal/store"
)

type runtimeTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type runtimeClock interface {
	Now() time.Time
	NewTicker(time.Duration) runtimeTicker
}

type realRuntimeClock struct{}

func (realRuntimeClock) Now() time.Time {
	return time.Now()
}

func (realRuntimeClock) NewTicker(interval time.Duration) runtimeTicker {
	return realRuntimeTicker{Ticker: time.NewTicker(interval)}
}

type realRuntimeTicker struct {
	*time.Ticker
}

func (ticker realRuntimeTicker) Chan() <-chan time.Time {
	return ticker.C
}

type Runtime struct {
	Maintenance        func(context.Context, time.Time) error
	ProfileRepair      func(context.Context, time.Time) (bool, error)
	Refresh            func(context.Context) error
	Qualify            func(context.Context, time.Time) error
	Active             func(context.Context, time.Time) error
	QoE                func(context.Context, time.Time) error
	Place              func(context.Context, time.Time, PlacementReason) error
	StartupHardFailure func(context.Context, time.Time) (bool, error)
	StartupNormalize   func(context.Context, time.Time) error
	RecoveryReady      func(context.Context, time.Time) error
	CapacityReady      func(context.Context, time.Time) error

	HardFailures      <-chan struct{}
	HardFailureEvents *HardFailureMailbox
	ManualReassigns   <-chan struct{}
	ClientChanges     <-chan struct{}
	SourceChanges     <-chan struct{}
	CapacityChanges   <-chan struct{}
	Promotions        <-chan struct{}
	QoEDegradations   <-chan struct{}

	SourceRefreshInterval      time.Duration
	QualificationInterval      time.Duration
	PlacementInterval          time.Duration
	ActiveInterval             time.Duration
	ActiveDeadline             time.Duration
	ActivePlanningDeadline     time.Duration
	ActiveOverlap              int
	QoEInterval                time.Duration
	MaintenanceInterval        time.Duration
	ProfileRepairInterval      time.Duration
	PlacementRetryBase         time.Duration
	PlacementRetryMax          time.Duration
	PlacementPreemptTimeout    time.Duration
	Unready                    func(error)
	Ready                      func()
	NormalizationRetryInterval time.Duration

	clock runtimeClock
}

var ErrPlacementPreemptionTimeout = errors.New(
	"lower-priority placement ignored hard-failure cancellation",
)

var ErrHardFailoverDeadlineExceeded = errors.New(
	"hard-failure placement deadline exceeded",
)

func (runtime Runtime) Start(ctx context.Context) error {
	rootCtx := ctx
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	clock := runtime.clock
	if clock == nil {
		clock = realRuntimeClock{}
	}
	capacityCheckGate := make(chan struct{}, 1)
	capacityCheckGate <- struct{}{}
	checkCapacityReady := func(checkCtx context.Context, at time.Time) error {
		if runtime.CapacityReady == nil {
			return nil
		}
		select {
		case <-checkCtx.Done():
			return checkCtx.Err()
		case <-capacityCheckGate:
		}
		defer func() { capacityCheckGate <- struct{}{} }()
		return runtime.CapacityReady(checkCtx, at)
	}
	runMaintenance := func() {
		if runtime.Maintenance == nil {
			return
		}
		if err := runtime.Maintenance(
			ctx, clock.Now(),
		); err != nil && !expectedRuntimeStop(err) {
			log.Printf("diagnostic maintenance: %v", err)
		}
	}
	var capacityDegraded atomic.Bool
	markCapacityUnready := func(err error) bool {
		transitioned := !capacityDegraded.Swap(true)
		if transitioned && runtime.Unready != nil {
			runtime.Unready(err)
		}
		return transitioned
	}
	markCapacityReady := func() {
		capacityDegraded.Store(false)
		if runtime.Ready != nil {
			runtime.Ready()
		}
	}
	if runtime.ProfileRepair != nil {
		if _, err := runtime.ProfileRepair(ctx, clock.Now()); err != nil {
			if expectedRuntimeStop(err) || ctx.Err() != nil {
				return nil
			}
			if runtime.Unready != nil {
				runtime.Unready(err)
			}
			return err
		}
	}
	startupHardFailure, err := runtime.inspectStartupHardFailure(ctx, clock)
	if err != nil {
		if runtime.Unready != nil {
			runtime.Unready(err)
		}
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	if startupHardFailure {
		if err := runtime.placeStartupHardFailure(ctx, clock); err != nil {
			if expectedRuntimeStop(err) || ctx.Err() != nil {
				return nil
			}
			if runtime.Unready != nil {
				runtime.Unready(err)
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	normalizationPending := false
	if runtime.StartupNormalize != nil {
		if err := runtime.normalizeStartup(ctx, clock); err != nil {
			if expectedRuntimeStop(err) || ctx.Err() != nil {
				return nil
			}
			if recoverableCapacityNormalizationError(err) {
				normalizationPending = true
				markCapacityUnready(err)
			} else {
				if runtime.Unready != nil {
					runtime.Unready(err)
				}
				return err
			}
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	if !normalizationPending && runtime.CapacityReady != nil {
		if err := checkCapacityReady(ctx, clock.Now()); err != nil {
			if errors.Is(err, ErrActiveCriticalCoverageExceeded) {
				normalizationPending = true
				markCapacityUnready(err)
			} else {
				if runtime.Unready != nil {
					runtime.Unready(err)
				}
				return err
			}
		}
	}
	if runtime.RecoveryReady != nil {
		if err := runtime.RecoveryReady(ctx, clock.Now()); err != nil {
			normalizationPending = true
			markCapacityUnready(err)
		}
	}
	runMaintenance()
	if ctx.Err() != nil {
		return nil
	}

	sourceSignal := make(chan struct{}, 1)
	qualificationSignal := make(chan struct{}, 1)
	activeSignal := make(chan struct{}, 1)
	placementWake := make(chan struct{}, 1)
	ordinaryGate := make(chan struct{})
	var ordinaryOnce sync.Once
	enableOrdinary := func() bool {
		enabled := false
		ordinaryOnce.Do(func() {
			enabled = true
			markCapacityReady()
			close(ordinaryGate)
		})
		return enabled
	}
	if !normalizationPending {
		enableOrdinary()
	}
	ordinaryEnabled := func() bool {
		select {
		case <-ordinaryGate:
			return true
		default:
			return false
		}
	}
	completeCapacityReady := func() {
		if !enableOrdinary() && capacityDegraded.Load() {
			markCapacityReady()
		}
	}
	waitForOrdinary := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-ordinaryGate:
			return true
		}
	}
	queue := NewPlacementQueue()
	enqueue := func(reason PlacementReason) {
		queue.Enqueue(reason)
		select {
		case placementWake <- struct{}{}:
		default:
		}
	}
	signal := func(channel chan<- struct{}) {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
	var workers sync.WaitGroup

	if runtime.Maintenance != nil {
		maintenanceTicker := clock.NewTicker(positiveInterval(
			runtime.MaintenanceInterval, time.Minute,
		))
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer maintenanceTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-maintenanceTicker.Chan():
					runMaintenance()
				}
			}
		}()
	}

	if runtime.ProfileRepair != nil {
		profileTicker := clock.NewTicker(positiveInterval(
			runtime.ProfileRepairInterval, 5*time.Second,
		))
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer profileTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case at := <-profileTicker.Chan():
					repaired, err := runtime.ProfileRepair(ctx, at)
					if err != nil {
						if !expectedRuntimeStop(err) {
							log.Printf("Tor profile runtime repair: %v", err)
						}
						continue
					}
					if repaired {
						signal(activeSignal)
						if capacityDegraded.Load() {
							enqueue(PlacementStartupNormalization)
						}
					}
				}
			}
		}()
	}

	runtimeFatal := make(chan error, 1)
	var fatalOnce sync.Once
	latchFatal := func(err error) {
		fatalOnce.Do(func() {
			if runtime.Unready != nil {
				runtime.Unready(err)
			}
			runtimeFatal <- err
		})
	}
	if runtime.CapacityReady != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if !waitForOrdinary() {
				return
			}
			interval := positiveInterval(runtime.ActiveInterval, time.Second)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case at := <-ticker.C:
					if capacityDegraded.Load() {
						continue
					}
					err := checkCapacityReady(ctx, at)
					if err == nil || expectedRuntimeStop(err) {
						continue
					}
					if recoverableCapacityNormalizationError(err) {
						if markCapacityUnready(err) {
							enqueue(PlacementStartupNormalization)
						}
						continue
					}
					latchFatal(err)
					return
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sourceSignal:
				if runtime.Refresh != nil {
					if err := runtime.Refresh(ctx); err != nil && !expectedRuntimeStop(err) {
						log.Printf("source refresh: %v", err)
					}
				}
				signal(qualificationSignal)
				if !ordinaryEnabled() || capacityDegraded.Load() {
					signal(activeSignal)
				}
			}
		}
	}()

	if runtime.QoE != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			interval := positiveInterval(runtime.QoEInterval, 15*time.Second)
			timer := time.NewTimer(interval)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					if err := runtime.QoE(ctx, time.Now()); err != nil && !expectedRuntimeStop(err) {
						log.Printf("QoE cycle: %v", err)
					}
					if ctx.Err() != nil {
						return
					}
					timer.Reset(interval)
				}
			}
		}()
	}

	if runtime.Active != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			overlap := runtime.ActiveOverlap
			if overlap <= 0 {
				overlap = 1
			}
			activeSlots := make(chan struct{}, overlap)
			activeInterval := positiveInterval(runtime.ActiveInterval, time.Second)
			var lastActiveStart time.Time
			var activeRuns sync.WaitGroup
			defer activeRuns.Wait()
			for {
				select {
				case <-ctx.Done():
					return
				case <-activeSignal:
					if !lastActiveStart.IsZero() {
						remaining := activeInterval - time.Since(lastActiveStart)
						if remaining > 0 {
							timer := time.NewTimer(remaining)
							select {
							case <-timer.C:
							case <-ctx.Done():
								if !timer.Stop() {
									select {
									case <-timer.C:
									default:
									}
								}
								return
							}
						}
					}
					select {
					case activeSlots <- struct{}{}:
					case <-ctx.Done():
						return
					default:
						continue
					}
					started := make(chan time.Time, 1)
					activeRuns.Add(1)
					go func() {
						defer activeRuns.Done()
						defer func() { <-activeSlots }()
						started <- time.Now()
						deadline := positiveInterval(
							runtime.ActiveDeadline, 700*time.Millisecond,
						)
						if runtime.ActivePlanningDeadline > 0 &&
							deadline <= time.Duration(1<<63-1)-runtime.ActivePlanningDeadline {
							deadline += runtime.ActivePlanningDeadline
						}
						probeCtx, cancel := context.WithTimeout(ctx, deadline)
						err := runtime.Active(probeCtx, clock.Now())
						cancel()
						if errors.Is(err, ErrActiveCriticalCoverageExceeded) {
							markCapacityUnready(err)
							return
						}
						if err != nil && !expectedRuntimeStop(err) {
							log.Printf("active liveness cycle: %v", err)
						}
					}()
					select {
					case lastActiveStart = <-started:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-qualificationSignal:
				if runtime.Qualify != nil {
					if err := runtime.Qualify(ctx, time.Now()); err != nil {
						if !errors.Is(err, store.ErrCandidateInventoryChanged) &&
							!expectedRuntimeStop(err) {
							log.Printf("qualification cycle: %v", err)
						}
					}
				}
				if !ordinaryEnabled() || capacityDegraded.Load() {
					signal(activeSignal)
				}
			}
		}
	}()

	workers.Add(1)
	go func() {
		defer workers.Done()
		type retrySignal struct {
			reason PlacementReason
			serial uint64
		}
		type retryState struct {
			attempt int
			serial  uint64
			timer   *time.Timer
			event   *HardFailureEvent
		}
		type placementResult struct {
			reason PlacementReason
			event  *HardFailureEvent
			err    error
		}
		type placementAttempt struct {
			reason          PlacementReason
			event           *HardFailureEvent
			cancel          context.CancelFunc
			canceledForHard bool
		}
		retryWake := make(chan retrySignal, 16)
		results := make(chan placementResult, 1)
		retries := make(map[PlacementReason]retryState)
		deferredAfterHard := make(map[PlacementReason]bool)
		var current *placementAttempt
		var pendingHard *HardFailureEvent
		var preemptTimer *time.Timer
		var preemptDeadline <-chan time.Time
		var preemptFailure error
		retainPendingHard := func(event *HardFailureEvent) {
			if event == nil {
				return
			}
			if pendingHard == nil || event.Deadline.Before(pendingHard.Deadline) {
				copy := *event
				pendingHard = &copy
			}
		}
		clearRetry := func(reason PlacementReason) {
			state, exists := retries[reason]
			if !exists {
				return
			}
			if state.timer != nil {
				state.timer.Stop()
			}
			delete(retries, reason)
		}
		expireHardDeadline := func() {
			clearRetry(PlacementHardFailure)
			markCapacityUnready(ErrHardFailoverDeadlineExceeded)
			enqueue(PlacementStartupNormalization)
		}
		defer func() {
			for reason := range retries {
				clearRetry(reason)
			}
		}()
		scheduleRetry := func(reason PlacementReason, event *HardFailureEvent) {
			state := retries[reason]
			if state.timer != nil {
				state.timer.Stop()
			}
			state.attempt++
			state.serial++
			if event != nil && (state.event == nil ||
				event.Deadline.Before(state.event.Deadline)) {
				copy := *event
				state.event = &copy
			}
			signal := retrySignal{reason: reason, serial: state.serial}
			delay := placementRetryDelay(
				runtime.PlacementRetryBase,
				runtime.PlacementRetryMax,
				state.attempt,
			)
			if reason == PlacementStartupNormalization {
				delay = positiveInterval(
					runtime.NormalizationRetryInterval, 5*time.Second,
				)
			}
			if reason == PlacementHardFailure && state.event != nil &&
				!state.event.Deadline.IsZero() {
				remaining := state.event.Deadline.Sub(clock.Now())
				if remaining < delay {
					delay = max(remaining, 0)
				}
			}
			state.timer = time.AfterFunc(delay, func() {
				select {
				case retryWake <- signal:
				case <-ctx.Done():
				}
			})
			retries[reason] = state
		}
		fatal := latchFatal
		admitHard := func() *HardFailureEvent {
			if state, exists := retries[PlacementHardFailure]; exists {
				retainPendingHard(state.event)
				if state.timer != nil {
					state.timer.Stop()
					state.timer = nil
				}
				state.serial++
				retries[PlacementHardFailure] = state
			}
			if runtime.HardFailureEvents != nil {
				if event, exists := runtime.HardFailureEvents.Pop(); exists {
					retainPendingHard(&event)
				}
			}
			event := pendingHard
			pendingHard = nil
			return event
		}
		start := func(reason PlacementReason, event *HardFailureEvent) bool {
			if runtime.Place == nil {
				return false
			}
			attemptCtx := ctx
			var cancel context.CancelFunc
			if reason == PlacementHardFailure && event != nil && !event.Deadline.IsZero() {
				if !clock.Now().Before(event.Deadline) {
					expireHardDeadline()
					return false
				}
				attemptCtx, cancel = context.WithDeadline(ctx, event.Deadline)
			} else {
				attemptCtx, cancel = context.WithCancel(ctx)
			}
			attempt := &placementAttempt{reason: reason, event: event, cancel: cancel}
			current = attempt
			go func() {
				err := runtime.Place(attemptCtx, clock.Now(), reason)
				if reason != PlacementHardFailure && runtime.CapacityReady != nil {
					readyErr := checkCapacityReady(attemptCtx, clock.Now())
					// A bounded planning attempt can expire just after another
					// recovery lane has already committed a complete plan. Durable
					// readiness is authoritative in that case; retrying the stale
					// planning error keeps /api/ready red forever despite healthy
					// assignments and reserves.
					if readyErr == nil {
						err = nil
					} else if err == nil {
						err = readyErr
					}
				}
				results <- placementResult{reason: reason, event: event, err: err}
			}()
			return true
		}
		var startNext func()
		startNext = func() {
			if current != nil {
				return
			}
			if pendingHard != nil {
				queue.Take(PlacementHardFailure)
				event := admitHard()
				start(PlacementHardFailure, event)
				return
			}
			reason, ok := queue.Pop()
			if !ok {
				return
			}
			var event *HardFailureEvent
			if reason == PlacementHardFailure {
				event = admitHard()
				if runtime.HardFailureEvents != nil && event == nil {
					startNext()
					return
				}
			}
			start(reason, event)
		}
		for {
			select {
			case <-ctx.Done():
				if current != nil {
					current.cancel()
				}
				return
			case <-preemptDeadline:
				fatal(preemptFailure)
				return
			case result := <-results:
				if current == nil || result.reason != current.reason {
					continue
				}
				attempt := current
				current = nil
				attempt.cancel()
				if preemptTimer != nil {
					preemptTimer.Stop()
					preemptTimer = nil
					preemptDeadline = nil
					preemptFailure = nil
				}
				if result.reason == PlacementHardFailure && result.event != nil &&
					!result.event.Deadline.IsZero() &&
					!clock.Now().Before(result.event.Deadline) {
					expireHardDeadline()
					startNext()
					continue
				}
				if attempt.canceledForHard {
					deferredAfterHard[result.reason] = true
					startNext()
					continue
				}
				if result.err != nil && !expectedRuntimeStop(result.err) {
					log.Printf("placement cycle (%s): %v", result.reason, result.err)
				}
				if result.err != nil && !expectedRuntimeStop(result.err) &&
					errors.Is(result.err, ErrActiveCriticalCoverageExceeded) {
					markCapacityUnready(result.err)
					if retryActiveCriticalCoverage(result.err) {
						scheduleRetry(result.reason, result.event)
					} else {
						clearRetry(result.reason)
					}
					startNext()
					continue
				}
				if result.err != nil && !expectedRuntimeStop(result.err) &&
					retryablePlacementError(result.err) {
					scheduleRetry(result.reason, result.event)
					if result.reason == PlacementHardFailure &&
						runtime.HardFailureEvents != nil {
						if event, exists := runtime.HardFailureEvents.Pop(); exists {
							retainPendingHard(&event)
							enqueue(PlacementHardFailure)
						}
					}
					startNext()
					continue
				}
				if result.reason == PlacementHardFailure && result.err != nil &&
					!expectedRuntimeStop(result.err) {
					fatal(result.err)
					return
				}
				if result.reason == PlacementStartupNormalization && result.err != nil &&
					!expectedRuntimeStop(result.err) {
					fatal(result.err)
					return
				}
				clearRetry(result.reason)
				if result.reason == PlacementStartupNormalization && result.err == nil {
					completeCapacityReady()
				} else if result.reason != PlacementHardFailure && result.err == nil &&
					runtime.CapacityReady != nil && capacityDegraded.Load() {
					markCapacityReady()
				}
				if result.reason == PlacementHardFailure && result.err == nil {
					if !ordinaryEnabled() || capacityDegraded.Load() {
						enqueue(PlacementStartupNormalization)
					}
					for reason := range deferredAfterHard {
						delete(deferredAfterHard, reason)
						enqueue(reason)
					}
				}
				startNext()
			case signal := <-retryWake:
				state, exists := retries[signal.reason]
				if !exists || state.serial != signal.serial {
					continue
				}
				state.timer = nil
				retries[signal.reason] = state
				if signal.reason == PlacementHardFailure && state.event != nil {
					if !clock.Now().Add(time.Millisecond).Before(state.event.Deadline) {
						expireHardDeadline()
						startNext()
						continue
					}
					retainPendingHard(state.event)
					enqueue(PlacementHardFailure)
				} else {
					enqueue(signal.reason)
				}
			case <-placementWake:
				if current != nil && current.reason != PlacementHardFailure &&
					queue.Take(PlacementHardFailure) {
					event := admitHard()
					if runtime.HardFailureEvents != nil && event == nil {
						continue
					}
					retainPendingHard(event)
					current.canceledForHard = true
					current.cancel()
					timeout := positiveInterval(
						runtime.PlacementPreemptTimeout, 100*time.Millisecond,
					)
					preemptFailure = ErrPlacementPreemptionTimeout
					if pendingHard != nil && !pendingHard.Deadline.IsZero() {
						remaining := pendingHard.Deadline.Sub(clock.Now())
						if remaining <= timeout {
							timeout = max(remaining, 0)
							preemptFailure = ErrHardFailoverDeadlineExceeded
						}
					}
					preemptTimer = time.NewTimer(timeout)
					preemptDeadline = preemptTimer.C
					continue
				}
				startNext()
			}
		}
	}()

	workers.Add(1)
	go func() {
		defer workers.Done()
		runtime.watchEvents(
			ctx, ordinaryGate,
			sourceSignal, qualificationSignal, activeSignal, enqueue,
		)
	}()

	if normalizationPending {
		enqueue(PlacementStartupNormalization)
	}
	signal(sourceSignal)
	signal(activeSignal)
	select {
	case <-rootCtx.Done():
		cancelRun()
		workers.Wait()
		return nil
	case err := <-runtimeFatal:
		cancelRun()
		workers.Wait()
		return err
	}
}
