package controller

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

func retryActiveCriticalCoverage(err error) bool {
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) {
		return false
	}
	return coverageErr.SearchExhausted
}

func (runtime Runtime) normalizeStartup(
	ctx context.Context,
	clock runtimeClock,
) error {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := runtime.StartupNormalize(ctx, clock.Now())
		if err == nil || expectedRuntimeStop(err) || ctx.Err() != nil {
			return err
		}
		// Capacity search owns a resumable 450ms frontier and is retried by the
		// degraded recovery worker. Replaying it synchronously here would stack
		// three slices before readiness can report red.
		if recoverableCapacityNormalizationError(err) {
			return err
		}
		if !retryablePlacementError(err) || attempt == maxAttempts {
			return err
		}
		log.Printf("startup active-critical normalization: %v", err)
		delay := placementRetryDelay(
			runtime.PlacementRetryBase, runtime.PlacementRetryMax, attempt,
		)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func recoverableCapacityNormalizationError(err error) bool {
	var coverageErr *ActiveCriticalCoveragePlanError
	if errors.As(err, &coverageErr) {
		return true
	}
	var limitErr *ActiveCriticalRouteLimitError
	return errors.As(err, &limitErr)
}

func (runtime Runtime) placeStartupHardFailure(
	ctx context.Context,
	clock runtimeClock,
) error {
	if runtime.Place == nil {
		return errors.New("persisted hard failure requires placement")
	}
	for attempt := 1; ; attempt++ {
		err := runtime.Place(ctx, clock.Now(), PlacementHardFailure)
		if err == nil {
			return nil
		}
		if expectedRuntimeStop(err) || ctx.Err() != nil {
			return err
		}
		if !retryablePlacementError(err) {
			return err
		}
		log.Printf("startup hard-failure placement: %v", err)
		delay := placementRetryDelay(
			runtime.PlacementRetryBase, runtime.PlacementRetryMax, attempt,
		)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (runtime Runtime) inspectStartupHardFailure(
	ctx context.Context,
	clock runtimeClock,
) (bool, error) {
	if runtime.StartupHardFailure == nil {
		return false, nil
	}
	for attempt := 1; ; attempt++ {
		hardFailure, err := runtime.StartupHardFailure(ctx, clock.Now())
		if err == nil {
			return hardFailure, nil
		}
		if expectedRuntimeStop(err) || ctx.Err() != nil {
			return false, nil
		}
		if !retryablePlacementError(err) {
			return false, err
		}
		delay := placementRetryDelay(
			runtime.PlacementRetryBase, runtime.PlacementRetryMax, attempt,
		)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false, nil
		case <-timer.C:
		}
	}
}

func retryablePlacementError(err error) bool {
	if errors.Is(err, dataplane.ErrRuntimeRecovering) ||
		errors.Is(err, store.ErrCandidateInventoryChanged) {
		return true
	}
	var temporary dataplane.TemporaryError
	return errors.As(err, &temporary) && temporary.Temporary()
}

func placementRetryDelay(base, maximum time.Duration, attempt int) time.Duration {
	base = positiveInterval(base, 250*time.Millisecond)
	maximum = positiveInterval(maximum, 5*time.Second)
	if maximum < base {
		maximum = base
	}
	delay := base
	for index := 1; index < attempt && delay < maximum; index++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func (runtime Runtime) watchEvents(
	ctx context.Context,
	ordinaryGate <-chan struct{},
	sourceSignal chan<- struct{},
	qualificationSignal chan<- struct{},
	activeSignal chan<- struct{},
	enqueue func(PlacementReason),
) {
	refreshTicker := time.NewTicker(positiveInterval(runtime.SourceRefreshInterval, time.Hour))
	qualificationTicker := time.NewTicker(positiveInterval(runtime.QualificationInterval, 5*time.Minute))
	placementTicker := time.NewTicker(positiveInterval(runtime.PlacementInterval, 5*time.Minute))
	activeTicker := time.NewTicker(positiveInterval(runtime.ActiveInterval, time.Second))
	defer refreshTicker.Stop()
	defer qualificationTicker.Stop()
	defer placementTicker.Stop()
	defer activeTicker.Stop()
	var placementTicks <-chan time.Time
	var manualReassigns <-chan struct{}
	var clientChanges <-chan struct{}
	var qoeDegradations <-chan struct{}
	ordinaryWake := ordinaryGate
	for {
		select {
		case <-ctx.Done():
			return
		case <-ordinaryWake:
			ordinaryWake = nil
			placementTicks = placementTicker.C
			manualReassigns = runtime.ManualReassigns
			clientChanges = runtime.ClientChanges
			qoeDegradations = runtime.QoEDegradations
		case <-refreshTicker.C:
			nonBlockingSignal(sourceSignal)
		case <-qualificationTicker.C:
			nonBlockingSignal(qualificationSignal)
		case <-placementTicks:
			enqueue(PlacementPeriodic)
		case <-activeTicker.C:
			nonBlockingSignal(activeSignal)
		case <-runtime.HardFailures:
			enqueue(PlacementHardFailure)
		case <-runtime.HardFailureEvents.Wake():
			enqueue(PlacementHardFailure)
		case <-manualReassigns:
			enqueue(PlacementManual)
		case <-clientChanges:
			enqueue(PlacementClientLifecycle)
		case <-runtime.SourceChanges:
			nonBlockingSignal(sourceSignal)
		case <-runtime.CapacityChanges:
			enqueue(PlacementStartupNormalization)
		case <-runtime.Promotions:
			enqueue(PlacementPromotion)
		case <-qoeDegradations:
			enqueue(PlacementQoEDegraded)
		}
	}
}

func nonBlockingSignal(channel chan<- struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

func positiveInterval(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func expectedRuntimeStop(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
