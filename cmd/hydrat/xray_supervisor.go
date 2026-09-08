package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/supervisor"
)

type xraySupervisorGroup struct {
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	mu                      sync.Mutex
	generation              uint64
	invalidatedGeneration   uint64
	readyGeneration         uint64
	startPending            bool
	pendingStartInvalidated bool
	lastRehydrateError      error
	startEvents             chan struct{}
	retryInterval           time.Duration
	readinessCheck          func(context.Context) error
	invalidateRuntime       func()
	rehydrate               func(context.Context) error
	rehydrationStarted      bool
}

func newXraySupervisor(output io.Writer) supervisor.Supervisor {
	return supervisor.Supervisor{
		Runner:  supervisor.ExecRunner{Output: output},
		Backoff: time.Second,
	}
}

func startXraySupervisors(
	ctx context.Context,
	managed supervisor.Supervisor,
	binary, mainConfig string,
) *xraySupervisorGroup {
	childCtx, cancel := context.WithCancel(ctx)
	group := &xraySupervisorGroup{
		ctx:           childCtx,
		cancel:        cancel,
		startEvents:   make(chan struct{}, 1),
		retryInterval: 100 * time.Millisecond,
	}
	runner := managed.Runner
	if runner == nil {
		runner = supervisor.ExecRunner{}
	}
	managed.Runner = xrayStartNotifyingRunner{
		delegate:    runner,
		beforeStart: group.beginStart,
		afterStart:  group.finishStart,
	}
	processes := []struct {
		name   string
		config string
	}{
		{name: "xray-main", config: mainConfig},
	}
	group.workers.Add(len(processes))
	for _, process := range processes {
		process := process
		go func() {
			defer group.workers.Done()
			logSupervisor(process.name, managed.Run(childCtx, supervisor.Spec{
				Name: process.name,
				Path: binary,
				Args: []string{"run", "-config", process.config},
			}))
		}()
	}
	return group
}

type xrayStartNotifyingRunner struct {
	delegate    supervisor.Runner
	beforeStart func()
	afterStart  func()
}

func (runner xrayStartNotifyingRunner) Start(
	ctx context.Context,
	path string,
	args ...string,
) (supervisor.Process, error) {
	runner.beforeStart()
	process, err := runner.delegate.Start(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	runner.afterStart()
	return process, nil
}

func (group *xraySupervisorGroup) beginStart() {
	group.mu.Lock()
	if !group.startPending {
		group.pendingStartInvalidated = false
	}
	group.startPending = true
	group.readyGeneration = 0
	group.lastRehydrateError = errors.New("main Xray runtime rehydration is pending")
	invalidate := group.invalidateRuntime
	group.mu.Unlock()

	if invalidate != nil {
		invalidate()
		group.mu.Lock()
		if group.startPending {
			group.pendingStartInvalidated = true
		}
		group.mu.Unlock()
	}
}

func (group *xraySupervisorGroup) finishStart() {
	group.mu.Lock()
	group.generation++
	generation := group.generation
	group.startPending = false
	if group.pendingStartInvalidated {
		group.invalidatedGeneration = generation
	}
	group.pendingStartInvalidated = false
	group.mu.Unlock()
	group.signalStart()
}

func (group *xraySupervisorGroup) StartRehydration(
	readinessCheck func(context.Context) error,
	invalidateRuntime func(),
	rehydrate func(context.Context) error,
) {
	if readinessCheck == nil || invalidateRuntime == nil || rehydrate == nil {
		panic("Xray rehydration callbacks are required")
	}
	group.mu.Lock()
	if group.rehydrationStarted {
		group.mu.Unlock()
		panic("Xray rehydration was already started")
	}
	group.readinessCheck = readinessCheck
	group.invalidateRuntime = invalidateRuntime
	group.rehydrate = rehydrate
	group.rehydrationStarted = true
	generation := group.generation
	startPending := group.startPending
	group.mu.Unlock()

	if generation > 0 || startPending {
		invalidateRuntime()
		group.mu.Lock()
		if group.startPending {
			group.pendingStartInvalidated = true
		} else if group.generation > 0 {
			group.invalidatedGeneration = group.generation
		}
		group.mu.Unlock()
	}
	group.workers.Add(1)
	go group.runRehydration()
	group.signalStart()
}

func (group *xraySupervisorGroup) Readiness(
	endpointReadiness func(context.Context) error,
) func(context.Context) error {
	return func(ctx context.Context) error {
		if endpointReadiness != nil {
			if err := endpointReadiness(ctx); err != nil {
				return err
			}
		}
		group.mu.Lock()
		generation := group.generation
		readyGeneration := group.readyGeneration
		startPending := group.startPending
		lastRehydrateError := group.lastRehydrateError
		group.mu.Unlock()
		if startPending || generation == 0 || readyGeneration != generation {
			if lastRehydrateError != nil {
				return fmt.Errorf("main Xray generation %d is not rehydrated; retry pending", generation)
			}
			return fmt.Errorf("main Xray generation %d is not rehydrated", generation)
		}
		return nil
	}
}

func (group *xraySupervisorGroup) runRehydration() {
	defer group.workers.Done()
	for {
		select {
		case <-group.ctx.Done():
			return
		case <-group.startEvents:
		}
		for {
			generation, invalidatedGeneration, readyGeneration, startPending, check, rehydrate :=
				group.rehydrationSnapshot()
			if generation == 0 || readyGeneration == generation && !startPending {
				break
			}
			if startPending || invalidatedGeneration != generation || check == nil || rehydrate == nil {
				break
			}
			err := check(group.ctx)
			if err == nil && group.isCurrentInvalidatedGeneration(generation) {
				err = rehydrate(group.ctx)
			}
			if err == nil {
				if group.markReady(generation) {
					break
				}
				continue
			}
			if errors.Is(err, context.Canceled) && group.ctx.Err() != nil {
				return
			}
			if group.recordRehydrateError(generation, err) {
				log.Printf("main Xray generation %d rehydrate failed; retrying: %v", generation, err)
			}
			timer := time.NewTimer(group.retryInterval)
			select {
			case <-group.ctx.Done():
				timer.Stop()
				return
			case <-group.startEvents:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

func (group *xraySupervisorGroup) rehydrationSnapshot() (
	generation uint64,
	invalidatedGeneration uint64,
	readyGeneration uint64,
	startPending bool,
	readinessCheck func(context.Context) error,
	rehydrate func(context.Context) error,
) {
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.generation,
		group.invalidatedGeneration,
		group.readyGeneration,
		group.startPending,
		group.readinessCheck,
		group.rehydrate
}

func (group *xraySupervisorGroup) isCurrentInvalidatedGeneration(generation uint64) bool {
	group.mu.Lock()
	defer group.mu.Unlock()
	return !group.startPending &&
		group.generation == generation &&
		group.invalidatedGeneration == generation
}

func (group *xraySupervisorGroup) markReady(generation uint64) bool {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.startPending ||
		group.generation != generation ||
		group.invalidatedGeneration != generation {
		return false
	}
	group.readyGeneration = generation
	group.lastRehydrateError = nil
	return true
}

func (group *xraySupervisorGroup) recordRehydrateError(generation uint64, err error) bool {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.startPending || group.generation != generation {
		return false
	}
	changed := group.lastRehydrateError == nil || group.lastRehydrateError.Error() != err.Error()
	if group.generation == generation {
		group.readyGeneration = 0
		group.lastRehydrateError = err
	}
	return changed
}

func (group *xraySupervisorGroup) signalStart() {
	select {
	case group.startEvents <- struct{}{}:
	default:
	}
}

func (group *xraySupervisorGroup) generationState() (uint64, uint64) {
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.generation, group.readyGeneration
}

func (group *xraySupervisorGroup) StopAndWait() {
	group.cancel()
	group.workers.Wait()
}
