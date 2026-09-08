package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/store"
)

type activeTargetSnapshot struct {
	targets           []ActiveTarget
	appliedGeneration int64
}

func cloneActiveTargetSnapshot(snapshot activeTargetSnapshot) activeTargetSnapshot {
	snapshot.targets = append([]ActiveTarget(nil), snapshot.targets...)
	return snapshot
}

func (monitor *ActiveMonitor) planActiveTargets(
	ctx context.Context,
	now time.Time,
) (activeTargetSnapshot, error) {
	planningCtx := ctx
	cancelPlanning := func() {}
	if monitor.PlanningDeadline > 0 {
		planningCtx, cancelPlanning = context.WithTimeout(ctx, monitor.PlanningDeadline)
	}
	before, err := monitor.Store.LoadPlanState(planningCtx)
	if err != nil {
		cancelPlanning()
		return activeTargetSnapshot{}, err
	}
	targets, err := monitor.Targets.ActiveTargets(planningCtx, now)
	after, stateErr := monitor.Store.LoadPlanState(planningCtx)
	cancelPlanning()
	if err == nil {
		err = stateErr
	}
	if err == nil && before.AppliedGeneration != after.AppliedGeneration {
		err = store.ErrCandidateInventoryChanged
	}
	if err == nil {
		err = monitor.validateActiveTargets(targets)
	}
	return activeTargetSnapshot{
		targets:           append([]ActiveTarget(nil), targets...),
		appliedGeneration: after.AppliedGeneration,
	}, err
}

func (monitor *ActiveMonitor) validateActiveTargets(targets []ActiveTarget) error {
	if monitor.CriticalLimit <= 0 {
		return nil
	}
	roles := make(map[string]ActiveTargetRole, len(targets))
	for _, target := range targets {
		candidateID := target.Candidate.ID
		if candidateID == "" {
			continue
		}
		role := target.Role
		if role == "" {
			if target.TriggerPlacementOnSuccess {
				role = ActiveTargetProspective
			} else {
				role = ActiveTargetCritical
			}
		}
		roles[candidateID] = mergeActiveTargetRole(roles[candidateID], role)
	}
	critical := 0
	for _, role := range roles {
		if role == ActiveTargetCritical {
			critical++
		}
	}
	if critical > monitor.CriticalLimit {
		return fmt.Errorf("%w: critical=%d limit=%d",
			ErrActiveCriticalCoverageExceeded, critical, monitor.CriticalLimit)
	}
	return nil
}

func (monitor *ActiveMonitor) appliedCriticalTargets(
	ctx context.Context,
) (int64, map[string]bool, error) {
	before, err := monitor.Store.LoadPlanState(ctx)
	if err != nil {
		return 0, nil, err
	}
	assignments, err := monitor.Store.ListAssignments(ctx)
	if err != nil {
		return 0, nil, err
	}
	mappingGeneration, mappings, err := monitor.Store.ListAppliedReserveMappings(ctx)
	if err != nil {
		return 0, nil, err
	}
	after, err := monitor.Store.LoadPlanState(ctx)
	if err != nil {
		return 0, nil, err
	}
	if before.AppliedGeneration != after.AppliedGeneration ||
		mappingGeneration != after.AppliedGeneration {
		return 0, nil, store.ErrCandidateInventoryChanged
	}
	critical := make(map[string]bool)
	for _, assignment := range assignments {
		for _, candidateID := range []string{
			assignment.TCPOutbound, assignment.UDPOutbound,
		} {
			if candidateID != "" {
				critical[candidateID] = true
			}
		}
	}
	for _, mapping := range mappings {
		for _, candidateID := range []string{
			mapping.TCPPrimaryCandidateID, mapping.TCPReserveCandidateID,
			mapping.UDPPrimaryCandidateID, mapping.UDPReserveCandidateID,
		} {
			if candidateID != "" {
				critical[candidateID] = true
			}
		}
	}
	return after.AppliedGeneration, critical, nil
}

func (monitor *ActiveMonitor) reconcileAppliedTargetGeneration(
	ctx context.Context,
	snapshot activeTargetSnapshot,
) (activeTargetSnapshot, error) {
	state, err := monitor.Store.LoadPlanState(ctx)
	if err != nil {
		return activeTargetSnapshot{}, err
	}
	if state.AppliedGeneration == snapshot.appliedGeneration {
		return snapshot, nil
	}
	generation, critical, err := monitor.appliedCriticalTargets(ctx)
	if err != nil {
		return activeTargetSnapshot{}, err
	}
	targets := append([]ActiveTarget(nil), snapshot.targets...)
	byID := make(map[string]int, len(targets))
	for index := range targets {
		candidateID := targets[index].Candidate.ID
		if candidateID == "" {
			continue
		}
		byID[candidateID] = index
		if critical[candidateID] {
			targets[index].Role = ActiveTargetCritical
			targets[index].TriggerPlacementOnSuccess = false
		} else if targets[index].Role == ActiveTargetCritical ||
			targets[index].Role == "" {
			targets[index].Role = ActiveTargetProspective
		}
	}
	missing := make([]string, 0)
	for candidateID := range critical {
		if _, exists := byID[candidateID]; !exists {
			missing = append(missing, candidateID)
		}
	}
	if len(missing) != 0 {
		candidates, listErr := monitor.Store.ListRoutableCandidates(ctx, missing)
		if listErr != nil {
			return activeTargetSnapshot{}, listErr
		}
		for _, candidate := range candidates {
			if critical[candidate.ID] {
				byID[candidate.ID] = len(targets)
				targets = append(targets, ActiveTarget{
					Candidate: candidate, Role: ActiveTargetCritical,
				})
			}
		}
		for _, candidateID := range missing {
			if _, exists := byID[candidateID]; !exists {
				return activeTargetSnapshot{}, store.ErrCandidateInventoryChanged
			}
		}
	}
	if err := monitor.validateActiveTargets(targets); err != nil {
		return activeTargetSnapshot{}, err
	}
	reconciled := activeTargetSnapshot{
		targets: targets, appliedGeneration: generation,
	}
	monitor.targetsMu.Lock()
	if monitor.targetsReady &&
		monitor.targetsSnapshot.appliedGeneration == snapshot.appliedGeneration {
		monitor.targetsSnapshot = cloneActiveTargetSnapshot(reconciled)
	}
	monitor.targetsMu.Unlock()
	return reconciled, nil
}

func (monitor *ActiveMonitor) finishTargetPlanning(
	snapshot activeTargetSnapshot,
	err error,
) {
	monitor.targetsMu.Lock()
	if err == nil && (!monitor.targetsReady ||
		snapshot.appliedGeneration >= monitor.targetsSnapshot.appliedGeneration) {
		monitor.targetsSnapshot = cloneActiveTargetSnapshot(snapshot)
		monitor.targetsReady = true
	}
	monitor.targetsPlanErr = err
	monitor.targetsPlanning = false
	done := monitor.targetsPlanDone
	monitor.targetsPlanDone = nil
	monitor.targetsMu.Unlock()
	close(done)
}

// activeTargets returns the last successfully planned snapshot immediately.
// The run that starts a refresh keeps it bound to its own context and waits for
// it only after probes have already started. During bootstrap, concurrent runs
// share the first synchronous plan so readiness cannot observe a partial cache.
func (monitor *ActiveMonitor) activeTargets(
	ctx context.Context,
	now time.Time,
) (activeTargetSnapshot, func() error, error) {
	for {
		monitor.targetsMu.Lock()
		if monitor.targetsReady {
			snapshot := cloneActiveTargetSnapshot(monitor.targetsSnapshot)
			if monitor.targetsPlanning {
				monitor.targetsMu.Unlock()
				return snapshot, nil, nil
			}
			monitor.targetsPlanning = true
			monitor.targetsPlanDone = make(chan struct{})
			monitor.targetsMu.Unlock()

			result := make(chan error, 1)
			go func() {
				planned, err := monitor.planActiveTargets(ctx, now)
				monitor.finishTargetPlanning(planned, err)
				result <- err
			}()
			return snapshot, func() error { return <-result }, nil
		}
		if monitor.targetsPlanning {
			done := monitor.targetsPlanDone
			monitor.targetsMu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return activeTargetSnapshot{}, nil, ctx.Err()
			}
			monitor.targetsMu.Lock()
			ready := monitor.targetsReady
			err := monitor.targetsPlanErr
			snapshot := cloneActiveTargetSnapshot(monitor.targetsSnapshot)
			monitor.targetsMu.Unlock()
			if !ready {
				return activeTargetSnapshot{}, nil, err
			}
			return snapshot, nil, nil
		}
		monitor.targetsPlanning = true
		monitor.targetsPlanDone = make(chan struct{})
		monitor.targetsMu.Unlock()

		planned, err := monitor.planActiveTargets(ctx, now)
		monitor.finishTargetPlanning(planned, err)
		if err != nil {
			return activeTargetSnapshot{}, nil, err
		}
		return planned, nil, nil
	}
}

// WarmTargets prepares the first target snapshot without issuing network
// probes. Controller readiness calls this gate before advertising capacity.
func (monitor *ActiveMonitor) WarmTargets(ctx context.Context, now time.Time) error {
	if monitor.Targets == nil {
		return nil
	}
	monitor.targetsMu.Lock()
	ready := monitor.targetsReady
	monitor.targetsMu.Unlock()
	if ready {
		return nil
	}
	_, waitRefresh, err := monitor.activeTargets(ctx, now)
	if err != nil {
		return err
	}
	if waitRefresh != nil {
		return waitRefresh()
	}
	return nil
}

var ErrActiveCriticalCoverageExceeded = errors.New(
	"active critical candidate coverage exceeds configured capacity",
)

type activeObservation struct {
	observation      health.Observation
	availability     *qoe.Observation
	reservation      store.ObservationReservation
	probeStartedAt   time.Time
	completedAt      time.Time
	promoteOnSuccess bool
	proofFreshAfter  time.Time
}

type activeProbeResult struct {
	candidateID      string
	observation      health.Observation
	availability     *qoe.Observation
	reservation      store.ObservationReservation
	err              error
	infrastructure   bool
	probeStartedAt   time.Time
	completedAt      time.Time
	promoteOnSuccess bool
	proofFreshAfter  time.Time
}

type activeProbeJob struct {
	candidate        store.Candidate
	payload          string
	role             ActiveTargetRole
	promoteOnSuccess bool
	proofFreshAfter  time.Time
}

func mergeActiveTargetRole(current, incoming ActiveTargetRole) ActiveTargetRole {
	if current == ActiveTargetCritical || incoming == ActiveTargetCritical {
		return ActiveTargetCritical
	}
	if incoming != "" {
		return incoming
	}
	return current
}

