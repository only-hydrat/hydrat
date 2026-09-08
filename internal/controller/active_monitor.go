package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qualifier"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

type ActiveVLESSProbe interface {
	Observe(context.Context, []qualifier.Input) []qualifier.ActiveResult
}

type TorLivenessProbe interface {
	Observe(context.Context, string) health.Observation
}

type ActiveProbeAgent interface {
	ProbeActive(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)
}

type CriticalActiveProbeAgent interface {
	ProbeActiveCritical(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)
}

type ActiveMonitorClock interface {
	Now() time.Time
}

type ActiveTargetRole string

const (
	ActiveTargetCritical    ActiveTargetRole = "critical"
	ActiveTargetProspective ActiveTargetRole = "prospective"
)

type ActiveTarget struct {
	Candidate                 store.Candidate
	Role                      ActiveTargetRole
	TriggerPlacementOnSuccess bool
	ProofFreshAfter           time.Time
}

type ActiveTargetProvider interface {
	ActiveTargets(context.Context, time.Time) ([]ActiveTarget, error)
}

type realActiveMonitorClock struct{}

func (realActiveMonitorClock) Now() time.Time { return time.Now() }

type ActiveMonitor struct {
	Store               *store.Store
	Agent               ActiveProbeAgent
	VLESS               ActiveVLESSProbe
	Tor                 TorLivenessProbe
	Profiles            ProfileProvider
	Slots               int
	CriticalLimit       int
	PlanningDeadline    time.Duration
	ProbeDeadline       time.Duration
	ProofFreshness      time.Duration
	Trigger             chan<- struct{}
	HardFailures        *HardFailureMailbox
	HardFailureDeadline time.Duration
	// ConfirmCompleteFailureInCycle is enabled in production because each
	// liveness observation already contains two independent HTTP checks.
	ConfirmCompleteFailureInCycle bool
	// AvailabilityFailureThreshold and AvailabilityFailureFreshness require
	// routed-DNS failures to be adjacent, current active observations. Missing,
	// infrastructure, stale and out-of-order observations break the sequence.
	AvailabilityFailureThreshold int
	AvailabilityFailureFreshness time.Duration
	Promotions                   chan<- struct{}
	CapacityChanges              chan<- struct{}
	Targets                      ActiveTargetProvider
	Clock                        ActiveMonitorClock
	stateOnce                    sync.Once
	criticalSlots                chan struct{}
	targetsMu                    sync.Mutex
	targetsReady                 bool
	targetsSnapshot              activeTargetSnapshot
	targetsPlanning              bool
	targetsPlanDone              chan struct{}
	targetsPlanErr               error
	prospectiveMu                sync.Mutex
	cursorMu                     sync.Mutex
	trackerMu                    sync.Mutex
	trackers                     map[string]*health.Tracker
	hardFailureSuspects          map[string]time.Time
	availabilityFailures         map[string]availabilityFailureState
	vlessNext                    int
	singleNext                   ActiveTargetRole
	criticalNext                 int
	prospectiveNext              int
}

type availabilityFailureState struct {
	count           int
	lastSequence    int64
	lastCompletedAt time.Time
}


func (monitor *ActiveMonitor) completionTime() time.Time {
	if monitor.Clock != nil {
		return monitor.Clock.Now()
	}
	return (realActiveMonitorClock{}).Now()
}

func (monitor *ActiveMonitor) initializeConcurrentState() {
	monitor.stateOnce.Do(func() {
		slots := monitor.Slots
		if slots <= 0 {
			slots = 4
		}
		monitor.criticalSlots = make(chan struct{}, slots)
	})
}

func (monitor *ActiveMonitor) Run(ctx context.Context, now time.Time) (runErr error) {
	if monitor.Store == nil {
		return fmt.Errorf("active monitor store is required")
	}
	monitor.initializeConcurrentState()
	assigned := make(map[string]bool)
	promoteOnSuccess := make(map[string]bool)
	proofFreshAfter := make(map[string]time.Time)
	roleByID := make(map[string]ActiveTargetRole)
	var candidates []store.Candidate
	if monitor.Targets != nil {
		snapshot, waitRefresh, err := monitor.activeTargets(ctx, now)
		if err != nil {
			return err
		}
		if waitRefresh != nil {
			defer func() {
				if err := waitRefresh(); runErr == nil && err != nil {
					runErr = err
				}
			}()
		}
		snapshot, err = monitor.reconcileAppliedTargetGeneration(ctx, snapshot)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(snapshot.targets))
		for _, target := range snapshot.targets {
			candidateID := target.Candidate.ID
			if candidateID == "" {
				continue
			}
			assigned[candidateID] = true
			role := target.Role
			if role == "" {
				if target.TriggerPlacementOnSuccess {
					role = ActiveTargetProspective
				} else {
					role = ActiveTargetCritical
				}
			}
			roleByID[candidateID] = mergeActiveTargetRole(roleByID[candidateID], role)
			promoteOnSuccess[candidateID] = promoteOnSuccess[candidateID] ||
				target.TriggerPlacementOnSuccess
			if target.ProofFreshAfter.After(proofFreshAfter[candidateID]) {
				proofFreshAfter[candidateID] = target.ProofFreshAfter
			}
			if !seen[candidateID] {
				seen[candidateID] = true
				candidates = append(candidates, target.Candidate)
			}
		}
	} else {
		assignments, err := monitor.Store.ListAssignments(ctx)
		if err != nil {
			return err
		}
		for _, assignment := range assignments {
			if assignment.TCPOutbound != "" {
				assigned[assignment.TCPOutbound] = true
			}
			if assignment.UDPOutbound != "" {
				assigned[assignment.UDPOutbound] = true
			}
		}
		for candidateID := range assigned {
			roleByID[candidateID] = ActiveTargetCritical
		}
	}
	if len(assigned) == 0 {
		return nil
	}
	if monitor.CriticalLimit > 0 {
		critical := 0
		for _, role := range roleByID {
			if role == ActiveTargetCritical {
				critical++
			}
		}
		if critical > monitor.CriticalLimit {
			return fmt.Errorf("%w: critical=%d limit=%d",
				ErrActiveCriticalCoverageExceeded, critical, monitor.CriticalLimit)
		}
	}
	if monitor.Targets == nil {
		referencedIDs := make([]string, 0, len(assigned))
		for candidateID := range assigned {
			referencedIDs = append(referencedIDs, candidateID)
		}
		var err error
		candidates, err = monitor.Store.ListRoutableCandidates(ctx, referencedIDs)
		if err != nil {
			return err
		}
	}
	candidateByID := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		candidateByID[candidate.ID] = candidate
	}
	healthRows, err := monitor.Store.ListCandidateHealth(ctx)
	if err != nil {
		return err
	}
	healthByID := make(map[string]store.CandidateHealth, len(healthRows))
	for _, row := range healthRows {
		healthByID[row.CandidateID] = row
	}
	// Target planning, applied-generation reconciliation, and local health
	// reads are bounded by the caller's active-run context. Start the network
	// probe budget only after that preparation so local contention cannot
	// silently consume the failover observation window.
	if monitor.ProbeDeadline > 0 {
		probeCtx, cancelProbes := context.WithTimeout(ctx, monitor.ProbeDeadline)
		defer cancelProbes()
		ctx = probeCtx
	}
	if monitor.Agent != nil {
		results, err := monitor.observeWithAgent(
			ctx, candidates, assigned, healthByID, promoteOnSuccess,
			proofFreshAfter, roleByID,
		)
		if err != nil {
			return err
		}
		var firstErr error
		for item := range results {
			if errors.Is(item.err, store.ErrCandidateNoLongerCurrent) {
				monitor.trackerMu.Lock()
				monitor.clearCandidateActiveStateLocked(item.candidateID)
				monitor.trackerMu.Unlock()
				continue
			}
			if item.err != nil && item.reservation.Sequence == 0 {
				if firstErr == nil {
					firstErr = item.err
				}
				continue
			}
			if item.err != nil || item.infrastructure {
				if item.reservation.Sequence > 0 {
					monitor.trackerMu.Lock()
					if monitor.availabilityFailures == nil {
						monitor.availabilityFailures = make(
							map[string]availabilityFailureState,
						)
					}
					monitor.observeAvailabilityLocked(
						item.candidateID,
						activeObservation{
							reservation: item.reservation,
							completedAt: item.completedAt,
						},
					)
					monitor.trackerMu.Unlock()
				}
				continue
			}
			if err := monitor.applyReservedObservations(
				ctx, now,
				map[string]activeObservation{item.candidateID: {
					observation: item.observation, availability: item.availability,
					reservation:      item.reservation,
					probeStartedAt:   item.probeStartedAt,
					completedAt:      item.completedAt,
					promoteOnSuccess: item.promoteOnSuccess,
					proofFreshAfter:  item.proofFreshAfter,
				}},
				healthByID, candidateByID,
			); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	vlessInputs := make([]qualifier.Input, 0)
	torCandidates := make([]string, 0)
	for _, candidate := range candidates {
		if !assigned[candidate.ID] {
			continue
		}
		if _, exists := healthByID[candidate.ID]; !exists {
			continue
		}
		switch candidate.Kind {
		case sources.KindVLESS:
			payload, err := monitor.Store.CandidatePayload(ctx, candidate.ID)
			if err != nil {
				return err
			}
			vlessInputs = append(vlessInputs, qualifier.Input{ID: candidate.ID, Payload: payload})
		case sources.KindTorBridge:
			torCandidates = append(torCandidates, candidate.ID)
		}
	}

	type observedCandidate struct {
		candidateID      string
		observation      health.Observation
		reservation      store.ObservationReservation
		completedAt      time.Time
		promoteOnSuccess bool
		proofFreshAfter  time.Time
	}
	selectedVLESS := []qualifier.Input(nil)
	if monitor.VLESS != nil && len(vlessInputs) > 0 {
		selectedVLESS = monitor.rotateVLESS(vlessInputs)
	}
	addresses := make(map[string]string)
	if monitor.Tor != nil && monitor.Profiles != nil && len(torCandidates) > 0 {
		for _, profile := range monitor.Profiles.Profiles() {
			if profile.Role == "warm" {
				addresses[profile.CandidateID] = profile.SocksAddr
			}
		}
	}
	requests := make([]store.ObservationRequest, 0, len(selectedVLESS)+len(addresses))
	for _, input := range selectedVLESS {
		if candidate, exists := candidateByID[input.ID]; exists {
			requests = append(requests, store.ObservationRequest{
				Candidate: candidate, Stage: store.ObservationActive,
			})
		}
	}
	if monitor.Tor != nil && monitor.Profiles != nil {
		for _, candidateID := range torCandidates {
			if candidate, exists := candidateByID[candidateID]; exists {
				requests = append(requests, store.ObservationRequest{
					Candidate: candidate, Stage: store.ObservationActive,
				})
			}
		}
	}
	reservations, err := monitor.Store.ReserveCandidateObservations(ctx, requests)
	if err != nil {
		return err
	}
	reservationByID := make(map[string]store.ObservationReservation, len(reservations))
	for _, reservation := range reservations {
		reservationByID[reservation.CandidateID] = reservation
	}
	observed := make(chan observedCandidate, len(vlessInputs)+len(torCandidates))
	var probes sync.WaitGroup
	if len(selectedVLESS) > 0 {
		probes.Add(1)
		go func() {
			defer probes.Done()
			for _, result := range monitor.VLESS.Observe(ctx, selectedVLESS) {
				completedAt := monitor.completionTime()
				if result.Err != nil {
					// A shared probe-Xray/API failure says nothing about the live
					// production outbound. Preserve health and retry next tick.
					continue
				}
				observed <- observedCandidate{
					candidateID:      result.CandidateID,
					observation:      result.Observation,
					reservation:      reservationByID[result.CandidateID],
					completedAt:      completedAt,
					promoteOnSuccess: promoteOnSuccess[result.CandidateID],
					proofFreshAfter:  proofFreshAfter[result.CandidateID],
				}
			}
		}()
	}
	if monitor.Tor != nil && monitor.Profiles != nil && len(torCandidates) > 0 {
		for _, candidateID := range torCandidates {
			address, exists := addresses[candidateID]
			if !exists {
				observed <- observedCandidate{
					candidateID:      candidateID,
					reservation:      reservationByID[candidateID],
					promoteOnSuccess: promoteOnSuccess[candidateID],
					proofFreshAfter:  proofFreshAfter[candidateID],
				}
				continue
			}
			probes.Add(1)
			go func(candidateID, address string) {
				defer probes.Done()
				observed <- observedCandidate{
					candidateID:      candidateID,
					observation:      monitor.Tor.Observe(ctx, address),
					reservation:      reservationByID[candidateID],
					completedAt:      monitor.completionTime(),
					promoteOnSuccess: promoteOnSuccess[candidateID],
					proofFreshAfter:  proofFreshAfter[candidateID],
				}
			}(candidateID, address)
		}
	}
	go func() {
		probes.Wait()
		close(observed)
	}()
	observations := make(map[string]activeObservation)
	for result := range observed {
		observations[result.candidateID] = activeObservation{
			observation:      result.observation,
			reservation:      result.reservation,
			completedAt:      result.completedAt,
			promoteOnSuccess: result.promoteOnSuccess,
			proofFreshAfter:  result.proofFreshAfter,
		}
	}

	return monitor.applyReservedObservations(
		ctx, now, observations, healthByID, candidateByID,
	)
}

func (monitor *ActiveMonitor) observeWithAgent(
	ctx context.Context,
	candidates []store.Candidate,
	assigned map[string]bool,
	healthByID map[string]store.CandidateHealth,
	promoteOnSuccess map[string]bool,
	proofFreshAfter map[string]time.Time,
	roleByID map[string]ActiveTargetRole,
) (<-chan activeProbeResult, error) {
	critical := make([]activeProbeJob, 0, len(assigned))
	prospective := make([]activeProbeJob, 0, len(assigned))
	for _, candidate := range candidates {
		if !assigned[candidate.ID] {
			continue
		}
		if _, exists := healthByID[candidate.ID]; !exists {
			continue
		}
		payload, err := monitor.Store.CandidatePayload(ctx, candidate.ID)
		if err != nil {
			return nil, err
		}
		job := activeProbeJob{
			candidate: candidate, payload: payload, role: roleByID[candidate.ID],
			promoteOnSuccess: promoteOnSuccess[candidate.ID],
			proofFreshAfter:  proofFreshAfter[candidate.ID],
		}
		if job.role == ActiveTargetProspective {
			prospective = append(prospective, job)
		} else {
			critical = append(critical, job)
		}
	}
	monitor.cursorMu.Lock()
	criticalNext := monitor.criticalNext
	prospectiveNext := monitor.prospectiveNext
	monitor.cursorMu.Unlock()
	critical = rotateActiveProbeJobs(critical, criticalNext)
	prospective = rotateActiveProbeJobs(prospective, prospectiveNext)
	ownsProspective := false
	if len(prospective) > 0 {
		if monitor.prospectiveMu.TryLock() {
			ownsProspective = true
		} else {
			prospective = nil
		}
	}
	total := len(critical) + len(prospective)
	results := make(chan activeProbeResult, total)
	if total == 0 {
		if ownsProspective {
			monitor.prospectiveMu.Unlock()
		}
		close(results)
		return results, nil
	}
	type queues struct {
		sync.Mutex
		critical    []activeProbeJob
		prospective []activeProbeJob
	}
	pending := &queues{critical: critical, prospective: prospective}
	pop := func(preferred ActiveTargetRole) (activeProbeJob, bool) {
		pending.Lock()
		defer pending.Unlock()
		first, second := &pending.critical, &pending.prospective
		if preferred == ActiveTargetProspective {
			first, second = second, first
		}
		if len(*first) > 0 {
			job := (*first)[0]
			*first = (*first)[1:]
			monitor.advanceRoleCursor(job.role)
			return job, true
		}
		if len(*second) > 0 {
			job := (*second)[0]
			*second = (*second)[1:]
			monitor.advanceRoleCursor(job.role)
			return job, true
		}
		return activeProbeJob{}, false
	}
	run := func(job activeProbeJob) {
		if job.role == ActiveTargetCritical {
			select {
			case monitor.criticalSlots <- struct{}{}:
				defer func() { <-monitor.criticalSlots }()
			case <-ctx.Done():
				return
			}
		}
		candidate := job.candidate
		probeStartedAt := monitor.completionTime()
		reservation, err := monitor.Store.ReserveCandidateObservation(
			ctx, candidate, store.ObservationActive,
		)
		if err != nil {
			results <- activeProbeResult{
				candidateID: candidate.ID, probeStartedAt: probeStartedAt, err: err,
			}
			return
		}
		request := agentapi.ProbeRequest{
			CandidateID: candidate.ID, Kind: candidate.Kind, Payload: job.payload,
		}
		var response agentapi.ProbeResponse
		var probeErr error
		if job.role == ActiveTargetCritical {
			critical, ok := monitor.Agent.(CriticalActiveProbeAgent)
			if !ok {
				results <- activeProbeResult{
					candidateID: candidate.ID, reservation: reservation,
					probeStartedAt: probeStartedAt,
					err:            errors.New("critical active probe lane is unavailable"),
				}
				return
			}
			response, probeErr = critical.ProbeActiveCritical(ctx, request)
		} else {
			response, probeErr = monitor.Agent.ProbeActive(ctx, request)
		}
		completedAt := monitor.completionTime()
		results <- activeProbeResult{
			candidateID: candidate.ID, observation: response.Observation,
			availability: response.QoE,
			reservation:  reservation, err: probeErr,
			infrastructure:   response.FailureClass == agentapi.FailureInfrastructure,
			probeStartedAt:   probeStartedAt,
			completedAt:      completedAt,
			promoteOnSuccess: job.promoteOnSuccess,
			proofFreshAfter:  job.proofFreshAfter,
		}
	}
	slots := monitor.Slots
	if slots <= 0 {
		slots = 4
	}
	if slots > total {
		slots = total
	}
	var probes sync.WaitGroup
	if slots == 1 {
		monitor.cursorMu.Lock()
		next := monitor.singleNext
		monitor.cursorMu.Unlock()
		if next != ActiveTargetProspective {
			next = ActiveTargetCritical
		}
		probes.Add(1)
		go func() {
			defer probes.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				job, ok := pop(next)
				if !ok {
					return
				}
				run(job)
				if job.role == ActiveTargetProspective {
					next = ActiveTargetCritical
				} else {
					next = ActiveTargetProspective
				}
				monitor.cursorMu.Lock()
				monitor.singleNext = next
				monitor.cursorMu.Unlock()
			}
		}()
	} else {
		for lane := 0; lane < slots; lane++ {
			preferred := ActiveTargetCritical
			if lane == slots-1 {
				preferred = ActiveTargetProspective
			}
			probes.Add(1)
			go func() {
				defer probes.Done()
				for {
					if ctx.Err() != nil {
						return
					}
					job, ok := pop(preferred)
					if !ok {
						return
					}
					run(job)
				}
			}()
		}
	}
	go func() {
		probes.Wait()
		close(results)
		if ownsProspective {
			monitor.prospectiveMu.Unlock()
		}
	}()
	return results, nil
}

func rotateActiveProbeJobs(jobs []activeProbeJob, cursor int) []activeProbeJob {
	if len(jobs) == 0 {
		return jobs
	}
	start := cursor % len(jobs)
	if start == 0 {
		return jobs
	}
	rotated := make([]activeProbeJob, 0, len(jobs))
	rotated = append(rotated, jobs[start:]...)
	rotated = append(rotated, jobs[:start]...)
	return rotated
}

func (monitor *ActiveMonitor) advanceRoleCursor(role ActiveTargetRole) {
	monitor.cursorMu.Lock()
	defer monitor.cursorMu.Unlock()
	if role == ActiveTargetProspective {
		monitor.prospectiveNext++
		return
	}
	monitor.criticalNext++
}

