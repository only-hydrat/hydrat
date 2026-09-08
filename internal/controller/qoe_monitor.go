package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

const (
	defaultQoEActiveInterval   = 15 * time.Second
	defaultQoEIdleInterval     = 5 * time.Minute
	defaultQoEDegradedInterval = time.Minute
	defaultQoERetention        = 7 * 24 * time.Hour
	defaultQoEWorkers          = 4
	defaultQoEStandby          = 3
	maxQoEWorkers              = 4
	qoeRetentionInterval       = time.Hour
	qoeRetentionBatch          = 1000
	udpFailureThreshold        = 2
	udpRecoveryThreshold       = 3
)

type QoEProbeAgent interface {
	ProbeQoE(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)
}

type QoEMonitor struct {
	Store             *store.Store
	Agent             QoEProbeAgent
	Profiles          ProfileProvider
	Policy            qoe.Policy
	ActiveInterval    time.Duration
	IdleInterval      time.Duration
	DegradedInterval  time.Duration
	Retention         time.Duration
	Workers           int
	StandbyCandidates int
	Trigger           chan<- struct{}
	Now               func() time.Time
	SyncActivity      func(context.Context, time.Time) error

	runMu sync.Mutex
	mu    sync.Mutex

	inFlight    map[string]bool
	lastAttempt map[string]time.Time
	lastPrune   time.Time
	udpSignals  map[string]udpSignalState
}

type udpSignalState struct {
	failures  int
	successes int
}

type qoeProbeJob struct {
	candidate store.Candidate
}

func (monitor *QoEMonitor) Run(ctx context.Context, now time.Time) error {
	if monitor.Store == nil {
		return errors.New("qoe monitor store is required")
	}
	if monitor.Agent == nil {
		return errors.New("qoe monitor agent is required")
	}
	if !monitor.runMu.TryLock() {
		return nil
	}
	defer monitor.runMu.Unlock()
	if monitor.SyncActivity != nil {
		if err := monitor.SyncActivity(ctx, now); err != nil {
			return fmt.Errorf("sync WireGuard activity: %w", err)
		}
	}

	healthRows, err := monitor.Store.ListCandidateHealth(ctx)
	if err != nil {
		return err
	}
	probeStates, err := monitor.Store.ListCandidateProbeStates(ctx)
	if err != nil {
		return err
	}
	assignments, err := monitor.Store.ListAssignments(ctx)
	if err != nil {
		return err
	}
	clients, err := monitor.Store.ListClients(ctx)
	if err != nil {
		return err
	}
	qoeStates, err := monitor.Store.ListCandidateQoEStates(ctx)
	if err != nil {
		return err
	}

	if err := monitor.prune(ctx, now); err != nil {
		return err
	}

	healthByID := make(map[string]store.CandidateHealth, len(healthRows))
	for _, row := range healthRows {
		healthByID[row.CandidateID] = row
	}
	probeByID := make(map[string]store.CandidateProbeState, len(probeStates))
	for _, state := range probeStates {
		probeByID[state.CandidateID] = state
	}
	qoeByID := make(map[string]qoe.State, len(qoeStates))
	for _, state := range qoeStates {
		qoeByID[state.CandidateID] = state
	}

	clientByID := make(map[string]store.ClientRecord, len(clients))
	for _, client := range clients {
		clientByID[client.ID] = client
	}
	assigned := make(map[string]bool)
	active := make(map[string]bool)
	activeCutoff := now.Add(-2 * time.Minute)
	for _, assignment := range assignments {
		client, exists := clientByID[assignment.ClientID]
		if !exists || client.Paused {
			continue
		}
		isActive := client.LastTrafficAt != nil && !time.Unix(*client.LastTrafficAt, 0).Before(activeCutoff)
		for _, candidateID := range []string{assignment.TCPOutbound, assignment.UDPOutbound} {
			if candidateID == "" {
				continue
			}
			assigned[candidateID] = true
			active[candidateID] = active[candidateID] || isActive
		}
	}
	referencedIDs := make([]string, 0, len(assigned))
	for candidateID := range assigned {
		referencedIDs = append(referencedIDs, candidateID)
	}
	candidates, err := monitor.Store.ListRoutableCandidates(ctx, referencedIDs)
	if err != nil {
		return err
	}
	candidateByID := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		candidateByID[candidate.ID] = candidate
	}

	qualified := func(candidateID string) bool {
		health, exists := healthByID[candidateID]
		if !exists || !health.Available || (!health.TCPQualified && !health.UDPQualified) {
			return false
		}
		if len(probeStates) == 0 {
			return true
		}
		state, exists := probeByID[candidateID]
		if !exists {
			return false
		}
		return state.InWorkingPool || state.Draining
	}
	liveWarm := make(map[string]bool)
	if monitor.Profiles != nil {
		for _, profile := range monitor.Profiles.Profiles() {
			if profile.Role == "warm" {
				liveWarm[profile.CandidateID] = true
			}
		}
	}

	selected := make([]store.Candidate, 0)
	seen := make(map[string]bool)
	selectCandidate := func(candidateID string, interval time.Duration) {
		if seen[candidateID] {
			return
		}
		candidate, exists := candidateByID[candidateID]
		if !exists || !monitor.reserve(candidateID, now, interval, qoeByID[candidateID].LastValidAt) {
			return
		}
		seen[candidateID] = true
		selected = append(selected, candidate)
	}

	assignedIDs := make([]string, 0, len(assigned))
	for candidateID := range assigned {
		assignedIDs = append(assignedIDs, candidateID)
	}
	sort.Strings(assignedIDs)
	for _, candidateID := range assignedIDs {
		interval := monitor.idleInterval()
		if active[candidateID] {
			interval = monitor.activeInterval()
		}
		if qoeByID[candidateID].Status == qoe.StatusDegraded {
			interval = shortestPositiveDuration(interval, monitor.degradedInterval())
		}
		selectCandidate(candidateID, interval)
	}

	degradedIDs := make([]string, 0)
	for candidateID, state := range qoeByID {
		candidate, current := candidateByID[candidateID]
		if assigned[candidateID] || !current || state.Status != qoe.StatusDegraded {
			continue
		}
		if candidate.Kind == sources.KindTorBridge && !liveWarm[candidateID] {
			continue
		}
		degradedIDs = append(degradedIDs, candidateID)
	}
	sort.Strings(degradedIDs)
	for _, candidateID := range degradedIDs {
		selectCandidate(candidateID, monitor.degradedInterval())
	}

	standby := make([]store.CandidateHealth, 0, len(healthRows))
	for _, health := range healthRows {
		candidate, exists := candidateByID[health.CandidateID]
		if !exists || candidate.Kind != sources.KindVLESS || assigned[candidate.ID] ||
			qoeByID[candidate.ID].Status == qoe.StatusDegraded || !qualified(candidate.ID) {
			continue
		}
		standby = append(standby, health)
	}
	sort.Slice(standby, func(left, right int) bool {
		if standby[left].Score == standby[right].Score {
			return standby[left].CandidateID < standby[right].CandidateID
		}
		return standby[left].Score > standby[right].Score
	})
	standbyLimit := monitor.standbyCandidates()
	tcpSelected, udpSelected := 0, 0
	for _, health := range standby {
		eligibleTCP := health.TCPQualified && tcpSelected < standbyLimit
		eligibleUDP := health.UDPQualified && udpSelected < standbyLimit
		if !eligibleTCP && !eligibleUDP {
			continue
		}
		if eligibleTCP {
			tcpSelected++
		}
		if eligibleUDP {
			udpSelected++
		}
		selectCandidate(health.CandidateID, monitor.activeInterval())
		if tcpSelected >= standbyLimit && udpSelected >= standbyLimit {
			break
		}
	}

	warmIDs := make([]string, 0, len(liveWarm))
	for candidateID := range liveWarm {
		if !assigned[candidateID] {
			warmIDs = append(warmIDs, candidateID)
		}
	}
	sort.Strings(warmIDs)
	for _, candidateID := range warmIDs {
		candidate, exists := candidateByID[candidateID]
		if exists && candidate.Kind == sources.KindTorBridge {
			selectCandidate(candidateID, monitor.activeInterval())
		}
	}

	return monitor.runSelected(ctx, now, selected)
}

func (monitor *QoEMonitor) reserve(candidateID string, now time.Time, interval time.Duration, lastValid time.Time) bool {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.inFlight == nil {
		monitor.inFlight = make(map[string]bool)
	}
	if monitor.inFlight[candidateID] {
		return false
	}
	last := lastValid
	if attempt := monitor.lastAttempt[candidateID]; attempt.After(last) {
		last = attempt
	}
	if !last.IsZero() && now.Before(last.Add(interval)) {
		return false
	}
	monitor.inFlight[candidateID] = true
	return true
}

func (monitor *QoEMonitor) markAttempt(candidateID string, now time.Time) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.lastAttempt == nil {
		monitor.lastAttempt = make(map[string]time.Time)
	}
	monitor.lastAttempt[candidateID] = now
}

func (monitor *QoEMonitor) release(candidateID string) {
	monitor.mu.Lock()
	delete(monitor.inFlight, candidateID)
	monitor.mu.Unlock()
}

func (monitor *QoEMonitor) runSelected(ctx context.Context, now time.Time, selected []store.Candidate) error {
	if len(selected) == 0 {
		return ctx.Err()
	}
	workers := monitor.workerCount()
	clockStartedAt := monitor.clockNow()
	jobs := make(chan qoeProbeJob, workers)
	errorsFound := make(chan error, len(selected))
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for job := range jobs {
				if err := monitor.probe(ctx, now, clockStartedAt, job.candidate); err != nil {
					errorsFound <- err
				}
				monitor.release(job.candidate.ID)
			}
		}()
	}

	for index, candidate := range selected {
		select {
		case jobs <- qoeProbeJob{candidate: candidate}:
		case <-ctx.Done():
			for _, skipped := range selected[index:] {
				monitor.release(skipped.ID)
			}
			close(jobs)
			group.Wait()
			close(errorsFound)
			return ctx.Err()
		}
	}
	close(jobs)
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		return err
	}
	return ctx.Err()
}

func (monitor *QoEMonitor) probe(
	ctx context.Context,
	sweepAt, clockStartedAt time.Time,
	candidate store.Candidate,
) error {
	payload, err := monitor.Store.CandidatePayload(ctx, candidate.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	monitor.markAttempt(candidate.ID, monitor.probeTime(sweepAt, clockStartedAt))
	response, err := monitor.Agent.ProbeQoE(ctx, agentapi.ProbeRequest{
		CandidateID: candidate.ID, Kind: candidate.Kind, Payload: payload,
	})
	// Persist the completed measurement time and start the next cadence from
	// completion, so a slow probe is fresh without being immediately retried.
	completedAt := monitor.probeTime(sweepAt, clockStartedAt)
	monitor.markAttempt(candidate.ID, completedAt)
	if err != nil || response.FailureClass == agentapi.FailureInfrastructure {
		return nil
	}
	if response.CandidateID != "" && response.CandidateID != candidate.ID {
		return nil
	}
	var observation qoe.Observation
	switch {
	case response.QoE != nil:
		observation = *response.QoE
	case response.FailureClass == agentapi.FailureCandidate:
		observation.ErrorCode = response.ErrorCode
	default:
		return nil
	}
	if observation.Infrastructure {
		return nil
	}
	if observation.UDPReachable != nil {
		if _, err := monitor.applyUDPObservation(
			ctx, candidate.ID, *observation.UDPReachable,
		); err != nil {
			return err
		}
	}
	observation.At = completedAt
	_, transition, err := monitor.Store.RecordCandidateQoE(ctx, candidate, observation, monitor.policy())
	if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
		return nil
	}
	if err != nil {
		return err
	}
	if transition.Changed() && transition.To == qoe.StatusDegraded {
		monitor.signalPlanning()
	}
	return nil
}

func (monitor *QoEMonitor) applyUDPObservation(
	ctx context.Context,
	candidateID string,
	reachable bool,
) (bool, error) {
	monitor.mu.Lock()
	if monitor.udpSignals == nil {
		monitor.udpSignals = make(map[string]udpSignalState)
	}
	state := monitor.udpSignals[candidateID]
	qualified := false
	ready := false
	if reachable {
		state.failures = 0
		if state.successes < udpRecoveryThreshold {
			state.successes++
		}
		qualified = true
		ready = state.successes >= udpRecoveryThreshold
	} else {
		state.successes = 0
		if state.failures < udpFailureThreshold {
			state.failures++
		}
		ready = state.failures >= udpFailureThreshold
	}
	monitor.udpSignals[candidateID] = state
	monitor.mu.Unlock()
	if !ready {
		return false, nil
	}
	changed, err := monitor.Store.UpdateCandidateUDPQualified(ctx, candidateID, qualified)
	if err == nil && changed {
		monitor.signalPlanning()
	}
	return changed, err
}

func (monitor *QoEMonitor) signalPlanning() {
	if monitor.Trigger == nil {
		return
	}
	select {
	case monitor.Trigger <- struct{}{}:
	default:
	}
}

func (monitor *QoEMonitor) clockNow() time.Time {
	if monitor.Now != nil {
		return monitor.Now()
	}
	return time.Now()
}

func (monitor *QoEMonitor) probeTime(sweepAt, clockStartedAt time.Time) time.Time {
	elapsed := monitor.clockNow().Sub(clockStartedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	return sweepAt.Add(elapsed).Truncate(time.Second)
}

func (monitor *QoEMonitor) prune(ctx context.Context, now time.Time) error {
	monitor.mu.Lock()
	due := monitor.lastPrune.IsZero() || !now.Before(monitor.lastPrune.Add(qoeRetentionInterval))
	monitor.mu.Unlock()
	if !due {
		return nil
	}
	if _, err := monitor.Store.PruneCandidateQoESamples(ctx, now.Add(-monitor.retention()), qoeRetentionBatch); err != nil {
		return err
	}
	monitor.mu.Lock()
	monitor.lastPrune = now
	monitor.mu.Unlock()
	return nil
}

func (monitor *QoEMonitor) policy() qoe.Policy {
	if monitor.Policy.WindowSize <= 0 {
		return qoe.DefaultPolicy()
	}
	return monitor.Policy
}

func (monitor *QoEMonitor) activeInterval() time.Duration {
	if monitor.ActiveInterval > 0 {
		return monitor.ActiveInterval
	}
	return defaultQoEActiveInterval
}

func (monitor *QoEMonitor) idleInterval() time.Duration {
	if monitor.IdleInterval > 0 {
		return monitor.IdleInterval
	}
	return defaultQoEIdleInterval
}

func (monitor *QoEMonitor) degradedInterval() time.Duration {
	if monitor.DegradedInterval > 0 {
		return monitor.DegradedInterval
	}
	return defaultQoEDegradedInterval
}

// QoEWakeInterval returns the shortest positive configured monitor cadence.
func QoEWakeInterval(active, idle, degraded time.Duration) time.Duration {
	interval := shortestPositiveDuration(active, idle, degraded)
	if interval <= 0 {
		return defaultQoEActiveInterval
	}
	return interval
}

func shortestPositiveDuration(values ...time.Duration) time.Duration {
	var shortest time.Duration
	for _, value := range values {
		if value > 0 && (shortest == 0 || value < shortest) {
			shortest = value
		}
	}
	return shortest
}

func (monitor *QoEMonitor) retention() time.Duration {
	if monitor.Retention > 0 {
		return monitor.Retention
	}
	return defaultQoERetention
}

func (monitor *QoEMonitor) workerCount() int {
	workers := monitor.Workers
	if workers <= 0 {
		workers = defaultQoEWorkers
	}
	if workers > maxQoEWorkers {
		workers = maxQoEWorkers
	}
	return workers
}

func (monitor *QoEMonitor) standbyCandidates() int {
	if monitor.StandbyCandidates > 0 {
		return monitor.StandbyCandidates
	}
	return defaultQoEStandby
}
