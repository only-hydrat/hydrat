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
	defaultQoEActiveInterval   = 30 * time.Second
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

	inFlight          map[string]bool
	lastAttempt       map[string]time.Time
	lastPrune         time.Time
	udpSignals        map[string]udpSignalState
	standbyRotation   int
	standbySamples    map[string]int
	standbyExploring  string
	dispatchCursor    int
	backgroundCursor  int
	infraLast         map[string]qoeDiagnosticWindow
	comparisons       map[string]qoeComparison
	controlRequests   map[string]time.Time
	comparisonVersion uint64
}

type qoeDiagnosticWindow struct {
	last       time.Time
	suppressed uint64
}

type udpSignalState struct {
	failures   int
	successes  int
	generation int64
}

type qoeProbeJob struct {
	candidate store.Candidate
	control   bool
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
	_, reserves, err := monitor.Store.ListAppliedReserveMappings(ctx)
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
	for _, reserve := range reserves {
		client, exists := clientByID[reserve.ClientID]
		if !exists || client.Paused {
			continue
		}
		for _, id := range []string{reserve.TCPReserveCandidateID, reserve.UDPReserveCandidateID} {
			if id != "" {
				assigned[id], active[id] = true, true
			}
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
	intervalByID := make(map[string]time.Duration)
	selectCandidate := func(candidateID string, interval time.Duration) {
		if seen[candidateID] {
			return
		}
		candidate, exists := candidateByID[candidateID]
		if !exists || !monitor.due(candidateID, now, interval, qoeByID[candidateID].LastValidAt) {
			return
		}
		seen[candidateID] = true
		intervalByID[candidateID] = interval
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
	tcpTotal, udpTotal := 0, 0
	for _, health := range standby {
		if health.TCPQualified {
			tcpTotal++
		}
		if health.UDPQualified {
			udpTotal++
		}
	}
	rotation := monitor.standbyRotation
	tcpRank, udpRank := 0, 0
	tcpSelected, udpSelected := 0, 0
	explorationKey := ""
	exploringIDs := make([]string, 0, 2)
	for _, health := range standby {
		eligibleTCP := health.TCPQualified && tcpSelected < standbyLimit &&
			(tcpRank < standbyLimit-1 ||
				tcpRank == standbyLimit-1+rotation%max(1, tcpTotal-standbyLimit+1))
		eligibleUDP := health.UDPQualified && udpSelected < standbyLimit &&
			(udpRank < standbyLimit-1 ||
				udpRank == standbyLimit-1+rotation%max(1, udpTotal-standbyLimit+1))
		if health.TCPQualified {
			tcpRank++
		}
		if health.UDPQualified {
			udpRank++
		}
		if !eligibleTCP && !eligibleUDP {
			continue
		}
		if eligibleTCP {
			tcpSelected++
		}
		if eligibleUDP {
			udpSelected++
		}
		exploring := (eligibleTCP && tcpRank >= standbyLimit) ||
			(eligibleUDP && udpRank >= standbyLimit)
		selectCandidate(health.CandidateID, monitor.activeInterval())
		if exploring {
			explorationKey += health.CandidateID + "\x00"
			exploringIDs = append(exploringIDs, health.CandidateID)
		}
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

	// Bound each sweep so a large recovery pool cannot monopolize the loop.
	controls := monitor.requestedQoEControls(now, candidateByID, func(id string) bool {
		candidate, health, state := candidateByID[id], healthByID[id], probeByID[id]
		return qualified(id) && health.TCPQualified && !health.ActiveHardFailure && candidate.Lifecycle == store.CandidateLifecycleActive && state.Status == store.CandidateQualified && !state.Stale && !state.Draining && qoeByID[id].Status != qoe.StatusDegraded
	})
	for id := range controls {
		if seen[id] {
			intervalByID[id] = min(intervalByID[id], 10*time.Second)
		} else {
			selectCandidate(id, 10*time.Second)
		}
	}
	// Critical routes get three launches for each background launch; background
	// classes rotate so degraded routes cannot starve standby discovery or Tor.
	var groups [4][]store.Candidate
	for _, candidate := range selected {
		group := 1 // qualified standby
		switch {
		case assigned[candidate.ID]:
			group = 0
		case candidate.Kind == sources.KindTorBridge:
			group = 3
		case qoeByID[candidate.ID].Status == qoe.StatusDegraded:
			group = 2
		}
		groups[group] = append(groups[group], candidate)
	}
	for i := range groups {
		sort.SliceStable(groups[i], func(a, b int) bool {
			left, right := groups[i][a].ID, groups[i][b].ID
			l := monitor.lastAttemptAt(left, qoeByID[left].LastValidAt, now)
			r := monitor.lastAttemptAt(right, qoeByID[right].LastValidAt, now)
			if l.Equal(r) {
				return left < right
			}
			return l.Before(r)
		})
	}
	popBackground := func() (store.Candidate, bool) {
		for i := 0; i < 3; i++ {
			group := 1 + monitor.backgroundCursor%3
			monitor.backgroundCursor = (monitor.backgroundCursor + 1) % 3
			if len(groups[group]) > 0 {
				candidate := groups[group][0]
				groups[group] = groups[group][1:]
				return candidate, true
			}
		}
		return store.Candidate{}, false
	}
	selected = nil
	clear(seen)
	for len(selected) < monitor.workerCount() {
		var candidate store.Candidate
		var ok bool
		if monitor.dispatchCursor%4 == 3 || len(groups[0]) == 0 {
			candidate, ok = popBackground()
		}
		if !ok && len(groups[0]) > 0 {
			candidate, ok = groups[0][0], true
			groups[0] = groups[0][1:]
		}
		if !ok {
			candidate, ok = popBackground()
		}
		if !ok {
			break
		}
		monitor.dispatchCursor = (monitor.dispatchCursor + 1) % 4
		if monitor.reserve(candidate.ID, now, intervalByID[candidate.ID], qoeByID[candidate.ID].LastValidAt) {
			selected = append(selected, candidate)
			seen[candidate.ID] = true
		}
	}
	if explorationKey != monitor.standbyExploring {
		monitor.standbyExploring, monitor.standbySamples = explorationKey, make(map[string]int)
	}
	complete := len(exploringIDs) > 0
	for _, id := range exploringIDs {
		if seen[id] {
			monitor.standbySamples[id]++
		}
		complete = complete && monitor.standbySamples[id] >= monitor.policy().WindowSize
	}
	if complete {
		monitor.standbyRotation++
		monitor.standbySamples = nil
		monitor.standbyExploring = ""
	}
	return monitor.runSelected(ctx, now, selected, controls)
}

func latestQoEAttempt(lastValid, attempt, now time.Time) time.Time {
	if lastValid.After(now) {
		lastValid = time.Time{}
	}
	if !attempt.After(now) && attempt.After(lastValid) {
		return attempt
	}
	return lastValid
}

func (monitor *QoEMonitor) lastAttemptAt(candidateID string, lastValid, now time.Time) time.Time {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return latestQoEAttempt(lastValid, monitor.lastAttempt[candidateID], now)
}

func (monitor *QoEMonitor) due(candidateID string, now time.Time, interval time.Duration, lastValid time.Time) bool {
	last := monitor.lastAttemptAt(candidateID, lastValid, now)
	return last.IsZero() || !now.Before(last.Add(interval))
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
	last := latestQoEAttempt(lastValid, monitor.lastAttempt[candidateID], now)
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

func (monitor *QoEMonitor) runSelected(ctx context.Context, now time.Time, selected []store.Candidate, controls map[string]bool) error {
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
				if err := monitor.probe(ctx, now, clockStartedAt, job.candidate, job.control); err != nil {
					errorsFound <- err
				}
				monitor.release(job.candidate.ID)
			}
		}()
	}

	for index, candidate := range selected {
		select {
		case jobs <- qoeProbeJob{candidate: candidate, control: controls[candidate.ID]}:
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
	controlJob ...bool,
) error {
	payload, err := monitor.Store.CandidatePayload(ctx, candidate.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	generation, err := monitor.Store.CandidateQoEGeneration(ctx, candidate.ID)
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
	unconfirmed := response.QoE != nil && response.QoE.UnconfirmedHTTP && !response.QoE.Success && response.QoE.ComparisonPolicy != ""
	if err != nil || response.FailureClass == agentapi.FailureInfrastructure && !unconfirmed {
		monitor.forgetComparison(candidate.ID)
		if ctx.Err() != nil {
			return nil
		}
		return monitor.recordInfrastructure(ctx, candidate.ID, response, err, completedAt)
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
	if observation.UnconfirmedHTTP {
		confirmed, controlChecks, compareErr := monitor.compareHTTPFailure(ctx, candidate, observation, completedAt)
		if compareErr != nil {
			return compareErr
		}
		if confirmed {
			observation.Infrastructure = false
			monitor.mu.Lock()
			delete(monitor.controlRequests, candidate.ID)
			monitor.mu.Unlock()
		} else {
			observation.Infrastructure = true
			if len(controlJob) == 0 || !controlJob[0] {
				monitor.requestQoEControl(candidate, completedAt)
			}
		}
		observation.ApplicationChecks = append(observation.ApplicationChecks, controlChecks...)
	}
	if observation.Infrastructure && !observation.UnconfirmedHTTP {
		monitor.forgetComparison(candidate.ID)
		response.ErrorCode = observation.ErrorCode
		return monitor.recordInfrastructure(ctx, candidate.ID, response, nil, completedAt)
	}
	observation.At = completedAt
	_, transition, err := monitor.Store.RecordCandidateQoEObserved(ctx, candidate, observation, monitor.policy(), generation)
	if errors.Is(err, store.ErrCandidateNoLongerCurrent) || errors.Is(err, store.ErrQoEObservationSuperseded) {
		return nil
	}
	if err != nil {
		return err
	}
	monitor.rememberComparison(candidate, generation, observation, completedAt)
	if observation.Infrastructure {
		response.ErrorCode = "qoe_comparison_unknown"
		return monitor.recordDiagnostic(ctx, candidate.ID, "qoe_comparison_unknown", response.ErrorCode, qoe.HTTPFailureSummary(observation.ApplicationChecks), observation.ApplicationChecks, completedAt)
	}
	if observation.UDPReachable != nil {
		if _, err := monitor.applyUDPObservation(ctx, candidate.ID, *observation.UDPReachable, generation); err != nil {
			return err
		}
	}
	if transition.Changed() && transition.To == qoe.StatusDegraded {
		monitor.signalPlanning()
	}
	if observation.UnconfirmedHTTP {
		_ = monitor.recordDiagnostic(ctx, candidate.ID, "qoe_comparison_confirmed", observation.ErrorCode, qoe.HTTPFailureSummary(observation.ApplicationChecks), observation.ApplicationChecks, completedAt)
	} else if observation.ErrorCode == qoe.ReasonApplicationGates && len(observation.ApplicationChecks) > 0 {
		_ = monitor.recordDiagnostic(ctx, candidate.ID, "qoe_application_failure", qoe.ReasonApplicationGates,
			qoe.HTTPFailureSummary(observation.ApplicationChecks), observation.ApplicationChecks, completedAt)
	}
	return nil
}

func (monitor *QoEMonitor) recordInfrastructure(ctx context.Context, candidateID string, response agentapi.ProbeResponse, probeErr error, now time.Time) error {
	code, details := agentapi.ProbeFailureDetails(response, probeErr)
	var checks []qoe.HTTPCheck
	if response.QoE != nil {
		checks = response.QoE.ApplicationChecks
	}
	return monitor.recordDiagnostic(ctx, candidateID, "probe_infrastructure", code, details, checks, now)
}

func (monitor *QoEMonitor) recordDiagnostic(ctx context.Context, candidateID, kind, code, details string, checks []qoe.HTTPCheck, now time.Time) error {
	// Ignore timing variation in the suppression key. Different failing services
	// remain visible, while memory is bounded independently of candidate count.
	safe := qoe.SafeHTTPChecks(checks)
	for i := range safe {
		safe[i].ElapsedMS = 0
	}
	key := code + qoe.HTTPFailureSummary(safe)
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.infraLast == nil {
		monitor.infraLast = make(map[string]qoeDiagnosticWindow)
	}
	if _, exists := monitor.infraLast[key]; !exists && len(monitor.infraLast) >= 63 {
		key = "overflow"
	}
	window := monitor.infraLast[key]
	if !window.last.IsZero() && now.Before(window.last.Add(time.Minute)) {
		window.suppressed++
		monitor.infraLast[key] = window
		return nil
	}
	err := monitor.Store.AppendEvent(ctx, store.Event{Kind: kind, CandidateID: candidateID,
		Message: fmt.Sprintf("stage=qoe code=%s %s suppressed=%d", code, details, window.suppressed), CreatedAt: now})
	if err == nil {
		monitor.infraLast[key] = qoeDiagnosticWindow{last: now}
	}
	return err
}

func (monitor *QoEMonitor) applyUDPObservation(
	ctx context.Context,
	candidateID string,
	reachable bool,
	generation ...int64,
) (bool, error) {
	monitor.mu.Lock()
	if monitor.udpSignals == nil {
		monitor.udpSignals = make(map[string]udpSignalState)
	}
	state := monitor.udpSignals[candidateID]
	if len(generation) > 0 && state.generation != generation[0] {
		state = udpSignalState{generation: generation[0]}
	}
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
	changed, err := monitor.Store.UpdateCandidateUDPQualified(ctx, candidateID, qualified, generation...)
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

// QoEWakeInterval caps admission at one second, independently of probe cadence.
func QoEWakeInterval(active, idle, degraded time.Duration) time.Duration {
	interval := shortestPositiveDuration(active, idle, degraded)
	if interval <= 0 {
		return time.Second
	}
	return min(interval, time.Second)
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
