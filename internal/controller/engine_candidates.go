package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

type routeCandidateSnapshot struct {
	allByID             map[string]scheduler.Candidate
	placementCandidates []scheduler.Candidate
	rowsByID            map[string]store.Candidate
	healthByID          map[string]store.CandidateHealth
	profilesByCandidate map[string]torpool.Profile
	payloadByCandidate  map[string]string
	evidenceByCandidate map[string]string
	inventoryEpoch      int64
}

func (engine *Engine) loadRouteCandidateSnapshot(
	ctx context.Context,
	now time.Time,
	referencedIDs []string,
	activeCandidateIDs map[string]bool,
) (routeCandidateSnapshot, error) {
	return engine.loadRouteCandidateSnapshotWithProfiles(
		ctx, now, referencedIDs, activeCandidateIDs, engine.profiles,
	)
}

func (engine *Engine) loadRouteCandidateSnapshotWithProfiles(
	ctx context.Context,
	now time.Time,
	referencedIDs []string,
	activeCandidateIDs map[string]bool,
	profiles ProfileProvider,
) (routeCandidateSnapshot, error) {
	result := routeCandidateSnapshot{
		allByID:             make(map[string]scheduler.Candidate),
		rowsByID:            make(map[string]store.Candidate),
		healthByID:          make(map[string]store.CandidateHealth),
		profilesByCandidate: make(map[string]torpool.Profile),
		payloadByCandidate:  make(map[string]string),
		evidenceByCandidate: make(map[string]string),
	}
	evidence, err := engine.store.LoadRoutingEvidenceSnapshot(ctx, referencedIDs)
	if err != nil {
		return result, err
	}
	result.inventoryEpoch = evidence.InventoryEpoch
	probeByID := make(map[string]store.CandidateProbeState, len(evidence.Candidates))
	workingCandidateIDs := make(map[string]bool, len(evidence.Candidates))
	drainingCandidateIDs := make(map[string]bool)
	openDomains := make(map[string]bool)
	qoeByID := make(map[string]qoe.State)
	for _, row := range evidence.Candidates {
		candidateID := row.Candidate.ID
		result.rowsByID[candidateID] = row.Candidate
		result.payloadByCandidate[candidateID] = row.Payload
		result.evidenceByCandidate[candidateID] = row.Digest
		if row.HasHealth {
			result.healthByID[candidateID] = row.Health
		}
		if row.HasProbe {
			probeByID[candidateID] = row.Probe
			if row.Probe.InWorkingPool || row.Probe.Draining {
				workingCandidateIDs[candidateID] = true
			}
			if row.Probe.Draining {
				drainingCandidateIDs[candidateID] = true
			}
		}
		if row.HasFailureDomain && row.FailureDomain.OpenUntil.After(now) {
			openDomains[row.FailureDomain.Domain] = true
		}
		if engine.qoeEnabled && row.HasQoE {
			qoeByID[candidateID] = row.QoE
		}
	}
	if profiles != nil {
		for _, profile := range profiles.Profiles() {
			if profile.Role == "warm" {
				result.profilesByCandidate[profile.CandidateID] = profile
			}
		}
	}
	for _, health := range result.healthByID {
		candidate, exists := result.rowsByID[health.CandidateID]
		if !exists {
			continue
		}
		protocol := scheduler.ProtocolVLESS
		tcpQualified := health.TCPQualified
		udpQualified := health.UDPQualified
		retiring := drainingCandidateIDs[candidate.ID] ||
			candidate.Lifecycle == store.CandidateLifecycleDraining
		profileID := ""
		warm := false
		if candidate.Kind == sources.KindTorBridge {
			protocol = scheduler.ProtocolTor
			profile, exists := result.profilesByCandidate[candidate.ID]
			warm = exists && !profile.Retiring
			tcpQualified = tcpQualified && warm
			udpQualified = false
			retiring = retiring || (exists && profile.Retiring)
			if exists {
				profileID = fmt.Sprintf("tor-profile-%d", profile.Slot)
			}
		}
		qoeState := qoeByID[candidate.ID]
		freshness := standbyCandidateQoEFreshness
		if activeCandidateIDs[candidate.ID] {
			freshness = activeCandidateQoEFreshness
		}
		qoeFresh := !qoeState.LastValidAt.IsZero() &&
			!qoeState.LastValidAt.After(now) &&
			now.Sub(qoeState.LastValidAt) <= freshness
		probe, hasProbe := probeByID[candidate.ID]
		reserveEligible := health.Available && hasProbe &&
			probe.Status == store.CandidateQualified &&
			probe.InWorkingPool && !probe.Stale && !probe.Draining &&
			candidate.Lifecycle == store.CandidateLifecycleActive
		if engine.disallowRUEgress && sources.IsRussianEgress(candidate.Label, result.payloadByCandidate[candidate.ID]) {
			tcpQualified = false
			udpQualified = false
			reserveEligible = false
		}
		routeCandidate := scheduler.Candidate{
			ID: candidate.ID, Protocol: protocol, RouteKey: candidate.RouteKey,
			ProfileID: profileID, Score: health.Score,
			TCPQualified: tcpQualified, UDPQualified: udpQualified,
			ReserveEligible: reserveEligible,
			ActiveEligible:  health.ActiveSuccess && health.ActiveCurrent,
			ActiveFresh: engine.reserveActiveObservationFresh(
				now, health.ActiveObservedAt,
			),
			Warm: warm, Retiring: retiring,
			FailureDomain: candidate.FailureDomain,
			CircuitOpen:   openDomains[candidate.FailureDomain],
			QoEStatus:     qoeState.Status,
			QoEEffective:  qoeState.MedianEffectiveTime,
			QoEFresh:      qoeFresh,
			QoEReason:     qoeState.LastReason,
			QoETracked:    engine.qoeEnabled,
			QoEPromotionReady: promotionQoEReady(
				now, qoeState,
				engine.qoePromotionWindow,
				engine.qoePromotionFreshness,
				engine.qoePromotionWindowFreshness,
				engine.qoePromotionMaximumSampleGap,
			),
		}
		result.allByID[candidate.ID] = routeCandidate
		placementEligible := false
		if health.Available && (!engine.disallowRUEgress || !sources.IsRussianEgress(candidate.Label, result.payloadByCandidate[candidate.ID])) {
			if len(probeByID) == 0 {
				// Preserve compatibility for stores created before probe-state
				// tracking existed. Once any probe state exists, health alone is
				// not sufficient evidence for a new placement.
				placementEligible = true
			} else if hasProbe && !probe.Stale && workingCandidateIDs[candidate.ID] &&
				(probe.Status == store.CandidateQualified ||
					probe.Status == store.CandidateDraining) {
				placementEligible = true
			}
		}
		if placementEligible {
			result.placementCandidates = append(
				result.placementCandidates, routeCandidate,
			)
		}
	}
	return result, nil
}

func (engine *Engine) ActiveTargets(
	ctx context.Context,
	now time.Time,
) ([]ActiveTarget, error) {
	if engine.store == nil {
		return nil, fmt.Errorf("controller engine store is required")
	}
	selector := engine.scheduler.ReadView()
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	clientByID := make(map[string]store.ClientRecord, len(clients))
	for _, client := range clients {
		clientByID[client.ID] = client
	}
	assignments, err := engine.store.ListAssignments(ctx)
	if err != nil {
		return nil, err
	}
	assignmentByClient := make(map[string]store.AssignmentRecord, len(assignments))
	references := make(map[string]bool)
	activeIDs := make(map[string]bool)
	for _, assignment := range assignments {
		assignmentByClient[assignment.ClientID] = assignment
		for _, candidateID := range []string{
			assignment.TCPOutbound, assignment.UDPOutbound,
		} {
			if candidateID != "" {
				references[candidateID] = true
				activeIDs[candidateID] = true
			}
		}
	}
	_, appliedMappings, err := engine.store.ListAppliedReserveMappings(ctx)
	if err != nil {
		return nil, err
	}
	appliedMappingByClient := make(
		map[string]store.RouteReserveMapping, len(appliedMappings),
	)
	for _, mapping := range appliedMappings {
		appliedMappingByClient[mapping.ClientID] = mapping
		for _, candidateID := range []string{
			mapping.TCPPrimaryCandidateID, mapping.TCPReserveCandidateID,
			mapping.UDPPrimaryCandidateID, mapping.UDPReserveCandidateID,
		} {
			if candidateID == "" {
				continue
			}
			references[candidateID] = true
		}
	}
	blockedAssignment := false
	incompleteAppliedFailover := false
	for _, client := range clients {
		if client.Paused {
			continue
		}
		assignment, exists := assignmentByClient[client.ID]
		if !exists || assignment.TCPOutbound == "" || assignment.UDPOutbound == "" {
			blockedAssignment = true
			break
		}
		mapping, exists := appliedMappingByClient[client.ID]
		if !exists || mapping.TCPPrimaryCandidateID == "" ||
			mapping.UDPPrimaryCandidateID == "" ||
			mapping.TCPReserveCandidateID == "" ||
			mapping.UDPReserveCandidateID == "" ||
			mapping.TCPPrimaryCandidateID == mapping.TCPReserveCandidateID ||
			mapping.UDPPrimaryCandidateID == mapping.UDPReserveCandidateID {
			incompleteAppliedFailover = true
		}
	}
	referencedIDs := make([]string, 0, len(references))
	for candidateID := range references {
		referencedIDs = append(referencedIDs, candidateID)
	}
	snapshot, err := engine.loadRouteCandidateSnapshot(
		ctx, now, referencedIDs, activeIDs,
	)
	if err != nil {
		return nil, err
	}
	if engine.activeCriticalRouteLimit > 0 &&
		len(references) > engine.activeCriticalRouteLimit {
		return engine.bootstrapActiveTargets(
			ctx, now, selector, clients, assignmentByClient, snapshot,
		)
	}
	if engine.activeCriticalRouteLimit > 0 &&
		(blockedAssignment || incompleteAppliedFailover) {
		bootstrap, bootstrapErr := engine.bootstrapActiveTargets(
			ctx, now, selector, clients, assignmentByClient, snapshot,
		)
		if bootstrapErr == nil {
			return bootstrap, nil
		}
		var coverageErr *ActiveCriticalCoveragePlanError
		if blockedAssignment && (!errors.As(bootstrapErr, &coverageErr) ||
			(coverageErr.SearchExhausted && coverageErr.Evaluations > 0)) {
			return nil, bootstrapErr
		}
		// A statically impossible full cover must not suppress active probes
		// for the assignments that are still serving traffic. Qualification
		// can make the missing transport feasible on a later pass.
	}
	targets := make(map[string]ActiveTarget)
	addTarget := func(candidateID string, role ActiveTargetRole, promote bool) {
		candidate, exists := snapshot.rowsByID[candidateID]
		if !exists {
			return
		}
		target := targets[candidateID]
		target.Candidate = candidate
		target.Role = mergeActiveTargetRole(target.Role, role)
		target.TriggerPlacementOnSuccess =
			target.TriggerPlacementOnSuccess || promote
		if engine.reserveActiveFreshness > 0 {
			target.ProofFreshAfter = now.Add(-engine.reserveActiveFreshness)
		}
		targets[candidateID] = target
	}
	for _, assignment := range assignments {
		addTarget(assignment.TCPOutbound, ActiveTargetCritical, false)
		addTarget(assignment.UDPOutbound, ActiveTargetCritical, false)
	}
	for _, mapping := range appliedMappings {
		reserves := scheduler.ReserveSelection{
			TCP: mapping.TCPReserveCandidateID,
			UDP: mapping.UDPReserveCandidateID,
		}
		addTarget(reserves.TCP, ActiveTargetCritical, false)
		addTarget(reserves.UDP, ActiveTargetCritical, false)
	}
	for clientID, assignment := range assignmentByClient {
		client, exists := clientByID[clientID]
		if !exists || client.Paused {
			continue
		}
		candidates := append(
			[]scheduler.Candidate(nil), snapshot.placementCandidates...,
		)
		present := make(map[string]bool, len(candidates))
		for _, candidate := range candidates {
			present[candidate.ID] = true
		}
		for _, candidateID := range []string{
			assignment.TCPOutbound, assignment.UDPOutbound,
		} {
			if candidate, exists := snapshot.allByID[candidateID]; exists && !present[candidateID] {
				candidates = append(candidates, candidate)
				present[candidateID] = true
			}
		}
		prospective := selector.SelectProspectiveReserves(
			now,
			clientID,
			scheduler.Assignment{
				TCP: assignment.TCPOutbound,
				UDP: assignment.UDPOutbound,
			},
			candidates,
		)
		for _, candidateID := range []string{prospective.TCP, prospective.UDP} {
			candidate, exists := snapshot.allByID[candidateID]
			if !exists {
				continue
			}
			needsProof := !candidate.ActiveEligible || !candidate.ActiveFresh
			addTarget(candidateID, ActiveTargetProspective, needsProof)
		}
	}
	ids := make([]string, 0, len(targets))
	for candidateID := range targets {
		ids = append(ids, candidateID)
	}
	sort.Strings(ids)
	result := make([]ActiveTarget, 0, len(ids))
	for _, candidateID := range ids {
		result = append(result, targets[candidateID])
	}
	return result, nil
}

func (engine *Engine) bootstrapActiveTargets(
	ctx context.Context,
	now time.Time,
	selector *scheduler.Scheduler,
	clients []store.ClientRecord,
	assignmentByClient map[string]store.AssignmentRecord,
	snapshot routeCandidateSnapshot,
) ([]ActiveTarget, error) {
	scheduleClients := make([]scheduler.Client, 0, len(clients))
	for _, client := range clients {
		if client.Paused {
			continue
		}
		assignment := assignmentByClient[client.ID]
		var traffic time.Time
		if client.LastTrafficAt != nil {
			traffic = time.Unix(*client.LastTrafficAt, 0)
		}
		scheduleClients = append(scheduleClients, scheduler.Client{
			ID: client.ID, LastTraffic: traffic,
			Assignment: scheduler.Assignment{
				TCP: assignment.TCPOutbound, UDP: assignment.UDPOutbound,
				TCPSince: assignment.TCPSince, UDPSince: assignment.UDPSince,
			},
		})
	}
	pool, err := engine.cappedProspectiveScheduleCandidates(
		ctx, now, selector, scheduleClients, snapshot.placementCandidates,
	)
	if err != nil {
		return nil, err
	}
	placement, err := selector.ScheduleContext(ctx, now, scheduleClients, pool)
	if err != nil {
		return nil, err
	}
	reserves := make(map[string]scheduler.ReserveSelection, len(scheduleClients))
	for _, client := range scheduleClients {
		reserve, selectErr := selector.SelectProspectiveReservesContext(
			ctx, now, client.ID, placement.Assignments[client.ID], pool,
		)
		if selectErr != nil {
			return nil, selectErr
		}
		reserves[client.ID] = reserve
	}
	if err := validateProspectiveScheduledCriticalCapacity(
		ctx, selector, now, engine.activeCriticalRouteLimit,
		scheduleClients, pool, placement, reserves,
	); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(pool))
	seen := make(map[string]bool, len(pool))
	for _, candidate := range pool {
		if !seen[candidate.ID] {
			seen[candidate.ID] = true
			ids = append(ids, candidate.ID)
		}
	}
	sort.Strings(ids)
	result := make([]ActiveTarget, 0, len(ids))
	proofFreshAfter := time.Time{}
	if engine.reserveActiveFreshness > 0 {
		proofFreshAfter = now.Add(-engine.reserveActiveFreshness)
	}
	for _, candidateID := range ids {
		candidate, exists := snapshot.rowsByID[candidateID]
		if !exists {
			return nil, store.ErrCandidateInventoryChanged
		}
		result = append(result, ActiveTarget{
			Candidate: candidate, Role: ActiveTargetCritical,
			ProofFreshAfter: proofFreshAfter,
		})
	}
	return result, nil
}

func (engine *Engine) HasFreshAssignedHardFailure(
	ctx context.Context,
	now time.Time,
) (bool, error) {
	if engine.store == nil {
		return false, fmt.Errorf("controller engine store is required")
	}
	assignments, err := engine.store.ListAssignments(ctx)
	if err != nil {
		return false, err
	}
	assigned := make(map[string]bool)
	for _, assignment := range assignments {
		if assignment.TCPOutbound != "" {
			assigned[assignment.TCPOutbound] = true
		}
		if assignment.UDPOutbound != "" {
			assigned[assignment.UDPOutbound] = true
		}
	}
	if len(assigned) == 0 {
		return false, nil
	}
	healthRows, err := engine.store.ListCandidateHealth(ctx)
	if err != nil {
		return false, err
	}
	for _, health := range healthRows {
		if assigned[health.CandidateID] && health.ActiveCurrent &&
			health.ActiveHardFailure && engine.activeHardFailureObservationFresh(
			now, health.ActiveObservedAt,
		) {
			return true, nil
		}
	}
	return false, nil
}

func (engine *Engine) HasStartupHardFailure(
	ctx context.Context,
	now time.Time,
) (bool, error) {
	if engine.store == nil {
		return false, fmt.Errorf("controller engine store is required")
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return false, err
	}
	if state.DesiredGeneration > state.AppliedGeneration &&
		state.DesiredReason == string(PlacementHardFailure) {
		return true, nil
	}
	return engine.HasFreshAssignedHardFailure(ctx, now)
}
