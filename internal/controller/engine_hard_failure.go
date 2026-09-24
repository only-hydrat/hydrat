package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

type hardFailureCandidateState struct {
	hardFailed bool
	candidate  scheduler.Candidate
}

func (engine *Engine) hardFailureCycle(
	ctx context.Context,
	now time.Time,
	profiles ProfileProvider,
	profileFence *planProfileFence,
) error {
	if engine.store == nil || engine.agent == nil {
		return errors.New("controller engine requires store and agent")
	}
	state, err := engine.settlePendingAppliedPlan(ctx, now, profiles, profileFence)
	if err != nil {
		return err
	}
	if state.AppliedGeneration == 0 {
		return nil
	}
	mustSupersedePending := state.DesiredGeneration > state.AppliedGeneration ||
		state.InvalidatedGeneration != 0
	includeStaleHardFailures := state.DesiredGeneration > state.AppliedGeneration &&
		state.DesiredReason == string(PlacementHardFailure)
	plan, _, err := decodePersistedPlan(
		"applied", state.AppliedGeneration, state.AppliedPlan,
	)
	if err != nil {
		return err
	}
	legacyAppliedCapacity := activeCriticalPlanCandidateCount(plan)
	candidateStates, candidateSnapshot, err := engine.hardFailureCandidateStates(
		ctx, now, plan, profiles, includeStaleHardFailures,
	)
	if err != nil {
		return err
	}
	rowsByID := candidateSnapshot.rowsByID
	inventoryEpoch := candidateSnapshot.inventoryEpoch
	emergencyCandidates := make(map[string][]scheduler.Candidate)
	for candidateID, state := range candidateStates {
		if state.hardFailed {
			emergencyCandidates[candidateID] = hardFailureEmergencyCandidates(
				candidateID, candidateSnapshot,
			)
		}
	}
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return err
	}
	assignments, err := engine.store.ListAssignments(ctx)
	if err != nil {
		return err
	}
	assignmentByClient := make(map[string]store.AssignmentRecord, len(assignments))
	for _, assignment := range assignments {
		assignmentByClient[assignment.ClientID] = assignment
	}
	candidateLoad, domainLoad := hardFailureLoads(assignments, candidateStates)
	planOutbounds := make(map[string]dataplane.Outbound, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		planOutbounds[outbound.ID] = outbound
	}
	originalOutboundCount := len(planOutbounds)
	routeByClient := make(map[string]int, len(plan.Clients))
	for index, route := range plan.Clients {
		routeByClient[route.ClientID] = index
	}
	changed := false
	requiresTorFence := false
	for clientID, assignment := range assignmentByClient {
		routeIndex, routed := routeByClient[clientID]
		if !routed {
			continue
		}
		route := &plan.Clients[routeIndex]
		clientChanged := false
		if assignment.TCPOutbound != "" &&
			candidateStates[assignment.TCPOutbound].hardFailed {
			failedCandidateID := assignment.TCPOutbound
			replacementApplied := false
			reserve, ok, err := engine.store.AppliedReserveForFailure(
				ctx, clientID, store.RouteTransportTCP, failedCandidateID,
			)
			if err != nil {
				return err
			}
			reserveState := candidateStates[reserve]
			selection := engine.scheduler.SelectReserves(
				now, clientID, scheduler.Assignment{TCP: failedCandidateID},
				[]scheduler.Candidate{
					candidateStates[failedCandidateID].candidate,
					reserveState.candidate,
				},
			)
			reserveHandlerValid := ok && selection.TCP == reserve &&
				candidateIDFromHandler(route.TCPReserveOutbound, clientID) == reserve &&
				engine.mappedReserveHandlerMatchesCurrentProfile(
					clientID, reserve, route.TCPReserveOutbound, plan.Outbounds,
					rowsByID, profiles,
				)
			reserveDNS := dnsHandlerForClientTarget(
				clientID, route.TCPReserveOutbound, plan.Outbounds,
			)
			if reserveHandlerValid && reserveDNS != "" {
				requiresTorFence = requiresTorFence ||
					reserveState.candidate.Protocol == scheduler.ProtocolTor
				assignment.TCPOutbound = reserve
				assignment.TCPSince = now
				route.TCPOutbound = route.TCPReserveOutbound
				route.DNSOutbound = reserveDNS
				route.BlockTCP = false
				replacementApplied = true
			} else {
				fallback := engine.scheduler.SelectEmergency(
					now, clientID, "tcp", failedCandidateID,
					emergencyCandidates[failedCandidateID],
					candidateLoad, domainLoad,
				)
				if fallback != "" {
					fallbackState := candidateStates[fallback]
					fallbackHandler, err := engine.outbound(
						clientID, fallback, rowsByID,
						candidateSnapshot.payloadByCandidate,
						candidateSnapshot.profilesByCandidate,
						planOutbounds,
					)
					if err != nil {
						return err
					}
					resolver, resolverErr := engine.dnsResolverForCandidate(fallback)
					if resolverErr != nil {
						return resolverErr
					}
					dnsOutbound, dnsErr := dataplane.BuildDNSOutbound(
						clientID, planOutbounds[fallbackHandler],
						resolver,
					)
					if dnsErr != nil {
						return dnsErr
					}
					planOutbounds[dnsOutbound.ID] = dnsOutbound
					requiresTorFence = requiresTorFence ||
						fallbackState.candidate.Protocol == scheduler.ProtocolTor
					assignment.TCPOutbound = fallback
					assignment.TCPSince = now
					route.TCPOutbound = fallbackHandler
					route.DNSOutbound = dnsOutbound.ID
					route.BlockTCP = false
					replacementApplied = true
				}
			}
			if replacementApplied {
				adjustHardFailureLoad(
					candidateLoad, domainLoad, candidateStates,
					failedCandidateID, assignment.TCPOutbound,
				)
				route.TCPReserveOutbound = ""
				clientChanged = true
				changed = true
			}
		}
		if assignment.UDPOutbound != "" &&
			candidateStates[assignment.UDPOutbound].hardFailed {
			failedCandidateID := assignment.UDPOutbound
			replacementApplied := false
			reserve, ok, err := engine.store.AppliedReserveForFailure(
				ctx, clientID, store.RouteTransportUDP, failedCandidateID,
			)
			if err != nil {
				return err
			}
			reserveState := candidateStates[reserve]
			selection := engine.scheduler.SelectReserves(
				now, clientID, scheduler.Assignment{UDP: failedCandidateID},
				[]scheduler.Candidate{
					candidateStates[failedCandidateID].candidate,
					reserveState.candidate,
				},
			)
			reserveHandlerValid := ok && selection.UDP == reserve &&
				candidateIDFromHandler(route.UDPReserveOutbound, clientID) == reserve
			if reserveHandlerValid {
				assignment.UDPOutbound = reserve
				assignment.UDPSince = now
				route.UDPOutbound = route.UDPReserveOutbound
				route.BlockUDP = false
				replacementApplied = true
			} else {
				fallback := engine.scheduler.SelectEmergency(
					now, clientID, "udp", failedCandidateID,
					emergencyCandidates[failedCandidateID],
					candidateLoad, domainLoad,
				)
				if fallback != "" {
					fallbackHandler, err := engine.outbound(
						clientID, fallback, rowsByID,
						candidateSnapshot.payloadByCandidate,
						candidateSnapshot.profilesByCandidate,
						planOutbounds,
					)
					if err != nil {
						return err
					}
					assignment.UDPOutbound = fallback
					assignment.UDPSince = now
					route.UDPOutbound = fallbackHandler
					route.BlockUDP = false
					replacementApplied = true
				}
			}
			if replacementApplied {
				adjustHardFailureLoad(
					candidateLoad, domainLoad, candidateStates,
					failedCandidateID, assignment.UDPOutbound,
				)
				route.UDPReserveOutbound = ""
				clientChanged = true
				changed = true
			}
		}
		if clientChanged {
			assignment.UpdatedAt = now
			assignmentByClient[clientID] = assignment
		}
	}
	if !changed && !mustSupersedePending {
		return nil
	}
	if len(planOutbounds) != originalOutboundCount {
		plan.Outbounds = appendNewPlanOutbounds(plan.Outbounds, planOutbounds)
	}
	plan.Generation = max(
		state.DesiredGeneration, state.InvalidatedGeneration,
	) + 1
	expectations := make([]store.CandidatePlanExpectation, 0, len(rowsByID))
	for _, candidateID := range uniqueCandidateReferences(plan.Outbounds) {
		candidate, exists := rowsByID[candidateID]
		if !exists {
			return store.ErrCandidateInventoryChanged
		}
		expectations = append(expectations, store.CandidatePlanExpectation{
			Candidate: candidate, AllowDraining: true,
			EvidenceDigest: candidateSnapshot.evidenceByCandidate[candidateID],
		})
	}
	reserveMappings := hardPlanReserveMappings(plan, assignmentByClient)
	assignmentUpdates := make([]store.AssignmentRecord, 0, len(clients))
	for _, client := range clients {
		assignment := assignmentByClient[client.ID]
		if assignment.ClientID == "" {
			assignment = store.AssignmentRecord{
				ClientID: client.ID, TCPSince: now, UDPSince: now,
			}
		}
		assignmentUpdates = append(assignmentUpdates, assignment)
	}
	if engine.beforeDesiredPlanSave != nil {
		engine.beforeDesiredPlanSave()
	}
	hardProfileFence := (*planProfileFence)(nil)
	if requiresTorFence {
		hardProfileFence = profileFence
	}
	return engine.saveApplyAndMark(
		ctx, plan, PlacementHardFailure, assignmentUpdates, inventoryEpoch, expectations,
		reserveMappings, nil, hardProfileFence, legacyAppliedCapacity,
	)
}

func hardFailureEmergencyCandidates(
	failedCandidateID string,
	snapshot routeCandidateSnapshot,
) []scheduler.Candidate {
	candidates := append(
		[]scheduler.Candidate(nil), snapshot.placementCandidates...,
	)
	for _, candidate := range candidates {
		if candidate.ID == failedCandidateID {
			return candidates
		}
	}
	if failed, exists := snapshot.allByID[failedCandidateID]; exists {
		candidates = append(candidates, failed)
	}
	return candidates
}

func hardFailureLoads(
	assignments []store.AssignmentRecord,
	states map[string]hardFailureCandidateState,
) (map[string]int, map[string]int) {
	load := make(map[string]int)
	domainLoad := make(map[string]int)
	for _, assignment := range assignments {
		for _, candidateID := range []string{
			assignment.TCPOutbound, assignment.UDPOutbound,
		} {
			if candidateID == "" {
				continue
			}
			load[candidateID]++
			domainLoad[hardFailureDomain(candidateID, states)]++
		}
	}
	return load, domainLoad
}

func adjustHardFailureLoad(
	load, domainLoad map[string]int,
	states map[string]hardFailureCandidateState,
	oldCandidateID, newCandidateID string,
) {
	if oldCandidateID == newCandidateID {
		return
	}
	if oldCandidateID != "" {
		load[oldCandidateID]--
		domainLoad[hardFailureDomain(oldCandidateID, states)]--
	}
	if newCandidateID != "" {
		load[newCandidateID]++
		domainLoad[hardFailureDomain(newCandidateID, states)]++
	}
}

func hardFailureDomain(
	candidateID string,
	states map[string]hardFailureCandidateState,
) string {
	domain := states[candidateID].candidate.FailureDomain
	if domain == "" {
		return candidateID
	}
	return domain
}

func appendNewPlanOutbounds(
	existing []dataplane.Outbound,
	all map[string]dataplane.Outbound,
) []dataplane.Outbound {
	result := append([]dataplane.Outbound(nil), existing...)
	existingIDs := make(map[string]bool, len(existing))
	for _, outbound := range existing {
		existingIDs[outbound.ID] = true
	}
	ids := make([]string, 0, len(all)-len(existing))
	for id := range all {
		if !existingIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		result = append(result, all[id])
	}
	return result
}

func (engine *Engine) mappedReserveHandlerMatchesCurrentProfile(
	clientID string,
	candidateID string,
	handlerID string,
	outbounds []dataplane.Outbound,
	rowsByID map[string]store.Candidate,
	profiles ProfileProvider,
) bool {
	candidate, exists := rowsByID[candidateID]
	if !exists {
		return false
	}
	if candidate.Kind != sources.KindTorBridge {
		return handlerID == candidateID
	}
	if profiles == nil {
		return false
	}
	var currentProfile *struct {
		slot      int
		socksAddr string
	}
	for _, profile := range profiles.Profiles() {
		if profile.CandidateID != candidateID || profile.Role != "warm" ||
			profile.Retiring {
			continue
		}
		if currentProfile != nil {
			return false
		}
		currentProfile = &struct {
			slot      int
			socksAddr string
		}{slot: profile.Slot, socksAddr: profile.SocksAddr}
	}
	if currentProfile == nil {
		return false
	}
	expectedID := torProfileOutboundID(candidateID, torpool.Profile{
		Slot: currentProfile.slot, SocksAddr: currentProfile.socksAddr,
	}, clientID)
	if handlerID != expectedID {
		return false
	}
	var actual dataplane.Outbound
	for _, outbound := range outbounds {
		if outbound.ID == handlerID {
			actual = outbound
			break
		}
	}
	if actual.ID == "" || actual.Protocol != dataplane.ProtocolTor {
		return false
	}
	expectedConfig, err := json.Marshal(xrayconfig.TorOutbound(
		currentProfile.socksAddr, expectedID, clientID, engine.torSecret,
	))
	if err != nil {
		return false
	}
	return semanticJSONEqual(actual.Config, expectedConfig)
}

func semanticJSONEqual(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil ||
		json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func (engine *Engine) settlePendingAppliedPlan(
	ctx context.Context,
	now time.Time,
	profiles ProfileProvider,
	profileFence *planProfileFence,
) (store.PlanState, error) {
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return store.PlanState{}, err
	}
	desired, _, hasDesired, err := validatePersistedPlanState(state)
	if err != nil {
		return store.PlanState{}, err
	}
	if hasDesired && state.DesiredGeneration > state.AppliedGeneration &&
		state.DesiredReason == string(PlacementHardFailure) {
		var applied dataplane.DesiredPlan
		if state.AppliedGeneration > 0 {
			var err error
			applied, _, err = decodePersistedPlan(
				"applied", state.AppliedGeneration, state.AppliedPlan,
			)
			if err != nil {
				return store.PlanState{}, err
			}
		}
		if err := engine.validateActiveCriticalRouteCapacity(
			desired, activeCriticalPlanCandidateCount(applied),
		); err != nil {
			return store.PlanState{}, err
		}
		current, err := engine.pendingHardPlanPrimariesCurrent(
			ctx, now, desired, profiles,
		)
		if err != nil {
			return store.PlanState{}, err
		}
		if !current {
			return state, nil
		}
		release, err := acquireTorPlanFence(desired, profileFence)
		if err != nil {
			return store.PlanState{}, err
		}
		defer release()
		if err := engine.applyPlan(ctx, desired, state.DesiredPlan); err != nil {
			return store.PlanState{}, err
		}
		state, err = engine.store.LoadPlanState(ctx)
		if err != nil {
			return store.PlanState{}, err
		}
		if _, _, _, err := validatePersistedPlanState(state); err != nil {
			return store.PlanState{}, err
		}
	}
	return state, nil
}

func (engine *Engine) pendingHardPlanPrimariesCurrent(
	ctx context.Context,
	now time.Time,
	plan dataplane.DesiredPlan,
	profiles ProfileProvider,
) (bool, error) {
	referenced := make(map[string]bool)
	for _, route := range plan.Clients {
		for _, handler := range []string{route.TCPOutbound, route.UDPOutbound} {
			if candidateID := candidateIDFromHandler(handler, route.ClientID); candidateID != "" {
				referenced[candidateID] = true
			}
		}
	}
	ids := make([]string, 0, len(referenced))
	for candidateID := range referenced {
		ids = append(ids, candidateID)
	}
	snapshot, err := engine.loadRouteCandidateSnapshotWithProfiles(
		ctx, now, ids, referenced, profiles,
	)
	if err != nil {
		return false, err
	}
	for _, route := range plan.Clients {
		tcpID := candidateIDFromHandler(route.TCPOutbound, route.ClientID)
		if tcpID != "" {
			candidate, exists := snapshot.allByID[tcpID]
			health, healthy := snapshot.healthByID[tcpID]
			if !exists || !healthy || !health.Available ||
				!candidate.TCPQualified || candidate.CircuitOpen {
				return false, nil
			}
		}
		udpID := candidateIDFromHandler(route.UDPOutbound, route.ClientID)
		if udpID != "" {
			candidate, exists := snapshot.allByID[udpID]
			health, healthy := snapshot.healthByID[udpID]
			if !exists || !healthy || !health.Available ||
				candidate.Protocol != scheduler.ProtocolVLESS ||
				!candidate.UDPQualified || candidate.CircuitOpen {
				return false, nil
			}
		}
	}
	return true, nil
}

func rewritePlanDNS(
	plan dataplane.DesiredPlan,
	resolver string,
) (dataplane.DesiredPlan, bool, error) {
	return rewritePlanDNSWithResolvers(plan, []string{resolver})
}

func rewritePlanDNSWithResolvers(
	plan dataplane.DesiredPlan,
	resolvers []string,
) (dataplane.DesiredPlan, bool, error) {
	byID := make(map[string]dataplane.Outbound, len(plan.Outbounds))
	rewritten := plan
	rewritten.Outbounds = make([]dataplane.Outbound, 0, len(plan.Outbounds))
	actualDNS := make(map[string]dataplane.Outbound)
	actualDNSCount := 0
	for _, outbound := range plan.Outbounds {
		byID[outbound.ID] = outbound
		if outbound.Protocol == dataplane.ProtocolDNS {
			actualDNSCount++
			actualDNS[outbound.ID] = outbound
			continue
		}
		rewritten.Outbounds = append(rewritten.Outbounds, outbound)
	}
	expectedDNS := make(map[string]dataplane.Outbound)
	for index := range rewritten.Clients {
		route := &rewritten.Clients[index]
		if route.TCPOutbound == "" {
			route.DNSOutbound = ""
			continue
		}
		target, exists := byID[route.TCPOutbound]
		if !exists {
			return dataplane.DesiredPlan{}, false,
				fmt.Errorf("DNS rewrite target %q is missing", route.TCPOutbound)
		}
		candidateID := candidateIDFromHandler(route.TCPOutbound, route.ClientID)
		resolver, err := dataplane.SelectDNSResolver(candidateID, resolvers)
		if err != nil {
			return dataplane.DesiredPlan{}, false, err
		}
		dns, err := dataplane.BuildDNSOutbound(route.ClientID, target, resolver)
		if err != nil {
			return dataplane.DesiredPlan{}, false, err
		}
		expectedDNS[dns.ID] = dns
		route.DNSOutbound = dns.ID
		if route.TCPReserveOutbound != "" {
			reserve, exists := byID[route.TCPReserveOutbound]
			if !exists {
				return dataplane.DesiredPlan{}, false,
					fmt.Errorf("reserve DNS rewrite target %q is missing",
						route.TCPReserveOutbound)
			}
			reserveCandidateID := candidateIDFromHandler(
				route.TCPReserveOutbound, route.ClientID,
			)
			reserveResolver, err := dataplane.SelectDNSResolver(
				reserveCandidateID, resolvers,
			)
			if err != nil {
				return dataplane.DesiredPlan{}, false, err
			}
			reserveDNS, err := dataplane.BuildDNSOutbound(
				route.ClientID, reserve, reserveResolver,
			)
			if err != nil {
				return dataplane.DesiredPlan{}, false, err
			}
			expectedDNS[reserveDNS.ID] = reserveDNS
		}
	}
	ids := make([]string, 0, len(expectedDNS))
	for id := range expectedDNS {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rewritten.Outbounds = append(rewritten.Outbounds, expectedDNS[id])
	}
	matches := actualDNSCount == len(expectedDNS) &&
		len(actualDNS) == len(expectedDNS)
	for id, expected := range expectedDNS {
		actual, exists := actualDNS[id]
		if !exists || actual.Protocol != expected.Protocol ||
			!bytes.Equal(actual.Config, expected.Config) {
			matches = false
			break
		}
	}
	if matches {
		for index := range plan.Clients {
			if plan.Clients[index].DNSOutbound !=
				rewritten.Clients[index].DNSOutbound {
				matches = false
				break
			}
		}
	}
	return rewritten, matches, nil
}

func (engine *Engine) hardFailureCandidateStates(
	ctx context.Context,
	now time.Time,
	plan dataplane.DesiredPlan,
	profiles ProfileProvider,
	includeStale bool,
) (map[string]hardFailureCandidateState, routeCandidateSnapshot, error) {
	references := uniqueCandidateReferences(plan.Outbounds)
	snapshot, err := engine.loadRouteCandidateSnapshotWithProfiles(
		ctx, now, references, map[string]bool{}, profiles,
	)
	if err != nil {
		return nil, routeCandidateSnapshot{}, err
	}
	result := make(map[string]hardFailureCandidateState, len(snapshot.allByID))
	for candidateID, candidate := range snapshot.allByID {
		health := snapshot.healthByID[candidateID]
		result[candidateID] = hardFailureCandidateState{
			hardFailed: health.ActiveCurrent &&
				((includeStale && !health.Available) ||
					engine.activeHardFailureObservationFresh(now, health.ActiveObservedAt)) &&
				health.ActiveHardFailure,
			candidate: candidate,
		}
	}
	return result, snapshot, nil
}

func uniqueCandidateReferences(outbounds []dataplane.Outbound) []string {
	seen := make(map[string]bool)
	references := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		if outbound.Protocol != dataplane.ProtocolVLESS &&
			outbound.Protocol != dataplane.ProtocolTor {
			continue
		}
		candidateID := candidateIDFromHandler(outbound.ID, "")
		if candidateID != "" && !seen[candidateID] {
			seen[candidateID] = true
			references = append(references, candidateID)
		}
	}
	return references
}

func candidateIDFromHandler(handlerID, clientID string) string {
	if handlerID == "" {
		return ""
	}
	candidateID, suffix, tor := strings.Cut(handlerID, "-profile-")
	if !tor {
		return sources.CandidateIDFromVLESSHandler(handlerID)
	}
	_, boundClientID, valid := strings.Cut(suffix, "-client-")
	if candidateID == "" || !valid || boundClientID == "" ||
		(clientID != "" && boundClientID != clientID) {
		return ""
	}
	return candidateID
}

func dnsHandlerForClientTarget(
	clientID, targetID string,
	outbounds []dataplane.Outbound,
) string {
	var target dataplane.Outbound
	for _, outbound := range outbounds {
		if outbound.ID == targetID {
			target = outbound
			break
		}
	}
	if target.ID == "" {
		return ""
	}
	for _, outbound := range outbounds {
		if outbound.Protocol != dataplane.ProtocolDNS {
			continue
		}
		var config struct {
			Settings struct {
				RewriteAddress string `json:"rewriteAddress"`
			} `json:"settings"`
			StreamSettings struct {
				Sockopt struct {
					DialerProxy string `json:"dialerProxy"`
				} `json:"sockopt"`
			} `json:"streamSettings"`
			ProxySettings struct {
				Tag string `json:"tag"`
			} `json:"proxySettings"`
		}
		if json.Unmarshal(outbound.Config, &config) != nil {
			continue
		}
		dialerProxy := config.StreamSettings.Sockopt.DialerProxy
		if dialerProxy == "" {
			dialerProxy = config.ProxySettings.Tag
		}
		if dialerProxy != targetID {
			continue
		}
		expected, err := dataplane.BuildDNSOutbound(
			clientID, target, config.Settings.RewriteAddress,
		)
		if err == nil && expected.ID == outbound.ID {
			return outbound.ID
		}
	}
	return ""
}

func hardPlanReserveMappings(
	plan dataplane.DesiredPlan,
	assignments map[string]store.AssignmentRecord,
) []store.RouteReserveMapping {
	result := make([]store.RouteReserveMapping, 0, len(plan.Clients))
	for _, route := range plan.Clients {
		assignment := assignments[route.ClientID]
		mapping := store.RouteReserveMapping{ClientID: route.ClientID}
		if route.TCPReserveOutbound != "" {
			mapping.TCPPrimaryCandidateID = assignment.TCPOutbound
			mapping.TCPReserveCandidateID = candidateIDFromHandler(
				route.TCPReserveOutbound, route.ClientID,
			)
		}
		if route.UDPReserveOutbound != "" {
			mapping.UDPPrimaryCandidateID = assignment.UDPOutbound
			mapping.UDPReserveCandidateID = candidateIDFromHandler(
				route.UDPReserveOutbound, route.ClientID,
			)
		}
		if mapping.TCPReserveCandidateID != "" ||
			mapping.UDPReserveCandidateID != "" {
			result = append(result, mapping)
		}
	}
	return result
}
