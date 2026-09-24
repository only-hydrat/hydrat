package controller

import (
	"encoding/json"
	"sort"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

func activeCriticalPlanCandidateCount(plan dataplane.DesiredPlan) int {
	ids := make(map[string]struct{})
	for _, route := range plan.Clients {
		for _, handlerID := range []string{
			route.TCPOutbound, route.UDPOutbound,
			route.TCPReserveOutbound, route.UDPReserveOutbound,
		} {
			candidateID := candidateIDFromHandler(handlerID, route.ClientID)
			if candidateID == "" && handlerID != "" {
				candidateID = handlerID
			}
			if candidateID != "" {
				ids[candidateID] = struct{}{}
			}
		}
	}
	return len(ids)
}

func canRecoverStaticallyBlockedAppliedTransport(
	state store.PlanState,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	limit int,
) bool {
	if limit <= 0 || state.AppliedGeneration <= 0 || len(state.AppliedPlan) == 0 {
		return false
	}
	var applied dataplane.DesiredPlan
	if err := json.Unmarshal(state.AppliedPlan, &applied); err != nil {
		return false
	}
	blockedTCP, blockedUDP := false, false
	appliedClients := make(map[string]bool, len(applied.Clients))
	for _, route := range applied.Clients {
		appliedClients[route.ClientID] = true
		blockedTCP = blockedTCP || route.BlockTCP
		blockedUDP = blockedUDP || route.BlockUDP
	}
	for _, client := range clients {
		if !appliedClients[client.ID] {
			blockedTCP = true
			blockedUDP = true
		}
	}
	canTCP, canUDP := false, false
	for _, candidate := range candidates {
		canTCP = canTCP || candidate.TCPQualified
		canUDP = canUDP ||
			(candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified)
	}
	if !(blockedTCP && canTCP) && !(blockedUDP && canUDP) {
		return false
	}
	return staticallyImpossibleCriticalCoverage(
		clients, candidates, limit, false,
	) != nil
}

// canRecoverDegradedAssignedTransport allows an already detected route
// failure to be replaced even while the pool cannot provide a complete set of
// reserves. Missing reserves keep readiness degraded, but must not pin client
// traffic to a route that QoE has proved unusable.
func canRecoverDegradedAssignedTransport(
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) bool {
	byID := make(map[string]scheduler.Candidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	canReplace := func(network, currentID string) bool {
		current, exists := byID[currentID]
		if !exists || current.QoEStatus != qoe.StatusDegraded ||
			!qoe.RequiresEvacuation(current.QoEReason) {
			return false
		}
		for _, candidate := range candidates {
			if candidate.ID == currentID || candidate.Retiring ||
				candidate.CircuitOpen || candidate.QoEStatus != qoe.StatusHealthy ||
				!candidate.QoEFresh || candidate.QoEEffective <= 0 {
				continue
			}
			qualified := candidate.TCPQualified
			if network == "udp" {
				qualified = candidate.Protocol == scheduler.ProtocolVLESS &&
					candidate.UDPQualified
			}
			if qualified {
				return true
			}
		}
		return false
	}
	for _, client := range clients {
		if canReplace("tcp", client.Assignment.TCP) ||
			canReplace("udp", client.Assignment.UDP) {
			return true
		}
	}
	return false
}

// boundedDegradedAvailabilityCandidates keeps ordinary placement useful when
// complete primary/reserve coverage is temporarily impossible. It never
// weakens the configured active-critical cardinality ceiling: already-serving
// routes are retained first, then candidates that cover more transports and
// have better health scores fill the remaining slots deterministically.
func boundedDegradedAvailabilityCandidates(
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	limit int,
) []scheduler.Candidate {
	if limit <= 0 {
		return candidates
	}
	current := make(map[string]bool)
	for _, client := range clients {
		if client.Assignment.TCP != "" {
			current[client.Assignment.TCP] = true
		}
		if client.Assignment.UDP != "" {
			current[client.Assignment.UDP] = true
		}
	}
	result := make([]scheduler.Candidate, 0, min(len(candidates), limit))
	for _, candidate := range candidates {
		if !candidate.TCPQualified &&
			!(candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified) {
			continue
		}
		result = append(result, candidate)
	}
	transportCount := func(candidate scheduler.Candidate) int {
		count := 0
		if candidate.TCPQualified {
			count++
		}
		if candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified {
			count++
		}
		return count
	}
	sort.SliceStable(result, func(left, right int) bool {
		if current[result[left].ID] != current[result[right].ID] {
			return current[result[left].ID]
		}
		leftTransports := transportCount(result[left])
		rightTransports := transportCount(result[right])
		if leftTransports != rightTransports {
			return leftTransports > rightTransports
		}
		if result[left].CircuitOpen != result[right].CircuitOpen {
			return !result[left].CircuitOpen
		}
		if result[left].Retiring != result[right].Retiring {
			return !result[left].Retiring
		}
		if result[left].Score != result[right].Score {
			return result[left].Score > result[right].Score
		}
		return result[left].ID < result[right].ID
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
