package controller

import (
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

// WithMobileRoutes reuses the durable pool while requiring a fresh proof
// before installing a route on the phone's new network.
func WithMobileRoutes(started time.Time, reserves int, preferred []string) EngineOption {
	return func(engine *Engine) {
		engine.mobileStartedAt = started.Truncate(time.Millisecond)
		engine.mobileReserves = reserves
		engine.mobilePreferred = append([]string(nil), preferred...)
	}
}

func WithMobileMinimumVLESSScore(score float64) EngineOption {
	return func(engine *Engine) { engine.mobileMinVLESSScore = score }
}

func (engine *Engine) mobileActiveTargets(now time.Time, snapshot routeCandidateSnapshot, primaryIDs map[string]bool, mappings []store.RouteReserveMapping) []ActiveTarget {
	proofAfter := now.Add(-engine.reserveActiveFreshness)
	if engine.mobileStartedAt.After(proofAfter) {
		proofAfter = engine.mobileStartedAt
	}
	seen := make(map[string]bool)
	routes := make(map[string]bool)
	targets := make([]ActiveTarget, 0, len(primaryIDs)+engine.mobileReserves)
	add := func(id string, role ActiveTargetRole) {
		row, exists := snapshot.rowsByID[id]
		if !exists || seen[id] {
			return
		}
		seen[id] = true
		candidate := snapshot.allByID[id]
		if health := snapshot.healthByID[id]; health.Available && !health.ActiveHardFailure {
			routes[mobileRouteKey(candidate)] = true
		}
		targets = append(targets, ActiveTarget{
			Candidate: row, Role: role,
			TriggerPlacementOnSuccess: !candidate.ActiveEligible || !candidate.ActiveFresh,
			ProofFreshAfter:           proofAfter,
		})
	}
	for id := range primaryIDs {
		add(id, ActiveTargetCritical)
	}
	// Cover the reserves that can be activated directly by the current plan.
	// The other proven routes are available to the same emergency scheduler.
	limit := len(targets) + engine.mobileReserves
	for _, mapping := range mappings {
		for _, id := range []string{mapping.TCPReserveCandidateID, mapping.UDPReserveCandidateID} {
			if len(targets) < limit {
				add(id, ActiveTargetCritical)
			}
		}
	}
	// Before the first route is installed, verify up to primary + reserves.
	limit = max(1, len(primaryIDs)) + engine.mobileReserves
	candidates := append([]scheduler.Candidate(nil), snapshot.placementCandidates...)
	preference := make(map[string]int, len(engine.mobilePreferred))
	for index, id := range engine.mobilePreferred {
		if preference[id] == 0 {
			preference[id] = len(engine.mobilePreferred) - index
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if preference[a.ID] != preference[b.ID] {
			return preference[a.ID] > preference[b.ID]
		}
		if a.UDPQualified != b.UDPQualified {
			return a.UDPQualified
		}
		return a.Score > b.Score
	})
	for _, candidate := range candidates {
		if len(targets) >= limit {
			break
		}
		if candidate.ReserveEligible && !candidate.Retiring && !candidate.CircuitOpen &&
			(candidate.TCPQualified || candidate.UDPQualified) && !routes[mobileRouteKey(candidate)] {
			add(candidate.ID, ActiveTargetProspective)
		}
	}
	return targets
}

func mobileRouteKey(candidate scheduler.Candidate) string {
	if candidate.RouteKey != "" {
		return candidate.RouteKey
	}
	return candidate.ID
}

func (engine *Engine) mobilePlacementCandidates(clients []scheduler.Client, candidates []scheduler.Candidate) []scheduler.Candidate {
	primaries := make(map[string]bool)
	for _, client := range clients {
		primaries[client.Assignment.TCP] = true
		primaries[client.Assignment.UDP] = true
	}
	verified := candidates[:0]
	for _, candidate := range candidates {
		if candidate.ActiveEligible && candidate.ActiveFresh {
			verified = append(verified, candidate)
		} else if engine.localPlanInstalled && primaries[candidate.ID] {
			candidate.ServingOnly = true
			verified = append(verified, candidate)
		}
	}
	return verified
}
