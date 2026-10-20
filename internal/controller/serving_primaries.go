package controller

import (
	"context"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

// Apply constraints before coverage search: a witness obtained by moving a
// serving primary cannot repair that primary's reserves. Working-pool admission
// is separate from permission to keep serving an existing assignment.
func (engine *Engine) servingPrimaries(ctx context.Context, now time.Time, reason PlacementReason, placement *scheduler.Scheduler, clients []scheduler.Client, snapshot routeCandidateSnapshot) ([]scheduler.Client, []scheduler.Candidate, error) {
	clients = append([]scheduler.Client(nil), clients...)
	candidates := append([]scheduler.Candidate(nil), snapshot.placementCandidates...)
	indices := make(map[string]int, len(candidates))
	for i, candidate := range candidates {
		indices[candidate.ID] = i
	}
	serving := make(map[string]bool)
	for _, client := range clients {
		for _, id := range []string{client.Assignment.TCP, client.Assignment.UDP} {
			if id != "" {
				serving[id] = true
			}
		}
	}
	// Retain the bounded legacy-normalization escape hatch for oversized plans.
	if engine.activeCriticalRouteLimit > 0 && len(serving) > engine.activeCriticalRouteLimit {
		return clients, candidates, nil
	}
	admission := make([]scheduler.Candidate, 0, len(snapshot.allByID))
	for _, candidate := range snapshot.allByID {
		admission = append(admission, candidate)
	}
	for i := range clients {
		client := &clients[i]
		if client.Dormant {
			continue
		}
		// Repair coverage first. Optional balancing cannot make a proof arrive
		// sooner, and must not replace the primary the monitor is repairing.
		repairing := false
		if reason == PlacementPeriodic && engine.activeCriticalRouteLimit > 0 {
			validation, err := placement.ValidateReserveSelectionContext(ctx, now, client.ID, client.Assignment, client.AppliedReserve, admission)
			if err != nil {
				return nil, nil, err
			}
			repairing = !validation.TCP || !validation.UDP
		}
		for _, transport := range []struct {
			network, id string
			since       time.Time
			preserve    *bool
		}{
			{"tcp", client.Assignment.TCP, client.Assignment.TCPSince, &client.PreserveTCP},
			{"udp", client.Assignment.UDP, client.Assignment.UDPSince, &client.PreserveUDP},
		} {
			candidate, exists := snapshot.allByID[transport.id]
			health := snapshot.healthByID[transport.id]
			row := snapshot.rowsByID[transport.id]
			qualified := candidate.TCPQualified
			if transport.network == "udp" {
				qualified = candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified
			}
			if !exists || !qualified || !health.Available || health.ActiveHardFailure || candidate.CircuitOpen ||
				row.Lifecycle != store.CandidateLifecycleActive || placement.IsExcluded(now, client.ID, transport.id) {
				continue
			}
			index, inPool := indices[candidate.ID]
			// Probe-pool draining does not revoke a still-qualified source entry.
			if !inPool || candidate.Retiring {
				candidate.ServingOnly = true
				candidate.Retiring = false
				if inPool {
					candidates[index] = candidate
				} else {
					indices[candidate.ID] = len(candidates)
					candidates = append(candidates, candidate)
				}
			}
			urgent := candidate.QoEStatus == qoe.StatusDegraded && qoe.RequiresEvacuation(candidate.QoEReason)
			*transport.preserve = !urgent && (reason != PlacementPeriodic || repairing || now.Sub(transport.since) < placement.MinimumDwell())
		}
	}
	return clients, candidates, nil
}

func reservesForMapping(mapping store.RouteReserveMapping) scheduler.ReserveSelection {
	return scheduler.ReserveSelection{TCP: mapping.TCPReserveCandidateID, UDP: mapping.UDPReserveCandidateID}
}
