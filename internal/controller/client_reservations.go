package controller

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

// Enabled by the application composition root. Embedded callers can keep
// legacy assignment semantics until they opt into the shared bootstrap.
func WithClientReservations() EngineOption {
	return func(engine *Engine) { engine.clientReservations = true }
}

func dormantClients(state store.PlanState) (map[string]bool, error) {
	var plan dataplane.DesiredPlan
	result := make(map[string]bool)
	if len(state.AppliedPlan) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(state.AppliedPlan, &plan); err != nil {
		return nil, err
	}
	for _, route := range plan.Clients {
		result[route.ClientID] = route.Dormant
	}
	return result, nil
}

// One non-reserving representative keeps a common, monitored primary/reserve
// pair warm for idle devices. Expanding its bindings does not consume extra
// candidate slots, probe targets, or per-device capacity.
func collapseDormantClients(clients []scheduler.Client) ([]scheduler.Client, map[string]string) {
	ordered := append([]scheduler.Client(nil), clients...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	result := make([]scheduler.Client, 0, len(clients))
	aliases := make(map[string]string)
	representative := ""
	for _, client := range ordered {
		if !client.Dormant {
			result = append(result, client)
			continue
		}
		if representative == "" {
			representative = client.ID
			result = append(result, client)
		} else {
			aliases[client.ID] = representative
		}
	}
	return result, aliases
}

// Returning clients already sent their first packets through the monitored
// bootstrap. Keep that path when it is freshly proved and has a spare slot;
// clearing it unconditionally caused a second move immediately after wakeup.
// Failed/stale transports still enter ordinary fresh placement independently.
func returningAssignment(now time.Time, client scheduler.Client, clients []scheduler.Client, candidates []scheduler.Candidate) scheduler.Assignment {
	byID := make(map[string]scheduler.Candidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	routeKey := func(id string) string {
		if key := byID[id].RouteKey; key != "" {
			return key
		}
		return id
	}
	keep := func(id, network string) bool {
		candidate, exists := byID[id]
		if !exists || !candidate.ReserveEligible || !candidate.ActiveEligible || !candidate.ActiveFresh ||
			candidate.Retiring || candidate.CircuitOpen || candidate.QoEStatus == qoe.StatusDegraded {
			return false
		}
		if network == "tcp" && !candidate.TCPQualified || network == "udp" && (!candidate.UDPQualified || candidate.Protocol != scheduler.ProtocolVLESS) {
			return false
		}
		load := 0
		for _, other := range clients {
			if other.ID == client.ID || other.LastTraffic.IsZero() || other.LastTraffic.After(now) || now.Sub(other.LastTraffic) >= store.ClientInactiveAfter {
				continue
			}
			if other.Assignment.TCP != "" && routeKey(other.Assignment.TCP) == routeKey(id) ||
				other.Assignment.UDP != "" && routeKey(other.Assignment.UDP) == routeKey(id) {
				load++
			}
		}
		return load < 2
	}
	assignment := client.Assignment
	if !keep(assignment.TCP, "tcp") {
		assignment.TCP = ""
		assignment.TCPSince = time.Time{}
	}
	if !keep(assignment.UDP, "udp") {
		assignment.UDP = ""
		assignment.UDPSince = time.Time{}
	}
	return assignment
}

func (engine *Engine) reservationRecords(clients []store.ClientRecord, now time.Time) []store.ClientRecord {
	if !engine.clientReservations {
		return clients
	}
	ordered := append([]store.ClientRecord(nil), clients...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	result := make([]store.ClientRecord, 0, len(ordered))
	bootstrap := false
	for _, client := range ordered {
		if client.Paused {
			continue
		}
		if client.RouteReserved(now) {
			result = append(result, client)
		} else if !bootstrap {
			result = append(result, client)
			bootstrap = true
		}
	}
	return result
}

// ReservationChanges only collects evidence. Placement remains serialized by
// Runtime's existing priority queue and Engine's apply/commit boundary.
func (engine *Engine) ReservationChanges(ctx context.Context, now time.Time) (bool, error) {
	if err := engine.SyncActivity(ctx, now); err != nil {
		return false, err
	}
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return false, err
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return false, err
	}
	previous, err := dormantClients(state)
	if err != nil {
		return false, err
	}
	for _, client := range clients {
		if client.Paused {
			continue
		}
		wasDormant, exists := previous[client.ID]
		if !exists || wasDormant == client.RouteReserved(now) {
			return true, nil
		}
	}
	return false, nil
}
