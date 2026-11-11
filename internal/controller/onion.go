package controller

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
	"sort"
	"time"
)

// Onion uses existing warm profiles but a separate per-client SOCKS identity.
// Retain healthy streams; throughput changes do not trigger onion migration.
func (e *Engine) attachOnion(route *dataplane.ClientRoute, client store.ClientRecord, previous dataplane.ClientRoute, candidates []scheduler.Candidate, profiles map[string]torpool.Profile, out map[string]dataplane.Outbound, quality map[string]store.OnionQoEState, now time.Time) {
	route.OnionEnabled = client.OnionEnabled && !client.Paused
	route.OnionOutbound = ""
	route.OnionReserveOutbound = ""
	if !route.OnionEnabled {
		return
	}
	eligible := make([]scheduler.Candidate, 0, len(profiles))
	for _, c := range candidates {
		p, ok := profiles[c.ID]
		if ok && p.OnionReady && p.Role == "warm" && !p.Retiring && c.Protocol == scheduler.ProtocolTor && c.TCPQualified && !c.CircuitOpen && !c.Retiring && !c.ServingOnly {
			eligible = append(eligible, c)
		}
	}
	identity := "onion-" + client.ID
	tag := func(c scheduler.Candidate) string {
		return torProfileOutboundID(c.ID, profiles[c.ID], identity)
	}
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		ar, at := onionQualityRank(quality[a.ID], profiles[a.ID].Instance, now)
		br, bt := onionQualityRank(quality[b.ID], profiles[b.ID].Instance, now)
		// Keep a healthy or unproven serving route; a confirmed bad window permits
		// migration. Reserve selection always prefers complete fresh evidence.
		if tag(a) == previous.OnionOutbound && ar != 2 {
			return true
		}
		if tag(b) == previous.OnionOutbound && br != 2 {
			return false
		}
		if ar != br {
			return ar < br
		}
		if ar == 0 && at != bt {
			return at < bt
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})
	for i, c := range eligible {
		if i == 2 {
			break
		}
		id := tag(c)
		config := xrayconfig.TorOutbound(profiles[c.ID].SocksAddr, id, identity, e.torSecret)
		encoded, _ := json.Marshal(config)
		out[id] = dataplane.Outbound{ID: id, Protocol: dataplane.ProtocolTor, Config: encoded}
		if i == 0 {
			route.OnionOutbound = id
		} else {
			route.OnionReserveOutbound = id
		}
	}
}
func decodeClientRoutes(encoded []byte) map[string]dataplane.ClientRoute {
	var p dataplane.DesiredPlan
	_ = json.Unmarshal(encoded, &p)
	result := map[string]dataplane.ClientRoute{}
	for _, r := range p.Clients {
		result[r.ClientID] = r
	}
	return result
}

func (e *Engine) clientPermissionsCurrent(ctx context.Context, plan dataplane.DesiredPlan) (bool, error) {
	clients, err := e.store.ListClients(ctx)
	if err != nil {
		return false, err
	}
	allowed := make(map[string]bool, len(clients))
	i2pAllowed := make(map[string]bool, len(clients))
	for _, client := range clients {
		allowed[client.ID] = client.OnionEnabled && !client.Paused
		i2pAllowed[client.ID] = client.I2PEnabled && !client.Paused
	}
	for _, route := range plan.Clients {
		if route.OnionEnabled != allowed[route.ClientID] || route.I2PEnabled != i2pAllowed[route.ClientID] {
			return false, nil
		}
	}
	return true, nil
}

// Onion-only profiles share the existing bounded prospective probe lane.
// They must not consume the reserved critical capacity for ordinary traffic.
// Applied plans reference at most the four materialized Tor profiles, shared
// across clients; each candidate is probed once regardless of client count.
func appendOnionActiveTargets(ctx context.Context, db *store.Store, applied []byte, targets []ActiveTarget) ([]ActiveTarget, error) {
	references := make(map[string]bool)
	for _, route := range decodeClientRoutes(applied) {
		if !route.OnionEnabled {
			continue
		}
		for _, handler := range []string{route.OnionOutbound, route.OnionReserveOutbound} {
			if id := candidateIDFromHandler(handler, "onion-"+route.ClientID); id != "" {
				references[id] = true
			}
		}
	}
	for _, target := range targets {
		delete(references, target.Candidate.ID)
	}
	if len(references) == 0 {
		return targets, nil
	}
	ids := make([]string, 0, len(references))
	for id := range references {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	candidates, err := db.ListRoutableCandidates(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if references[candidate.ID] && candidate.Kind == sources.KindTorBridge {
			targets = append(targets, ActiveTarget{Candidate: candidate, Role: ActiveTargetProspective})
		}
	}
	return targets, nil
}

func (e *Engine) hasPrivateAccessPolicy(ctx context.Context) (bool, error) {
	state, err := e.store.LoadPlanState(ctx)
	if err != nil {
		return false, err
	}
	if state.AppliedGeneration == 0 {
		return false, nil
	}
	for _, r := range decodeClientRoutes(state.AppliedPlan) {
		if r.OnionEnabled || r.OnionOutbound != "" || r.I2PEnabled || r.I2POutbound != "" {
			return true, nil
		}
	}
	clients, err := e.store.ListClients(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range clients {
		if (c.OnionEnabled || c.I2PEnabled) && !c.Paused {
			return true, nil
		}
	}
	return false, nil
}

func prunePrivateHandlers(plan *dataplane.DesiredPlan, previous map[string]dataplane.ClientRoute, outbounds map[string]dataplane.Outbound) {
	used := map[string]bool{}
	for _, r := range plan.Clients {
		for _, id := range []string{r.I2POutbound, r.OnionOutbound, r.OnionReserveOutbound, r.TCPOutbound, r.UDPOutbound, r.TCPReserveOutbound, r.UDPReserveOutbound, r.DNSOutbound} {
			used[id] = true
		}
	}
	obsolete := map[string]bool{}
	for _, r := range previous {
		for _, id := range []string{r.I2POutbound, r.OnionOutbound, r.OnionReserveOutbound} {
			if id != "" && !used[id] {
				obsolete[id] = true
				delete(outbounds, id)
			}
		}
	}
	kept := make([]dataplane.Outbound, 0, len(plan.Outbounds))
	for _, o := range plan.Outbounds {
		if !obsolete[o.ID] {
			kept = append(kept, o)
		}
	}
	plan.Outbounds = kept
}
