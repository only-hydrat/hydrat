package controller

import (
	"context"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

const qoeComparisonMaxAge = 30 * time.Second
const qoeComparisonEntries = 64

type qoeComparison struct {
	candidate  store.Candidate
	generation int64
	at         time.Time
	policy     string
	checks     []qoe.HTTPCheck
	version    uint64
}

// Unknown identities are not independent controls. In particular, two labels
// for one subscription endpoint must never corroborate each other.
func independentQoERoutes(a, b store.Candidate) bool {
	return a.ID != b.ID && a.Fingerprint != "" && b.Fingerprint != "" && a.Fingerprint != b.Fingerprint &&
		a.RouteKey != "" && b.RouteKey != "" && a.RouteKey != b.RouteKey &&
		a.FailureDomain != "" && b.FailureDomain != "" && a.FailureDomain != b.FailureDomain
}

func (monitor *QoEMonitor) forgetComparison(id string) {
	monitor.mu.Lock()
	delete(monitor.comparisons, id)
	monitor.mu.Unlock()
}

func (monitor *QoEMonitor) rememberComparison(candidate store.Candidate, generation int64, observation qoe.Observation, at time.Time) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.comparisons == nil {
		monitor.comparisons = make(map[string]qoeComparison)
	}
	delete(monitor.comparisons, candidate.ID)
	if observation.ComparisonPolicy == "" || len(observation.ComparisonPolicy) > 64 || len(observation.ApplicationChecks) == 0 {
		return
	}
	if len(monitor.comparisons) >= qoeComparisonEntries {
		oldestID := ""
		var oldest time.Time
		for id, entry := range monitor.comparisons {
			if oldestID == "" || entry.at.Before(oldest) {
				oldestID, oldest = id, entry.at
			}
		}
		delete(monitor.comparisons, oldestID)
	}
	var checks []qoe.HTTPCheck
	for _, check := range qoe.SafeHTTPChecks(observation.ApplicationChecks) {
		if check.Path == "route" {
			checks = append(checks, check)
		}
	}
	monitor.comparisonVersion++
	monitor.comparisons[candidate.ID] = qoeComparison{candidate: candidate, generation: generation, at: at, policy: observation.ComparisonPolicy, checks: checks[:min(16, len(checks))], version: monitor.comparisonVersion}
	if observation.Success {
		delete(monitor.controlRequests, candidate.ID)
	}
}

func routedQoEOutcomes(checks []qoe.HTTPCheck) map[string]bool {
	result := make(map[string]bool)
	for _, check := range checks {
		if check.Path != "route" {
			continue
		}
		// A duplicate service is conservatively false, not last-writer-wins.
		previous, exists := result[check.Service]
		result[check.Service] = check.OK && (!exists || previous)
	}
	return result
}

func confirmsHTTPFailure(target qoe.Observation, checks []qoe.HTTPCheck) bool {
	failed, peer := routedQoEOutcomes(target.ApplicationChecks), routedQoEOutcomes(checks)
	routeFailure := func(service string) bool {
		seen := false
		for _, check := range target.ApplicationChecks {
			if check.Path != "route" || check.Service != service {
				continue
			}
			seen = true
			if check.OK {
				return false
			}
			switch check.Code {
			case "timeout", "dns", "tls", "transport", "body", "http_status":
			default:
				return false
			}
		}
		return seen
	}
	if target.ErrorCode != qoe.ReasonApplicationGates {
		return routeFailure("qoe_endpoint") && peer["qoe_endpoint"]
	}
	for _, service := range []string{"youtube", "telegram"} {
		if routeFailure(service) && peer[service] {
			return true
		}
	}
	// Preserve YouTube && Telegram && (ChatGPT || OpenAI), not a majority.
	aiFailed := !failed["chatgpt"] && !failed["openai"]
	_, hasChatGPT := failed["chatgpt"]
	_, hasOpenAI := failed["openai"]
	return aiFailed && hasChatGPT && hasOpenAI && routeFailure("chatgpt") && routeFailure("openai") && (peer["chatgpt"] || peer["openai"])
}

func (monitor *QoEMonitor) compareHTTPFailure(ctx context.Context, candidate store.Candidate, observation qoe.Observation, now time.Time) (bool, []qoe.HTTPCheck, error) {
	if !comparableHTTPFailure(observation) {
		return false, nil, nil
	}
	monitor.mu.Lock()
	entries := make([]qoeComparison, 0, len(monitor.comparisons))
	for _, entry := range monitor.comparisons {
		if entry.policy == observation.ComparisonPolicy && !entry.at.After(now) && now.Sub(entry.at) <= qoeComparisonMaxAge && independentQoERoutes(candidate, entry.candidate) {
			entries = append(entries, entry)
		}
	}
	monitor.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].at.Equal(entries[j].at) {
			return entries[i].candidate.ID < entries[j].candidate.ID
		}
		return entries[i].at.After(entries[j].at)
	})
	if len(entries) == 0 {
		return false, nil, nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.candidate.ID)
	}
	snapshot, err := monitor.Store.LoadRoutingReferencesSnapshot(ctx, ids)
	if err != nil {
		return false, nil, err
	}
	current := make(map[string]store.CandidateRoutingEvidence, len(snapshot.Candidates))
	for _, row := range snapshot.Candidates {
		current[row.Candidate.ID] = row
	}
	var selected []store.Candidate
	var controlChecks []qoe.HTTPCheck
	for _, entry := range entries {
		row, exists := current[entry.candidate.ID]
		if !exists || row.Candidate.Fingerprint != entry.candidate.Fingerprint || row.Candidate.RouteKey != entry.candidate.RouteKey || row.Candidate.FailureDomain != entry.candidate.FailureDomain || row.FailureGeneration != entry.generation ||
			!row.Health.Available || row.Health.ActiveHardFailure || !row.Health.TCPQualified || !row.HasProbe || row.Probe.Status != store.CandidateQualified || row.Probe.Stale || !row.Probe.InWorkingPool || row.Probe.Draining || row.QoE.Status == qoe.StatusDegraded || row.FailureDomain.OpenUntil.After(now) {
			continue
		}
		if row.Candidate.Kind == sources.KindTorBridge && !monitor.warmQoEControl(row.Candidate.ID) {
			continue
		}
		independent := true
		for _, other := range selected {
			independent = independent && independentQoERoutes(row.Candidate, other)
		}
		if !independent {
			continue
		}
		// Another worker may have replaced this control during the DB read.
		monitor.mu.Lock()
		latest, exists := monitor.comparisons[entry.candidate.ID]
		stillCurrent := exists && latest.version == entry.version
		monitor.mu.Unlock()
		if !stillCurrent {
			continue
		}
		selected = append(selected, row.Candidate)
		controlChecks = append([]qoe.HTTPCheck(nil), entry.checks...)
		for i := range controlChecks {
			controlChecks[i].Path = "control"
		}
		if confirmsHTTPFailure(observation, entry.checks) {
			return true, controlChecks, nil
		}
		if len(selected) == 2 {
			break
		}
	}
	return false, controlChecks, nil
}

func comparableHTTPFailure(observation qoe.Observation) bool {
	if !observation.UnconfirmedHTTP || observation.Success || observation.ComparisonPolicy == "" || len(observation.ComparisonPolicy) > 64 {
		return false
	}
	switch observation.ErrorCode {
	case qoe.ReasonRouteTimeout, qoe.ReasonRouteTLS, qoe.ReasonRouteTransport, qoe.ReasonApplicationGates, "qoe_endpoint_http", "qoe_endpoint_size":
		return true
	default:
		return false
	}
}

func (monitor *QoEMonitor) warmQoEControl(id string) bool {
	if monitor.Profiles == nil {
		return false
	}
	for _, profile := range monitor.Profiles.Profiles() {
		if profile.CandidateID == id && profile.Role == "warm" && !profile.Retiring {
			return true
		}
	}
	return false
}

func (monitor *QoEMonitor) requestQoEControl(candidate store.Candidate, at time.Time) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.controlRequests == nil {
		monitor.controlRequests = make(map[string]time.Time)
	}
	if len(monitor.controlRequests) < qoeComparisonEntries {
		monitor.controlRequests[candidate.ID] = at
	}
}

// Controls are ordinary jobs admitted to the same 4 workers and 3:1 lanes.
// No probe waits for another job, no recursive control, no retrospective fail.
func (monitor *QoEMonitor) requestedQoEControls(now time.Time, candidates map[string]store.Candidate, qualified func(string) bool) map[string]bool {
	monitor.mu.Lock()
	requests := make([]string, 0, len(monitor.controlRequests))
	for id, at := range monitor.controlRequests {
		if at.After(now) || now.Sub(at) > time.Minute {
			delete(monitor.controlRequests, id)
		} else {
			requests = append(requests, id)
		}
	}
	monitor.mu.Unlock()
	sort.Strings(requests)
	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	selected := make(map[string]bool)
	var routes []store.Candidate
	for _, targetID := range requests {
		target, exists := candidates[targetID]
		if !exists {
			continue
		}
		for _, id := range ids {
			control := candidates[id]
			if !qualified(id) || !independentQoERoutes(target, control) || control.Kind == sources.KindTorBridge && !monitor.warmQoEControl(id) {
				continue
			}
			independent := true
			for _, other := range routes {
				independent = independent && independentQoERoutes(control, other)
			}
			if !independent {
				continue
			}
			selected[id] = true
			routes = append(routes, control)
			if len(routes) == 2 {
				return selected
			}
		}
	}
	return selected
}
