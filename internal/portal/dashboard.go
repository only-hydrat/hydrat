package portal

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

//go:embed web/*
var dashboardFiles embed.FS

func (server *Server) dashboard(response http.ResponseWriter, _ *http.Request) {
	content, err := dashboardFiles.ReadFile("web/index.html")
	if err != nil {
		writeError(response, http.StatusInternalServerError, "dashboard unavailable")
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = response.Write(content)
}

func (server *Server) asset(response http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if name != "app.js" && name != "styles.css" {
		http.NotFound(response, request)
		return
	}
	content, err := fs.ReadFile(dashboardFiles, "web/"+name)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	if name == "app.js" {
		response.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	} else {
		response.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	response.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = response.Write(content)
}

type candidateView struct {
	store.Candidate
	State  *store.CandidateProbeState `json:"state,omitempty"`
	Health *store.CandidateHealth     `json:"health,omitempty"`
	QoE    *candidateQoEView          `json:"qoe,omitempty"`
}

type candidateQoEView struct {
	Status                 qoe.Status `json:"status"`
	TTFBMS                 float64    `json:"ttfb_ms"`
	ThroughputMbps         float64    `json:"throughput_mbps"`
	BaselineTTFBMS         float64    `json:"baseline_ttfb_ms"`
	BaselineThroughputMbps float64    `json:"baseline_throughput_mbps"`
	WindowValid            int        `json:"window_valid"`
	WindowBad              int        `json:"window_bad"`
	LastValidAt            *time.Time `json:"last_valid_at,omitempty"`
	LastReason             string     `json:"last_reason,omitempty"`
}

func (server *Server) listCandidates(response http.ResponseWriter, request *http.Request) {
	limit := boundedQueryInt(request, "limit", 100, 1, 200)
	offset := boundedQueryInt(request, "offset", 0, 0, 1_000_000)
	statusFilter := strings.TrimSpace(request.URL.Query().Get("status"))
	kindFilter := strings.TrimSpace(request.URL.Query().Get("kind"))
	search := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("q")))

	candidates, err := server.store.ListCandidates(request.Context(), "")
	if err != nil {
		writeError(response, http.StatusInternalServerError, "candidate list failed")
		return
	}
	states, err := server.store.ListCandidateProbeStates(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "candidate state list failed")
		return
	}
	healthRows, err := server.store.ListCandidateHealth(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "candidate health list failed")
		return
	}
	qoeStates, err := server.store.ListCandidateQoEStates(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "candidate QoE state list failed")
		return
	}
	stateByFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		stateByFingerprint[state.Fingerprint] = state
	}
	healthByID := make(map[string]store.CandidateHealth, len(healthRows))
	for _, health := range healthRows {
		healthByID[health.CandidateID] = health
	}
	qoeByID := make(map[string]qoe.State, len(qoeStates))
	for _, state := range qoeStates {
		qoeByID[state.CandidateID] = state
	}
	filtered := make([]candidateView, 0, len(candidates))
	for _, candidate := range candidates {
		state, hasState := stateByFingerprint[candidate.Fingerprint]
		health, hasHealth := healthByID[candidate.ID]
		qoeState, hasQoE := qoeByID[candidate.ID]
		if statusFilter != "" && (!hasState || string(state.Status) != statusFilter) {
			continue
		}
		if kindFilter != "" && string(candidate.Kind) != kindFilter {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(candidate.Label+" "+candidate.Fingerprint), search) {
			continue
		}
		view := candidateView{Candidate: candidate}
		if hasState {
			stateCopy := state
			stateCopy.LastErrorMessage = ""
			view.State = &stateCopy
		}
		if hasHealth {
			healthCopy := health
			view.Health = &healthCopy
		}
		if hasQoE {
			view.QoE = qoeView(qoeState)
		}
		filtered = append(filtered, view)
	}
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"candidates": filtered[offset:end], "total": total, "offset": offset, "limit": limit,
	})
}

func qoeView(state qoe.State) *candidateQoEView {
	view := &candidateQoEView{
		Status:                 state.Status,
		TTFBMS:                 float64(state.CurrentTTFB) / float64(time.Millisecond),
		ThroughputMbps:         state.CurrentThroughputMbps,
		BaselineTTFBMS:         float64(state.BaselineTTFB) / float64(time.Millisecond),
		BaselineThroughputMbps: state.BaselineThroughputMbps,
		WindowValid:            state.WindowValid,
		WindowBad:              state.WindowBad,
		LastReason:             state.LastReason,
	}
	if !state.LastValidAt.IsZero() {
		lastValidAt := state.LastValidAt
		view.LastValidAt = &lastValidAt
	}
	return view
}

func (server *Server) systemSummary(response http.ResponseWriter, request *http.Request) {
	clients, clientsErr := server.store.ListClients(request.Context())
	sources, sourcesErr := server.store.ListSources(request.Context())
	candidates, candidatesErr := server.store.ListCandidates(request.Context(), "")
	states, statesErr := server.store.ListCandidateProbeStates(request.Context())
	healthRows, healthErr := server.store.ListCandidateHealth(request.Context())
	domainStates, domainStatesErr := server.store.ListFailureDomainStates(request.Context())
	qoeStates, qoeStatesErr := server.store.ListCandidateQoEStates(request.Context())
	events, eventsErr := server.store.ListEvents(request.Context(), 100)
	if err := errors.Join(
		clientsErr, sourcesErr, candidatesErr, statesErr, healthErr,
		domainStatesErr, qoeStatesErr, eventsErr,
	); err != nil {
		writeError(response, http.StatusInternalServerError, "system summary failed")
		return
	}
	statuses, working, draining := candidateProbeSummary(candidates, states)
	workingByKind, effective := effectiveRouteCapacity(
		time.Now(), candidates, states, healthRows, domainStates,
		server.profileList(),
	)
	qoeStatuses := candidateQoEStatuses(candidates, qoeStates)
	recentMigrations := make([]store.Event, 0, 20)
	for _, event := range events {
		if event.Kind != "assignment.migrated" {
			continue
		}
		recentMigrations = append(recentMigrations, event)
		if len(recentMigrations) == 20 {
			break
		}
	}
	runtimeSnapshot := proberuntime.Snapshot{Status: "unavailable"}
	activeRuntimeSnapshot := proberuntime.Snapshot{Status: "unavailable"}
	if server.probeRuntime != nil {
		if snapshot, err := server.probeRuntime.ProbeRuntimeHealth(
			request.Context(),
		); err == nil {
			runtimeSnapshot = snapshot
		}
		if provider, ok := server.probeRuntime.(ActiveProbeRuntimeHealthProvider); ok {
			if snapshot, err := provider.ActiveProbeRuntimeHealth(
				request.Context(),
			); err == nil {
				activeRuntimeSnapshot = snapshot
			}
		}
	}
	desired, applied, err := server.store.PlanGenerations(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "plan state failed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "ok", "client_count": len(clients), "source_count": len(sources),
		"candidate_count": len(candidates), "working_pool_count": working,
		"draining_count": draining, "candidate_statuses": statuses,
		"working_pool_by_kind": workingByKind,
		"effective_capacity":   effective,
		"probe_runtime":        runtimeSnapshot,
		"active_probe_runtime": activeRuntimeSnapshot,
		"qoe_statuses":         qoeStatuses,
		"recent_migrations":    recentMigrations,
		"desired_generation":   desired, "applied_generation": applied,
	})
}

type effectiveCapacity struct {
	VLESSFailureDomains int `json:"vless_failure_domains"`
	TorWarmProfiles     int `json:"tor_warm_profiles"`
}

func (server *Server) profileList() []torpool.Profile {
	if server.profiles == nil {
		return nil
	}
	return server.profiles.Profiles()
}

func effectiveRouteCapacity(
	now time.Time,
	candidates []store.Candidate,
	states []store.CandidateProbeState,
	healthRows []store.CandidateHealth,
	domainStates []store.FailureDomainState,
	profiles []torpool.Profile,
) (map[string]int, effectiveCapacity) {
	workingByKind := map[string]int{
		string(sources.KindVLESS):     0,
		string(sources.KindTorBridge): 0,
	}
	stateByFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		stateByFingerprint[state.Fingerprint] = state
	}
	healthByCandidate := make(map[string]store.CandidateHealth, len(healthRows))
	for _, health := range healthRows {
		healthByCandidate[health.CandidateID] = health
	}
	openDomains := make(map[string]bool, len(domainStates))
	for _, state := range domainStates {
		if state.OpenUntil.After(now) {
			openDomains[state.Domain] = true
		}
	}
	effectiveDomains := make(map[string]struct{})
	for _, candidate := range candidates {
		state, exists := stateByFingerprint[candidate.Fingerprint]
		if !exists || !state.InWorkingPool {
			continue
		}
		workingByKind[string(candidate.Kind)]++
		if candidate.Kind != sources.KindVLESS ||
			candidate.FailureDomain == "" ||
			openDomains[candidate.FailureDomain] {
			continue
		}
		health, healthy := healthByCandidate[candidate.ID]
		if healthy && health.Available {
			effectiveDomains[candidate.FailureDomain] = struct{}{}
		}
	}
	capacity := effectiveCapacity{
		VLESSFailureDomains: len(effectiveDomains),
	}
	for _, profile := range profiles {
		if profile.Role == "warm" && !profile.Retiring {
			capacity.TorWarmProfiles++
		}
	}
	return workingByKind, capacity
}

func candidateProbeSummary(
	candidates []store.Candidate,
	states []store.CandidateProbeState,
) (map[string]int, int, int) {
	statuses := map[string]int{
		string(store.CandidateUnknown):   0,
		string(store.CandidatePreflight): 0,
		string(store.CandidateProbing):   0,
		string(store.CandidateQualified): 0,
		string(store.CandidateBanned):    0,
		string(store.CandidateDraining):  0,
	}
	byFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		byFingerprint[state.Fingerprint] = state
	}
	working := 0
	draining := 0
	for _, candidate := range candidates {
		state, exists := byFingerprint[candidate.Fingerprint]
		status := store.CandidateUnknown
		if exists {
			if _, supported := statuses[string(state.Status)]; supported {
				status = state.Status
			}
			if state.InWorkingPool {
				working++
			}
			if state.Draining {
				draining++
			}
		}
		statuses[string(status)]++
	}
	return statuses, working, draining
}

func candidateQoEStatuses(candidates []store.Candidate, states []qoe.State) map[string]int {
	statuses := map[string]int{
		string(qoe.StatusLearning): 0,
		string(qoe.StatusHealthy):  0,
		string(qoe.StatusDegraded): 0,
	}
	stateByCandidateID := make(map[string]qoe.Status, len(states))
	for _, state := range states {
		stateByCandidateID[state.CandidateID] = state.Status
	}
	for _, candidate := range candidates {
		status := stateByCandidateID[candidate.ID]
		if _, known := statuses[string(status)]; !known {
			status = qoe.StatusLearning
		}
		statuses[string(status)]++
	}
	return statuses
}

func boundedQueryInt(request *http.Request, name string, fallback, minimum, maximum int) int {
	value := request.URL.Query().Get(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum {
		return fallback
	}
	if parsed > maximum {
		return maximum
	}
	return parsed
}
