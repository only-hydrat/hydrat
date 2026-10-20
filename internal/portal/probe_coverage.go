package portal

import (
	"context"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/store"
)

func (server *Server) policyExclusions(ctx context.Context) (map[string]string, error) {
	if server.routing == nil {
		return map[string]string{}, nil
	}
	routing, err := server.routing.GetRouting(ctx)
	if err != nil {
		return nil, err
	}
	return server.store.CandidatePolicyExclusions(ctx, routing.DisallowRUEgress)
}

func probeReason(state store.CandidateProbeState, excluded string) string {
	if excluded != "" {
		return excluded
	}
	if agentapi.IsProbeInfrastructureCode(state.LastErrorCode) {
		return "infrastructure_error"
	}
	if state.LastFastProbeAt.IsZero() && state.LastFullProbeAt.IsZero() {
		return "never_attempted"
	}
	if state.LastErrorCode != "" {
		return "candidate_failed"
	}
	if state.Status == store.CandidateQualified && !state.Stale {
		return "qualified"
	}
	return "awaiting_qualification"
}

func probeCoverage(now time.Time, candidates []store.Candidate, states []store.CandidateProbeState, excluded map[string]string) map[string]int {
	byFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		byFingerprint[state.Fingerprint] = state
	}
	result := map[string]int{"excluded_policy": 0, "never_attempted": 0, "infrastructure_error": 0, "candidate_failed": 0, "awaiting_qualification": 0, "qualified": 0, "fast_checked_5h": 0, "full_checked_5h": 0}
	for _, candidate := range candidates {
		state := byFingerprint[candidate.Fingerprint]
		reason := probeReason(state, excluded[candidate.ID])
		if excluded[candidate.ID] != "" {
			result["excluded_policy"]++
			continue
		}
		result[reason]++
		if !state.LastFastProbeAt.Before(now.Add(-5*time.Hour)) && !state.LastFastProbeAt.After(now) {
			result["fast_checked_5h"]++
		}
		if !state.LastFullProbeAt.Before(now.Add(-5*time.Hour)) && !state.LastFullProbeAt.After(now) {
			result["full_checked_5h"]++
		}
	}
	return result
}
