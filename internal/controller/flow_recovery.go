package controller

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

type flowRecoveryAgent interface {
	ApplyWithRecovery(context.Context, dataplane.DesiredPlan, []dataplane.FlowRecovery) error
}

// The persisted trigger, not a caller's current cycle reason, fences retries.
// Recovery scopes remain an ephemeral API envelope: DesiredPlan/DB semantics
// stay compatible with a controller rollback.
func confirmedFlowRecoveries(state store.PlanState, next dataplane.DesiredPlan) ([]dataplane.FlowRecovery, error) {
	if state.DesiredGeneration != next.Generation || state.AppliedGeneration == 0 ||
		state.AppliedGeneration >= next.Generation || state.DesiredReason != string(PlacementHardFailure) {
		return nil, nil
	}
	previous, _, err := decodePersistedPlan("applied", state.AppliedGeneration, state.AppliedPlan)
	if err != nil {
		return nil, err
	}
	oldRoutes := make(map[string]dataplane.ClientRoute, len(previous.Clients))
	for _, route := range previous.Clients {
		oldRoutes[route.ClientID] = route
	}
	var scopes []dataplane.FlowRecovery
	for _, route := range next.Clients {
		old, ok := oldRoutes[route.ClientID]
		if !ok || old.SourceCIDR != route.SourceCIDR || old.BlockTCP || route.BlockTCP ||
			old.TCPOutbound == "" || route.TCPOutbound == "" || old.TCPOutbound == route.TCPOutbound {
			continue
		}
		scopes = append(scopes, dataplane.FlowRecovery{ClientID: route.ClientID, SourceCIDR: route.SourceCIDR,
			FailedOutbound: old.TCPOutbound, ReplacementOutbound: route.TCPOutbound})
	}
	return scopes, nil
}

// A lifecycle reconciliation can move another client's healthy route in the
// same generation. A hard reason alone must not reset that client's sessions.
func (engine *Engine) fenceFlowRecoveries(ctx context.Context, scopes []dataplane.FlowRecovery) ([]dataplane.FlowRecovery, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	debt, err := engine.store.PendingRouteRecoveries(ctx)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	for _, scope := range scopes {
		ids[candidateIDFromHandler(scope.FailedOutbound, scope.ClientID)] = true
	}
	references := make([]string, 0, len(ids))
	for id := range ids {
		if id != "" {
			references = append(references, id)
		}
	}
	evidence, err := engine.store.LoadRoutingReferencesSnapshot(ctx, references)
	if err != nil {
		return nil, err
	}
	confirmed := make(map[string]bool, len(evidence.Candidates))
	for _, row := range evidence.Candidates {
		confirmed[row.Candidate.ID] = row.Health.ActiveCurrent && row.Health.ActiveHardFailure
	}
	var result []dataplane.FlowRecovery
	for _, scope := range scopes {
		failed := confirmed[candidateIDFromHandler(scope.FailedOutbound, scope.ClientID)]
		for _, job := range debt {
			if job.Transport == store.RouteTransportTCP && job.ClientID == scope.ClientID && job.SourceCIDR == scope.SourceCIDR && job.FailedOutbound == scope.FailedOutbound {
				failed = true
				break
			}
		}
		if failed {
			result = append(result, scope)
		}
	}
	return result, nil
}
