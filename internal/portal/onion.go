package portal

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

func (s *Server) appliedClientRoutes(ctx context.Context) map[string]dataplane.ClientRoute {
	result := map[string]dataplane.ClientRoute{}
	state, err := s.store.LoadPlanState(ctx)
	if err != nil {
		return result
	}
	var plan dataplane.DesiredPlan
	if json.Unmarshal(state.AppliedPlan, &plan) != nil {
		return result
	}
	for _, r := range plan.Clients {
		result[r.ClientID] = r
	}
	return result
}
func onionStatus(c store.ClientRecord, routes map[string]dataplane.ClientRoute) string {
	r := routes[c.ID]
	if !c.OnionEnabled || c.Paused {
		if r.OnionOutbound != "" {
			return "disabling"
		}
		return "disabled"
	}
	if !r.OnionEnabled {
		return "pending"
	}
	if r.OnionOutbound == "" {
		return "unavailable"
	}
	return "ready"
}
