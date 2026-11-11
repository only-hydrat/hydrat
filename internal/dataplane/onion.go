package dataplane

// OnionPolicy returns a consistent applied policy; desired DB changes never
// grant DNS access before routing is applied.
func (r *Reconciler) OnionPolicy() []ClientRoute {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.runtimeReady || r.recoveryRequired.Load() {
		return nil
	}
	return append([]ClientRoute(nil), r.applied.Clients...)
}

func onionRecoveries(old, next DesiredPlan) []FlowRecovery {
	var scopes []FlowRecovery
	current := make(map[string]ClientRoute, len(next.Clients))
	for _, r := range next.Clients {
		current[r.ClientID] = r
	}
	for _, r := range old.Clients {
		if r.OnionOutbound == "" {
			continue
		}
		n, exists := current[r.ClientID]
		if exists && (n.SourceCIDR != r.SourceCIDR || n.OnionOutbound == r.OnionOutbound) {
			continue
		}
		scopes = append(scopes, FlowRecovery{Onion: true, ClientID: r.ClientID, SourceCIDR: r.SourceCIDR, FailedOutbound: r.OnionOutbound, ReplacementOutbound: n.OnionOutbound})
	}
	return scopes
}
