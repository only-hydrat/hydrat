package gateway

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
)

// ConfigureOnionQoE binds measurements to the serving manager, not the isolated
// qualification mirror. Configure once before the agent starts serving requests.
func (p *Prober) ConfigureOnionQoE(serving TorProbeManager, allowed func() bool) {
	p.onionTor = serving
	p.onionAllowed = allowed
}
func (p *Prober) probeOnion(ctx context.Context, r agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	unavailable := func() (agentapi.ProbeResponse, error) {
		return infrastructureProbeFailure(r.CandidateID, "tor_profile_unavailable"), nil
	}
	m, ok := p.qoe.(interface {
		MeasureOnion(context.Context, string, string) qoe.Observation
	})
	if !ok || p.onionTor == nil || p.onionAllowed == nil || !p.onionAllowed() {
		return unavailable()
	}
	before, exists := p.onionTor.ProfileStatus(r.CandidateID)
	if !exists || before.Exited || !before.Profile.OnionReady || before.Profile.Instance == "" || before.Profile.Instance != r.ProfileInstance {
		return unavailable()
	}
	o := m.MeasureOnion(ctx, r.CandidateID, before.Profile.SocksAddr)
	after, exists := p.onionTor.ProfileStatus(r.CandidateID)
	if !exists || after.Exited || after.Profile.Instance != before.Profile.Instance || !after.Profile.OnionReady || !p.onionAllowed() {
		return unavailable()
	}
	response := qoeProbeResponse(r.CandidateID, o)
	response.ProfileInstance = before.Profile.Instance
	return response, nil
}
