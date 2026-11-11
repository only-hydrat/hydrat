package gateway

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"testing"
)

type onionMeasureFunc func(context.Context, string, string) qoe.Observation

func (f onionMeasureFunc) Measure(context.Context, string, string) qoe.Observation {
	panic("ordinary measure used")
}
func (f onionMeasureFunc) MeasureOnion(c context.Context, id, a string) qoe.Observation {
	return f(c, id, a)
}
func TestOnionQoEUsesServingInstanceAndRejectsReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "serving", true: "replacement"}[replace], func(t *testing.T) {
			p := torpool.Profile{CandidateID: "bridge", Instance: "process-a", Role: "warm", OnionReady: true, SocksAddr: "serving"}
			serving := newMutableTorProbeManager(p)
			prober := &Prober{tor: newMutableTorProbeManager(torpool.Profile{SocksAddr: "mirror"}), onionTor: serving, onionAllowed: func() bool { return true }}
			prober.qoe = onionMeasureFunc(func(_ context.Context, _, addr string) qoe.Observation {
				if addr != "serving" {
					t.Errorf("wrong process %s", addr)
				}
				if replace {
					p.Instance = "process-b"
					serving.replaceProfile(p)
				}
				return qoe.Observation{Success: true}
			})
			r, err := prober.Probe(t.Context(), agentapi.ProbeModeQoE, agentapi.ProbeRequest{CandidateID: "bridge", Kind: sources.KindTorBridge, Onion: true, ProfileInstance: "process-a"})
			if err != nil {
				t.Fatal(err)
			}
			if replace {
				if r.FailureClass != agentapi.FailureInfrastructure {
					t.Fatal("stale sample accepted", r)
				}
			} else if !r.Success || r.ProfileInstance != "process-a" {
				t.Fatal(r)
			}
		})
	}
}
func TestOnionQoEWithoutDemandDoesNotProbe(t *testing.T) {
	p := &Prober{onionAllowed: func() bool { return false }, qoe: onionMeasureFunc(func(context.Context, string, string) qoe.Observation {
		t.Fatal("probe without demand")
		return qoe.Observation{}
	})}
	r, _ := p.Probe(t.Context(), agentapi.ProbeModeQoE, agentapi.ProbeRequest{CandidateID: "bridge", Kind: sources.KindTorBridge, Onion: true})
	if r.FailureClass != agentapi.FailureInfrastructure {
		t.Fatal(r)
	}
}
