package portal

import (
	"github.com/only-hydrat/hydrat/internal/store"
	"testing"
)

func TestProbeCoverageClassifiesSpecificInfrastructureCauses(t *testing.T) {
	for _, code := range []string{"agent_unavailable", "worker_timeout", "probe_runtime_unavailable", "probe_setup_failed", "probe_cleanup_failed", "agent_transport", "agent_deadline", "agent_response_invalid"} {
		if got := probeReason(store.CandidateProbeState{LastErrorCode: code}, ""); got != "infrastructure_error" {
			t.Fatalf("%s classified as %s", code, got)
		}
	}
	if got := probeReason(store.CandidateProbeState{LastErrorCode: "probe_runtime_unavailable"}, "ru_egress_forbidden"); got != "ru_egress_forbidden" {
		t.Fatalf("policy lost precedence: %s", got)
	}
}
