package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

type unavailableProbeAgent struct{ calls int }

func (agent *unavailableProbeAgent) ProbeFast(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.calls++
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, FailureClass: agentapi.FailureInfrastructure, ErrorCode: "probe_runtime_unavailable"}, nil
}
func (agent *unavailableProbeAgent) ProbeFull(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return agent.ProbeFast(ctx, request)
}

func TestQualificationDefersBatchWhenSharedRuntimeIsUnavailable(t *testing.T) {
	specs := make([]qoeCandidateSpec, 20)
	for i := range specs {
		specs[i] = qoeCandidateSpec{name: fmt.Sprint(i), tcp: true, score: 90}
	}
	database, candidates := qoeMonitorStore(t, specs)
	jobs := make([]qualificationJob, 0, len(candidates))
	for _, candidate := range candidates {
		jobs = append(jobs, qualificationJob{candidate: candidate})
	}
	agent := &unavailableProbeAgent{}
	service := QualificationService{Store: database, Agent: agent}
	if err := service.runProbeJobs(context.Background(), time.Unix(1_900_000_000, 0), jobs, tournament.ProbeFull, 1); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 {
		t.Fatalf("runtime outage fanned out to %d nodes", agent.calls)
	}
	states, err := database.ListCandidateProbeStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, state := range states {
		if state.LastErrorCode == "probe_runtime_unavailable" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("specific infrastructure cause stored on %d nodes", count)
	}
}
