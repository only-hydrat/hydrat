package controller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qualifier"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

func TestQualificationObservationReservationOccursBeforeAgentRPC(t *testing.T) {
	for _, stage := range []tournament.ProbeStage{
		tournament.ProbeFast,
		tournament.ProbeFull,
	} {
		t.Run(string(stage), func(t *testing.T) {
			database, candidates := qualificationStore(t, []store.CandidateInput{{
				Kind: sources.KindVLESS, Label: "candidate", Fingerprint: "candidate",
				Payload: "vless://candidate@example.net:443?security=tls",
			}})
			candidate := candidates["candidate"]
			agent := &reservationInspectingQualificationAgent{
				database: database, candidate: candidate, stage: stage,
			}
			service := QualificationService{Store: database, Agent: agent}
			result := service.executeProbe(
				context.Background(),
				qualificationJob{candidate: candidate, payload: "opaque"},
				stage,
			)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.reservation.Sequence != 1 {
				t.Fatalf("controller reservation=%+v", result.reservation)
			}
			if agent.inside.Sequence != 2 {
				t.Fatalf("agent-side reservation=%+v, controller did not reserve before RPC",
					agent.inside)
			}
		})
	}
}

func TestQualificationObservationBatchCompletesBeforeFirstAgentRPC(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a", Fingerprint: "a",
			Payload: "vless://a@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
			Payload: "vless://b@example.net:443?security=tls",
		},
	})
	ordered := orderedCandidatesByID(candidates)
	agent := &batchInspectingQualificationAgent{
		database: database, candidates: ordered,
	}
	service := QualificationService{Store: database, Agent: agent}
	jobs := make([]qualificationJob, 0, len(ordered))
	for _, candidate := range ordered {
		jobs = append(jobs, qualificationJob{candidate: candidate, payload: "opaque"})
	}
	if err := service.runProbeJobs(
		context.Background(), time.Unix(1_800_000_000, 0),
		jobs, tournament.ProbeFast, 1,
	); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 2 {
		t.Fatalf("agent calls=%d, want 2", agent.calls)
	}
	if len(agent.inside) != 2 {
		t.Fatalf("inside reservations=%+v", agent.inside)
	}
	for _, reservation := range agent.inside {
		if reservation.Sequence != 2 {
			t.Fatalf("first RPC began before full batch reservation: %+v",
				agent.inside)
		}
	}
}

func TestQualificationObservationBatchFailureStartsZeroAgentRPCs(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "stale", Fingerprint: "stale",
			Payload: "vless://stale@example.net:443?security=tls",
		},
	})
	current, stale := candidates["current"], candidates["stale"]
	if err := database.ReplaceCandidates(
		context.Background(), current.SourceID, []store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		}},
	); err != nil {
		t.Fatal(err)
	}
	agent := &countingQualificationAgent{}
	service := QualificationService{Store: database, Agent: agent}
	err := service.runProbeJobs(
		context.Background(), time.Unix(1_800_000_000, 0),
		[]qualificationJob{
			{candidate: current, payload: "current"},
			{candidate: stale, payload: "stale"},
		},
		tournament.ProbeFast,
		1,
	)
	if !errors.Is(err, store.ErrCandidateNoLongerCurrent) {
		t.Fatalf("error=%v, want ErrCandidateNoLongerCurrent", err)
	}
	if agent.calls != 0 {
		t.Fatalf("agent calls=%d after atomic batch failure", agent.calls)
	}
}

func TestVLESSFullProbeOrderingInterleavesFailureDomainsWithinPriority(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a1", Fingerprint: "a1",
			Payload: "vless://a1@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "a2", Fingerprint: "a2",
			Payload: "vless://a2@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "b1", Fingerprint: "b1",
			Payload: "vless://b1@example.net:443?security=tls", FailureDomain: "domain-b",
		},
		{
			Kind: sources.KindVLESS, Label: "c1", Fingerprint: "c1",
			Payload: "vless://c1@example.net:443?security=tls", FailureDomain: "domain-c",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, candidates, now, true)

	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		context.Background(), orderedCandidatesByID(candidates), now.Add(time.Minute),
		tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := qualificationJobFingerprints(jobs), []string{"a1", "b1", "c1", "a2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("full probe order=%v want=%v", got, want)
	}
}

func TestVLESSFullProbeOrderingPreservesPriorityClasses(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a1-success", Fingerprint: "a1-success",
			Payload: "vless://a@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "a2-success", Fingerprint: "a2-success",
			Payload: "vless://a2@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "b1-success", Fingerprint: "b1-success",
			Payload: "vless://b@example.net:443?security=tls", FailureDomain: "domain-b",
		},
		{
			Kind: sources.KindVLESS, Label: "c1-failed", Fingerprint: "c1-failed",
			Payload: "vless://c@example.net:443?security=tls", FailureDomain: "domain-c",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"a1-success": candidates["a1-success"],
		"a2-success": candidates["a2-success"],
		"b1-success": candidates["b1-success"],
	}, now, true)
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"c1-failed": candidates["c1-failed"],
	}, now, false)

	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		context.Background(), orderedCandidatesByID(candidates), now.Add(time.Minute),
		tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := qualificationJobFingerprints(jobs), []string{
		"a1-success", "b1-success", "a2-success", "c1-failed",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("priority order=%v want=%v", got, want)
	}
}

func TestVLESSFullProbeOrderingTreatsMissingDomainsAsDistinct(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a1", Fingerprint: "a1",
			Payload: "vless://a1@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "a2", Fingerprint: "a2",
			Payload: "vless://a2@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "b1", Fingerprint: "b1",
			Payload: "vless://b1@example.net:443?security=tls", FailureDomain: "domain-b",
		},
		{
			Kind: sources.KindVLESS, Label: "b2", Fingerprint: "b2",
			Payload: "vless://b2@example.net:443?security=tls", FailureDomain: "domain-b",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, candidates, now, true)

	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		context.Background(), orderedCandidatesByID(candidates), now.Add(time.Minute),
		tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := qualificationJobFingerprints(jobs), []string{"a1", "a2", "b1", "b2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing-domain order=%v want=%v", got, want)
	}
}

func TestVLESSFastProbeOrderingRemainsTournamentOrder(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a1", Fingerprint: "a1",
			Payload: "vless://a1@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "a2", Fingerprint: "a2",
			Payload: "vless://a2@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "b1", Fingerprint: "b1",
			Payload: "vless://b1@example.net:443?security=tls", FailureDomain: "domain-b",
		},
	})
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		context.Background(), orderedCandidatesByID(candidates),
		time.Unix(1_800_000_000, 0), tournament.ProbeFast,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := qualificationJobFingerprints(jobs), []string{"a1", "a2", "b1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fast probe order=%v want=%v", got, want)
	}
}

func TestDiscoveryJobsPrioritizeAssignedCandidateAndWorkingReserve(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "assigned", Fingerprint: "assigned", Payload: "vless://assigned@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
		{Kind: sources.KindVLESS, Label: "unknown", Fingerprint: "unknown", Payload: "vless://unknown@example.net:443"},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, candidates, now, true)
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "client", Name: "client", Address: "10.44.0.2/32", PublicKey: "key",
	}, "config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "client", TCPOutbound: candidates["assigned"].ID,
		UDPOutbound: candidates["assigned"].ID, TCPSince: now, UDPSince: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
		Fingerprint: candidates["reserve"].Fingerprint,
		CandidateID: candidates["reserve"].ID,
		SourceID:    candidates["reserve"].SourceID,
		Full:        true, Success: true, Score: 80,
		At: now.Add(time.Minute), ResetWindow: 5 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReplaceWorkingPoolCurrent(ctx,
		[]store.Candidate{candidates["reserve"]}, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(ctx, orderedCandidatesByID(candidates), now.Add(2*time.Minute), tournament.ProbeFull)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := qualificationJobFingerprints(jobs), []string{"assigned", "reserve", "unknown"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("qualification order=%v want=%v", got, want)
	}
}

func TestQualificationCycleBoundsAndRotatesUnknownExploration(t *testing.T) {
	inputs := make([]store.CandidateInput, 80)
	for index := range inputs {
		fingerprint := fmt.Sprintf("unknown-%03d", index)
		inputs[index] = store.CandidateInput{
			Kind: sources.KindVLESS, Label: fingerprint, Fingerprint: fingerprint,
			Payload: "vless://" + fingerprint + "@example.net:443",
		}
	}
	database, _ := qualificationStore(t, inputs)
	agent := &recordingExplorationAgent{seen: make(map[string]bool)}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4,
	}
	now := time.Unix(1_800_000_000, 0)
	if err := service.runAgent(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := agent.count(); got != 64 {
		t.Fatalf("first cycle probed %d unknown candidates, want 64", got)
	}
	if err := service.runAgent(context.Background(), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := agent.uniqueCount(); got != 80 {
		t.Fatalf("two cycles reached %d unique candidates, want 80", got)
	}
}

func TestQualificationCycleBoundsAndRotatesFullExploration(t *testing.T) {
	inputs := make([]store.CandidateInput, 40)
	for index := range inputs {
		fingerprint := fmt.Sprintf("unknown-%03d", index)
		inputs[index] = store.CandidateInput{
			Kind: sources.KindVLESS, Label: fingerprint, Fingerprint: fingerprint,
			Payload: "vless://" + fingerprint + "@example.net:443",
		}
	}
	database, candidates := qualificationStore(t, inputs)
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, candidates, now.Add(-time.Hour), false)
	agent := &recordingExplorationAgent{seen: make(map[string]bool)}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4,
	}
	if err := service.runAgent(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := agent.count(); got != 32 {
		t.Fatalf("first cycle fully probed %d unknown candidates, want 32", got)
	}
	if err := service.runAgent(context.Background(), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := agent.uniqueCount(); got != 40 {
		t.Fatalf("two cycles fully probed %d unique candidates, want 40", got)
	}
}

func TestQualificationCycleRotatesWhenAgentUnavailable(t *testing.T) {
	inputs := make([]store.CandidateInput, 80)
	for index := range inputs {
		fingerprint := fmt.Sprintf("unknown-%03d", index)
		inputs[index] = store.CandidateInput{
			Kind: sources.KindVLESS, Label: fingerprint, Fingerprint: fingerprint,
			Payload: "vless://" + fingerprint + "@example.net:443",
		}
	}
	database, _ := qualificationStore(t, inputs)
	agent := &recordingExplorationAgent{
		seen: make(map[string]bool), infrastructure: true,
	}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4,
	}
	now := time.Unix(1_800_000_000, 0)
	if err := service.runAgent(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := service.runAgent(context.Background(), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := agent.uniqueCount(); got != 80 {
		t.Fatalf("agent outage repeatedly selected the same %d candidates, want 80", got)
	}
}

type recordingExplorationAgent struct {
	mu             sync.Mutex
	calls          int
	seen           map[string]bool
	infrastructure bool
}

func (agent *recordingExplorationAgent) ProbeFast(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.calls++
	agent.seen[request.CandidateID] = true
	agent.mu.Unlock()
	if agent.infrastructure {
		return agentapi.ProbeResponse{
			CandidateID:  request.CandidateID,
			FailureClass: agentapi.FailureInfrastructure,
		}, nil
	}
	return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
}

func (agent *recordingExplorationAgent) ProbeFull(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.calls++
	agent.seen[request.CandidateID] = true
	agent.mu.Unlock()
	if agent.infrastructure {
		return agentapi.ProbeResponse{
			CandidateID:  request.CandidateID,
			FailureClass: agentapi.FailureInfrastructure,
		}, nil
	}
	return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
}

func (agent *recordingExplorationAgent) count() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.calls
}

func (agent *recordingExplorationAgent) uniqueCount() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return len(agent.seen)
}

func TestVLESSIndependentDomainsRunBeforeSlowSameDomainTail(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a1", Fingerprint: "a1",
			Payload: "vless://a1@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "a2", Fingerprint: "a2",
			Payload: "vless://a2@example.net:443?security=tls", FailureDomain: "domain-a",
		},
		{
			Kind: sources.KindVLESS, Label: "b1", Fingerprint: "b1",
			Payload: "vless://b1@example.net:443?security=tls", FailureDomain: "domain-b",
		},
		{
			Kind: sources.KindVLESS, Label: "c1", Fingerprint: "c1",
			Payload: "vless://c1@example.net:443?security=tls", FailureDomain: "domain-c",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, candidates, now, true)
	agent := newBlockingVLESSJobsAgent(candidates["a2"].ID)
	service := QualificationService{
		Store: database, Agent: agent, PoolSize: 200,
		PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
	}
	jobs, err := service.discoveryJobs(
		context.Background(), orderedCandidatesByID(candidates), now.Add(time.Minute),
		tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- service.runProbeJobs(
			context.Background(), now.Add(time.Minute), jobs, tournament.ProbeFull, 1,
		)
	}()
	released := false
	defer func() {
		if !released {
			close(agent.release)
			<-done
		}
	}()
	agent.waitStarted(t)
	if got, want := agent.callIDs(), []string{
		candidates["a1"].ID, candidates["b1"].ID,
		candidates["c1"].ID, candidates["a2"].ID,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls before slow same-domain tail=%v want=%v", got, want)
	}
	close(agent.release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQualificationExcludesDrainingCandidateFromFreshWork(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "draining", Fingerprint: "draining",
			Payload: "vless://draining@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "active", Fingerprint: "active",
			Payload: "vless://active@example.net:443?security=tls",
		},
	})
	draining := candidates["draining"]
	if err := database.ReplaceCandidates(
		context.Background(),
		draining.SourceID,
		[]store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "active", Fingerprint: "active",
			Payload: "vless://active@example.net:443?security=tls",
		}},
		15*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	var probed []string
	service := QualificationService{
		Store: database,
		VLESS: vlessQualifierFunc(func(
			_ context.Context,
			inputs []qualifier.Input,
		) []qualifier.Result {
			results := make([]qualifier.Result, 0, len(inputs))
			for _, input := range inputs {
				probed = append(probed, input.ID)
				results = append(results, qualifier.Result{
					CandidateID: input.ID,
					Metrics:     qualifiedMetrics(true),
				})
			}
			return results
		}),
	}
	if err := service.Run(
		context.Background(), time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}
	for _, candidateID := range probed {
		if candidateID == draining.ID {
			t.Fatalf("draining candidate received fresh qualification: %v", probed)
		}
	}
}

func TestQualificationObservationLegacyVLESSReservesBeforeQualifyRPC(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "candidate", Fingerprint: "candidate",
		Payload:       "vless://candidate@example.net:443?security=tls",
		FailureDomain: "domain-hash",
	}})
	candidate := candidates["candidate"]
	base := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidate.ID, Score: 91, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	metrics := qualifiedMetrics(true)
	service := QualificationService{
		Store: database,
		VLESS: vlessQualifierFunc(func(
			ctx context.Context,
			inputs []qualifier.Input,
		) []qualifier.Result {
			active, err := database.ReserveCandidateObservation(
				ctx, candidate, store.ObservationActive,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
				ctx, candidate, active, base.Add(time.Second),
			); err != nil || !commit.Accepted {
				t.Fatalf("hard failure commit=%+v err=%v", commit, err)
			}
			return []qualifier.Result{{
				CandidateID: candidate.ID, Metrics: metrics,
				Evaluation: health.Evaluate(metrics, health.ProtocolVLESS),
			}}
		}),
	}
	if err := service.Run(context.Background(), base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	rows := mustCandidateHealth(t, database)
	if len(rows) != 1 || rows[0].Available || rows[0].Score != 91 {
		t.Fatalf("legacy delayed success crossed newer failure: %+v", rows)
	}
}

type batchInspectingQualificationAgent struct {
	database   *store.Store
	candidates []store.Candidate
	inside     []store.ObservationReservation
	calls      int
}

func (agent *batchInspectingQualificationAgent) ProbeFast(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.calls++
	if agent.calls == 1 {
		requests := make([]store.ObservationRequest, 0, len(agent.candidates))
		for _, candidate := range agent.candidates {
			requests = append(requests, store.ObservationRequest{
				Candidate: candidate, Stage: store.ObservationFast,
			})
		}
		reservations, err := agent.database.ReserveCandidateObservations(ctx, requests)
		if err != nil {
			return agentapi.ProbeResponse{}, err
		}
		agent.inside = reservations
	}
	return agentapi.ProbeResponse{
		CandidateID:  request.CandidateID,
		FailureClass: agentapi.FailureInfrastructure,
	}, nil
}

func (agent *batchInspectingQualificationAgent) ProbeFull(
	context.Context,
	agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{}, errors.New("unexpected full probe")
}

type countingQualificationAgent struct {
	calls int
}

func (agent *countingQualificationAgent) ProbeFast(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.calls++
	return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
}

func (agent *countingQualificationAgent) ProbeFull(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.calls++
	return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
}

type orderedQualificationAgent struct {
	probes                 []string
	fullInfrastructureOnce map[string]bool
}

func (agent *orderedQualificationAgent) ProbeFast(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.probes = append(agent.probes, "fast:"+request.CandidateID)
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
}

func (agent *orderedQualificationAgent) ProbeFull(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.probes = append(agent.probes, "full:"+request.CandidateID)
	if agent.fullInfrastructureOnce[request.CandidateID] {
		delete(agent.fullInfrastructureOnce, request.CandidateID)
		return agentapi.ProbeResponse{
			CandidateID:  request.CandidateID,
			FailureClass: agentapi.FailureInfrastructure,
		}, nil
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Success:     true,
		Evaluation: health.Evaluation{
			Score: 90, TCPQualified: true, UDPQualified: true,
		},
	}, nil
}

func TestQualificationPromotesOneSuccessBeforeFastDiscovery(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a-udp-recheck", Fingerprint: "a-udp-recheck",
			Payload: "vless://a-udp-recheck@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "a-one-success", Fingerprint: "a-one-success",
			Payload: "vless://a-one-success@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "z-udp-one-success", Fingerprint: "z-udp-one-success",
			Payload: "vless://z-udp-one-success@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "unseen", Fingerprint: "unseen",
			Payload: "vless://unseen@example.net:443?security=tls",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"a-one-success":     candidates["a-one-success"],
		"z-udp-one-success": candidates["z-udp-one-success"],
	}, now, true)
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"a-udp-recheck": candidates["a-udp-recheck"],
	}, now, true)
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"a-udp-recheck": candidates["a-udp-recheck"],
	}, now.Add(time.Second), false)
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidates["z-udp-one-success"].ID,
		Available:   true, TCPQualified: true, UDPQualified: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidates["a-udp-recheck"].ID,
		Available:   true, TCPQualified: true, UDPQualified: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	agent := &orderedQualificationAgent{}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 1, FullWorkers: 1,
	}
	if err := service.runAgent(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantFirst := "full:" + candidates["z-udp-one-success"].ID
	if len(agent.probes) == 0 || agent.probes[0] != wantFirst {
		t.Fatalf("probe order=%v, want %q first", agent.probes, wantFirst)
	}
	wantSecond := "full:" + candidates["a-udp-recheck"].ID
	if len(agent.probes) < 2 || agent.probes[1] != wantSecond {
		t.Fatalf("probe order=%v, want %q second", agent.probes, wantSecond)
	}
	confirmations := 0
	for _, probe := range agent.probes {
		if probe == "fast:"+candidates["unseen"].ID {
			break
		}
		if probe == wantSecond {
			confirmations++
		}
	}
	if confirmations != 2 {
		t.Fatalf("probe order=%v, UDP recheck confirmations=%d want 2 before fast",
			agent.probes, confirmations)
	}
}

func TestQualificationRecoversCachedUDPBeforeOrdinaryFastDiscovery(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "a-regular", Fingerprint: "a-regular",
			Payload: "vless://a-regular@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "z-udp-recovery", Fingerprint: "z-udp-recovery",
			Payload: "vless://z-udp-recovery@example.net:443?security=tls",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidates["z-udp-recovery"].ID,
		Available:   true, TCPQualified: true, UDPQualified: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for _, transition := range []store.ProbeTransition{
		{
			Fingerprint: candidates["z-udp-recovery"].Fingerprint,
			CandidateID: candidates["z-udp-recovery"].ID,
			SourceID:    candidates["z-udp-recovery"].SourceID,
			Success:     true, At: now.Add(-2 * time.Minute),
		},
		{
			Fingerprint: candidates["z-udp-recovery"].Fingerprint,
			CandidateID: candidates["z-udp-recovery"].ID,
			SourceID:    candidates["z-udp-recovery"].SourceID,
			Full:        true, Success: false, ErrorCode: "full_probe_failed", At: now,
		},
	} {
		if _, err := database.RecordCandidateProbe(context.Background(), transition); err != nil {
			t.Fatal(err)
		}
	}
	udpID := candidates["z-udp-recovery"].ID
	agent := &orderedQualificationAgent{
		fullInfrastructureOnce: map[string]bool{udpID: true},
	}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 1, FullWorkers: 1,
	}
	if err := service.runAgent(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := []string{"full:" + udpID, "full:" + udpID, "full:" + udpID}
	if len(agent.probes) < len(want) || !reflect.DeepEqual(agent.probes[:len(want)], want) {
		t.Fatalf("probe order=%v want prefix=%v", agent.probes, want)
	}
}

func TestQualificationRecoversCachedTCPBeforeOrdinaryDiscovery(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "cached", Fingerprint: "cached",
			Payload: "vless://cached@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "unseen", Fingerprint: "unseen",
			Payload: "vless://unseen@example.net:443?security=tls",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	cached := candidates["cached"]
	if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
		Fingerprint: cached.Fingerprint, CandidateID: cached.ID,
		SourceID: cached.SourceID, Success: true, At: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: cached.ID, Available: true, TCPQualified: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	agent := &orderedQualificationAgent{
		fullInfrastructureOnce: map[string]bool{cached.ID: true},
	}
	service := QualificationService{
		Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
		FastWorkers: 1, FullWorkers: 1,
	}
	if err := service.runAgent(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := []string{"full:" + cached.ID, "full:" + cached.ID, "full:" + cached.ID}
	if len(agent.probes) < len(want) || !reflect.DeepEqual(agent.probes[:len(want)], want) {
		t.Fatalf("probe order=%v want prefix=%v", agent.probes, want)
	}
}

type reservationInspectingQualificationAgent struct {
	database  *store.Store
	candidate store.Candidate
	stage     tournament.ProbeStage
	inside    store.ObservationReservation
}

func (agent *reservationInspectingQualificationAgent) ProbeFast(
	ctx context.Context,
	_ agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.inspect(ctx, store.ObservationFast)
}

func (agent *reservationInspectingQualificationAgent) ProbeFull(
	ctx context.Context,
	_ agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.inspect(ctx, store.ObservationFull)
}

func (agent *reservationInspectingQualificationAgent) inspect(
	ctx context.Context,
	stage store.ObservationStage,
) (agentapi.ProbeResponse, error) {
	if (agent.stage == tournament.ProbeFast) != (stage == store.ObservationFast) {
		return agentapi.ProbeResponse{}, errors.New("unexpected probe stage")
	}
	reservation, err := agent.database.ReserveCandidateObservation(
		ctx, agent.candidate, stage,
	)
	if err != nil {
		return agentapi.ProbeResponse{}, err
	}
	agent.inside = reservation
	return agentapi.ProbeResponse{
		CandidateID:  agent.candidate.ID,
		FailureClass: agentapi.FailureInfrastructure,
	}, nil
}

func TestVLESSProbeWorkersDiscardCandidatesRemovedWhileInFlightAndContinue(t *testing.T) {
	for _, stage := range []tournament.ProbeStage{tournament.ProbeFast, tournament.ProbeFull} {
		t.Run(string(stage), func(t *testing.T) {
			database, candidates := torPromotionStore(t)
			removed := candidates["a"]
			remaining := candidates["b"]
			removed.Kind = sources.KindVLESS
			remaining.Kind = sources.KindVLESS
			agent := newBlockingVLESSJobsAgent(removed.ID)
			service := QualificationService{
				Store: database, Agent: agent, ResetWindow: 5 * time.Hour,
			}
			done := make(chan error, 1)
			go func() {
				done <- service.runProbeJobs(
					context.Background(),
					time.Unix(1_800_000_000, 0),
					[]qualificationJob{
						{candidate: removed, payload: "vless://removed@example.net:443"},
						{candidate: remaining, payload: "vless://remaining@example.net:443"},
					},
					stage,
					1,
				)
			}()
			agent.waitStarted(t)
			if err := database.ReplaceCandidates(context.Background(), removed.SourceID, []store.CandidateInput{
				{
					Kind: sources.KindVLESS, Label: "b", Fingerprint: "b",
					Payload: "vless://remaining@example.net:443",
				},
			}); err != nil {
				t.Fatal(err)
			}
			close(agent.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			requireNoCandidateProbeArtifacts(t, database, removed)
			if got := agent.callIDs(); len(got) != 2 ||
				got[0] != removed.ID || got[1] != remaining.ID {
				t.Fatalf("worker calls=%v, want removed then remaining", got)
			}
		})
	}
}

func TestVLESSQualifiedCandidatePromotesBeforeSlowBatchPeerCompletes(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "fast", Fingerprint: "fast",
			Payload: "vless://fast@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "slow", Fingerprint: "slow",
			Payload: "vless://slow@example.net:443?security=tls",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	fast, slow := candidates["fast"], candidates["slow"]
	if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
		Fingerprint: fast.Fingerprint, CandidateID: fast.ID, SourceID: fast.SourceID,
		Full: true, Success: true, Score: 80, At: now, ResetWindow: 5 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	agent := newBlockingVLESSJobsAgent(slow.ID)
	promotions := make(chan struct{}, 1)
	service := QualificationService{
		Store: database, Agent: agent, PoolSize: 200,
		PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
		Promotions: promotions,
	}
	done := make(chan error, 1)
	go func() {
		done <- service.runProbeJobs(
			context.Background(), now.Add(time.Minute),
			[]qualificationJob{
				{candidate: fast, payload: "vless://fast@example.net:443"},
				{candidate: slow, payload: "vless://slow@example.net:443"},
			},
			tournament.ProbeFull,
			2,
		)
	}()
	agent.waitStarted(t)

	select {
	case <-promotions:
	case <-time.After(time.Second):
		close(agent.release)
		<-done
		t.Fatal("qualified VLESS candidate waited for the slow batch peer before promotion")
	}
	state, err := database.CandidateProbeState(context.Background(), fast.Fingerprint)
	if err != nil {
		close(agent.release)
		<-done
		t.Fatal(err)
	}
	if state.Status != store.CandidateQualified || !state.InWorkingPool || state.Draining {
		close(agent.release)
		<-done
		t.Fatalf("promoted VLESS state=%+v", state)
	}
	select {
	case err := <-done:
		t.Fatalf("qualification batch completed before slow peer release: %v", err)
	default:
	}
	close(agent.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyVLESSQualificationDiscardsCandidateRemovedWhileInFlight(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "removed", Fingerprint: "removed",
			Payload: "vless://removed@example.net:443?security=tls",
		},
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		},
	})
	removed := candidates["removed"]
	current := candidates["current"]
	started := make(chan struct{})
	release := make(chan struct{})
	metrics := qualifiedMetrics(true)
	service := QualificationService{
		Store: database,
		VLESS: vlessQualifierFunc(func(ctx context.Context, inputs []qualifier.Input) []qualifier.Result {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil
			}
			results := make([]qualifier.Result, 0, len(inputs))
			for _, input := range inputs {
				results = append(results, qualifier.Result{
					CandidateID: input.ID,
					Metrics:     metrics, Evaluation: health.Evaluate(metrics, health.ProtocolVLESS),
				})
			}
			return results
		}),
	}
	done := make(chan error, 1)
	go func() {
		done <- service.Run(context.Background(), time.Unix(1_800_000_000, 0))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("legacy VLESS qualification did not block")
	}
	if err := database.ReplaceCandidates(context.Background(), removed.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "current", Fingerprint: "current",
			Payload: "vless://current@example.net:443?security=tls",
		},
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	healthRows := mustCandidateHealth(t, database)
	for _, row := range healthRows {
		if row.CandidateID == removed.ID {
			t.Fatalf("stale legacy VLESS result wrote ghost health: %+v", row)
		}
	}
	if !hasCandidateHealth(healthRows, current.ID) {
		t.Fatalf("remaining current VLESS candidate was not persisted: %+v", healthRows)
	}
}

func TestLegacyTorQualificationDiscardsCandidateRemovedWhileInFlight(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "removed", Fingerprint: "removed",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindTorBridge, Label: "current", Fingerprint: "current",
			Payload: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
	})
	removed := candidates["removed"]
	current := candidates["current"]
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	metrics := qualifiedMetrics(false)
	service := QualificationService{
		Store: database,
		Tor:   &allTorProfiles{},
		Measurer: measureFuncController(func(ctx context.Context, address string, _ health.Protocol) (health.Metrics, error) {
			if address == removed.ID {
				once.Do(func() { close(started) })
				select {
				case <-release:
				case <-ctx.Done():
					return health.Metrics{}, ctx.Err()
				}
			}
			return metrics, nil
		}),
	}
	done := make(chan error, 1)
	go func() {
		done <- service.Run(context.Background(), time.Unix(1_800_000_000, 0))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("legacy Tor qualification did not block")
	}
	if err := database.ReplaceCandidates(context.Background(), removed.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "current", Fingerprint: "current",
			Payload: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	healthRows := mustCandidateHealth(t, database)
	for _, row := range healthRows {
		if row.CandidateID == removed.ID {
			t.Fatalf("stale legacy Tor result wrote ghost health: %+v", row)
		}
	}
	if !hasCandidateHealth(healthRows, current.ID) {
		t.Fatalf("remaining current Tor candidate was not persisted: %+v", healthRows)
	}
}

func TestOpenFailureDomainDiscoveryQueuesOnlyStoredCanaryForFullProbe(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, failureDomainQualificationInputs())
	now := time.Unix(1_800_000_000, 0)
	ordered := orderedCandidatesByID(candidates)
	for _, candidate := range ordered[:3] {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidate.ID, now,
		); err != nil {
			t.Fatal(err)
		}
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}

	fastJobs, err := service.discoveryJobs(ctx, ordered, now.Add(time.Minute), tournament.ProbeFast)
	if err != nil {
		t.Fatal(err)
	}
	if len(fastJobs) != 0 {
		t.Fatalf("open domain queued ordinary fast probes: %+v", fastJobs)
	}
	fullJobs, err := service.discoveryJobs(ctx, ordered, now.Add(time.Minute), tournament.ProbeFull)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullJobs) != 1 || fullJobs[0].candidate.ID != states[0].CanaryCandidate {
		t.Fatalf("full jobs=%+v canary=%q", fullJobs, states[0].CanaryCandidate)
	}
}

func TestOpenFailureDomainCanaryRemainsAfterOrdinaryFullJobs(t *testing.T) {
	ctx := context.Background()
	inputs := append(failureDomainQualificationInputs(), store.CandidateInput{
		Kind: sources.KindVLESS, Label: "ordinary", Fingerprint: "ordinary",
		Payload:       "vless://ordinary@example.net:443?security=tls",
		FailureDomain: "ordinary-domain",
	})
	database, candidates := qualificationStore(t, inputs)
	now := time.Unix(1_800_000_000, 0)
	domainCandidates := make([]store.Candidate, 0, len(candidates)-1)
	for fingerprint, candidate := range candidates {
		if fingerprint != "ordinary" {
			domainCandidates = append(domainCandidates, candidate)
		}
	}
	sort.Slice(domainCandidates, func(i, j int) bool {
		return domainCandidates[i].ID < domainCandidates[j].ID
	})
	for _, candidate := range domainCandidates[:3] {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidate.ID, now,
		); err != nil {
			t.Fatal(err)
		}
	}
	seedVLESSFullProbeState(t, database, map[string]store.Candidate{
		"ordinary": candidates["ordinary"],
	}, now, true)
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		ctx, orderedCandidatesByID(candidates), now.Add(time.Minute), tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].candidate.ID != candidates["ordinary"].ID ||
		jobs[1].candidate.ID != states[0].CanaryCandidate {
		t.Fatalf("full jobs=%+v ordinary=%q canary=%q",
			qualificationJobFingerprints(jobs), candidates["ordinary"].ID,
			states[0].CanaryCandidate)
	}
}

func TestOpenFailureDomainDiscoveryUsesDeterministicCurrentCanaryWhenStoredOneIsMissing(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, failureDomainQualificationInputs())
	now := time.Unix(1_800_000_000, 0)
	for _, candidateID := range []string{"gone-c", "gone-a", "gone-b"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidateID, now,
		); err != nil {
			t.Fatal(err)
		}
	}
	ordered := orderedCandidatesByID(candidates)
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(ctx, ordered, now.Add(time.Minute), tournament.ProbeFull)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].candidate.ID != ordered[0].ID {
		t.Fatalf("fallback jobs=%+v want=%q", jobs, ordered[0].ID)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	if states[0].CanaryCandidate != ordered[0].ID {
		t.Fatalf("fallback canary was not persisted: %+v", states[0])
	}
}

func TestElectedFailureDomainCanaryCanCloseInSameCycle(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, failureDomainQualificationInputs())
	base := time.Unix(1_800_000_000, 0)
	for _, candidateID := range []string{"gone-c", "gone-a", "gone-b"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidateID, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	now := base.Add(time.Minute)
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		ctx, orderedCandidatesByID(candidates), now, tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("full canary jobs=%+v", jobs)
	}
	if _, err := service.recordProbeResult(
		ctx,
		now,
		qualificationResult{
			job: jobs[0],
			response: agentapi.ProbeResponse{
				Success: true,
				Evaluation: health.Evaluation{
					Score: 95, TCPQualified: true, UDPQualified: true,
				},
			},
		},
		tournament.ProbeFull,
	); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	if !states[0].OpenUntil.IsZero() || states[0].FailureCount != 0 ||
		!states[0].UpdatedAt.Equal(now) {
		t.Fatalf("same-cycle canary success did not close: %+v", states[0])
	}
}

func TestOpenFailureDomainDiscoveryNeverElectsNonVLESSCanary(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "vless-a", Fingerprint: "vless-a",
			Payload: "vless://a@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "vless-b", Fingerprint: "vless-b",
			Payload: "vless://b@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
	})
	now := time.Unix(1_800_000_000, 0)
	tor := candidates["tor"]
	for _, candidateID := range []string{tor.ID, "zz-candidate-a", "zz-candidate-b"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidateID, now,
		); err != nil {
			t.Fatal(err)
		}
	}
	tor.FailureDomain = "domain-hash"
	current := []store.Candidate{tor, candidates["vless-b"], candidates["vless-a"]}
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	jobs, err := service.discoveryJobs(
		ctx, current, now.Add(time.Minute), tournament.ProbeFull,
	)
	if err != nil {
		t.Fatal(err)
	}
	vless := orderedCandidatesByID(map[string]store.Candidate{
		"vless-a": candidates["vless-a"],
		"vless-b": candidates["vless-b"],
	})
	if len(jobs) != 1 || jobs[0].candidate.Kind != sources.KindVLESS ||
		jobs[0].candidate.ID != vless[0].ID {
		t.Fatalf("jobs=%+v want VLESS canary %q", jobs, vless[0].ID)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 ||
		states[0].CanaryCandidate != vless[0].ID {
		t.Fatalf("persisted state=%+v err=%v", states, err)
	}
}

func TestOnlySuccessfulFullVLESSQualificationClosesFailureDomain(t *testing.T) {
	tests := []struct {
		name        string
		stage       tournament.ProbeStage
		response    agentapi.ProbeResponse
		err         error
		closed      bool
		extendedFor time.Duration
	}{
		{
			name:  "fast success",
			stage: tournament.ProbeFast,
			response: agentapi.ProbeResponse{
				Success: true,
			},
		},
		{
			name:  "full ChatGPT gate failure",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "chatgpt_web_failed",
			},
		},
		{
			name:  "full OpenAI gate failure",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "openai_api_failed",
			},
		},
		{
			name:  "full Telegram gate failure",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "telegram_web_failed",
			},
		},
		{
			name:  "full invalid candidate failure",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "invalid_candidate",
			},
		},
		{
			name:  "full infrastructure cancellation",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureInfrastructure,
				ErrorCode:    "probe_canceled",
			},
		},
		{
			name:  "full runtime error",
			stage: tournament.ProbeFull,
			err:   errors.New("agent unavailable"),
		},
		{
			name:  "fast candidate network failure",
			stage: tournament.ProbeFast,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "full_probe_failed",
			},
		},
		{
			name:  "full candidate network failure",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "full_probe_failed",
			},
			extendedFor: 11 * time.Minute,
		},
		{
			name:  "full success",
			stage: tournament.ProbeFull,
			response: agentapi.ProbeResponse{
				Success: true,
				Evaluation: health.Evaluation{
					Score: 95, TCPQualified: true, UDPQualified: true,
				},
			},
			closed: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := qualificationStore(t, failureDomainQualificationInputs()[:1])
			candidate := candidates["candidate-a"]
			now := time.Unix(1_800_000_000, 0)
			for _, candidateID := range []string{"gone-a", "gone-b", "gone-c"} {
				if _, err := database.RecordFailureDomainFailure(
					ctx, "domain-hash", candidateID, now,
				); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := database.ElectFailureDomainCanary(
				ctx, "domain-hash", []string{candidate.ID}, now,
			); err != nil {
				t.Fatal(err)
			}
			service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
			if _, err := service.recordProbeResult(
				ctx,
				now.Add(time.Minute),
				qualificationResult{
					job:      qualificationJob{candidate: candidate, payload: "opaque"},
					response: test.response,
					err:      test.err,
				},
				test.stage,
			); err != nil {
				t.Fatal(err)
			}
			states, err := database.ListFailureDomainStates(ctx)
			if err != nil || len(states) != 1 {
				t.Fatalf("states=%+v err=%v", states, err)
			}
			if test.closed {
				if !states[0].OpenUntil.IsZero() || states[0].FailureCount != 0 {
					t.Fatalf("successful full VLESS did not close: %+v", states[0])
				}
			} else {
				wantOpenUntil := now.Add(10 * time.Minute)
				if test.extendedFor != 0 {
					wantOpenUntil = now.Add(test.extendedFor)
				}
				if !states[0].OpenUntil.Equal(wantOpenUntil) {
					t.Fatalf("result changed circuit incorrectly: %+v", states[0])
				}
			}
		})
	}
}

func TestFullVLESSCanaryNetworkFailureAtOpenBoundaryDoesNotExtend(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, failureDomainQualificationInputs()[:1])
	candidate := candidates["candidate-a"]
	base := time.Unix(1_800_000_000, 0)
	for _, candidateID := range []string{"gone-a", "gone-b", "gone-c"} {
		if _, err := database.RecordFailureDomainFailure(
			ctx, "domain-hash", candidateID, base,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ElectFailureDomainCanary(
		ctx, "domain-hash", []string{candidate.ID}, base,
	); err != nil {
		t.Fatal(err)
	}
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	if _, err := service.recordProbeResult(
		ctx,
		base.Add(10*time.Minute),
		qualificationResult{
			job: qualificationJob{candidate: candidate, payload: "opaque"},
			response: agentapi.ProbeResponse{
				FailureClass: agentapi.FailureCandidate,
				ErrorCode:    "full_probe_failed",
			},
		},
		tournament.ProbeFull,
	); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil || len(states) != 1 ||
		!states[0].OpenUntil.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("boundary state=%+v err=%v", states, err)
	}
}

func TestVLESSQualificationGateFailureDoesNotCreateFailureDomainEvidence(t *testing.T) {
	ctx := context.Background()
	database, candidates := qualificationStore(t, failureDomainQualificationInputs()[:1])
	candidate := candidates["candidate-a"]
	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	if _, err := service.recordProbeResult(
		ctx,
		time.Unix(1_800_000_000, 0),
		qualificationResult{
			job: qualificationJob{candidate: candidate, payload: "opaque"},
			response: agentapi.ProbeResponse{
				Success:   true,
				ErrorCode: "chatgpt_web_failed",
				Evaluation: health.Evaluation{
					Score: 95, TCPQualified: false,
				},
			},
		},
		tournament.ProbeFull,
	); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListFailureDomainStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("candidate gate failure created domain evidence: %+v", states)
	}
}

func failureDomainQualificationInputs() []store.CandidateInput {
	return []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "candidate-a", Fingerprint: "candidate-a",
			Payload: "vless://a@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "candidate-b", Fingerprint: "candidate-b",
			Payload: "vless://b@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "candidate-c", Fingerprint: "candidate-c",
			Payload: "vless://c@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
		{
			Kind: sources.KindVLESS, Label: "candidate-d", Fingerprint: "candidate-d",
			Payload: "vless://d@example.net:443?security=tls", FailureDomain: "domain-hash",
		},
	}
}

func orderedCandidatesByID(candidates map[string]store.Candidate) []store.Candidate {
	ordered := make([]store.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].ID < ordered[j].ID
	})
	return ordered
}

func qualificationJobFingerprints(jobs []qualificationJob) []string {
	fingerprints := make([]string, 0, len(jobs))
	for _, job := range jobs {
		fingerprints = append(fingerprints, job.candidate.Fingerprint)
	}
	return fingerprints
}

func seedVLESSFullProbeState(
	t *testing.T,
	database *store.Store,
	candidates map[string]store.Candidate,
	now time.Time,
	success bool,
) {
	t.Helper()
	for _, candidate := range candidates {
		if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
			SourceID: candidate.SourceID, Full: true, Success: success,
			Score: 80, At: now, ResetWindow: 5 * time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func qualificationStore(
	t *testing.T,
	inputs []store.CandidateInput,
) (*store.Store, map[string]store.Candidate) {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(context.Background())
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	if err := database.ReplaceCandidates(context.Background(), listed[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]store.Candidate, len(rows))
	for _, candidate := range rows {
		result[candidate.Fingerprint] = candidate
	}
	return database, result
}

func qualifiedMetrics(udp bool) health.Metrics {
	return health.Metrics{
		SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 50,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
		UDP: udp,
	}
}

func hasCandidateHealth(rows []store.CandidateHealth, candidateID string) bool {
	for _, row := range rows {
		if row.CandidateID == candidateID {
			return true
		}
	}
	return false
}

type allTorProfiles struct{}

func (*allTorProfiles) ReconcileProfiles(
	_ context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	profiles := make([]torpool.Profile, 0, len(candidates))
	for _, candidate := range candidates {
		profiles = append(profiles, torpool.Profile{
			CandidateID: candidate.ID, SocksAddr: candidate.ID, Role: "warm",
		})
	}
	return profiles, nil
}

func (*allTorProfiles) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return nil, nil
}

type blockingVLESSJobsAgent struct {
	mu        sync.Mutex
	blockedID string
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
	calls     []string
}

func newBlockingVLESSJobsAgent(candidateID string) *blockingVLESSJobsAgent {
	return &blockingVLESSJobsAgent{
		blockedID: candidateID, started: make(chan struct{}), release: make(chan struct{}),
	}
}

func (agent *blockingVLESSJobsAgent) ProbeFast(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.probe(ctx, request, false)
}

func (agent *blockingVLESSJobsAgent) ProbeFull(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agent.probe(ctx, request, true)
}

func (agent *blockingVLESSJobsAgent) probe(
	ctx context.Context,
	request agentapi.ProbeRequest,
	full bool,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.calls = append(agent.calls, request.CandidateID)
	block := request.CandidateID == agent.blockedID
	agent.mu.Unlock()
	if block {
		agent.once.Do(func() { close(agent.started) })
		select {
		case <-agent.release:
		case <-ctx.Done():
			return agentapi.ProbeResponse{}, ctx.Err()
		}
	}
	if !full {
		return agentapi.ProbeResponse{
			CandidateID: request.CandidateID, Success: true,
		}, nil
	}
	metrics := health.Metrics{
		SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 20,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: true, Metrics: metrics,
		Evaluation: health.Evaluate(metrics, health.ProtocolVLESS),
	}, nil
}

func (agent *blockingVLESSJobsAgent) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("VLESS probe did not start")
	}
}

func (agent *blockingVLESSJobsAgent) callIDs() []string {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return append([]string(nil), agent.calls...)
}

func TestQualificationCyclePersistsVLESSAndTorGates(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	_ = database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "v", Fingerprint: "v", Payload: "vless://id@example.net:443?security=tls"},
		{Kind: sources.KindTorBridge, Label: "t", Fingerprint: "t", Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"},
	})
	metrics := health.Metrics{SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 50, ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true}
	service := QualificationService{
		Store: database,
		VLESS: vlessQualifierFunc(func(_ context.Context, inputs []qualifier.Input) []qualifier.Result {
			return []qualifier.Result{{CandidateID: inputs[0].ID, Metrics: metrics, Evaluation: health.Evaluate(metrics, health.ProtocolVLESS)}}
		}),
		Tor: &torAgentRecorder{},
		Measurer: measureFuncController(func(context.Context, string, health.Protocol) (health.Metrics, error) {
			metrics.UDP = false
			return metrics, nil
		}),
	}
	if err := service.Run(context.Background(), time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	healthRows, _ := database.ListCandidateHealth(context.Background())
	if len(healthRows) != 2 {
		t.Fatalf("health=%+v", healthRows)
	}
}

func TestQualificationMeasuresOnlyWarmPoolAndAdvancesOneExplorer(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	inputs := make([]store.CandidateInput, 6)
	for index := range inputs {
		inputs[index] = store.CandidateInput{
			Kind: sources.KindTorBridge, Label: "bridge", Fingerprint: string(rune('a' + index)),
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		}
	}
	_ = database.ReplaceCandidates(context.Background(), listed[0].ID, inputs)
	agent := &boundedTorAgent{}
	measured := 0
	service := QualificationService{
		Store: database, Tor: agent,
		Measurer: measureFuncController(func(context.Context, string, health.Protocol) (health.Metrics, error) {
			measured++
			return health.Metrics{}, nil
		}),
	}
	if err := service.Run(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if measured != 4 || agent.exploreCalls != 1 {
		t.Fatalf("measured=%d explore_calls=%d", measured, agent.exploreCalls)
	}
}

func TestConcurrentQualificationLanesStartTorWithoutWaitingForVLESS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	vlessStarted := make(chan struct{})
	torStarted := make(chan struct{})
	releaseVLESS := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runConcurrentQualificationLanes(
			ctx,
			func(ctx context.Context) error {
				close(vlessStarted)
				select {
				case <-releaseVLESS:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			func(context.Context) error {
				close(torStarted)
				return nil
			},
		)
	}()
	select {
	case <-vlessStarted:
	case <-ctx.Done():
		t.Fatal("VLESS lane did not start")
	}
	select {
	case <-torStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Tor lane was starved behind VLESS")
	}
	close(releaseVLESS)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQualificationPreservesLastKnownHealthOnProbeInfrastructureFailure(t *testing.T) {
	database, candidateID := activeMonitorStore(t)
	service := QualificationService{
		Store: database,
		VLESS: vlessQualifierFunc(func(context.Context, []qualifier.Input) []qualifier.Result {
			return []qualifier.Result{{CandidateID: candidateID, Err: errors.New("probe Xray unavailable"), InfrastructureFailure: true}}
		}),
	}
	if err := service.Run(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListCandidateHealth(context.Background())
	if len(rows) != 1 || !rows[0].Available || rows[0].Score != 95 {
		t.Fatalf("last-known health was overwritten: %+v", rows)
	}
}

type vlessQualifierFunc func(context.Context, []qualifier.Input) []qualifier.Result

func (function vlessQualifierFunc) Qualify(ctx context.Context, inputs []qualifier.Input) []qualifier.Result {
	return function(ctx, inputs)
}

type torAgentRecorder struct{ profiles []torpool.Profile }

func (agent *torAgentRecorder) ReconcileProfiles(_ context.Context, candidates []torpool.Candidate) ([]torpool.Profile, error) {
	agent.profiles = []torpool.Profile{{CandidateID: candidates[0].ID, SocksAddr: "127.0.0.1:19050", Role: "warm"}}
	return agent.profiles, nil
}
func (agent *torAgentRecorder) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return agent.profiles, nil
}

type boundedTorAgent struct {
	profiles     []torpool.Profile
	exploreCalls int
}

func (agent *boundedTorAgent) ReconcileProfiles(_ context.Context, candidates []torpool.Candidate) ([]torpool.Profile, error) {
	limit := 4
	if len(candidates) < limit {
		limit = len(candidates)
	}
	agent.profiles = make([]torpool.Profile, limit)
	for index := range agent.profiles {
		agent.profiles[index] = torpool.Profile{CandidateID: candidates[index].ID, SocksAddr: "127.0.0.1:19050", Role: "warm"}
	}
	return agent.profiles, nil
}

func (agent *boundedTorAgent) ExploreNext(context.Context) ([]torpool.Profile, error) {
	agent.exploreCalls++
	return agent.profiles, nil
}

type measureFuncController func(context.Context, string, health.Protocol) (health.Metrics, error)

func (function measureFuncController) Measure(ctx context.Context, address string, protocol health.Protocol) (health.Metrics, error) {
	return function(ctx, address, protocol)
}

func TestQualificationDisallowsRussianEgressWhenEnabled(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls\nvless://id@beget.tech:443?security=tls\n")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	_ = database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "🇩🇪 Germany | VLESS", Fingerprint: "vless-de", Payload: "vless://id@194.48.217.164:443?security=reality"},
		{Kind: sources.KindVLESS, Label: "🇷🇺 Russia | VLESS", Fingerprint: "vless-ru", Payload: "vless://id@31.128.36.48:443?security=reality"},
	})
	metrics := health.Metrics{
		SuccessRatio: 1, Latency: 50 * time.Millisecond, ThroughputMbps: 50,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true,
		YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}
	service := QualificationService{
		Store:            database,
		DisallowRUEgress: true,
		VLESS: vlessQualifierFunc(func(_ context.Context, inputs []qualifier.Input) []qualifier.Result {
			results := make([]qualifier.Result, len(inputs))
			for i, in := range inputs {
				results[i] = qualifier.Result{
					CandidateID: in.ID,
					Metrics:     metrics,
					Evaluation:  health.Evaluate(metrics, health.ProtocolVLESS),
				}
			}
			return results
		}),
	}
	if err := service.Run(context.Background(), time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	healthRows, _ := database.ListCandidateHealth(context.Background())
	healthByID := make(map[string]store.CandidateHealth, len(healthRows))
	for _, h := range healthRows {
		healthByID[h.CandidateID] = h
	}
	candidates, _ := database.ListCandidates(context.Background(), "")
	for _, c := range candidates {
		healthRow, ok := healthByID[c.ID]
		if !ok {
			t.Fatalf("missing health for %s", c.Label)
		}
		if c.Label == "🇷🇺 Russia | VLESS" {
			if healthRow.Available || healthRow.TCPQualified || healthRow.Score > 0 {
				t.Fatalf("Russian candidate was not disqualified: %+v", healthRow)
			}
		} else if c.Label == "🇩🇪 Germany | VLESS" {
			if !healthRow.Available || !healthRow.TCPQualified || healthRow.Score == 0 {
				t.Fatalf("German candidate was incorrectly disqualified: %+v", healthRow)
			}
		}
	}
}

func TestQualificationJobsDisallowsRussianEgress(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "🇩🇪 Germany | VLESS", Fingerprint: "vless-de",
			Payload: "vless://id@194.48.217.164:443?security=reality",
		},
		{
			Kind: sources.KindVLESS, Label: "8086 | 🌐 Unknown | 🏳️ CIDR-Yandex | VLESS", Fingerprint: "vless-yandex",
			Payload: "vless://id@1.2.3.4:443?security=reality",
		},
		{
			Kind: sources.KindVLESS, Label: "1685 | 🇷🇺 Russia | VLESS", Fingerprint: "vless-ru",
			Payload: "vless://id@31.128.36.48:443?security=reality",
		},
	})

	now := time.Unix(1_800_000_000, 0)
	service := QualificationService{
		Store:            database,
		DisallowRUEgress: true,
	}
	successResp := agentapi.ProbeResponse{
		Success: true,
		Metrics: health.Metrics{
			Latency:        50 * time.Millisecond,
			ThroughputMbps: 50,
		},
		Evaluation: health.Evaluation{
			Score:        90,
			TCPQualified: true,
			UDPQualified: true,
		},
	}

	for _, fp := range []string{"vless-de", "vless-yandex", "vless-ru"} {
		c := candidates[fp]
		payload, _ := database.CandidatePayload(context.Background(), c.ID)
		reservation, err := database.ReserveCandidateObservations(context.Background(), []store.ObservationRequest{{
			Candidate: c, Stage: store.ObservationFull,
		}})
		if err != nil {
			t.Fatal(err)
		}
		job := qualificationJob{candidate: c, payload: payload}
		result := qualificationResult{
			job:         job,
			reservation: reservation[0],
			response:    successResp,
		}
		if _, err := service.recordProbeResult(context.Background(), now, result, tournament.ProbeFull); err != nil {
			t.Fatal(err)
		}
	}

	healthRows, _ := database.ListCandidateHealth(context.Background())
	healthByID := make(map[string]store.CandidateHealth, len(healthRows))
	for _, h := range healthRows {
		healthByID[h.CandidateID] = h
	}

	deHealth := healthByID[candidates["vless-de"].ID]
	if !deHealth.Available || !deHealth.TCPQualified || deHealth.Score == 0 {
		t.Fatalf("Germany candidate should be qualified: %+v", deHealth)
	}

	yandexHealth := healthByID[candidates["vless-yandex"].ID]
	if yandexHealth.Available || yandexHealth.TCPQualified || yandexHealth.Score > 0 {
		t.Fatalf("CIDR-Yandex candidate should be disqualified: %+v", yandexHealth)
	}

	ruHealth := healthByID[candidates["vless-ru"].ID]
	if ruHealth.Available || ruHealth.TCPQualified || ruHealth.Score > 0 {
		t.Fatalf("Russia candidate should be disqualified: %+v", ruHealth)
	}
}

func TestDiscoveryJobsSkipsRussianEgressWhenDisallowed(t *testing.T) {
	database, candidates := qualificationStore(t, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "🇩🇪 Germany | VLESS", Fingerprint: "vless-de",
			Payload: "vless://id@194.48.217.164:443?security=reality",
		},
		{
			Kind: sources.KindVLESS, Label: "1685 | 🇷🇺 Russia | VLESS", Fingerprint: "vless-ru",
			Payload: "vless://id@31.128.36.48:443?security=reality",
		},
	})

	now := time.Unix(1_800_000_000, 0)
	service := QualificationService{
		Store:            database,
		DisallowRUEgress: true,
	}

	ordered := orderedCandidatesByID(candidates)
	jobs, err := service.discoveryJobs(context.Background(), ordered, now, tournament.ProbeFast)
	if err != nil {
		t.Fatal(err)
	}

	for _, j := range jobs {
		if j.candidate.Fingerprint == "vless-ru" {
			t.Fatalf("discoveryJobs should not queue Russian candidate: %+v", j.candidate)
		}
	}
}
