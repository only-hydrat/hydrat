package controller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestTorCandidatesPreserveSubscriptionOrder(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("tor-source https://subscription.example/tor")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "z", Fingerprint: "z",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a",
			Payload: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			Kind: sources.KindTorBridge, Label: "m", Fingerprint: "m",
			Payload: "Bridge 192.0.2.3:443 FEDCBA9876543210FEDCBA9876543210FEDCBA98",
		},
	}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintByID := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		fingerprintByID[candidate.ID] = candidate.Fingerprint
	}
	probeAgent := &probeOrderAgent{}
	service := QualificationService{Store: database, Agent: probeAgent}
	if err := service.runTorCandidates(
		context.Background(),
		candidates,
		candidates,
		time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}

	probeAgent.mu.Lock()
	order := append([]string(nil), probeAgent.order...)
	probeAgent.mu.Unlock()
	fingerprints := make([]string, 0, len(order))
	for _, candidateID := range order {
		fingerprints = append(fingerprints, fingerprintByID[candidateID])
	}
	want := []string{"z", "a", "m"}
	if fmt.Sprint(fingerprints) != fmt.Sprint(want) {
		t.Fatalf("probe order=%v want=%v", fingerprints, want)
	}
}

func TestTorCandidatesLimitBackgroundWorkPerCycle(t *testing.T) {
	database, candidates := torPromotionStore(t)
	queue := candidateList(candidates)
	probeAgent := &probeOrderAgent{}
	service := QualificationService{
		Store: database, Agent: probeAgent, TorCandidatesPerCycle: 2,
	}
	if err := service.runTorCandidates(
		context.Background(), queue, queue, time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}

	probeAgent.mu.Lock()
	order := append([]string(nil), probeAgent.order...)
	probeAgent.mu.Unlock()
	fingerprintByID := make(map[string]string, len(queue))
	for _, candidate := range queue {
		fingerprintByID[candidate.ID] = candidate.Fingerprint
	}
	fingerprints := make([]string, 0, len(order))
	for _, candidateID := range order {
		fingerprints = append(fingerprints, fingerprintByID[candidateID])
	}
	want := []string{"a", "b"}
	if fmt.Sprint(fingerprints) != fmt.Sprint(want) {
		t.Fatalf("probe order=%v want=%v", fingerprints, want)
	}
}

func TestTorCandidatesRotateOldestProbeFirstWithinPriority(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	recordQualifiedTorCandidate(t, database, candidates["a"], 100, now.Add(-time.Hour))
	recordQualifiedTorCandidate(t, database, candidates["b"], 100, now.Add(-3*time.Hour))
	recordQualifiedTorCandidate(t, database, candidates["c"], 100, now.Add(-2*time.Hour))

	service := QualificationService{Store: database, ResetWindow: 5 * time.Hour}
	ordered, err := service.prioritizeTorCandidates(
		context.Background(),
		[]store.Candidate{candidates["a"], candidates["b"], candidates["c"]},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints := make([]string, 0, len(ordered))
	for _, candidate := range ordered {
		fingerprints = append(fingerprints, candidate.Fingerprint)
	}
	want := []string{"b", "c", "a"}
	if fmt.Sprint(fingerprints) != fmt.Sprint(want) {
		t.Fatalf("candidate order=%v want=%v", fingerprints, want)
	}
}

func TestTorCandidatesStopWhenCycleBudgetExpires(t *testing.T) {
	database, candidates := torPromotionStore(t)
	service := QualificationService{
		Store: database, Agent: budgetBlockingTorAgent{},
		TorQualificationBudget: 50 * time.Millisecond,
	}
	started := time.Now()
	if err := service.runTorCandidates(
		context.Background(),
		[]store.Candidate{candidates["a"]},
		candidateList(candidates),
		time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Tor qualification exceeded cycle budget: %s", elapsed)
	}
	state, err := database.CandidateProbeState(context.Background(), candidates["a"].Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailureStreak != 0 || state.LastErrorCode != "agent_unavailable" {
		t.Fatalf("budget cancellation was not recorded as infrastructure: %+v", state)
	}
}

func TestWorkingPoolTorMutationHonorsServiceTimeout(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	recordQualifiedTorCandidate(t, database, candidates["a"], 100, now)
	profiles := &deadlineTorProfiles{release: make(chan struct{})}
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 3, PromotionRatio: 0.15,
		TorMutationTimeout: 50 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() {
		_, err := service.updateWorkingPool(
			context.Background(), candidateList(candidates), now,
		)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("working-pool Tor mutation error=%v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		close(profiles.release)
		<-done
		t.Fatal("working-pool Tor mutation ignored service timeout")
	}
}

type deadlineTorProfiles struct {
	release chan struct{}
}

func (profiles *deadlineTorProfiles) ReconcileProfiles(
	ctx context.Context,
	_ []torpool.Candidate,
) ([]torpool.Profile, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-profiles.release:
		return nil, errors.New("test released mutation")
	}
}

func (*deadlineTorProfiles) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return nil, nil
}

type budgetBlockingTorAgent struct{}

func (budgetBlockingTorAgent) ProbeFast(
	ctx context.Context,
	_ agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	<-ctx.Done()
	return agentapi.ProbeResponse{}, ctx.Err()
}

func (budgetBlockingTorAgent) ProbeFull(
	context.Context,
	agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{}, errors.New("unexpected full probe")
}

type probeOrderAgent struct {
	mu    sync.Mutex
	order []string
}

func (agent *probeOrderAgent) ProbeFast(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.order = append(agent.order, request.CandidateID)
	agent.mu.Unlock()
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Success:     false,
		ErrorCode:   "expected_test_failure",
	}, nil
}

func (agent *probeOrderAgent) ProbeFull(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{}, fmt.Errorf("unexpected full probe for %s", request.CandidateID)
}

func TestTorCandidatesAttemptUnseenBeforeFailedRetries(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	for _, fingerprint := range []string{"a", "b"} {
		candidate := candidates[fingerprint]
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
				Fingerprint: candidate.Fingerprint,
				CandidateID: candidate.ID,
				SourceID:    candidate.SourceID,
				Success:     false,
				ErrorCode:   "expected_prior_failure",
				At:          now.Add(time.Duration(attempt-2) * time.Minute),
				ResetWindow: 5 * time.Hour,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	probeAgent := &probeOrderAgent{}
	service := QualificationService{
		Store: database, Agent: probeAgent, ResetWindow: 5 * time.Hour,
	}
	queue := []store.Candidate{
		candidates["a"],
		candidates["b"],
		candidates["c"],
		candidates["d"],
	}
	if err := service.runTorCandidates(
		context.Background(),
		queue,
		candidateList(candidates),
		now,
	); err != nil {
		t.Fatal(err)
	}

	probeAgent.mu.Lock()
	order := append([]string(nil), probeAgent.order...)
	probeAgent.mu.Unlock()
	fingerprintByID := make(map[string]string, len(queue))
	for _, candidate := range queue {
		fingerprintByID[candidate.ID] = candidate.Fingerprint
	}
	fingerprints := make([]string, 0, len(order))
	for _, candidateID := range order {
		fingerprints = append(fingerprints, fingerprintByID[candidateID])
	}
	want := []string{"c", "d", "a", "b"}
	if fmt.Sprint(fingerprints) != fmt.Sprint(want) {
		t.Fatalf("probe order=%v want=%v", fingerprints, want)
	}
	for _, fingerprint := range []string{"a", "b"} {
		state, err := database.CandidateProbeState(context.Background(), fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if state.Status != store.CandidateBanned || state.FailureStreak != 3 {
			t.Fatalf("%s state=%+v", fingerprint, state)
		}
	}
}

func TestTorCandidatesSkipCandidateRemovedByRefresh(t *testing.T) {
	database, candidates := torPromotionStore(t)
	sourceID := candidates["a"].SourceID
	probeAgent := &refreshingProbeAgent{
		database: database,
		sourceID: sourceID,
		replacement: []store.CandidateInput{
			{
				Kind: sources.KindTorBridge, Label: "a", Fingerprint: "a",
				Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
			},
			{
				Kind: sources.KindTorBridge, Label: "c", Fingerprint: "c",
				Payload: "Bridge 192.0.2.3:443 0123456789ABCDEF0123456789ABCDEF01234567",
			},
		},
	}
	service := QualificationService{
		Store: database, Agent: probeAgent, ResetWindow: 5 * time.Hour,
	}
	queue := []store.Candidate{
		candidates["a"],
		candidates["b"],
		candidates["c"],
	}
	if err := service.runTorCandidates(
		context.Background(),
		queue,
		candidateList(candidates),
		time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatalf("Tor cycle aborted after refresh removed stale candidate: %v", err)
	}

	probeAgent.mu.Lock()
	order := append([]string(nil), probeAgent.order...)
	refreshErr := probeAgent.refreshErr
	probeAgent.mu.Unlock()
	if refreshErr != nil {
		t.Fatalf("refresh failed: %v", refreshErr)
	}
	fingerprintByID := map[string]string{
		candidates["a"].ID: "a",
		candidates["b"].ID: "b",
		candidates["c"].ID: "c",
	}
	fingerprints := make([]string, 0, len(order))
	for _, candidateID := range order {
		fingerprints = append(fingerprints, fingerprintByID[candidateID])
	}
	want := []string{"a", "c"}
	if fmt.Sprint(fingerprints) != fmt.Sprint(want) {
		t.Fatalf("probe order=%v want=%v", fingerprints, want)
	}
}

func TestUpdateWorkingPoolExcludesRemovedQualifiedCandidate(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	removed := candidates["a"]
	current := candidates["b"]
	recordQualifiedTorCandidate(t, database, removed, 100, now)
	recordQualifiedTorCandidate(t, database, current, 80, now)
	if err := database.ReplaceWorkingPool(context.Background(), []string{removed.Fingerprint}, nil); err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(context.Background(), removed.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "b", Fingerprint: "b",
			Payload: "Bridge 192.0.2.2:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
	}); err != nil {
		t.Fatal(err)
	}
	currentCandidates, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	profiles := newProductionTorProfiles(t)
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 1, PromotionRatio: 0.15,
	}
	reconciled, err := service.updateWorkingPool(context.Background(), currentCandidates, now)
	if err != nil {
		t.Fatal(err)
	}
	removedState, err := database.CandidateProbeState(context.Background(), removed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	currentState, err := database.CandidateProbeState(context.Background(), current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if removedState.InWorkingPool || removedState.Draining {
		t.Fatalf("removed state remained active: %+v", removedState)
	}
	if !currentState.InWorkingPool {
		t.Fatalf("current candidate was displaced: %+v", currentState)
	}
	if len(reconciled) != 1 || reconciled[0].CandidateID != current.ID {
		t.Fatalf("profiles=%+v, want only current candidate %s", reconciled, current.ID)
	}
}

func TestUpdateWorkingPoolKeepsAssignedDisplacedTorAsDraining(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	old := candidates["a"]
	challenger := candidates["b"]
	recordQualifiedTorCandidate(t, database, old, 80, now)
	recordQualifiedTorCandidate(t, database, challenger, 100, now)
	if err := database.ReplaceWorkingPool(
		context.Background(), []string{old.Fingerprint}, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(context.Background(), store.ClientRecord{
		ID: "assigned", Name: "Assigned", Address: "10.44.0.2/32", PublicKey: "public",
	}, "[Interface]\nPrivateKey = private\n"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
		ClientID: "assigned", TCPOutbound: old.ID,
		TCPSince: now, UDPSince: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	agent := &capturingTorProfiles{}
	service := QualificationService{
		Store: database, Tor: agent, PoolSize: 1, PromotionRatio: 0.15,
	}
	if _, err := service.updateWorkingPool(
		context.Background(), []store.Candidate{old, challenger}, now,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.candidates) != 2 {
		t.Fatalf("Tor reconciliation candidates=%+v", agent.candidates)
	}
	byID := make(map[string]torpool.Candidate, len(agent.candidates))
	for _, candidate := range agent.candidates {
		byID[candidate.ID] = candidate
	}
	if candidate := byID[challenger.ID]; candidate.ID == "" || candidate.Draining {
		t.Fatalf("challenger not active: %+v", candidate)
	}
	if candidate := byID[old.ID]; candidate.ID == "" || !candidate.Draining {
		t.Fatalf("assigned displaced route not draining: %+v", candidate)
	}
	if !byID[old.ID].Assigned {
		t.Fatalf("assigned route missing local protection: %+v", byID[old.ID])
	}
}

func TestUpdateWorkingPoolRecomputesAfterSnapshotCandidateIsRemoved(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	removed := candidates["a"]
	current := candidates["b"]
	recordQualifiedTorCandidate(t, database, removed, 100, now)
	recordQualifiedTorCandidate(t, database, current, 80, now)

	profiles := newProductionTorProfiles(t)
	refreshes := 0
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 1, PromotionRatio: 0.15,
		beforeWorkingPoolReplace: func(attempt int) {
			if attempt != 0 {
				return
			}
			refreshes++
			replaceTorCandidates(t, database, removed.SourceID, current.Fingerprint)
		},
	}
	reconciled, err := service.updateWorkingPool(
		context.Background(), []store.Candidate{removed, current}, now,
	)
	if err != nil {
		t.Fatalf("pool reconciliation aborted on the refresh interleaving: %v", err)
	}
	if refreshes != 1 {
		t.Fatalf("refresh barrier ran %d times, want 1", refreshes)
	}

	removedState, err := database.CandidateProbeState(context.Background(), removed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	currentState, err := database.CandidateProbeState(context.Background(), current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if removedState.InWorkingPool || removedState.Draining {
		t.Fatalf("removed candidate became ghost pool membership: %+v", removedState)
	}
	if !currentState.InWorkingPool {
		t.Fatalf("current qualified candidate did not fill capacity: %+v", currentState)
	}
	if len(reconciled) != 1 || reconciled[0].CandidateID != current.ID {
		t.Fatalf("profiles=%+v, want only current candidate %s", reconciled, current.ID)
	}
}

func TestUpdateWorkingPoolRejectsCandidateThatHardFailsBeforeReplacement(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	failed := candidates["a"]
	challenger := candidates["b"]
	recordQualifiedTorCandidate(t, database, failed, 100, now)
	recordQualifiedTorCandidate(t, database, challenger, 80, now)

	profiles := newProductionTorProfiles(t)
	failures := 0
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 1, PromotionRatio: 0.15,
		beforeWorkingPoolReplace: func(attempt int) {
			if attempt != 0 {
				return
			}
			failures++
			if _, err := database.RecordCandidateProbe(
				context.Background(),
				store.ProbeTransition{
					Fingerprint: failed.Fingerprint,
					CandidateID: failed.ID,
					SourceID:    failed.SourceID,
					Success:     false,
					ErrorCode:   "active_hard_failure",
					At:          now.Add(time.Minute),
				},
			); err != nil {
				t.Fatal(err)
			}
		},
	}
	reconciled, err := service.updateWorkingPool(
		context.Background(), []store.Candidate{failed, challenger}, now,
	)
	if err != nil {
		t.Fatalf("pool reconciliation aborted on hard-failure interleaving: %v", err)
	}
	if failures != 1 {
		t.Fatalf("hard-failure barrier ran %d times, want 1", failures)
	}
	failedState, err := database.CandidateProbeState(
		context.Background(), failed.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	challengerState, err := database.CandidateProbeState(
		context.Background(), challenger.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if failedState.InWorkingPool || failedState.Draining || profiles.hasWarm(failed.ID) {
		t.Fatalf("hard-failed candidate remained active: state=%+v profiles=%+v",
			failedState, profiles.snapshot())
	}
	if !challengerState.InWorkingPool || !profiles.hasWarm(challenger.ID) {
		t.Fatalf("qualified challenger did not fill capacity: state=%+v profiles=%+v",
			challengerState, profiles.snapshot())
	}
	if len(reconciled) != 1 || reconciled[0].CandidateID != challenger.ID {
		t.Fatalf("profiles=%+v, want only challenger %s", reconciled, challenger.ID)
	}
}

func TestUpdateWorkingPoolFinalPayloadCleanupReconcilesAppliedMembership(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	first := candidates["a"]
	second := candidates["b"]
	for index, candidate := range []store.Candidate{first, second} {
		recordQualifiedTorCandidate(t, database, candidate, 100-float64(index), now)
	}

	profiles := newProductionTorProfiles(t)
	refreshes := 0
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 2, PromotionRatio: 0.15,
		beforeWorkingPoolList: func(attempt int) {
			if attempt == 0 {
				return
			}
			replaceTorCandidates(t, database, first.SourceID, "a", "b")
		},
		beforeWorkingPoolPayload: func(_ int, index int, _ store.Candidate) {
			if index != 1 {
				return
			}
			refreshes++
			replaceTorCandidates(t, database, first.SourceID, "c")
		},
	}
	reconciled, err := service.updateWorkingPool(
		context.Background(), []store.Candidate{first, second}, now,
	)
	if !errors.Is(err, store.ErrCandidateInventoryChanged) {
		t.Fatalf("pool reconciliation error=%v, want inventory change", err)
	}
	if refreshes != 3 {
		t.Fatalf("payload refresh barrier ran %d times, want 3", refreshes)
	}
	if len(reconciled) != 0 || len(profiles.snapshot()) != 0 {
		t.Fatalf("stale profile survived final cleanup: reconciled=%+v live=%+v",
			reconciled, profiles.snapshot())
	}
	for _, candidate := range []store.Candidate{first, second} {
		state, err := database.CandidateProbeState(
			context.Background(), candidate.Fingerprint,
		)
		if err != nil {
			t.Fatal(err)
		}
		if state.InWorkingPool || state.Draining {
			t.Fatalf("stale candidate remained in pool: %+v", state)
		}
	}
}

func TestTorReconcileCompensatesWhenRefreshDrainsCandidateDuringRPC(t *testing.T) {
	for _, pathway := range []string{"agent working pool", "legacy"} {
		t.Run(pathway, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := torPromotionStore(t)
			now := time.Unix(1_800_000_000, 0)
			first := candidates["a"]
			second := candidates["b"]
			for index, candidate := range []store.Candidate{first, second} {
				recordQualifiedTorCandidate(
					t, database, candidate, 100-float64(index), now,
				)
			}
			profiles := &refreshingReconcileProfiles{
				database: database,
				sourceID: first.SourceID,
				replacement: []store.CandidateInput{{
					Kind: sources.KindTorBridge, Label: "b", Fingerprint: "b",
					Payload: "Bridge 192.0.2.2:443 0000000000000000000000000000000000000002",
				}},
			}
			service := QualificationService{
				Store: database, Tor: profiles,
				PoolSize: 1, PromotionRatio: 0.15,
			}
			switch pathway {
			case "agent working pool":
				if _, err := service.updateWorkingPool(
					ctx, []store.Candidate{first, second}, now,
				); err != nil {
					t.Fatal(err)
				}
			case "legacy":
				service.Measurer = measureFuncController(func(
					context.Context, string, health.Protocol,
				) (health.Metrics, error) {
					return qualifiedMetrics(false), nil
				})
				if err := service.Run(ctx, now); err != nil {
					t.Fatal(err)
				}
			}
			if len(profiles.calls) < 2 {
				t.Fatalf("calls=%+v, want compensating reconcile", profiles.calls)
			}
			last := profiles.calls[len(profiles.calls)-1]
			for _, candidate := range last {
				if candidate.ID == first.ID {
					t.Fatalf("compensating reconcile retained draining candidate: %+v",
						profiles.calls)
				}
			}
			state, err := database.CandidateProbeState(ctx, first.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if state.InWorkingPool {
				t.Fatalf("draining candidate gained pool membership: %+v", state)
			}
		})
	}
}

func TestTorCompensationExhaustionPreservesVLESSPoolAndAssignment(t *testing.T) {
	ctx := context.Background()
	inputs := []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "vless", Fingerprint: "vless",
			Payload: "vless://vless@example.net:443?security=tls",
		},
		{
			Kind: sources.KindTorBridge, Label: "tor-a", Fingerprint: "tor-a",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindTorBridge, Label: "tor-b", Fingerprint: "tor-b",
			Payload: "Bridge 192.0.2.2:443 1123456789ABCDEF0123456789ABCDEF01234567",
		},
	}
	database, candidates := qualificationStore(t, inputs)
	now := time.Unix(1_800_000_000, 0)
	for index, fingerprint := range []string{"vless", "tor-a", "tor-b"} {
		recordQualifiedTorCandidate(
			t, database, candidates[fingerprint],
			100-float64(index), now,
		)
	}
	if err := database.ReplaceWorkingPool(
		ctx, []string{"vless", "tor-a"}, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "alice", Name: "alice", Address: "10.44.0.2/32",
		PublicKey: "alice-key",
	}, "config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates["vless"].ID,
		TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	profiles := &churningReconcileProfiles{
		database: database,
		sourceID: candidates["vless"].SourceID,
		inputs:   inputs,
	}
	service := QualificationService{
		Store: database, Tor: profiles,
		PoolSize: 2, PromotionRatio: 0.15,
	}
	_, err := service.updateWorkingPool(
		ctx, candidateListByFingerprint(candidates), now,
	)
	if !errors.Is(err, store.ErrCandidateInventoryChanged) {
		t.Fatalf("error=%v want inventory change", err)
	}
	vlessState, err := database.CandidateProbeState(ctx, "vless")
	if err != nil {
		t.Fatal(err)
	}
	torState, err := database.CandidateProbeState(ctx, "tor-a")
	if err != nil {
		t.Fatal(err)
	}
	if !vlessState.InWorkingPool || vlessState.Draining {
		t.Fatalf("VLESS pool membership was cleared: %+v", vlessState)
	}
	if torState.InWorkingPool || torState.Draining {
		t.Fatalf("Tor membership survived fail-closed clear: %+v", torState)
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil || len(assignments) != 1 ||
		assignments[0].TCPOutbound != candidates["vless"].ID {
		t.Fatalf("VLESS assignment changed: %+v err=%v", assignments, err)
	}
}

func candidateListByFingerprint(
	candidates map[string]store.Candidate,
) []store.Candidate {
	result := make([]store.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, candidate)
	}
	return result
}

type churningReconcileProfiles struct {
	database *store.Store
	sourceID string
	inputs   []store.CandidateInput
}

func (profiles *churningReconcileProfiles) ReconcileProfiles(
	ctx context.Context,
	_ []torpool.Candidate,
) ([]torpool.Profile, error) {
	if err := profiles.database.ReplaceCandidates(
		ctx, profiles.sourceID, profiles.inputs,
	); err != nil {
		return nil, err
	}
	return nil, nil
}

func (*churningReconcileProfiles) ExploreNext(
	context.Context,
) ([]torpool.Profile, error) {
	return nil, nil
}

type refreshingReconcileProfiles struct {
	database    *store.Store
	sourceID    string
	replacement []store.CandidateInput
	calls       [][]torpool.Candidate
	once        sync.Once
	refreshErr  error
}

func (profiles *refreshingReconcileProfiles) ReconcileProfiles(
	ctx context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	profiles.calls = append(
		profiles.calls, append([]torpool.Candidate(nil), candidates...),
	)
	profiles.once.Do(func() {
		profiles.refreshErr = profiles.database.ReplaceCandidates(
			ctx, profiles.sourceID, profiles.replacement,
		)
	})
	if profiles.refreshErr != nil {
		return nil, profiles.refreshErr
	}
	result := make([]torpool.Profile, 0, len(candidates))
	for index, candidate := range candidates {
		result = append(result, torpool.Profile{
			Slot: index, CandidateID: candidate.ID,
			SocksAddr: fmt.Sprintf("127.0.0.1:%d", 19050+index),
			Role:      "warm",
		})
	}
	return result, nil
}

func (*refreshingReconcileProfiles) ExploreNext(
	context.Context,
) ([]torpool.Profile, error) {
	return nil, nil
}

func TestUpdateWorkingPoolReconcilesEmptyTorPool(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	candidate := candidates["a"]
	recordQualifiedTorCandidate(t, database, candidate, 100, now)
	profiles := newProductionTorProfiles(t)
	service := QualificationService{
		Store: database, Tor: profiles, PoolSize: 1, PromotionRatio: 0.15,
	}
	if _, err := service.updateWorkingPool(
		context.Background(), []store.Candidate{candidate}, now,
	); err != nil {
		t.Fatal(err)
	}
	if !profiles.hasWarm(candidate.ID) {
		t.Fatalf("initial warm profile missing: %+v", profiles.snapshot())
	}
	if err := database.ReplaceCandidates(context.Background(), candidate.SourceID, []store.CandidateInput{
		{
			Kind: sources.KindVLESS, Label: "replacement", Fingerprint: "replacement",
			Payload: "vless://replacement@example.net:443?security=tls",
		},
	}); err != nil {
		t.Fatal(err)
	}
	current, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := service.updateWorkingPool(context.Background(), current, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciled) != 0 || len(profiles.snapshot()) != 0 {
		t.Fatalf("removed last Tor profile survived: reconciled=%+v live=%+v",
			reconciled, profiles.snapshot())
	}
}

func TestTorCandidatesDiscardFastProbeRemovedWhileInFlightAndContinue(t *testing.T) {
	database, candidates := torPromotionStore(t)
	removed := candidates["a"]
	remaining := candidates["b"]
	agent := newBlockingStaleTorAgent(removed.ID, "fast")
	service := QualificationService{
		Store: database, Agent: agent, Tor: newProductionTorProfiles(t),
		PoolSize: 3, PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
	}
	done := make(chan error, 1)
	go func() {
		done <- service.runTorCandidates(
			context.Background(),
			[]store.Candidate{removed, remaining},
			candidateList(candidates),
			time.Unix(1_800_000_000, 0),
		)
	}()
	agent.waitBlocked(t)
	replaceTorCandidates(t, database, removed.SourceID, "b")
	close(agent.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	requireNoCandidateProbeArtifacts(t, database, removed)
	if got := agent.callsFor(remaining.ID); fmt.Sprint(got) != fmt.Sprint([]string{"fast"}) {
		t.Fatalf("remaining queue calls=%v, want [fast]", got)
	}
}

func TestTorCandidatesDiscardSecondFullProbeRemovedWhileInFlightAndContinue(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	removed := candidates["a"]
	remaining := candidates["b"]
	for _, transition := range []store.ProbeTransition{
		{
			Fingerprint: removed.Fingerprint, CandidateID: removed.ID, SourceID: removed.SourceID,
			Success: true, At: now, ResetWindow: 5 * time.Hour,
		},
		{
			Fingerprint: removed.Fingerprint, CandidateID: removed.ID, SourceID: removed.SourceID,
			Full: true, Success: true, Score: 90, At: now, ResetWindow: 5 * time.Hour,
		},
	} {
		if _, err := database.RecordCandidateProbe(context.Background(), transition); err != nil {
			t.Fatal(err)
		}
	}
	agent := newBlockingStaleTorAgent(removed.ID, "full")
	promotions := make(chan struct{}, 1)
	profiles := newProductionTorProfiles(t)
	service := QualificationService{
		Store: database, Agent: agent, Tor: profiles,
		PoolSize: 3, PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
		Promotions: promotions,
	}
	done := make(chan error, 1)
	go func() {
		done <- service.runTorCandidates(
			context.Background(),
			[]store.Candidate{removed, remaining},
			candidateList(candidates),
			now.Add(time.Minute),
		)
	}()
	agent.waitBlocked(t)
	replaceTorCandidates(t, database, removed.SourceID, "b")
	close(agent.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	state, err := database.CandidateProbeState(context.Background(), removed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if state.FullSuccessStreak != 1 || state.Status != store.CandidatePreflight ||
		state.InWorkingPool || state.Draining {
		t.Fatalf("stale second full probe mutated state: %+v", state)
	}
	for _, row := range mustCandidateHealth(t, database) {
		if row.CandidateID == removed.ID {
			t.Fatalf("stale second full probe wrote health: %+v", row)
		}
	}
	if got := agent.callsFor(remaining.ID); fmt.Sprint(got) != fmt.Sprint([]string{"fast"}) {
		t.Fatalf("remaining queue calls=%v, want [fast]", got)
	}
	if len(profiles.snapshot()) != 0 {
		t.Fatalf("stale candidate was promoted: %+v", profiles.snapshot())
	}
	select {
	case <-promotions:
		t.Fatal("stale candidate signaled promotion")
	default:
	}
}

type blockingStaleTorAgent struct {
	mu           sync.Mutex
	blockedID    string
	blockedStage string
	started      chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	calls        map[string][]string
}

func newBlockingStaleTorAgent(candidateID, stage string) *blockingStaleTorAgent {
	return &blockingStaleTorAgent{
		blockedID: candidateID, blockedStage: stage,
		started: make(chan struct{}), release: make(chan struct{}),
		calls: make(map[string][]string),
	}
}

func (agent *blockingStaleTorAgent) ProbeFast(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	if agent.recordAndBlock(ctx, request.CandidateID, "fast") {
		return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: false, ErrorCode: "expected_remaining_failure",
	}, nil
}

func (agent *blockingStaleTorAgent) ProbeFull(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	if !agent.recordAndBlock(ctx, request.CandidateID, "full") {
		return agentapi.ProbeResponse{}, fmt.Errorf("unexpected full probe for %s", request.CandidateID)
	}
	metrics := health.Metrics{
		SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 20,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: true, Metrics: metrics,
		Evaluation: health.Evaluate(metrics, health.ProtocolTor),
	}, nil
}

func (agent *blockingStaleTorAgent) recordAndBlock(
	ctx context.Context,
	candidateID, stage string,
) bool {
	agent.mu.Lock()
	agent.calls[candidateID] = append(agent.calls[candidateID], stage)
	block := candidateID == agent.blockedID && stage == agent.blockedStage
	agent.mu.Unlock()
	if !block {
		return false
	}
	agent.startOnce.Do(func() { close(agent.started) })
	select {
	case <-agent.release:
	case <-ctx.Done():
	}
	return true
}

func (agent *blockingStaleTorAgent) waitBlocked(t *testing.T) {
	t.Helper()
	select {
	case <-agent.started:
	case <-time.After(time.Second):
		t.Fatal("probe did not block")
	}
}

func (agent *blockingStaleTorAgent) callsFor(candidateID string) []string {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return append([]string(nil), agent.calls[candidateID]...)
}

func replaceTorCandidates(t *testing.T, database *store.Store, sourceID string, fingerprints ...string) {
	t.Helper()
	inputs := make([]store.CandidateInput, 0, len(fingerprints))
	for index, fingerprint := range fingerprints {
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindTorBridge, Label: fingerprint, Fingerprint: fingerprint,
			Payload: fmt.Sprintf(
				"Bridge 192.0.2.%d:443 0123456789ABCDEF0123456789ABCDEF01234567",
				index+10,
			),
		})
	}
	if err := database.ReplaceCandidates(context.Background(), sourceID, inputs); err != nil {
		t.Fatal(err)
	}
}

func requireNoCandidateProbeArtifacts(
	t *testing.T,
	database *store.Store,
	candidate store.Candidate,
) {
	t.Helper()
	for _, state := range mustProbeStates(t, database) {
		if state.Fingerprint == candidate.Fingerprint {
			t.Fatalf("stale probe wrote state: %+v", state)
		}
	}
	for _, row := range mustCandidateHealth(t, database) {
		if row.CandidateID == candidate.ID {
			t.Fatalf("stale probe wrote health: %+v", row)
		}
	}
}

func mustProbeStates(t *testing.T, database *store.Store) []store.CandidateProbeState {
	t.Helper()
	rows, err := database.ListCandidateProbeStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func mustCandidateHealth(t *testing.T, database *store.Store) []store.CandidateHealth {
	t.Helper()
	rows, err := database.ListCandidateHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

type refreshingProbeAgent struct {
	mu          sync.Mutex
	database    *store.Store
	sourceID    string
	replacement []store.CandidateInput
	order       []string
	refreshed   bool
	refreshErr  error
}

func (agent *refreshingProbeAgent) ProbeFast(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.order = append(agent.order, request.CandidateID)
	if !agent.refreshed {
		agent.refreshed = true
		agent.refreshErr = agent.database.ReplaceCandidates(ctx, agent.sourceID, agent.replacement)
	}
	agent.mu.Unlock()
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Success:     false,
		ErrorCode:   "expected_test_failure",
	}, nil
}

func (agent *refreshingProbeAgent) ProbeFull(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{}, fmt.Errorf("unexpected full probe for %s", request.CandidateID)
}

func TestTorCandidatePromotesBeforeRemainingQueue(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("tor-source https://subscription.example/tor")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(context.Background())
	if err := database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "first", Fingerprint: "a",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindTorBridge, Label: "second", Fingerprint: "b",
			Payload: "Bridge 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
	}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(context.Background(), "")
	var firstID, secondID string
	for _, candidate := range candidates {
		switch candidate.Fingerprint {
		case "a":
			firstID = candidate.ID
		case "b":
			secondID = candidate.ID
		}
	}
	agent := newSequentialTorAgent(secondID)
	promotions := make(chan struct{}, 1)
	profiles := newProductionTorProfiles(t)
	service := QualificationService{
		Store: database, Agent: agent, Tor: profiles,
		PoolSize: 200, PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4, Promotions: promotions,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- service.Run(ctx, time.Unix(1_800_000_000, 0))
	}()

	select {
	case <-promotions:
	case <-time.After(time.Second):
		t.Fatal("first qualified Tor candidate did not trigger promotion")
	}
	select {
	case <-agent.secondStarted:
	case <-time.After(time.Second):
		t.Fatal("remaining Tor queue did not continue in background")
	}

	states, err := database.ListCandidateProbeStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := findProbeState(states, "a")
	if first.Status != store.CandidateQualified || !first.InWorkingPool {
		t.Fatalf("first state=%+v", first)
	}
	if agent.maximumConcurrent() != 1 || !agent.isSecondBlocked() {
		t.Fatalf("Tor probes overlapped or queue already completed: max=%d blocked=%v",
			agent.maximumConcurrent(), agent.isSecondBlocked())
	}
	if fast, full := agent.counts(firstID); fast != 1 || full != 2 {
		t.Fatalf("first probes fast=%d full=%d", fast, full)
	}
	if !profiles.hasWarm(firstID) {
		t.Fatalf("first candidate is not warm: %+v", profiles.snapshot())
	}
	close(agent.releaseSecond)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTorCandidateSignalsOnlyAfterActualWarmPromotion(t *testing.T) {
	tests := []struct {
		name            string
		poolSize        int
		wantInPool      bool
		wantProfileRole string
	}{
		{name: "excluded from full working pool", poolSize: 3},
		{name: "assigned only to explorer", poolSize: 4, wantInPool: true, wantProfileRole: "explorer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, candidates := torPromotionStore(t)
			now := time.Unix(1_800_000_000, 0)
			for index, fingerprint := range []string{"a", "b", "c"} {
				candidate := candidates[fingerprint]
				recordQualifiedTorCandidate(t, database, candidate, 100-float64(index), now)
			}
			if err := database.ReplaceWorkingPool(
				context.Background(),
				[]string{"a", "b", "c"},
				nil,
			); err != nil {
				t.Fatal(err)
			}

			low := candidates["d"]
			remaining := candidates["e"]
			agent := newSequentialTorAgent(remaining.ID)
			promotions := make(chan struct{}, 1)
			profiles := newProductionTorProfiles(t)
			service := QualificationService{
				Store: database, Agent: agent, Tor: profiles,
				PoolSize: test.poolSize, PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
				FastWorkers: 8, FullWorkers: 4, Promotions: promotions,
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- service.runTorCandidates(
					ctx,
					[]store.Candidate{low, remaining},
					candidateList(candidates),
					now,
				)
			}()

			select {
			case <-agent.secondStarted:
			case <-time.After(time.Second):
				t.Fatal("remaining Tor queue did not continue")
			}
			select {
			case <-promotions:
				t.Fatal("candidate without a warm profile triggered promotion")
			default:
			}
			state, err := database.CandidateProbeState(context.Background(), low.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if state.Status != store.CandidateQualified || state.InWorkingPool != test.wantInPool {
				t.Fatalf("state=%+v", state)
			}
			if role := profiles.role(low.ID); role != test.wantProfileRole {
				t.Fatalf("profile role=%q want=%q profiles=%+v", role, test.wantProfileRole, profiles.snapshot())
			}

			close(agent.releaseSecond)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTorCandidateDoesNotResignalExistingWarmProfile(t *testing.T) {
	database, candidates := torPromotionStore(t)
	now := time.Unix(1_800_000_000, 0)
	candidate := candidates["a"]
	recordQualifiedTorCandidate(t, database, candidate, 100, now)
	if err := database.ReplaceWorkingPool(context.Background(), []string{"a"}, nil); err != nil {
		t.Fatal(err)
	}
	promotions := make(chan struct{}, 1)
	profiles := newProductionTorProfiles(t)
	service := QualificationService{
		Store: database, Agent: newSequentialTorAgent(""), Tor: profiles,
		PoolSize: 3, PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4, Promotions: promotions,
	}
	if err := service.runTorCandidates(
		context.Background(),
		[]store.Candidate{candidate},
		candidateList(candidates),
		now,
	); err != nil {
		t.Fatal(err)
	}
	if !profiles.hasWarm(candidate.ID) {
		t.Fatalf("existing candidate lost warm profile: %+v", profiles.snapshot())
	}
	select {
	case <-promotions:
		t.Fatal("existing qualified warm candidate triggered another promotion")
	default:
	}
}

func torPromotionStore(t *testing.T) (*store.Store, map[string]store.Candidate) {
	t.Helper()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("tor-source https://subscription.example/tor")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]store.CandidateInput, 0, 5)
	for index, fingerprint := range []string{"a", "b", "c", "d", "e"} {
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindTorBridge, Label: fingerprint, Fingerprint: fingerprint,
			Payload: fmt.Sprintf(
				"Bridge 192.0.2.%d:443 0123456789ABCDEF0123456789ABCDEF01234567",
				index+1,
			),
		})
	}
	if err := database.ReplaceCandidates(context.Background(), listed[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	candidates := make(map[string]store.Candidate, len(rows))
	for _, candidate := range rows {
		candidates[candidate.Fingerprint] = candidate
	}
	return database, candidates
}

func recordQualifiedTorCandidate(
	t *testing.T,
	database *store.Store,
	candidate store.Candidate,
	score float64,
	now time.Time,
) {
	t.Helper()
	transitions := []store.ProbeTransition{
		{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
			Success: true, At: now, ResetWindow: 5 * time.Hour,
		},
		{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
			Full: true, Success: true, Score: score, At: now, ResetWindow: 5 * time.Hour,
		},
		{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
			Full: true, Success: true, Score: score, At: now, ResetWindow: 5 * time.Hour,
		},
	}
	for _, transition := range transitions {
		if _, err := database.RecordCandidateProbe(context.Background(), transition); err != nil {
			t.Fatal(err)
		}
	}
}

func candidateList(candidates map[string]store.Candidate) []store.Candidate {
	result := make([]store.Candidate, 0, len(candidates))
	for _, fingerprint := range []string{"a", "b", "c", "d", "e"} {
		result = append(result, candidates[fingerprint])
	}
	return result
}

type sequentialTorAgent struct {
	mu              sync.Mutex
	secondID        string
	secondStarted   chan struct{}
	releaseSecond   chan struct{}
	secondStartOnce sync.Once
	current         int
	maxConcurrent   int
	fast            map[string]int
	full            map[string]int
}

func newSequentialTorAgent(secondID string) *sequentialTorAgent {
	return &sequentialTorAgent{
		secondID: secondID, secondStarted: make(chan struct{}), releaseSecond: make(chan struct{}),
		fast: make(map[string]int), full: make(map[string]int),
	}
}

func (agent *sequentialTorAgent) ProbeFast(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.enter()
	defer agent.leave()
	agent.mu.Lock()
	agent.fast[request.CandidateID]++
	agent.mu.Unlock()
	if request.CandidateID == agent.secondID {
		agent.secondStartOnce.Do(func() { close(agent.secondStarted) })
		select {
		case <-agent.releaseSecond:
		case <-ctx.Done():
			return agentapi.ProbeResponse{}, ctx.Err()
		}
	}
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
}

func (agent *sequentialTorAgent) ProbeFull(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	agent.enter()
	defer agent.leave()
	agent.mu.Lock()
	agent.full[request.CandidateID]++
	agent.mu.Unlock()
	metrics := health.Metrics{
		SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 20,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
	}
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: true, Metrics: metrics,
		Evaluation: health.Evaluate(metrics, health.ProtocolTor),
	}, nil
}

func (agent *sequentialTorAgent) enter() {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.current++
	if agent.current > agent.maxConcurrent {
		agent.maxConcurrent = agent.current
	}
}

func (agent *sequentialTorAgent) leave() {
	agent.mu.Lock()
	agent.current--
	agent.mu.Unlock()
}

func (agent *sequentialTorAgent) maximumConcurrent() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.maxConcurrent
}

func (agent *sequentialTorAgent) counts(id string) (int, int) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.fast[id], agent.full[id]
}

func (agent *sequentialTorAgent) isSecondBlocked() bool {
	select {
	case <-agent.secondStarted:
		return true
	default:
		return false
	}
}

type productionTorProfiles struct {
	manager *torpool.Manager
}

func newProductionTorProfiles(t *testing.T) *productionTorProfiles {
	t.Helper()
	manager, err := torpool.NewManager(torpool.Config{
		Binary: "tor", DataDir: filepath.Join(t.TempDir(), "tor-profiles"),
		SocksPortBase: 19050, WarmProfiles: 3, ExplorerProfiles: 1,
	}, torProfileRunner{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return &productionTorProfiles{manager: manager}
}

type capturingTorProfiles struct {
	candidates []torpool.Candidate
}

func (profiles *capturingTorProfiles) ReconcileProfiles(
	_ context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	profiles.candidates = append([]torpool.Candidate(nil), candidates...)
	return nil, nil
}

func (*capturingTorProfiles) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return nil, nil
}

func (profiles *productionTorProfiles) ReconcileProfiles(
	ctx context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	return profiles.manager.Reconcile(ctx, candidates)
}

func (profiles *productionTorProfiles) ExploreNext(ctx context.Context) ([]torpool.Profile, error) {
	return profiles.manager.ExploreNext(ctx)
}

func (profiles *productionTorProfiles) hasWarm(candidateID string) bool {
	return profiles.role(candidateID) == "warm"
}

func (profiles *productionTorProfiles) role(candidateID string) string {
	for _, profile := range profiles.snapshot() {
		if profile.CandidateID == candidateID {
			return profile.Role
		}
	}
	return ""
}

func (profiles *productionTorProfiles) snapshot() []torpool.Profile {
	return profiles.manager.Profiles()
}

type torProfileRunner struct{}

func (torProfileRunner) Start(context.Context, string, ...string) (torpool.Process, error) {
	return &torProfileProcess{}, nil
}

type torProfileProcess struct {
	mu      sync.Mutex
	stopped bool
}

func (process *torProfileProcess) Stop() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.stopped = true
	return nil
}

func (process *torProfileProcess) Exited() bool {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.stopped
}
