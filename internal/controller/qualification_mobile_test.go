package controller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

func TestMobileQualificationPromotesBeforeScanningAllCandidates(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	inputs := make([]store.CandidateInput, 12)
	for i := range inputs {
		name := fmt.Sprintf("route-%02d", i)
		inputs[i] = store.CandidateInput{Kind: sources.KindVLESS, Label: name,
			Fingerprint: name, Payload: "vless://test@" + name + ".example.net:443"}
	}
	db, _ := qualificationStore(t, inputs)
	agent := &mobileQualificationAgent{}
	service := QualificationService{
		Store: db, Agent: agent, MobileReserves: 3, FastWorkers: 1, FullWorkers: 1,
	}
	if err := service.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	states, err := db.ListCandidateProbeStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	working := 0
	for _, state := range states {
		if state.InWorkingPool && state.Status == store.CandidateQualified {
			working++
		}
	}
	if working != 4 || agent.full != 8 || agent.fast >= len(inputs) {
		t.Fatalf("want one primary and three reserves before exhausting discovery: working=%d fast=%d full=%d", working, agent.fast, agent.full)
	}
	agent.fast, agent.full = 0, 0
	if err := service.Run(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if agent.fast != 0 || agent.full != 0 {
		t.Fatalf("warmed pool must stop exploration after reconnect: fast=%d full=%d", agent.fast, agent.full)
	}
}

type mobileQualificationAgent struct {
	mu         sync.Mutex
	fast, full int
}

func (agent *mobileQualificationAgent) ProbeFast(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.fast++
	agent.mu.Unlock()
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
}

func (agent *mobileQualificationAgent) ProbeFull(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.full++
	agent.mu.Unlock()
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true,
		Evaluation: health.Evaluation{Score: 97, TCPQualified: true, UDPQualified: true}}, nil
}

func TestMobileContinuesQualificationWhileAnotherFastProbeIsBlocked(t *testing.T) {
	db, candidates := qualificationStore(t, []store.CandidateInput{
		{Kind: sources.KindVLESS, Fingerprint: "fast", Payload: "vless://test@fast.example.net:443"},
		{Kind: sources.KindVLESS, Fingerprint: "slow", Payload: "vless://test@slow.example.net:443"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fast, slow := candidates["fast"], candidates["slow"]
	agent := &blockedMobileProbeAgent{
		slow: slow.ID, slowStarted: make(chan struct{}), releaseSlow: make(chan struct{}),
	}
	promoted := make(chan struct{}, 1)
	service := QualificationService{
		Store: db, Agent: agent, MobileReserves: 3, FastWorkers: 2, FullWorkers: 1, Promotions: promoted,
	}
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx, time.Now()) }()
	defer func() {
		close(agent.releaseSlow)
		if err := <-done; err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()
	select {
	case <-promoted:
		state, err := db.CandidateProbeState(ctx, fast.Fingerprint)
		if err != nil || state.FullSuccessStreak != 2 || !state.InWorkingPool {
			t.Fatalf("promotion must follow both full checks: %+v, %v", state, err)
		}
	case <-ctx.Done():
		t.Fatal("the fast candidate did not qualify while the other check was blocked")
	}
}

type blockedMobileProbeAgent struct {
	slow        string
	slowStarted chan struct{}
	releaseSlow chan struct{}
}

func (agent *blockedMobileProbeAgent) ProbeFast(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	if request.CandidateID == agent.slow {
		close(agent.slowStarted)
		select {
		case <-ctx.Done():
			return agentapi.ProbeResponse{}, ctx.Err()
		case <-agent.releaseSlow:
			return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
		}
	}
	select {
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	case <-agent.slowStarted:
		return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
	}
}

func (agent *blockedMobileProbeAgent) ProbeFull(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true,
		Evaluation: health.Evaluation{Score: 97, TCPQualified: true, UDPQualified: true}}, nil
}

func TestMobileRechecksOnlyScoreBansAcceptedByLowerMinimum(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	cases := []struct {
		name, code string
		score      float64
	}{
		{"eligible", "score_too_low", 79.34},
		{"below", "score_too_low", 74.94},
		{"gate-failed", "chatgpt_web_failed", 79.34},
	}
	inputs := make([]store.CandidateInput, 0, len(cases))
	for _, fixture := range cases {
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindVLESS, Fingerprint: fixture.name, Payload: "vless://test@" + fixture.name + ".example.net:443",
		})
	}
	db, candidates := qualificationStore(t, inputs)
	for _, fixture := range cases {
		candidate := candidates[fixture.name]
		for i := range 3 {
			at := now.Add(time.Duration(i-3) * time.Second)
			if _, err := db.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
				Full: true, ErrorCode: fixture.code, Score: fixture.score, At: at,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: fixture.score, UpdatedAt: now.Add(-time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	agent := &mobileQualificationAgent{}
	service := QualificationService{
		Store: db, Agent: agent, MobileReserves: 3, MinVLESSScore: 75, FastWorkers: 2,
	}
	if err := service.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	if agent.fast != 0 || agent.full != 2 {
		t.Fatalf("expected two full confirmations for the score-only candidate, fast=%d full=%d", agent.fast, agent.full)
	}
	state, err := db.CandidateProbeState(ctx, "eligible")
	if err != nil || !state.InWorkingPool || state.FullSuccessStreak != 2 {
		t.Fatalf("score candidate must qualify again: %+v, %v", state, err)
	}
	for _, name := range []string{"below", "gate-failed"} {
		state, err := db.CandidateProbeState(ctx, name)
		if err != nil || state.Status != store.CandidateBanned || state.InWorkingPool {
			t.Fatalf("protected ban %s changed: %+v, %v", name, state, err)
		}
	}
}

func TestMobileDiscoveryWorkersFollowRouteHealth(t *testing.T) {
	t.Run("serving route uses four", func(t *testing.T) {
		checkMobileDiscoveryWorkers(t, false, 4)
	})
	t.Run("failed route uses eight", func(t *testing.T) {
		checkMobileDiscoveryWorkers(t, true, 8)
	})
}

func checkMobileDiscoveryWorkers(t *testing.T, failed bool, workers int) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	inputs := mobileTestCandidates(12)
	db, candidates := qualificationStore(t, inputs)
	ctx := context.Background()
	if err := db.EnsureLocalDevice(ctx, "device", "test", "10.1.0.2/32"); err != nil {
		t.Fatal(err)
	}
	active := make([]store.Candidate, 0, 4)
	for _, input := range inputs[:4] {
		candidate := candidates[input.Fingerprint]
		seedMobileQualifiedCandidate(t, db, candidate, now.Add(-time.Minute))
		active = append(active, candidate)
	}
	if _, err := db.ReplaceWorkingPoolCurrent(ctx, active, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAssignment(ctx, store.AssignmentRecord{ClientID: "device", TCPOutbound: active[0].ID, UDPOutbound: active[0].ID, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if failed {
		if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: active[0].ID, TCPQualified: true, UDPQualified: true, Available: false, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	agent := &backgroundMobileProbeAgent{started: make(chan struct{}, 12), release: make(chan struct{})}
	service := QualificationService{
		Store: db, Agent: agent, MobileReserves: 3, FastWorkers: 8,
		MobileRouteInstalled: func() bool { return true },
	}
	run, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Run(run, now) }()
	defer func() {
		close(agent.release)
		if err := <-done; err != nil && run.Err() == nil {
			t.Error(err)
		}
	}()
	for range workers {
		select {
		case <-agent.started:
		case <-run.Done():
			t.Fatal("the ready pool prevented discovery of newer candidates")
		}
	}
	select {
	case <-agent.started:
		t.Fatalf("discovery exceeded %d simultaneous checks", workers)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestMobileRevalidatesSavedRoutesBeforeReusingThem(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	inputs := mobileTestCandidates(2)
	db, candidates := qualificationStore(t, inputs)
	old := candidates[inputs[0].Fingerprint]
	newer := candidates[inputs[1].Fingerprint]
	seedMobileQualifiedCandidate(t, db, old, now.Add(-2*time.Hour))
	seedMobileQualifiedCandidate(t, db, newer, now.Add(-time.Minute))
	ctx := context.Background()
	agent := &mobileQualificationAgent{}
	service := QualificationService{Store: db, Agent: agent, MobileReserves: 3, FastWorkers: 4}
	if _, err := service.updateWorkingPool(ctx, nil, now); err != nil {
		t.Fatal(err)
	}
	before, err := db.CandidateProbeState(ctx, old.Fingerprint)
	if err != nil || before.InWorkingPool || before.Status != store.CandidateQualified {
		t.Fatalf("old candidate should be retained outside the working pool: %+v, %v", before, err)
	}
	if err := service.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	after, err := db.CandidateProbeState(ctx, old.Fingerprint)
	if err != nil || !after.InWorkingPool || !after.LastFullProbeAt.After(before.LastFullProbeAt) {
		t.Fatalf("saved candidate was not revalidated for recovery: %+v, %v", after, err)
	}
}

type backgroundMobileProbeAgent struct {
	mobileQualificationAgent
	started chan struct{}
	release chan struct{}
}

func (agent *backgroundMobileProbeAgent) ProbeFast(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.started <- struct{}{}
	select {
	case <-agent.release:
		return agentapi.ProbeResponse{CandidateID: request.CandidateID}, nil
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	}
}

func mobileTestCandidates(count int) []store.CandidateInput {
	inputs := make([]store.CandidateInput, count)
	for index := range inputs {
		name := fmt.Sprintf("route-%02d", index)
		inputs[index] = store.CandidateInput{
			Kind: sources.KindVLESS, Fingerprint: name, Label: name,
			Payload: "vless://test@" + name + ".example.net:443",
		}
	}
	return inputs
}

func seedMobileQualifiedCandidate(t *testing.T, db *store.Store, candidate store.Candidate, at time.Time) {
	t.Helper()
	ctx := context.Background()
	for offset := range 3 {
		if _, err := db.RecordCandidateProbe(ctx, store.ProbeTransition{
			Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID, SourceID: candidate.SourceID,
			Full: true, Success: true, Score: 90, At: at.Add(time.Duration(offset-2) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: candidate.ID, Score: 90, Available: true, TCPQualified: true, UDPQualified: true, UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHardFailureInterruptsMobileQualification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan struct{}, 1)
	qualify := make(chan struct{}, 1)
	interrupted := make(chan struct{}, 1)
	placements := make(chan PlacementReason, 1)
	runtime := Runtime{
		HardFailures: failures,
		InterruptQualification: func() {
			interrupted <- struct{}{}
		},
	}
	go runtime.watchEvents(ctx, nil, nil, qualify, nil, func(reason PlacementReason) {
		placements <- reason
	})
	failures <- struct{}{}
	select {
	case <-qualify:
		select {
		case <-interrupted:
		default:
			t.Fatal("recovery was queued before cancelling the current discovery")
		}
		if reason := <-placements; reason != PlacementHardFailure {
			t.Fatalf("placement reason = %s", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmed hard failure did not wake qualification")
	}
}

func TestMobilePoolRequiresDistinctUDPReserve(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	inputs := mobileTestCandidates(5)
	db, candidates := qualificationStore(t, inputs)
	var active []store.Candidate
	keys := make(map[string]mobileRouteIdentity)
	for i, input := range inputs {
		candidate := candidates[input.Fingerprint]
		seedMobileQualifiedCandidate(t, db, candidate, now)
		keys[candidate.ID] = mobileRouteIdentity{key: candidate.ID, vless: true}
		score := 95.0
		if i == 4 {
			score = 80
		}
		if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: score, Available: true,
			TCPQualified: true, UDPQualified: i == 0 || i == 4, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		if i < 4 {
			active = append(active, candidate)
		}
	}
	if err := db.EnsureLocalDevice(ctx, "device", "test", "10.1.0.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "device", TCPOutbound: active[0].ID, UDPOutbound: active[0].ID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceWorkingPoolCurrent(ctx, active, nil, now); err != nil {
		t.Fatal(err)
	}
	service := QualificationService{Store: db, MobileReserves: 3, MinVLESSScore: 75, PromotionRatio: 0.15}
	before, err := service.mobilePoolAvailability(ctx, keys)
	if err != nil || before.full {
		t.Fatalf("single UDP route: full=%v, %v", before.full, err)
	}
	if _, err := service.updateWorkingPool(ctx, nil, now); err != nil {
		t.Fatal(err)
	}
	after, err := service.mobilePoolAvailability(ctx, keys)
	if err != nil || !after.full {
		t.Fatalf("second UDP route not promoted: full=%v, %v", after.full, err)
	}
}

func TestMobileQualificationPersistsSafeLivenessFailureDetails(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	inputs := mobileTestCandidates(1)
	db, candidates := qualificationStore(t, inputs)
	candidate := candidates[inputs[0].Fingerprint]
	service := QualificationService{Store: db, MobileReserves: 3, ResetWindow: 5 * time.Hour}
	result := qualificationResult{
		job: qualificationJob{candidate: candidate},
		response: agentapi.ProbeResponse{
			CandidateID: candidate.ID,
			ErrorCode:   "liveness_failed", FailureClass: agentapi.FailureCandidate,
			Observation: health.Observation{
				PrimaryFailure: "timeout", PrimaryElapsedMS: 2910,
				ConfirmationFailure: "https://example.invalid/secret", ConfirmationElapsedMS: 90000,
			},
		},
	}
	state, err := service.recordProbeResult(ctx, now, result, tournament.ProbeFast)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastErrorCode != "liveness_failed" ||
		state.LastErrorMessage != "primary=timeout/2910ms confirmation=unknown/30000ms" {
		t.Fatalf("unexpected diagnostics code %q, summary %q", state.LastErrorCode, state.LastErrorMessage)
	}

	seedMobileQualifiedCandidate(t, db, candidate, now.Add(3*time.Second))
	result.response = agentapi.ProbeResponse{
		CandidateID: candidate.ID, ErrorCode: "probe_runtime_unavailable", FailureClass: agentapi.FailureInfrastructure,
	}
	state, err = service.recordProbeResult(ctx, now.Add(4*time.Second), result, tournament.ProbeFast)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != store.CandidateQualified || state.ConservativeScore != 90 || state.FailureStreak != 0 {
		t.Fatalf("infrastructure error changed qualification: status=%s score=%v failure streak=%d",
			state.Status, state.ConservativeScore, state.FailureStreak)
	}
}
