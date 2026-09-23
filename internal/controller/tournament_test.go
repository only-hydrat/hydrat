package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestAdaptiveTournamentEventuallySelectsLateCandidatesWithBoundedExploration(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("proxy-source https://subscription.example/list")
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	inputs := make([]store.CandidateInput, 40)
	for index := range inputs {
		inputs[index] = store.CandidateInput{
			Kind: sources.KindVLESS, Label: fmt.Sprintf("candidate-%03d", index),
			Fingerprint: fmt.Sprintf("fingerprint-%03d", index),
			Payload:     fmt.Sprintf("vless://user-%03d@example.net:443?security=tls", index),
		}
	}
	if err := database.ReplaceCandidates(ctx, listed[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, "")
	scores := make(map[string]float64, len(candidates))
	var lowFingerprint, highFingerprint string
	for _, candidate := range candidates {
		index, _ := strconv.Atoi(strings.TrimPrefix(candidate.Label, "candidate-"))
		scores[candidate.ID] = 50
		if index >= 20 {
			scores[candidate.ID] = 90
		}
		if index == 0 {
			lowFingerprint = candidate.Fingerprint
		}
		if index == 39 {
			highFingerprint = candidate.Fingerprint
		}
	}
	agent := &tournamentProbeAgent{scores: scores}
	service := QualificationService{
		Store: database, Agent: agent, PoolSize: 20,
		PromotionRatio: 0.15, ResetWindow: 5 * time.Hour,
		FastWorkers: 8, FullWorkers: 4,
	}
	start := time.Unix(1_800_000_000, 0)
	if err := service.Run(ctx, start); err != nil {
		t.Fatal(err)
	}
	states, _ := database.ListCandidateProbeStates(ctx)
	for _, state := range states {
		if state.InWorkingPool {
			t.Fatal("candidate entered working pool after only one full success")
		}
	}
	if err := service.Run(ctx, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Exploration is bounded per cycle; the last candidates need another turn.
	if err := service.Run(ctx, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	states, _ = database.ListCandidateProbeStates(ctx)
	working := make(map[string]bool)
	for _, state := range states {
		if state.InWorkingPool {
			working[state.Fingerprint] = true
		}
	}
	if len(working) != 20 || !working[highFingerprint] || working[lowFingerprint] {
		t.Fatalf("working=%d high=%v low=%v", len(working), working[highFingerprint], working[lowFingerprint])
	}
	if agent.fastCalls != 40 || agent.fullCalls < 80 {
		t.Fatalf("fast=%d full=%d", agent.fastCalls, agent.fullCalls)
	}
}

type tournamentProbeAgent struct {
	mu        sync.Mutex
	scores    map[string]float64
	fastCalls int
	fullCalls int
}

func (agent *tournamentProbeAgent) ProbeFast(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.fastCalls++
	agent.mu.Unlock()
	return agentapi.ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
}

func (agent *tournamentProbeAgent) ProbeFull(_ context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	agent.mu.Lock()
	agent.fullCalls++
	score := agent.scores[request.CandidateID]
	agent.mu.Unlock()
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: true,
		Metrics:    health.Metrics{SuccessRatio: 1},
		Evaluation: health.Evaluation{Score: score, TCPQualified: true, UDPQualified: true},
	}, nil
}
