package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

func TestFairProbeAdmissionReservesDiscoveryQuarter(t *testing.T) {
	jobs := make([]qualificationJob, 0, 160)
	for i := 0; i < 120; i++ {
		jobs = append(jobs, qualificationJob{candidate: store.Candidate{ID: fmt.Sprint(i)}, priority: tournament.PriorityWorkingPool})
	}
	for i := 0; i < 40; i++ {
		jobs = append(jobs, qualificationJob{candidate: store.Candidate{ID: fmt.Sprint(i + 120)}, priority: tournament.PriorityUnseen})
	}
	selected := fairProbeJobs(jobs, 32)
	discovered := 0
	for i, job := range selected {
		if job.priority == tournament.PriorityUnseen {
			discovered++
			if i > 0 && discovered == 1 && i > 3 {
				t.Fatal("discovery waits behind entire maintenance pool")
			}
		}
	}
	if len(selected) != 128 || discovered != 32 {
		t.Fatalf("selected=%d discovery=%d", len(selected), discovered)
	}
}

func TestQualificationDoesNotRecheckFreshHealthyPoolOnEveryWake(t *testing.T) {
	now := time.Unix(1800000000, 0)
	db, candidates := qualificationStore(t, []store.CandidateInput{{Kind: sources.KindVLESS, Label: "working", Fingerprint: "working", Payload: "vless://working@example.net:443"}})
	qualifyEngineReserveCandidates(t, db, now, candidates)
	if err := db.SaveCandidateHealth(context.Background(), store.CandidateHealth{CandidateID: candidates["working"].ID, Available: true, TCPQualified: true, UDPQualified: true, Score: 90, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	agent := &recordingExplorationAgent{seen: make(map[string]bool)}
	service := QualificationService{Store: db, Agent: agent, ResetWindow: 5 * time.Hour}
	if err := service.Run(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if agent.count() != 0 {
		t.Fatalf("fresh healthy route repeatedly probed: %d", agent.count())
	}
}

func TestDiscoveryAdmissionInterleavesSourcesWithinPriority(t *testing.T) {
	jobs := []qualificationJob{{candidate: store.Candidate{ID: "a1", SourceID: "a"}, priority: tournament.PriorityWorkingPool}, {candidate: store.Candidate{ID: "a2", SourceID: "a"}, priority: tournament.PriorityWorkingPool}, {candidate: store.Candidate{ID: "b1", SourceID: "b"}, priority: tournament.PriorityWorkingPool}, {candidate: store.Candidate{ID: "new", SourceID: "c"}, priority: tournament.PriorityUnseen}}
	ordered := interleaveProbeSources(jobs)
	if ordered[1].candidate.ID != "b1" || ordered[3].candidate.ID != "new" {
		t.Fatalf("source fairness or priority lost: %+v", ordered)
	}
}

func TestDiscoveryCovers2500CandidatesDespiteInfrastructureFailuresAndRefresh(t *testing.T) {
	now := time.Unix(1800000000, 0)
	queue := make([]tournament.Candidate, 2500)
	for i := range queue {
		queue[i] = tournament.Candidate{Fingerprint: fmt.Sprintf("%06d", i), Status: tournament.StatusUnknown}
	}
	seen := map[string]bool{}
	for cycle := 0; cycle < 50; cycle++ {
		jobs := tournament.BuildDiscoveryQueue(queue, tournament.QueuePolicy{Now: now, ResetWindow: 5 * time.Hour, PreferWorking: true})
		for _, job := range jobs[:min(64, len(jobs))] {
			seen[job.Fingerprint] = true
			for i := range queue {
				if queue[i].Fingerprint == job.Fingerprint {
					queue[i].LastFastProbeAt = now
					break
				}
			}
		}
		if cycle%5 == 0 {
			queue = append(queue, tournament.Candidate{Fingerprint: fmt.Sprintf("refresh-%d", cycle), Status: tournament.StatusUnknown})
		}
		now = now.Add(5 * time.Minute)
	}
	for i := 0; i < 2500; i++ {
		if !seen[fmt.Sprintf("%06d", i)] {
			t.Fatalf("candidate %d starved", i)
		}
	}
}
