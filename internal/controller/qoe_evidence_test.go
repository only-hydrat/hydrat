package controller

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestPromotionQoEToleratesSlowSuccessfulCadence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	for _, gap := range []time.Duration{55 * time.Second, 90 * time.Second} {
		state := qoe.State{Status: qoe.StatusHealthy, WindowValid: 5,
			LastValidAt: now, WindowStartedAt: now.Add(-4 * gap), WindowMaxGap: gap}
		if !promotionQoEReady(now, state, 5) {
			t.Fatalf("successful five-sample window at %s cadence was rejected", gap)
		}
	}
}

type qoeProbeFunc func(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)

func (f qoeProbeFunc) ProbeQoE(ctx context.Context, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return f(ctx, request)
}

func TestQoEInFlightSuccessCannotOutliveConfirmedFailure(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	candidate := candidates["route"]
	now := time.Unix(1_900_000_000, 0)
	monitor := &QoEMonitor{Store: database, Workers: 1, Now: func() time.Time { return now }}
	monitor.Agent = qoeProbeFunc(func(ctx context.Context, _ agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
		reservation, err := database.ReserveCandidateObservation(ctx, candidate, store.ObservationActive)
		if err != nil {
			t.Fatal(err)
		}
		_, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, candidate, reservation, now)
		if err != nil || !commit.Accepted {
			t.Fatalf("failure commit=%+v err=%v", commit, err)
		}
		observation := healthyQoE(now)
		return agentapi.ProbeResponse{CandidateID: candidate.ID, Success: true, QoE: &observation}, nil
	})
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("pre-failure observation became fresh QoE: %+v", states)
	}
}

func TestQoEInFlightSuccessCannotOutliveFastCandidateFailure(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	candidate := candidates["route"]
	now := time.Unix(1_900_000_000, 0)
	monitor := &QoEMonitor{Store: database, Workers: 1, Now: func() time.Time { return now }}
	monitor.Agent = qoeProbeFunc(func(ctx context.Context, _ agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
		reservation, err := database.ReserveCandidateObservation(ctx, candidate, store.ObservationFast)
		if err != nil {
			return agentapi.ProbeResponse{}, err
		}
		_, _, err = database.CommitCandidateProbeObservation(ctx, candidate, reservation, store.ProbeTransition{
			CandidateID: candidate.ID, SourceID: candidate.SourceID, Fingerprint: candidate.Fingerprint, At: now, ErrorCode: "liveness_failed",
		}, nil, nil)
		if err != nil {
			return agentapi.ProbeResponse{}, err
		}
		observation := healthyQoE(now)
		return agentapi.ProbeResponse{CandidateID: candidate.ID, Success: true, QoE: &observation}, nil
	})
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("pre-failure QoE survived fast failure: %+v", states)
	}
}

func TestUDPRecoveryDoesNotReuseSuccessesBeforeFailure(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, score: 90}})
	candidate := candidates["route"]
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	monitor := &QoEMonitor{Store: database}
	for i := 0; i < 2; i++ {
		if _, err := monitor.applyUDPObservation(ctx, candidate.ID, true, 0); err != nil {
			t.Fatal(err)
		}
	}
	reservation, err := database.ReserveCandidateObservation(ctx, candidate, store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.CommitCandidateActiveHardFailureObservation(ctx, candidate, reservation, now); err != nil {
		t.Fatal(err)
	}
	// Model successful full requalification after the outage; UDP still needs
	// its own three fresh positive observations in this failure generation.
	row := candidateHealthByID(t, database, candidate.ID)
	row.Available = true
	if err := database.SaveCandidateHealth(ctx, row); err != nil {
		t.Fatal(err)
	}
	if changed, err := monitor.applyUDPObservation(ctx, candidate.ID, true, 1); err != nil || changed {
		t.Fatalf("old UDP successes survived failure: changed=%t err=%v", changed, err)
	}
}

func TestQoEEvidenceSurvivesTwelveHoursWithJitterAndInfrastructureGaps(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	candidate := candidates["route"]
	base := time.Unix(1_900_000_000, 0)
	good, paused := 0, false
	for at, cycle := base, 0; at.Before(base.Add(12 * time.Hour)); cycle++ {
		gap := 55 * time.Second
		if cycle%2 == 1 {
			gap = 90 * time.Second
		}
		at = at.Add(gap)
		if cycle%17 == 0 {
			continue
		} // an infrastructure gap contributes no evidence
		if !paused && at.Sub(base) >= 6*time.Hour {
			at = at.Add(20 * time.Minute)
			good, paused = 0, true
		}
		state, _, err := database.RecordCandidateQoE(context.Background(), candidate, healthyQoE(at), qoe.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		good++
		if good < 5 && promotionQoEReady(at, state, 5) {
			t.Fatalf("promotion reused expired evidence after %d new samples", good)
		}
		if good >= 5 && !promotionQoEReady(at, state, 5) {
			t.Fatalf("healthy pool lost evidence at hour %.2f: %+v", at.Sub(base).Hours(), state)
		}
	}
}
