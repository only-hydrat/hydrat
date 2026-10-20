package controller

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestNormalizationRecoversConfirmedFailureAfterUrgentDeadline(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "b"},
		{name: "backup", kind: sources.KindVLESS, score: 85, tcp: true, udp: true, failureDomain: "c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, candidates["primary"].ID, candidates["primary"].ID)
	engine := NewEngine(database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithDNSResolver("1.1.1.1"), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16))
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	before := engineQoEAssignment(t, database, "alice")
	failed := engineCandidateByID(t, candidates, before.TCPOutbound)
	reservation, err := database.ReserveCandidateObservation(ctx, failed, store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, failed, reservation, now.Add(time.Second)); err != nil || !commit.Accepted {
		t.Fatalf("failure commit=%+v err=%v", commit, err)
	}
	if err := engine.CapacityReady(ctx, now.Add(2*time.Second)); err == nil {
		t.Error("failed applied primary was reported ready")
	}
	// Model urgent deadline expiry before SaveDesiredPlan. No pending hard plan
	// exists, and the failure has aged beyond the urgent observation window.
	for _, candidate := range candidates {
		if candidate.ID != failed.ID {
			setEngineActiveObservationAt(t, database, candidate, now.Add(5*time.Minute))
		}
	}
	if err := engine.NormalizeActiveCriticalRoutes(ctx, now.Add(5*time.Minute)); err != nil {
		t.Logf("reserve replenishment may still be pending: %v", err)
	}
	after := engineQoEAssignment(t, database, "alice")
	if after.TCPOutbound == failed.ID {
		t.Fatal("normalization retained the confirmed failed primary")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredReason != string(PlacementHardFailure) {
		t.Fatalf("failure repair lost scoped recovery reason: %s", state.DesiredReason)
	}
}

type lostRecoveryReplyAgent struct {
	*reconcilerEngineAgent
	loseReply bool
}

type scopedRecoveryRecordingAgent struct {
	engineAgent
	scopes []dataplane.FlowRecovery
}

func (agent *scopedRecoveryRecordingAgent) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, scopes []dataplane.FlowRecovery) error {
	agent.scopes = append(agent.scopes, scopes...)
	return agent.Apply(ctx, plan)
}

func TestRecoveryReconcilesConcurrentSourceRevocationWithoutResettingHealthyClient(t *testing.T) {
	for _, change := range []string{"source", "address", "pause", "new_client"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1900000000, 0)
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{{name: "failed", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"}})
			for _, name := range []string{"good-b", "good-c", "revoked"} {
				before, err := database.ListSources(ctx)
				if err != nil {
					t.Fatal(err)
				}
				known := make(map[string]bool)
				for _, source := range before {
					known[source.ID] = true
				}
				if _, err := database.ImportSources(ctx, sources.PreviewInput("https://"+name+".example/sub").Items); err != nil {
					t.Fatal(err)
				}
				after, err := database.ListSources(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var sourceID string
				for _, source := range after {
					if !known[source.ID] {
						sourceID = source.ID
					}
				}
				if sourceID == "" {
					t.Fatal("new source not found")
				}
				if err := database.ReplaceCandidates(ctx, sourceID, []store.CandidateInput{{Kind: sources.KindVLESS, Label: name, Fingerprint: name, RouteKey: name, FailureDomain: name, Payload: "vless://550e8400-e29b-41d4-a716-446655440000@" + name + ".example:443?security=tls"}}); err != nil {
					t.Fatal(err)
				}
				rows, err := database.ListCandidates(ctx, sourceID)
				if err != nil || len(rows) != 1 {
					t.Fatalf("candidates=%v %v", rows, err)
				}
				candidates[name] = rows[0]
				if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: rows[0].ID, Available: true, TCPQualified: true, UDPQualified: true, Score: 90, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			qualifyEngineReserveCandidates(t, database, now, candidates)
			putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, candidates["failed"].ID, candidates["failed"].ID)
			putEngineQoEClient(t, database, "bob", "10.44.0.3/32", now, false, candidates["revoked"].ID, candidates["revoked"].ID)
			agent := &scopedRecoveryRecordingAgent{}
			engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16))
			if err := engine.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}
			failed := candidates["failed"]
			if assignment := engineQoEAssignment(t, database, "bob"); assignment.TCPOutbound != candidates["revoked"].ID {
				t.Fatal("fixture did not install the independently healthy source")
			}
			reservation, err := database.ReserveCandidateObservation(ctx, failed, store.ObservationActive)
			if err != nil {
				t.Fatal(err)
			}
			if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, failed, reservation, now.Add(time.Second)); err != nil || !commit.Accepted {
				t.Fatalf("failure=%+v %v", commit, err)
			}
			switch change {
			case "source":
				if err := database.UpdateSource(ctx, candidates["revoked"].SourceID, "revoked by operator", false); err != nil {
					t.Fatal(err)
				}
			case "address":
				if err := database.PutClient(ctx, store.ClientRecord{ID: "bob", Name: "bob", Address: "10.44.0.9/32"}, "replacement config"); err != nil {
					t.Fatal(err)
				}
			case "pause":
				if err := database.UpdateClient(ctx, "bob", "bob", true); err != nil {
					t.Fatal(err)
				}
			case "new_client":
				putEngineQoEClient(t, database, "charlie", "10.44.0.4/32", now, false, candidates["good-b"].ID, candidates["good-b"].ID)
			}
			if err := engine.NormalizeActiveCriticalRoutes(ctx, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound == failed.ID {
				t.Fatal("unrelated source revocation stranded confirmed recovery")
			}
			if len(agent.scopes) != 1 || agent.scopes[0].ClientID != "alice" {
				t.Fatalf("healthy revoked-source client received a hard reset: %+v", agent.scopes)
			}
		})
	}
}

func (agent *lostRecoveryReplyAgent) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, scopes []dataplane.FlowRecovery) error {
	if err := agent.reconcilerEngineAgent.ApplyWithRecovery(ctx, plan, scopes); err != nil {
		return err
	}
	if agent.loseReply {
		agent.loseReply = false
		return dataplane.ErrRuntimeRecovering
	}
	return nil
}

func TestRouteRecoverySurvivesLostApplyReplyAndControllerGatewayReopen(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, candidates["primary"].ID, candidates["primary"].ID)
	adapter := &recordingEngineAdapter{}
	appliedPath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, err := dataplane.NewReconciler(adapter, appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	agent := &lostRecoveryReplyAgent{reconcilerEngineAgent: &reconcilerEngineAgent{reconciler: reconciler}}
	newEngine := func(database *store.Store) *Engine {
		return NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute))
	}
	engine := newEngine(database)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	failed := engineCandidateByID(t, candidates, engineQoEAssignment(t, database, "alice").TCPOutbound)
	reservation, err := database.ReserveCandidateObservation(ctx, failed, store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, failed, reservation, now.Add(time.Second)); err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v %v", commit, err)
	}
	agent.loseReply = true
	if err := engine.CycleForReason(ctx, now.Add(2*time.Second), PlacementHardFailure); !errors.Is(err, dataplane.ErrRuntimeRecovering) {
		t.Fatalf("lost reply=%v", err)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil || state.AppliedGeneration >= state.DesiredGeneration {
		t.Fatalf("lost acknowledgement marked applied: %+v %v", state, err)
	}
	if debt, err := database.PendingRouteRecoveries(ctx); err != nil || len(debt) != 2 {
		t.Fatalf("lost acknowledgement cleared debt: %+v %v", debt, err)
	}
	backupPath := filepath.Join(t.TempDir(), "reopened.db")
	if err := database.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	reopened, err := store.Open(backupPath, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reconciler, err = dataplane.NewReconciler(adapter, appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	agent.reconciler = reconciler
	if err := reconciler.Rehydrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.ID != failed.ID {
			setEngineActiveObservationAt(t, reopened, candidate, now.Add(5*time.Minute))
		}
	}
	if err := newEngine(reopened).CycleForReason(ctx, now.Add(5*time.Minute), PlacementPeriodic); err != nil {
		t.Fatal(err)
	}
	if after := engineQoEAssignment(t, reopened, "alice"); after.TCPOutbound == failed.ID {
		t.Fatal("reopened controller retained failed primary")
	}
	if debt, err := reopened.PendingRouteRecoveries(ctx); err != nil || len(debt) != 0 {
		t.Fatalf("acknowledged repair retained debt: %+v %v", debt, err)
	}
	if len(agent.recoveries) != 2 || len(agent.recoveries[0]) != 1 || !reflect.DeepEqual(agent.recoveries[0], agent.recoveries[1]) {
		t.Fatalf("retry changed client/flow recovery scope: %+v", agent.recoveries)
	}
}
