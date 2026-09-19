package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestEngineUnchangedPlanDoesNotWriteApplyOrIncrementAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	now := time.Unix(1_800_000_000, 0)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	before, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.DesiredGeneration != 1 || before.AppliedGeneration != 1 || len(agent.plans) != 1 {
		t.Fatalf("initial state=%+v plans=%+v", before, agent.plans)
	}
	if !bytes.Contains(before.DesiredPlan, []byte(`"outbounds":[]`)) ||
		!bytes.Contains(before.DesiredPlan, []byte(`"clients":[]`)) {
		t.Fatalf(
			"generated plan violates complete array contract: %s",
			before.DesiredPlan,
		)
	}
	installEngineWriteRejectingTrigger(t, path, "plan_state", "reject_unchanged_plan_state_update")

	restarted := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := restarted.Cycle(ctx, now.Add(time.Minute)); err != nil {
		t.Fatalf("unchanged restart cycle: %v", err)
	}
	after, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.DesiredGeneration != 1 || after.AppliedGeneration != 1 ||
		!bytes.Equal(after.DesiredPlan, before.DesiredPlan) ||
		!bytes.Equal(after.AppliedPlan, before.AppliedPlan) {
		t.Fatalf("unchanged plan state changed:\nbefore=%+v\nafter=%+v", before, after)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("unchanged plan was applied again: %+v", agent.plans)
	}
	if events, err := database.ListEvents(ctx, 10); err != nil || len(events) != 0 {
		t.Fatalf("unchanged cycle events=%+v err=%v", events, err)
	}
}

func TestEnginePendingIdenticalPlanRetriesPersistedGenerationAndBytes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "paused", Name: "Paused", Address: "10.44.0.2/32",
		PublicKey: "peer-paused", Paused: true,
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "paused", TCPOutbound: "persisted-old",
		TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	pending := dataplane.DesiredPlan{
		Generation:     7,
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	}
	encoded, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	epoch, err := database.InventoryEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, pending.Generation, encoded, epoch, nil, nil,
		[]store.AssignmentRecord{{
			ClientID: "paused", TCPSince: now, UDPSince: now, UpdatedAt: now,
		}},
	); err != nil {
		t.Fatal(err)
	}

	applyFailure := errors.New("agent apply failed")
	agent := &engineAgent{applyErr: applyFailure}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, now); !errors.Is(err, applyFailure) {
		t.Fatalf("first pending retry error=%v", err)
	}
	failed, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if failed.DesiredGeneration != 7 || failed.AppliedGeneration != 0 ||
		!bytes.Equal(failed.DesiredPlan, encoded) || len(failed.AppliedPlan) != 0 {
		t.Fatalf("failed retry changed pending state=%+v", failed)
	}

	agent.applyErr = nil
	restarted := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := restarted.Cycle(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	applied, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied.DesiredGeneration != 7 || applied.AppliedGeneration != 7 ||
		!bytes.Equal(applied.DesiredPlan, encoded) || !bytes.Equal(applied.AppliedPlan, encoded) {
		t.Fatalf("pending retry did not preserve desired bytes=%+v", applied)
	}
	if len(agent.plans) != 2 ||
		agent.plans[0].Generation != 7 || agent.plans[1].Generation != 7 {
		t.Fatalf("pending retry generations=%+v", agent.plans)
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != "" || assignments[0].UDPOutbound != "" {
		t.Fatalf("pending retry rewrote assignments=%+v", assignments)
	}
}

func TestEnginePendingApplyPromotesPersistedAssignmentsAndReserveAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "primary", Fingerprint: "primary", Payload: "vless://primary@example.net:443"},
		{Kind: sources.KindVLESS, Label: "reserve", Fingerprint: "reserve", Payload: "vless://reserve@example.net:443"},
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListCandidates(ctx, "")
	candidates := make(map[string]store.Candidate)
	for _, candidate := range rows {
		candidates[candidate.Label] = candidate
	}
	for _, client := range []store.ClientRecord{
		{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "alice-key"},
		{ID: "paused", Name: "Paused", Address: "10.44.0.3/32", PublicKey: "paused-key", Paused: true},
	} {
		if err := database.PutClient(ctx, client, "secret-"+client.ID); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Unix(1_900_000_000, 0)
	for _, clientID := range []string{"alice", "paused"} {
		if err := database.SetAssignment(ctx, store.AssignmentRecord{
			ClientID: clientID, TCPOutbound: "old", UDPOutbound: "old",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour), UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{
			{ID: candidates["primary"].ID, Protocol: dataplane.ProtocolVLESS},
			{ID: candidates["reserve"].ID, Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: candidates["primary"].ID, BlockUDP: true,
			TCPReserveOutbound: candidates["reserve"].ID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	encoded, _ := json.Marshal(plan)
	epoch, _ := database.InventoryEpoch(ctx)
	if err := database.SaveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, 1, encoded, epoch,
		[]store.CandidatePlanExpectation{
			{Candidate: candidates["primary"]}, {Candidate: candidates["reserve"]},
		},
		[]store.RouteReserveMapping{{
			ClientID: "alice", TCPPrimaryCandidateID: candidates["primary"].ID,
			TCPReserveCandidateID: candidates["reserve"].ID,
		}},
		[]store.AssignmentRecord{
			{ClientID: "alice", TCPOutbound: candidates["primary"].ID, TCPSince: now, UDPSince: now, UpdatedAt: now},
			{ClientID: "paused", TCPSince: now, UDPSince: now, UpdatedAt: now},
		},
	); err != nil {
		t.Fatal(err)
	}
	faultDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := faultDB.Exec(`
		CREATE TRIGGER fail_pending_promotion BEFORE INSERT ON assignments
		BEGIN SELECT RAISE(ABORT, 'forced promotion failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	_ = faultDB.Close()
	firstAgent := &engineAgent{}
	first := NewEngine(database, firstAgent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := first.applyPlan(ctx, plan, encoded); err == nil {
		t.Fatal("first applied mark unexpectedly succeeded")
	}
	if len(firstAgent.plans) != 1 {
		t.Fatalf("external apply calls=%d want=1", len(firstAgent.plans))
	}
	state, _ := database.LoadPlanState(ctx)
	assignments, _ := database.ListAssignments(ctx)
	if state.AppliedGeneration != 0 || assignments[0].TCPOutbound != "old" {
		t.Fatalf("failed mark state=%+v assignments=%+v", state, assignments)
	}
	faultDB, _ = sql.Open("sqlite", path)
	if _, err := faultDB.Exec(`DROP TRIGGER fail_pending_promotion`); err != nil {
		t.Fatal(err)
	}
	_ = faultDB.Close()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	secondAgent := &engineAgent{}
	restarted := NewEngine(database, secondAgent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := restarted.applyPlan(ctx, plan, encoded); err != nil {
		t.Fatal(err)
	}
	assignments, err = database.ListAssignments(ctx)
	if err != nil || len(assignments) != 2 ||
		assignments[0].ClientID != "alice" || assignments[0].TCPOutbound != candidates["primary"].ID ||
		assignments[1].ClientID != "paused" || assignments[1].TCPOutbound != "" {
		t.Fatalf("recovered assignments=%+v err=%v", assignments, err)
	}
	reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", store.RouteTransportTCP, candidates["primary"].ID,
	)
	if err != nil || !ok || reserve != candidates["reserve"].ID {
		t.Fatalf("recovered reserve=%q ok=%v err=%v", reserve, ok, err)
	}
}

func TestEngineNeverAppliesLegacyPendingPlanBeforeFreshSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "public",
	}, "wireguard-secret"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	oldPlan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds:  []dataplane.Outbound{{ID: "cand_old", Protocol: dataplane.ProtocolVLESS}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "cand_old", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	stalePlan := oldPlan
	stalePlan.Generation = 2
	stalePlan.Outbounds = []dataplane.Outbound{{ID: "cand_new", Protocol: dataplane.ProtocolVLESS}}
	stalePlan.Clients = []dataplane.ClientRoute{{
		ClientID: "alice", TCPOutbound: "cand_new", BlockUDP: true,
	}}
	oldEncoded, _ := json.Marshal(oldPlan)
	staleEncoded, _ := json.Marshal(stalePlan)
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: "cand_old", TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 1, oldEncoded); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, oldEncoded); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: "cand_new",
		TCPSince: now.Add(time.Minute), UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 2, staleEncoded); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		DELETE FROM schema_migrations WHERE version=11;
		DROP TABLE route_reserve_mappings;
		ALTER TABLE plan_state DROP COLUMN desired_assignments;
		ALTER TABLE plan_state DROP COLUMN desired_assignments_generation;
		ALTER TABLE plan_state DROP COLUMN invalidated_generation;
	`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	agent := &snapshotGateAgent{path: path, stalePlan: staleEncoded}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || agent.staleApplied || !agent.exactSnapshot {
		t.Fatalf("apply calls=%d stale=%v exact_snapshot=%v", agent.calls, agent.staleApplied, agent.exactSnapshot)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 3 || state.AppliedGeneration != 3 {
		t.Fatalf("fresh plan did not advance past invalidated generation: %+v", state)
	}
}

func TestEngineRebasesUnsafeRuntimePendingBeforeExternalApply(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	stalePlan := dataplane.DesiredPlan{
		Generation: 7, DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	staleEncoded, _ := json.Marshal(stalePlan)
	if err := database.SaveDesiredPlan(ctx, 7, staleEncoded); err != nil {
		t.Fatal(err)
	}
	agent := &snapshotGateAgent{path: path, stalePlan: staleEncoded}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, time.Unix(1_900_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || agent.staleApplied || !agent.exactSnapshot {
		t.Fatalf("apply calls=%d stale=%v exact_snapshot=%v", agent.calls, agent.staleApplied, agent.exactSnapshot)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 8 || state.AppliedGeneration != 8 {
		t.Fatalf("unsafe generation was not rebased before fresh publish: %+v", state)
	}
}

func TestEngineForcesFreshApplyAfterRebaseEvenWhenAppliedSemanticsWin(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	appliedPlan := dataplane.DesiredPlan{
		Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	stalePlan := dataplane.DesiredPlan{
		Generation: 7, DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	appliedEncoded, _ := json.Marshal(appliedPlan)
	staleEncoded, _ := json.Marshal(stalePlan)
	if err := database.SaveDesiredPlan(ctx, 1, appliedEncoded); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, appliedEncoded); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, 7, staleEncoded); err != nil {
		t.Fatal(err)
	}
	agent := &snapshotGateAgent{path: path, stalePlan: staleEncoded}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, time.Unix(1_900_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || agent.staleApplied || !agent.exactSnapshot {
		t.Fatalf("apply calls=%d stale=%v exact_snapshot=%v", agent.calls, agent.staleApplied, agent.exactSnapshot)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 8 || state.AppliedGeneration != 8 ||
		state.InvalidatedGeneration != 0 {
		t.Fatalf("forced fresh apply state=%+v", state)
	}
}

type snapshotGateAgent struct {
	path          string
	stalePlan     []byte
	calls         int
	staleApplied  bool
	exactSnapshot bool
}

func (agent *snapshotGateAgent) Apply(_ context.Context, plan dataplane.DesiredPlan) error {
	agent.calls++
	encoded, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	agent.staleApplied = bytes.Equal(encoded, agent.stalePlan)
	database, err := sql.Open("sqlite", agent.path)
	if err != nil {
		return err
	}
	defer database.Close()
	var generation int64
	var desiredPlan []byte
	if err := database.QueryRow(`
		SELECT desired_assignments_generation, desired_plan
		FROM plan_state WHERE singleton=1
	`).Scan(&generation, &desiredPlan); err != nil {
		return err
	}
	agent.exactSnapshot = generation == plan.Generation && bytes.Equal(desiredPlan, encoded)
	return nil
}

func (*snapshotGateAgent) Activity(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

func TestEngineSemanticAssignmentChangeIncrementsOnce(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "route", kind: sources.KindVLESS, score: 100, tcp: true, udp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, "", "")
	applied := dataplane.DesiredPlan{
		Generation:     4,
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	}
	encoded, err := json.Marshal(applied)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlan(ctx, applied.Generation, encoded); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, applied.Generation, encoded); err != nil {
		t.Fatal(err)
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 5 || state.AppliedGeneration != 5 ||
		len(agent.plans) != 1 || agent.plans[0].Generation != 5 {
		t.Fatalf("changed plan state=%+v plans=%+v", state, agent.plans)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["route"].ID ||
		assignment.UDPOutbound != candidates["route"].ID {
		t.Fatalf("changed assignment=%+v", assignment)
	}
	assignment.UpdatedAt = time.Unix(1_900_000_000, 0)
	if err := database.SetAssignment(ctx, assignment); err != nil {
		t.Fatal(err)
	}

	if err := engine.Cycle(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err = database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 5 || state.AppliedGeneration != 5 || len(agent.plans) != 1 {
		t.Fatalf("stable changed plan advanced again: state=%+v plans=%+v", state, agent.plans)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); !assignment.UpdatedAt.Equal(time.Unix(1_900_000_000, 0)) {
		t.Fatalf("stable semantic plan rewrote assignment=%+v", assignment)
	}
}

func TestEngineMalformedDesiredSemanticPlanDoesNotOverwriteState(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	malformed := []byte(`{"generation":3`)
	if err := database.SaveDesiredPlan(ctx, 3, malformed); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("malformed desired plan was accepted")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 3 || state.AppliedGeneration != 0 ||
		!bytes.Equal(state.DesiredPlan, malformed) || len(state.AppliedPlan) != 0 {
		t.Fatalf("malformed desired plan was overwritten=%+v", state)
	}
	if len(agent.plans) != 0 {
		t.Fatalf("malformed desired plan reached agent=%+v", agent.plans)
	}
}

func TestEngineRejectsCorruptPlanStateBeforeSemanticNoOp(t *testing.T) {
	valid := storedEnginePlanBytes(t, dataplane.DesiredPlan{
		Generation:     3,
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	})
	different := storedEnginePlanBytes(t, dataplane.DesiredPlan{
		Generation: 3,
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", BlockTCP: true, BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	})
	wrongGeneration := storedEnginePlanBytes(t, dataplane.DesiredPlan{
		Generation:     2,
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	})
	invalid := storedEnginePlanBytes(t, dataplane.DesiredPlan{
		Generation:     3,
		DirectSuffixes: []string{".ru"},
	})
	unknown := []byte(`{"generation":3,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true,"future_scalar":true}`)
	trailing := append(append([]byte(nil), valid...), []byte("\n{}")...)
	tests := []struct {
		name  string
		state store.PlanState
	}{
		{
			name:  "zero generation with desired bytes",
			state: store.PlanState{DesiredPlan: valid},
		},
		{
			name:  "zero generation with applied bytes",
			state: store.PlanState{AppliedPlan: valid},
		},
		{
			name: "missing applied bytes",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3, DesiredPlan: valid,
			},
		},
		{
			name: "malformed applied bytes",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: []byte(`{"generation":3`),
			},
		},
		{
			name: "unknown desired field",
			state: store.PlanState{
				DesiredGeneration: 3, DesiredPlan: unknown,
			},
		},
		{
			name: "unknown applied field",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: unknown,
			},
		},
		{
			name: "trailing desired value",
			state: store.PlanState{
				DesiredGeneration: 3, DesiredPlan: trailing,
			},
		},
		{
			name: "trailing applied value",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: trailing,
			},
		},
		{
			name: "applied generation mismatches bytes",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: wrongGeneration,
			},
		},
		{
			name: "applied plan is invalid",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: invalid,
			},
		},
		{
			name: "equal generations have different semantics",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3,
				DesiredPlan: valid, AppliedPlan: different,
			},
		},
		{
			name: "negative invalidated generation",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3, InvalidatedGeneration: -1,
				DesiredPlan: valid, AppliedPlan: valid,
			},
		},
		{
			name: "invalidated generation below applied generation",
			state: store.PlanState{
				DesiredGeneration: 3, AppliedGeneration: 3, InvalidatedGeneration: 2,
				DesiredPlan: valid, AppliedPlan: valid,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			database, err := store.Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			overwriteEnginePlanState(t, path, test.state)
			agent := &engineAgent{}
			engine := NewEngine(
				database, agent, nil,
				scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
			)
			err = engine.Cycle(ctx, time.Unix(1_800_000_000, 0))
			if err == nil || !strings.Contains(err.Error(), "corrupt plan state") {
				t.Fatalf("Cycle error=%v, want explicit corrupt plan state", err)
			}
			after, err := database.LoadPlanState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if after.DesiredGeneration != test.state.DesiredGeneration ||
				after.AppliedGeneration != test.state.AppliedGeneration ||
				after.InvalidatedGeneration != test.state.InvalidatedGeneration ||
				!bytes.Equal(after.DesiredPlan, test.state.DesiredPlan) ||
				!bytes.Equal(after.AppliedPlan, test.state.AppliedPlan) {
				t.Fatalf("corrupt state was overwritten:\nbefore=%+v\nafter=%+v", test.state, after)
			}
			if len(agent.plans) != 0 {
				t.Fatalf("corrupt state reached agent=%+v", agent.plans)
			}
		})
	}
}

func TestEngineConcurrentCyclesSerializePlanPublication(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "paused", Name: "Paused", Address: "10.44.0.2/32",
		PublicKey: "peer-paused", Paused: true,
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "paused", TCPOutbound: "stale",
		TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	agent := &serializedCycleAgent{
		applyEntered: make(chan int, 2),
		releaseFirst: make(chan struct{}),
	}
	engine := NewEngine(
		database, agent, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	firstDone := make(chan error, 1)
	go func() { firstDone <- engine.Cycle(ctx, now) }()
	if call := <-agent.applyEntered; call != 1 {
		t.Fatalf("first apply call=%d", call)
	}
	pending, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.DesiredGeneration != 1 || pending.AppliedGeneration != 0 {
		t.Fatalf("pending state=%+v", pending)
	}

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- engine.Cycle(ctx, now.Add(time.Second))
	}()
	<-secondStarted
	secondEnteredApply := false
	select {
	case call := <-agent.applyEntered:
		secondEnteredApply = true
		if call != 2 {
			t.Fatalf("second apply call=%d", call)
		}
	case <-time.After(100 * time.Millisecond):
	}
	during, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assignmentDuring := engineQoEAssignment(t, database, "paused")
	close(agent.releaseFirst)
	firstErr := <-firstDone
	secondErr := <-secondDone
	if secondEnteredApply {
		t.Fatal("overlapping Cycle entered agent Apply before the first cycle completed")
	}
	if firstErr != nil || secondErr != nil {
		t.Fatalf("cycle errors: first=%v second=%v", firstErr, secondErr)
	}
	if during.DesiredGeneration != 1 || during.AppliedGeneration != 0 {
		t.Fatalf("second cycle published while first apply was blocked: %+v", during)
	}
	if assignmentDuring.TCPOutbound != "stale" {
		t.Fatalf("second cycle rewrote assignment while first apply was blocked: %+v", assignmentDuring)
	}
	final, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if final.DesiredGeneration != 1 || final.AppliedGeneration != 1 {
		t.Fatalf("final generations=%+v", final)
	}
	assignment := engineQoEAssignment(t, database, "paused")
	if assignment.TCPOutbound != "" || assignment.UDPOutbound != "" {
		t.Fatalf("final assignment=%+v", assignment)
	}
	if calls := agent.ApplyCalls(); calls != 1 {
		t.Fatalf("agent apply calls=%d", calls)
	}
}

func TestEngineCycleAdmissionHonorsContextWhileAnotherCycleOwnsWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	agent := &serializedCycleAgent{
		applyEntered: make(chan int, 2), releaseFirst: make(chan struct{}),
	}
	engine := NewEngine(
		database, agent, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- engine.Cycle(context.Background(), time.Unix(1_800_000_000, 0))
	}()
	if call := <-agent.applyEntered; call != 1 {
		t.Fatalf("first apply call=%d", call)
	}

	admissionCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- engine.CycleForReason(
			admissionCtx, time.Unix(1_800_000_001, 0), PlacementHardFailure,
		)
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			close(agent.releaseFirst)
			<-firstDone
			t.Fatalf("admission error=%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		close(agent.releaseFirst)
		<-firstDone
		err := <-secondDone
		t.Fatalf("writer admission ignored context until owner completed: %v", err)
	}
	close(agent.releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if calls := agent.ApplyCalls(); calls != 1 {
		t.Fatalf("agent apply calls=%d", calls)
	}
}

func storedEnginePlanBytes(t *testing.T, plan dataplane.DesiredPlan) []byte {
	t.Helper()
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func overwriteEnginePlanState(t *testing.T, path string, state store.PlanState) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`
		UPDATE plan_state
		SET desired_generation=?, applied_generation=?, invalidated_generation=?,
		    desired_plan=?, applied_plan=?
		WHERE singleton=1
	`, state.DesiredGeneration, state.AppliedGeneration, state.InvalidatedGeneration,
		state.DesiredPlan, state.AppliedPlan); err != nil {
		t.Fatal(err)
	}
}

func installEngineWriteRejectingTrigger(t *testing.T, path, table, name string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`
		CREATE TRIGGER ` + name + `
		BEFORE UPDATE ON ` + table + `
		BEGIN SELECT RAISE(ABORT, 'unexpected unchanged write'); END
	`); err != nil {
		t.Fatal(err)
	}
}

func TestEngineBuildsIndependentTCPUDPPlanWithPersonalizedTorOutbound(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls")
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{
		{Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor-fp", Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"},
		{Kind: sources.KindVLESS, Label: "vless", Fingerprint: "vless-fp", Payload: "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls"},
	}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, listed[0].ID)
	var torID, vlessID string
	for _, candidate := range candidates {
		if candidate.Kind == sources.KindTorBridge {
			torID = candidate.ID
		} else {
			vlessID = candidate.ID
		}
	}
	now := time.Unix(1_800_000_000, 0)
	_ = database.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: torID, Score: 100, TCPQualified: true, Available: true, UpdatedAt: now})
	_ = database.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: vlessID, Score: 70, TCPQualified: false, UDPQualified: true, Available: true, UpdatedAt: now})
	_ = database.PutClient(ctx, store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer-a"}, "private config")
	_ = database.RecordActivity(ctx, "alice", now, 1, 1)

	agent := &engineAgent{}
	torSlot := 0
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{{Slot: torSlot, CandidateID: torID, SocksAddr: "127.0.0.1:19050", Role: "warm"}}
	})
	engine := NewEngine(database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()), []byte("credential-secret"))
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("plans=%+v", agent.plans)
	}
	plan := agent.plans[0]
	if len(plan.Clients) != 1 || plan.Clients[0].SourceCIDR != "10.44.0.2/32" || plan.Clients[0].UDPOutbound != vlessID || !strings.Contains(plan.Clients[0].TCPOutbound, torID) {
		t.Fatalf("routes=%+v", plan.Clients)
	}
	var torConfig string
	for _, outbound := range plan.Outbounds {
		if outbound.Protocol == dataplane.ProtocolTor {
			torConfig = string(outbound.Config)
		}
	}
	if !strings.Contains(torConfig, "hydrat-alice") {
		t.Fatalf("Tor outbound is not circuit-isolated per client: %s", torConfig)
	}
	firstTorOutbound := plan.Clients[0].TCPOutbound
	torSlot = 1
	if err := engine.Cycle(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if second := agent.plans[1].Clients[0].TCPOutbound; second == firstTorOutbound {
		t.Fatalf("Tor slot change reused live Xray tag %q", second)
	}
}

func TestEnginePreloadsDeterministicReservesAndDNS(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, "", "")

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 {
		t.Fatalf("plans=%+v", agent.plans)
	}
	plan := agent.plans[0]
	route := plan.Clients[0]
	if route.TCPReserveOutbound == "" || route.UDPReserveOutbound == "" ||
		route.TCPReserveOutbound == route.TCPOutbound ||
		route.UDPReserveOutbound == route.UDPOutbound {
		t.Fatalf("route did not preload distinct reserves: %+v", route)
	}
	outbounds := make(map[string]dataplane.Outbound, len(plan.Outbounds))
	dnsByTarget := make(map[string]dataplane.Outbound)
	for _, outbound := range plan.Outbounds {
		outbounds[outbound.ID] = outbound
		if outbound.Protocol == dataplane.ProtocolDNS {
			target, resolver := engineDNSConfig(t, outbound.Config)
			if resolver != "9.9.9.9" {
				t.Fatalf("DNS resolver=%q want configured 9.9.9.9", resolver)
			}
			dnsByTarget[target] = outbound
		}
	}
	if route.DNSOutbound == "" || dnsByTarget[route.TCPOutbound].ID != route.DNSOutbound {
		t.Fatalf("active DNS does not follow TCP: route=%+v targets=%v", route, dnsByTarget)
	}
	if dnsByTarget[route.TCPReserveOutbound].ID == "" {
		t.Fatalf("reserve DNS was not preloaded for %q", route.TCPReserveOutbound)
	}
	for _, handler := range []string{
		route.TCPOutbound, route.UDPOutbound,
		route.TCPReserveOutbound, route.UDPReserveOutbound,
	} {
		if _, exists := outbounds[handler]; !exists {
			t.Fatalf("handler %q was not materialized", handler)
		}
	}
	assignment := engineQoEAssignment(t, database, "alice")
	for transport, expected := range map[store.RouteTransport]struct {
		primary string
		reserve string
	}{
		store.RouteTransportTCP: {primary: assignment.TCPOutbound, reserve: route.TCPReserveOutbound},
		store.RouteTransportUDP: {primary: assignment.UDPOutbound, reserve: route.UDPReserveOutbound},
	} {
		reserve, ok, err := database.AppliedReserveForFailure(
			context.Background(), "alice", transport, expected.primary,
		)
		if err != nil || !ok || reserve != expected.reserve {
			t.Fatalf("%s reserve=%q ok=%v err=%v", transport, reserve, ok, err)
		}
	}
}

func TestEngineReserveActiveFreshnessUsesExactlyTwoConfiguredProbeIntervals(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	defaultEngine := NewEngine(nil, nil, nil, nil, nil)
	if defaultEngine.reserveActiveObservationFresh(now, now) {
		t.Fatal("engine without active probe interval did not fail closed")
	}
	if defaultEngine.activeHardFailureObservationFresh(now, now) {
		t.Fatal("engine without active probe interval accepted a hard failure")
	}
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveProbeInterval(time.Minute))
	for _, test := range []struct {
		name     string
		observed time.Time
		want     bool
	}{
		{name: "just before boundary", observed: now.Add(-2*time.Minute + time.Nanosecond), want: true},
		{name: "exact boundary", observed: now.Add(-2 * time.Minute), want: true},
		{name: "just after boundary", observed: now.Add(-2*time.Minute - time.Nanosecond), want: false},
		{name: "future", observed: now.Add(time.Nanosecond), want: false},
		{name: "missing", observed: time.Time{}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := engine.reserveActiveObservationFresh(now, test.observed); got != test.want {
				t.Fatalf("fresh=%v want=%v", got, test.want)
			}
			if got := engine.activeHardFailureObservationFresh(now, test.observed); got != test.want {
				t.Fatalf("hard failure fresh=%v want=%v", got, test.want)
			}
		})
	}
	for _, interval := range []time.Duration{
		0, -time.Second, time.Duration(1<<63-1)/2 + 1,
	} {
		restarted := NewEngine(
			nil, nil, nil, nil, nil, WithActiveProbeInterval(interval),
		)
		if restarted.reserveActiveObservationFresh(now, now) {
			t.Fatalf("invalid interval %s did not fail closed", interval)
		}
		if restarted.activeHardFailureObservationFresh(now, now) {
			t.Fatalf("invalid interval %s accepted a hard failure", interval)
		}
	}
	restarted := NewEngine(
		nil, nil, nil, nil, nil, WithActiveProbeInterval(time.Minute),
	)
	if !restarted.reserveActiveObservationFresh(now, now.Add(-2*time.Minute)) {
		t.Fatal("restart lost configured reserve freshness")
	}
	if !restarted.activeHardFailureObservationFresh(now, now.Add(-2*time.Minute)) {
		t.Fatal("restart lost configured hard failure freshness")
	}
}

func TestPromotionQoEReadyRequiresCompleteCleanFreshWindow(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	window := qoe.DefaultPolicy().WindowSize
	freshness := 40 * time.Second
	windowFreshness := 85 * time.Second
	maximumSampleGap := 25 * time.Second
	healthy := qoe.State{
		Status: qoe.StatusHealthy, WindowValid: window, WindowBad: 0,
		LastValidAt: now.Add(-freshness), WindowStartedAt: now.Add(-windowFreshness),
		WindowMaxGap: maximumSampleGap,
	}
	if !promotionQoEReady(now, healthy, window, freshness, windowFreshness, maximumSampleGap) {
		t.Fatal("complete clean window at freshness boundary was rejected")
	}
	for _, test := range []struct {
		name  string
		state qoe.State
	}{
		{name: "learning", state: func() qoe.State { state := healthy; state.Status = qoe.StatusLearning; return state }()},
		{name: "incomplete", state: func() qoe.State { state := healthy; state.WindowValid--; return state }()},
		{name: "bad sample", state: func() qoe.State { state := healthy; state.WindowBad = 1; return state }()},
		{name: "stale", state: func() qoe.State {
			state := healthy
			state.LastValidAt = now.Add(-freshness - time.Nanosecond)
			return state
		}()},
		{name: "old window", state: func() qoe.State {
			state := healthy
			state.WindowStartedAt = now.Add(-windowFreshness - time.Nanosecond)
			return state
		}()},
		{name: "future", state: func() qoe.State { state := healthy; state.LastValidAt = now.Add(time.Nanosecond); return state }()},
		{name: "missing", state: func() qoe.State { state := healthy; state.LastValidAt = time.Time{}; return state }()},
		{name: "future window", state: func() qoe.State { state := healthy; state.WindowStartedAt = now.Add(time.Nanosecond); return state }()},
		{name: "missing window", state: func() qoe.State { state := healthy; state.WindowStartedAt = time.Time{}; return state }()},
		{name: "window gap", state: func() qoe.State {
			state := healthy
			state.WindowMaxGap = maximumSampleGap + time.Nanosecond
			return state
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if promotionQoEReady(now, test.state, window, freshness, windowFreshness, maximumSampleGap) {
				t.Fatalf("unsafe state accepted: %+v", test.state)
			}
		})
	}
}

func TestEngineReserveFreshnessPreservesMillisecondPhaseOffset(t *testing.T) {
	base := time.Unix(1_900_000_000, 0)
	observedAt := base.Add(750 * time.Millisecond)
	database, candidates := newEngineQoEFixture(t, base, []engineQoECandidateSpec{{
		name: "candidate", kind: sources.KindVLESS, score: 100,
		tcp: true, udp: true, failureDomain: "domain-a",
	}})
	candidate := candidates["candidate"]
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveObservation(
		context.Background(), candidate, reservation, true, observedAt,
	); err != nil || !commit.Accepted {
		t.Fatalf("active commit=%+v err=%v", commit, err)
	}
	rows, err := database.ListCandidateHealth(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("health=%+v err=%v", rows, err)
	}
	if !rows[0].ActiveObservedAt.Equal(observedAt) {
		t.Fatalf("active observed=%s want=%s", rows[0].ActiveObservedAt, observedAt)
	}
	engine := NewEngine(
		database, nil, nil, nil, nil,
		WithActiveProbeInterval(500*time.Millisecond),
	)
	if !engine.reserveActiveObservationFresh(
		observedAt.Add(500*time.Millisecond), rows[0].ActiveObservedAt,
	) {
		t.Fatal("second+750ms observation became stale after 500ms")
	}
}

func TestEngineActiveCriticalRouteLimitNormalizesOrdinaryMultiClientPlan(
	t *testing.T,
) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	baselineAgent := &engineAgent{}
	baseline := NewEngine(
		database, baselineAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := baseline.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	before, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	err = engine.Cycle(context.Background(), now.Add(time.Second))
	if err != nil {
		t.Fatalf("ordinary normalization error=%v", err)
	}
	after, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(after, before) || len(agent.plans) != 1 {
		t.Fatalf("ordinary normalization missing before=%+v after=%+v plans=%d",
			before, after, len(agent.plans))
	}
	if count := enginePlanCriticalCandidateCount(agent.plans[0]); count > 16 {
		t.Fatalf("normalized critical candidates=%d", count)
	}
}

func TestExactCriticalCapacityRejectsIneligibleReserveBeforePublish(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	clients := []scheduler.Client{{ID: "alice"}}
	result := scheduler.Result{Assignments: map[string]scheduler.Assignment{
		"alice": {TCP: "primary", UDP: "primary"},
	}}
	candidates := []scheduler.Candidate{
		{
			ID: "primary", Protocol: scheduler.ProtocolVLESS,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true, FailureDomain: "primary-domain",
		},
		{
			ID: "unproven", Protocol: scheduler.ProtocolVLESS,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: false, ActiveFresh: false, FailureDomain: "bad-domain",
		},
		{
			ID: "qualified", Protocol: scheduler.ProtocolVLESS,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true, FailureDomain: "good-domain",
		},
	}
	invalid := map[string]scheduler.ReserveSelection{
		"alice": {TCP: "unproven", UDP: "unproven"},
	}
	err := validateScheduledCriticalCapacity(
		context.Background(), placement, now, 16,
		clients, candidates, result, invalid,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) ||
		!slices.Contains(coverErr.Unsatisfied, "alice:tcp:reserve") ||
		!slices.Contains(coverErr.Unsatisfied, "alice:udp:reserve") {
		t.Fatalf("invalid reserve prepublish error=%v", err)
	}
	valid := map[string]scheduler.ReserveSelection{
		"alice": {TCP: "qualified", UDP: "qualified"},
	}
	if err := validateScheduledCriticalCapacity(
		context.Background(), placement, now, 16,
		clients, candidates, result, valid,
	); err != nil {
		t.Fatalf("qualified reserve rejected: %v", err)
	}
}

func TestEngineActiveCriticalRouteLimitAllowsLegacyHardNonIncrease(
	t *testing.T,
) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seedAgent := &engineAgent{}
	seed := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	assignments, err := database.ListAssignments(context.Background())
	if err != nil || len(assignments) != 18 {
		t.Fatalf("seed assignments=%+v err=%v", assignments, err)
	}
	failedID := assignments[0].TCPOutbound
	var failed store.Candidate
	for _, candidate := range candidates {
		if candidate.ID == failedID {
			failed = candidate
			break
		}
	}
	if failed.ID == "" {
		t.Fatalf("assigned candidate %q not found", failedID)
	}
	reservation, err := database.ReserveCandidateObservation(
		context.Background(), failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitActiveVLESSHardFailureObservation(
		context.Background(), failed, reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("seed hard failure=%+v err=%v", commit, err)
	}
	before, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	err = engine.CycleForReason(
		context.Background(), now.Add(time.Second), PlacementHardFailure,
	)
	if err != nil {
		t.Fatalf("hard admission error=%v", err)
	}
	after, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(after, before) || len(agent.plans) != 1 {
		t.Fatalf("hard legacy failover missing before=%+v after=%+v plans=%d",
			before, after, len(agent.plans))
	}
	beforeCount := enginePlanCriticalCandidateCount(seedAgent.plans[len(seedAgent.plans)-1])
	afterCount := enginePlanCriticalCandidateCount(agent.plans[0])
	if afterCount > beforeCount {
		t.Fatalf("hard legacy cardinality grew before=%d after=%d", beforeCount, afterCount)
	}
}

func TestEngineActiveCriticalRouteLimitRejectsPendingHardLegacyIncreaseBeforeApply(
	t *testing.T,
) {
	database, _, _ := newEngineActiveCriticalLimitFixture(t, 1)
	ctx := context.Background()
	applied := engineCriticalCountPlan(1, 18)
	appliedBytes, err := json.Marshal(applied)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlanWithReason(
		ctx, 1, appliedBytes, string(PlacementPeriodic),
	); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, appliedBytes); err != nil {
		t.Fatal(err)
	}
	pending := engineCriticalCountPlan(2, 19)
	pendingBytes, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDesiredPlanWithReason(
		ctx, 2, pendingBytes, string(PlacementHardFailure),
	); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveCriticalRouteLimit(16),
	)
	err = engine.CycleForReason(ctx, time.Now(), PlacementHardFailure)
	var limitErr *ActiveCriticalRouteLimitError
	if !errors.As(err, &limitErr) || limitErr.Planned != 19 || limitErr.Limit != 18 {
		t.Fatalf("pending hard increase error=%v", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.AppliedGeneration != 1 || state.DesiredGeneration != 2 ||
		len(agent.plans) != 0 {
		t.Fatalf("pending hard increase mutated state=%+v plans=%d", state, len(agent.plans))
	}
}

func TestEngineActiveCriticalRouteLimitImpossibleCoverDoesNotPublishOrApply(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 17)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	placement := scheduler.New(scheduler.PolicyDefaults())
	for clientIndex := 0; clientIndex < 17; clientIndex++ {
		clientID := fmt.Sprintf("client-%02d", clientIndex)
		for candidateIndex := 0; candidateIndex < 17; candidateIndex++ {
			if candidateIndex == clientIndex {
				continue
			}
			placement.Exclude(
				clientID, candidates[fmt.Sprintf("route-%02d", candidateIndex)].ID,
				now.Add(time.Hour),
			)
		}
	}
	before, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, placement, []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	err = engine.Cycle(context.Background(), now.Add(time.Second))
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || coverErr.Limit != 16 {
		t.Fatalf("coverage error=%v", err)
	}
	after, loadErr := database.LoadPlanState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(after, before) || len(agent.plans) != 0 {
		t.Fatalf("impossible cover mutated state before=%+v after=%+v plans=%d",
			before, after, len(agent.plans))
	}
}

func TestEngineNormalizeActiveCriticalRoutesRepairsLegacySameSemanticPlan(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seedAgent := &engineAgent{}
	seed := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if count := enginePlanCriticalCandidateCount(seedAgent.plans[0]); count <= 16 {
		t.Fatalf("legacy seed count=%d want >16", count)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.NormalizeActiveCriticalRoutes(
		context.Background(), now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || enginePlanCriticalCandidateCount(agent.plans[0]) > 16 {
		t.Fatalf("normalization plans=%d count=%d", len(agent.plans),
			enginePlanCriticalCandidateCount(agent.plans[0]))
	}
	state, err := database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredReason != string(PlacementStartupNormalization) ||
		state.DesiredGeneration != state.AppliedGeneration {
		t.Fatalf("normalized state=%+v", state)
	}
}

func TestEngineActiveCriticalRouteLimitReusesPoolForNewClient(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 17)
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, 16)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, 17)
	if err := engine.Cycle(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	latest := agent.plans[len(agent.plans)-1]
	if count := enginePlanCriticalCandidateCount(latest); count > 16 {
		t.Fatalf("new-client critical candidates=%d", count)
	}
	for _, route := range latest.Clients {
		if route.ClientID != "client-16" {
			continue
		}
		if route.BlockTCP || route.BlockUDP || route.TCPOutbound == "" ||
			route.UDPOutbound == "" || route.TCPReserveOutbound == "" ||
			route.UDPReserveOutbound == "" || route.DNSOutbound == "" {
			t.Fatalf("new client route=%+v", route)
		}
		engineOutboundByID(t, latest, route.DNSOutbound)
		return
	}
	t.Fatal("new client route missing")
}

func TestEngineActiveCriticalCoveragePoolIsDeterministic(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 0, 18)
	clients := make([]scheduler.Client, 0, 18)
	for index := 0; index < 18; index++ {
		id := fmt.Sprintf("route-%02d", index)
		candidates = append(candidates, scheduler.Candidate{
			ID: id, Protocol: scheduler.ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true,
			FailureDomain: "domain-" + id,
		})
		clients = append(clients, scheduler.Client{
			ID:         fmt.Sprintf("client-%02d", index),
			Assignment: scheduler.Assignment{TCP: id, UDP: id},
		})
	}
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	placement := scheduler.New(scheduler.PolicyDefaults())
	first, err := engine.cappedScheduleCandidates(context.Background(), now, placement, clients, candidates)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.cappedScheduleCandidates(context.Background(), now, placement, clients, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || len(first) > 16 {
		t.Fatalf("coverage pool is not deterministic first=%+v second=%+v", first, second)
	}
}

func TestEngineActiveCriticalCoverageBacktrackingRecoversGreedyDeadEnd(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []scheduler.Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(2))
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		satisfied := make(map[string]bool)
		add := func(requirement string) { satisfied[requirement] = true }
		switch {
		case len(pool) == len(candidates):
			add("alice:tcp:primary")
			add("alice:udp:primary")
			add("alice:tcp:reserve")
			add("alice:udp:reserve")
		case present["b"] && present["c"]:
			add("alice:tcp:primary")
			add("alice:udp:primary")
			add("alice:tcp:reserve")
			add("alice:udp:reserve")
		case present["a"]:
			add("alice:tcp:primary")
			add("alice:udp:primary")
			add("alice:tcp:reserve")
		case present["b"]:
			add("alice:tcp:primary")
			add("alice:udp:primary")
		case present["c"]:
			add("alice:tcp:reserve")
			add("alice:udp:reserve")
		}
		return criticalCoverageEvaluation{satisfied: satisfied}, nil
	}
	pool, err := engine.cappedScheduleCandidates(context.Background(), now, placement, clients, candidates)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{pool[0].ID, pool[1].ID}
	if !reflect.DeepEqual(ids, []string{"b", "c"}) {
		t.Fatalf("backtracking pool=%v want [b c]", ids)
	}
}

func TestEngineActiveCriticalCoverageExtendsFullPoolWitnessBeforeRestartingGreedy(
	t *testing.T,
) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("route-%03d", index)
	}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	budgetErr := errors.New("test evaluation budget exhausted")
	evaluations := 0
	complete := func(witness ...string) criticalCoverageEvaluation {
		return criticalCoverageEvaluation{
			satisfied: map[string]bool{
				"alice:tcp:primary": true,
				"alice:udp:primary": true,
				"alice:tcp:reserve": true,
				"alice:udp:reserve": true,
			},
			witnessIDs: witness,
		}
	}
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		evaluations++
		if evaluations > 10 {
			return criticalCoverageEvaluation{}, budgetErr
		}
		if len(pool) == len(candidates) {
			return complete("route-198", "route-199"), nil
		}
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if present["route-000"] && present["route-198"] && present["route-199"] {
			return complete(), nil
		}
		if present["route-198"] && present["route-199"] {
			partial := complete()
			delete(partial.satisfied, "alice:udp:reserve")
			return partial, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}

	pool, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(pool))
	for _, candidate := range pool {
		ids = append(ids, candidate.ID)
	}
	if !reflect.DeepEqual(ids, []string{"route-198", "route-199", "route-000"}) {
		t.Fatalf("witness extension pool=%v", ids)
	}
	if evaluations != 4 {
		t.Fatalf("witness extension evaluations=%d want 4 including final revalidation", evaluations)
	}
}

func TestEngineCycleKeepsFullCandidatePoolWhenScheduledWitnessFitsLimit(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("route-%03d", index)
	}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	evaluations := 0
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		evaluations++
		if len(pool) != len(candidates) {
			t.Fatalf("evaluated candidate pool=%d want full %d", len(pool), len(candidates))
		}
		return criticalCoverageEvaluation{
			satisfied: map[string]bool{
				"alice:tcp:primary": true,
				"alice:udp:primary": true,
				"alice:tcp:reserve": true,
				"alice:udp:reserve": true,
			},
			witnessIDs: []string{"route-198", "route-199"},
		}, nil
	}

	pool, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != len(candidates) {
		t.Fatalf("cycle candidate pool=%d want full %d", len(pool), len(candidates))
	}
	if evaluations != 1 {
		t.Fatalf("cycle full-pool evaluations=%d want 1", evaluations)
	}
}

func TestEngineCycleUsesIncumbentPlusReserveBeforeBoundedSearch(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("route-%03d", index)
	}
	clients := []scheduler.Client{{
		ID: "alice", Assignment: scheduler.Assignment{
			TCP: "route-199", UDP: "route-199",
		},
	}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	required := criticalCoverageRequirements(clients)
	complete := func() criticalCoverageEvaluation {
		satisfied := make(map[string]bool, len(required))
		for _, requirement := range required {
			satisfied[requirement] = true
		}
		return criticalCoverageEvaluation{satisfied: satisfied}
	}
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if present["route-199"] && present["route-000"] && len(pool) <= 16 {
			return complete(), nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
		}}, nil
	}
	engine.bootstrapCoverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			result := complete()
			result.witnessIDs = []string{"route-001", "route-002"}
			return result, nil
		}
		return complete(), nil
	}

	pool, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{pool[0].ID, pool[1].ID}; !slices.Equal(got, []string{"route-199", "route-000"}) {
		t.Fatalf("coverage pool=%v want incumbent plus reserve", got)
	}
}

func TestProspectiveCoverageUsesIncumbentPlusReserveBeforeBoundedSearch(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("route-%03d", index)
	}
	clients := []scheduler.Client{{
		ID: "alice", Assignment: scheduler.Assignment{
			TCP: "route-199", UDP: "route-199",
		},
	}}
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	required := criticalCoverageRequirements(clients)
	calls := 0
	engine.bootstrapCoverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		calls++
		if calls > 205 {
			return criticalCoverageEvaluation{}, errors.New("test planning budget exhausted")
		}
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		satisfied := map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
		}
		if present["route-199"] && present["route-000"] {
			satisfied["alice:tcp:reserve"] = true
		}
		if present["route-199"] && present["route-000"] && present["route-001"] && len(pool) <= 16 {
			for _, requirement := range required {
				satisfied[requirement] = true
			}
		}
		return criticalCoverageEvaluation{satisfied: satisfied}, nil
	}

	pool, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, scheduler.New(scheduler.PolicyDefaults()), clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{pool[0].ID, pool[1].ID, pool[2].ID}; !slices.Equal(got, []string{"route-199", "route-000", "route-001"}) {
		t.Fatalf("prospective pool=%v want incumbent plus reserves", got)
	}
}

func TestProspectiveCoverageUsesPreferredBoundedPoolBeforeSubsetSearch(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID: fmt.Sprintf("route-%03d", index), Protocol: scheduler.ProtocolVLESS,
			TCPQualified: true, UDPQualified: true,
		}
	}
	clients := []scheduler.Client{{ID: "alice"}}
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(16))
	required := criticalCoverageRequirements(clients)
	calls := 0
	engine.bootstrapCoverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		calls++
		if calls > 2 {
			return criticalCoverageEvaluation{}, errors.New("subset search started")
		}
		if len(pool) != 16 && len(pool) != 2 {
			return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
		}
		satisfied := make(map[string]bool, len(required))
		for _, requirement := range required {
			satisfied[requirement] = true
		}
		return criticalCoverageEvaluation{
			satisfied: satisfied, witnessIDs: []string{"route-000", "route-001"},
		}, nil
	}

	pool, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, scheduler.New(scheduler.PolicyDefaults()), clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 2 {
		t.Fatalf("preferred prospective witness=%d want 2", len(pool))
	}
}

func TestEngineCycleReusesFullEvaluationWhenWitnessExceedsLimit(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []scheduler.Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(2))
	duplicateFullEvaluation := errors.New("full candidate pool evaluated twice")
	fullCalls := 0
	complete := criticalCoverageEvaluation{
		satisfied: map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
			"alice:tcp:reserve": true,
			"alice:udp:reserve": true,
		},
	}
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			fullCalls++
			if fullCalls > 1 {
				return criticalCoverageEvaluation{}, duplicateFullEvaluation
			}
			full := complete
			full.witnessIDs = []string{"a", "b", "c"}
			return full, nil
		}
		if len(pool) == 2 && pool[0].ID == "a" && pool[1].ID == "b" {
			return complete, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}

	pool, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{pool[0].ID, pool[1].ID}; !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("coverage pool=%v want [a b]", got)
	}
	if fullCalls != 1 {
		t.Fatalf("full candidate pool evaluations=%d want 1", fullCalls)
	}
}

func TestEngineCycleResumesRetainedCoverageWithoutReevaluatingFullPool(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []scheduler.Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, nil, nil, WithActiveCriticalRouteLimit(2))
	releaseSubset := make(chan struct{})
	fullCalls := 0
	complete := criticalCoverageEvaluation{
		satisfied: map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
			"alice:tcp:reserve": true,
			"alice:udp:reserve": true,
		},
	}
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			fullCalls++
			if fullCalls > 1 {
				return criticalCoverageEvaluation{}, errors.New("full pool reevaluated while retained search was pending")
			}
			full := complete
			full.witnessIDs = []string{"a", "b", "c"}
			return full, nil
		}
		<-releaseSubset
		if len(pool) == 2 && pool[0].ID == "a" && pool[1].ID == "b" {
			return complete, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}

	_, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) || !coverageErr.SearchExhausted {
		close(releaseSubset)
		t.Fatalf("first cycle error=%v want retained coverage slice", err)
	}
	close(releaseSubset)
	pool, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{pool[0].ID, pool[1].ID}; !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("coverage pool=%v want [a b]", got)
	}
	if fullCalls != 1 {
		t.Fatalf("full candidate pool evaluations=%d want 1", fullCalls)
	}
}

func TestCriticalCoverageSearchKeepsZeroGainBridge(t *testing.T) {
	ordered := []scheduler.Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	required := []string{"r1", "r2", "r3"}
	evaluate := func(_ context.Context, pool []scheduler.Candidate) (criticalCoverageEvaluation, error) {
		ids := make(map[string]bool)
		for _, candidate := range pool {
			ids[candidate.ID] = true
		}
		satisfied := make(map[string]bool)
		if ids["a"] || ids["b"] {
			satisfied["r1"] = true
		}
		if ids["b"] {
			satisfied["r2"] = true
		}
		if ids["a"] && ids["c"] && ids["d"] {
			satisfied["r2"] = true
			satisfied["r3"] = true
		}
		return criticalCoverageEvaluation{satisfied: satisfied}, nil
	}
	found, err := searchCriticalCoverage(
		context.Background(), ordered, 3, required,
		newCriticalCoverageBudget(3), evaluate,
	)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(found))
	for _, candidate := range found {
		ids = append(ids, candidate.ID)
	}
	if !reflect.DeepEqual(ids, []string{"a", "c", "d"}) {
		t.Fatalf("zero-gain bridge result=%v", ids)
	}
}

func TestCriticalCoverageSearchAllowsSixteenStepCoverAcrossTwoHundredCandidates(t *testing.T) {
	ordered := make([]scheduler.Candidate, 200)
	for index := range ordered {
		ordered[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	required := make([]string, 16)
	for index := range required {
		required[index] = fmt.Sprintf("requirement-%02d", index)
	}
	budget := newCriticalCoverageBudget(16)
	found, err := searchCriticalCoverage(
		context.Background(), ordered, 16, required, budget,
		func(_ context.Context, pool []scheduler.Candidate) (criticalCoverageEvaluation, error) {
			ids := make(map[string]bool, len(pool))
			for _, candidate := range pool {
				ids[candidate.ID] = true
			}
			satisfied := make(map[string]bool)
			for index := 0; index < 13; index++ {
				if ids[ordered[index].ID] {
					satisfied[required[index]] = true
				}
			}
			// The last three requirements only become visible together. This
			// forces the canonical search through two zero-gain bridge steps.
			if ids[ordered[13].ID] && ids[ordered[14].ID] && ids[ordered[15].ID] {
				for index := 13; index < 16; index++ {
					satisfied[required[index]] = true
				}
			}
			return criticalCoverageEvaluation{satisfied: satisfied}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 16 {
		t.Fatalf("cover size=%d want 16", len(found))
	}
	for index, candidate := range found {
		if candidate.ID != ordered[index].ID {
			t.Fatalf("cover[%d]=%q want %q", index, candidate.ID, ordered[index].ID)
		}
	}
	if budget.evaluations > activeCriticalCoverageEvaluationLimit {
		t.Fatalf("evaluations=%d exceeded one bounded slice", budget.evaluations)
	}
}

func TestCriticalCoverageSearchBoundsTwoHundredCandidateEvaluations(t *testing.T) {
	ordered := make([]scheduler.Candidate, 200)
	for index := range ordered {
		ordered[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	budget := newCriticalCoverageBudget(16)
	started := time.Now()
	_, err := searchCriticalCoverage(
		context.Background(), ordered, 16, []string{"unreachable"}, budget,
		func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error) {
			return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
		},
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted ||
		coverErr.Evaluations != activeCriticalCoverageEvaluationLimit {
		t.Fatalf("bounded search error=%v", err)
	}
	var temporary dataplane.TemporaryError
	if !errors.As(err, &temporary) || !temporary.Temporary() {
		t.Fatalf("search exhaustion is not temporary: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded search elapsed=%s", elapsed)
	}
}

func TestEngineActiveCriticalCoverageRejectsStaticallyMissingUDPWithoutSubsetSearch(
	t *testing.T,
) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID: fmt.Sprintf("tor-%03d", index), Protocol: scheduler.ProtocolTor,
			ProfileID:     fmt.Sprintf("profile-%03d", index),
			FailureDomain: fmt.Sprintf("domain-%03d", index), Score: 100,
			TCPQualified: true, Warm: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true,
		}
	}
	clients := []scheduler.Client{
		{ID: "client-a"}, {ID: "client-b"}, {ID: "client-c"},
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, placement, nil,
		WithActiveCriticalRouteLimit(16),
	)

	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) {
		t.Fatalf("coverage error=%v", err)
	}
	wantMissing := []string{
		"client-a:udp:primary", "client-a:udp:reserve",
		"client-b:udp:primary", "client-b:udp:reserve",
		"client-c:udp:primary", "client-c:udp:reserve",
	}
	if coverageErr.SearchExhausted || coverageErr.Evaluations != 0 ||
		!reflect.DeepEqual(coverageErr.Unsatisfied, wantMissing) {
		t.Fatalf("coverage error=%+v want static missing %v", coverageErr, wantMissing)
	}
}

func TestCriticalCoverageSearchHonorsCancellationPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ordered := make([]scheduler.Candidate, 200)
	for index := range ordered {
		ordered[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	evaluations := 0
	started := time.Now()
	_, err := searchCriticalCoverage(
		ctx, ordered, 16, []string{"unreachable"}, newCriticalCoverageBudget(16),
		func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error) {
			evaluations++
			if evaluations == 5 {
				cancel()
			}
			return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled search error=%v", err)
	}
	if evaluations > 5 || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("cancellation evaluations=%d elapsed=%s", evaluations, time.Since(started))
	}
}

func TestCriticalCoverageSearchEnforcesWallClockSlice(t *testing.T) {
	ordered := make([]scheduler.Candidate, 200)
	for index := range ordered {
		ordered[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	budget := newCriticalCoverageBudget(16)
	started := time.Now()
	_, err := searchCriticalCoverage(
		context.Background(), ordered, 16, []string{"unreachable"}, budget,
		func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error) {
			time.Sleep(5 * time.Millisecond)
			return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
		},
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted ||
		coverErr.Evaluations >= activeCriticalCoverageEvaluationLimit {
		t.Fatalf("wall-budget error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 800*time.Millisecond {
		t.Fatalf("wall-budget search elapsed=%s", elapsed)
	}
}

func TestProspectiveCoverageUsesFullScheduleWitnessBeforeBoundedSearch(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID:       fmt.Sprintf("candidate-%03d", index),
			Protocol: scheduler.ProtocolVLESS, Score: 100,
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			FailureDomain: fmt.Sprintf("domain-%03d", index),
		}
	}
	clients := []scheduler.Client{{ID: "client-a"}, {ID: "client-b"}, {ID: "client-c"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, placement, nil,
		WithActiveCriticalRouteLimit(16),
	)
	calls := 0
	engine.bootstrapCoverageEvaluate = func(
		ctx context.Context, at time.Time, selector *scheduler.Scheduler,
		clients []scheduler.Client, pool []scheduler.Candidate, required []string,
	) (criticalCoverageEvaluation, error) {
		calls++
		time.Sleep(4 * time.Millisecond)
		return evaluateProspectiveCriticalCoverage(
			ctx, at, selector, clients, pool, required,
		)
	}
	t.Cleanup(func() { engine.clearBootstrapCoverageCache() })

	started := time.Now()
	pool, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) == 0 || len(pool) > 12 {
		t.Fatalf("witness pool size=%d want 1..12", len(pool))
	}
	if calls > 3 {
		t.Fatalf("full-schedule witness required %d evaluations, want at most 3", calls)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("full-schedule witness elapsed=%s", elapsed)
	}
}

func TestCriticalCoverageKeepsReserveRequirementsMissingFromFullEvaluation(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []scheduler.Candidate{{ID: "primary"}, {ID: "tcp-reserve"}, {ID: "udp-reserve"}}
	clients := []scheduler.Client{{ID: "alice"}}
	engine := NewEngine(
		nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, required []string,
	) (criticalCoverageEvaluation, error) {
		satisfied := map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
		}
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if len(pool) < len(candidates) && present["tcp-reserve"] && present["udp-reserve"] {
			satisfied["alice:tcp:reserve"] = true
			satisfied["alice:udp:reserve"] = true
		}
		witness := []string(nil)
		if len(required) == 0 {
			witness = []string{"primary"}
		}
		return criticalCoverageEvaluation{satisfied: satisfied, witnessIDs: witness}, nil
	}

	pool, err := engine.cappedScheduleCandidates(
		context.Background(), now, engine.scheduler, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 2 {
		t.Fatalf("coverage pool=%v lost fixed reserve requirements", pool)
	}
	if got := []string{pool[0].ID, pool[1].ID}; !slices.Equal(got, []string{"tcp-reserve", "udp-reserve"}) {
		t.Fatalf("coverage pool=%v lost fixed reserve requirements", got)
	}
}

func TestCriticalCoverageRealSchedulerFindsLowerTierPrimaryReservePair(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	candidates := []scheduler.Candidate{
		{ID: "top", Protocol: scheduler.ProtocolVLESS, Score: 100,
			RouteKey: "shared-route", ProfileID: "shared-profile",
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true, FailureDomain: "domain-top"},
		{ID: "pair-a", Protocol: scheduler.ProtocolVLESS, Score: 70,
			RouteKey: "shared-route", ProfileID: "profile-a",
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true, FailureDomain: "domain-a"},
		{ID: "pair-b", Protocol: scheduler.ProtocolVLESS, Score: 65,
			RouteKey: "route-b", ProfileID: "shared-profile",
			TCPQualified: true, UDPQualified: true, ReserveEligible: true,
			ActiveEligible: true, ActiveFresh: true, FailureDomain: "domain-b"},
	}
	clients := []scheduler.Client{{ID: "alice"}}
	placement := scheduler.New(scheduler.PolicyDefaults())
	full, err := evaluateCriticalCoverage(
		context.Background(), now, placement, clients, candidates, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if full.satisfied["alice:tcp:reserve"] || full.satisfied["alice:udp:reserve"] {
		t.Fatalf("full pool unexpectedly had a quality-tier reserve: %+v", full.satisfied)
	}

	engine := NewEngine(
		nil, nil, nil, placement, nil, WithActiveCriticalRouteLimit(2),
	)
	pool, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 2 || pool[0].ID != "pair-a" || pool[1].ID != "pair-b" {
		t.Fatalf("real scheduler coverage pool=%+v want pair-a,pair-b", pool)
	}
	covered, err := evaluateCriticalCoverage(
		context.Background(), now, placement, clients, pool,
		criticalCoverageRequirements(clients),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !coverageComplete(covered, criticalCoverageRequirements(clients)) {
		t.Fatalf("selected pool lost route requirements: %+v", covered.satisfied)
	}
}

func TestCappedCoverageResumesPastFirstSliceWithoutEvaluationReplay(t *testing.T) {
	ordered := make([]scheduler.Candidate, 200)
	for index := range ordered {
		ordered[index] = scheduler.Candidate{ID: fmt.Sprintf("candidate-%03d", index)}
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	currentSlice := 1
	seenSlice := make(map[string]int)
	var replayed []string
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		ids := make([]string, len(pool))
		present := make(map[string]bool, len(pool))
		for index, candidate := range pool {
			ids[index] = candidate.ID
			present[candidate.ID] = true
		}
		signature := strings.Join(ids, ",")
		if previous := seenSlice[signature]; currentSlice > 1 && previous == 1 {
			replayed = append(replayed, signature)
		}
		seenSlice[signature] = currentSlice
		satisfied := make(map[string]bool)
		if len(pool) == len(ordered) ||
			(present[ordered[22].ID] && present[ordered[23].ID]) {
			satisfied["required"] = true
		}
		return criticalCoverageEvaluation{satisfied: satisfied}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, ordered,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted ||
		coverErr.Evaluations != activeCriticalCoverageEvaluationLimit {
		t.Fatalf("first slice error=%v", err)
	}
	currentSlice = 2
	found, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, ordered,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].ID != ordered[22].ID || found[1].ID != ordered[23].ID {
		t.Fatalf("resumed cover=%v", found)
	}
	if len(replayed) != 0 {
		t.Fatalf("second slice replayed %d completed evaluations, first=%q", len(replayed), replayed[0])
	}
	if engine.coverageSearch != nil {
		t.Fatal("successful cover retained stale search frontier")
	}
}

func TestCappedCoverageRetainsFrontierWhenRankingChanges(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	candidates[0].QoEStatus = qoe.StatusHealthy
	candidates[0].QoEFresh = true
	candidates[0].QoEEffective = time.Second
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	fullEvaluations := 0
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			fullEvaluations++
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, _ = engine.cappedScheduleCandidates(context.Background(), now, placement, nil, candidates)
	if engine.coverageSearch == nil || fullEvaluations != 1 {
		t.Fatalf("initial frontier=%v full evaluations=%d", engine.coverageSearch, fullEvaluations)
	}
	candidates[0].Score = 1
	candidates[0].QoEEffective = 2 * time.Second
	_, _ = engine.cappedScheduleCandidates(context.Background(), now, placement, nil, candidates)
	if fullEvaluations != 1 {
		t.Fatalf("score-only change replayed full evaluation; calls=%d", fullEvaluations)
	}
}

func TestCappedCoverageRetainsFrontierWhenUnselectedSafetyEvidenceChanges(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	fullEvaluations := 0
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			fullEvaluations++
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, _ = engine.cappedScheduleCandidates(context.Background(), now, placement, nil, candidates)
	if engine.coverageSearch == nil || fullEvaluations != 1 {
		t.Fatalf("initial frontier=%v full evaluations=%d", engine.coverageSearch, fullEvaluations)
	}
	candidates[0].TCPQualified = true
	_, _ = engine.cappedScheduleCandidates(context.Background(), now, placement, nil, candidates)
	if fullEvaluations != 1 {
		t.Fatalf("unselected safety churn replayed full evaluation; calls=%d", fullEvaluations)
	}
}

func TestResumeScheduleCoverageSessionRejectsCompletedFrontierWithoutCurrentCoverage(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	clients := []scheduler.Client{{ID: "alice"}}
	candidates := []scheduler.Candidate{
		{ID: "candidate-a", Protocol: scheduler.ProtocolVLESS},
		{ID: "candidate-b", Protocol: scheduler.ProtocolVLESS},
		{ID: "candidate-c", Protocol: scheduler.ProtocolVLESS},
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(nil, nil, nil, placement, nil, WithActiveCriticalRouteLimit(2))
	key, err := criticalCoveragePlanningKey(now, placement, clients, candidates, 2)
	if err != nil {
		t.Fatal(err)
	}
	sessionCtx, cancelSession := context.WithCancel(context.Background())
	t.Cleanup(cancelSession)
	engine.coverageSearch = &criticalCoverageSession{
		key: key, completed: true, completedIDs: []string{"candidate-a", "candidate-b"},
		ctx: sessionCtx, cancel: cancelSession,
	}
	evaluations := 0
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, _ []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		evaluations++
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}

	found, resumed, err := engine.resumeScheduleCoverageSession(
		context.Background(), now, placement, clients, candidates, engine.coverageEvaluate,
	)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !resumed || !errors.As(err, &coverageErr) || found != nil {
		t.Fatalf("found=%v resumed=%t err=%v", found, resumed, err)
	}
	if evaluations != 1 {
		t.Fatalf("current snapshot evaluations=%d want 1", evaluations)
	}
}

func TestCappedCoverageRetainsFrontierAfterParentCancellation(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	ctx, cancel := context.WithCancel(context.Background())
	evaluations := 0
	fullEvaluations := 0
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		evaluations++
		if len(pool) == len(candidates) {
			fullEvaluations++
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		if evaluations == 300 {
			cancel()
		}
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if present[candidates[22].ID] && present[candidates[23].ID] {
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(ctx, now, placement, nil, candidates)
	if !errors.Is(err, context.Canceled) || engine.coverageSearch == nil {
		t.Fatalf("canceled search error=%v frontier=%v", err, engine.coverageSearch)
	}
	found, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || fullEvaluations != 1 {
		t.Fatalf("resumed cover=%v full evaluations=%d", found, fullEvaluations)
	}
}

func TestCappedCoverageKeepsInFlightFullEvaluationAcrossSliceDeadline(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	fullStarted := make(chan struct{})
	releaseFull := make(chan struct{})
	fullCalls := 0
	engine.coverageEvaluate = func(
		ctx context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			fullCalls++
			if fullCalls == 1 {
				close(fullStarted)
			}
			select {
			case <-ctx.Done():
				return criticalCoverageEvaluation{}, ctx.Err()
			case <-releaseFull:
			}
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		if len(pool) == 1 && pool[0].ID == candidates[0].ID {
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted {
		t.Fatalf("first slice error=%v", err)
	}
	select {
	case <-fullStarted:
	default:
		t.Fatal("full evaluation did not start")
	}
	close(releaseFull)
	found, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != candidates[0].ID || fullCalls != 1 {
		t.Fatalf("found=%v full calls=%d", found, fullCalls)
	}
}

func TestCappedCoverageResumesMidGreedyPassAtNextCandidate(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	blocked := make(chan struct{})
	release := make(chan struct{})
	calls := make(map[string]int)
	engine.coverageEvaluate = func(
		ctx context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		key := criticalCoveragePoolKey(pool)
		calls[key]++
		if len(pool) == len(candidates) {
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		if len(pool) == 1 && pool[0].ID == candidates[50].ID {
			if calls[key] == 1 {
				close(blocked)
			}
			select {
			case <-ctx.Done():
				return criticalCoverageEvaluation{}, ctx.Err()
			case <-release:
			}
		}
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if present[candidates[22].ID] && present[candidates[23].ID] {
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted {
		t.Fatalf("mid-greedy slice error=%v", err)
	}
	select {
	case <-blocked:
	default:
		t.Fatal("greedy candidate 50 did not become the in-flight cursor")
	}
	close(release)
	var found []scheduler.Candidate
	for attempt := 0; attempt < 4; attempt++ {
		found, err = engine.cappedScheduleCandidates(
			context.Background(), now, placement, nil, candidates,
		)
		if err == nil {
			break
		}
		var retryErr *ActiveCriticalCoveragePlanError
		if !errors.As(err, &retryErr) || !retryErr.SearchExhausted {
			t.Fatalf("resume attempt %d error=%v", attempt, err)
		}
	}
	if err != nil || len(found) != 2 {
		t.Fatalf("eventual greedy/DFS result=%v error=%v", found, err)
	}
	if calls[criticalCoveragePoolKey([]scheduler.Candidate{candidates[50]})] != 1 {
		t.Fatalf("in-flight greedy candidate replayed: calls=%d",
			calls[criticalCoveragePoolKey([]scheduler.Candidate{candidates[50]})])
	}
}

func TestCappedCoverageParentCancellationStopsTaskAndRetainsCursor(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	started := make(chan struct{})
	stopped := make(chan struct{})
	engine.coverageEvaluate = func(
		ctx context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return criticalCoverageEvaluation{}, ctx.Err()
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := engine.cappedScheduleCandidates(
		ctx, time.Unix(1_900_000_000, 0), scheduler.New(scheduler.PolicyDefaults()),
		nil, candidates,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent cancellation error=%v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("in-flight task never started")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("cappedScheduleCandidates returned before canceled task joined")
	}
	if engine.coverageSearch == nil || engine.coverageSearch.pending != nil ||
		engine.coverageSearch.phase != criticalCoveragePhaseFull {
		t.Fatalf("cancellation lost safe full cursor: %+v", engine.coverageSearch)
	}
}

func TestCappedCoverageFingerprintInvalidationCancelsAndJoinsOldTask(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	firstStarted := make(chan struct{})
	firstStopped := make(chan struct{})
	var fullCalls atomic.Int32
	engine.coverageEvaluate = func(
		ctx context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			if fullCalls.Add(1) == 1 {
				close(firstStarted)
				<-ctx.Done()
				close(firstStopped)
				return criticalCoverageEvaluation{}, ctx.Err()
			}
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		if len(pool) == 1 && pool[0].ID == candidates[0].ID {
			return criticalCoverageEvaluation{satisfied: map[string]bool{"required": true}}, nil
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted {
		t.Fatalf("first slice error=%v", err)
	}
	select {
	case <-firstStarted:
	default:
		t.Fatal("old fingerprint task did not start")
	}
	candidates[0].FailureDomain = "changed-domain"
	found, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	if err != nil || len(found) != 1 {
		t.Fatalf("new fingerprint result=%v error=%v", found, err)
	}
	select {
	case <-firstStopped:
	default:
		t.Fatal("new fingerprint started before old task joined")
	}
}

func TestCappedCoverageFastPathCancelsAndJoinsPendingSearch(t *testing.T) {
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index].ID = fmt.Sprintf("candidate-%03d", index)
	}
	engine := NewEngine(nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	started := make(chan struct{})
	stopped := make(chan struct{})
	engine.coverageEvaluate = func(
		ctx context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return criticalCoverageEvaluation{}, ctx.Err()
		}
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}
	t.Cleanup(func() {
		engine.coverageMu.Lock()
		defer engine.coverageMu.Unlock()
		if engine.coverageSearch != nil {
			engine.coverageSearch.stop(true)
			engine.coverageSearch = nil
		}
	})
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	_, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates,
	)
	var coverErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverErr) || !coverErr.SearchExhausted {
		t.Fatalf("first slice error=%v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("pending full evaluation did not start")
	}
	startedAt := time.Now()
	pool, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, nil, candidates[:2],
	)
	if err != nil || len(pool) != 2 {
		t.Fatalf("fast path pool=%v error=%v", pool, err)
	}
	if elapsed := time.Since(startedAt); elapsed > 100*time.Millisecond {
		t.Fatalf("fast path cancellation/join took %s", elapsed)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("fast path returned before pending evaluation joined")
	}
	if engine.coverageSearch != nil {
		t.Fatalf("fast path retained stale search: %+v", engine.coverageSearch)
	}
}

func TestCriticalCoveragePlanningKeyUsesOnlyBucketedClientSemantics(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	candidates := []scheduler.Candidate{{
		ID: "route", Protocol: scheduler.ProtocolVLESS, TCPQualified: true,
		UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
	}}
	base := []scheduler.Client{{
		ID: "alice", LastTraffic: now.Add(-time.Minute),
		Assignment: scheduler.Assignment{
			TCP: "route", UDP: "route",
			TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
		},
	}}
	key, err := criticalCoveragePlanningKey(now, placement, base, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	equivalent := append([]scheduler.Client(nil), base...)
	equivalent[0].LastTraffic = now.Add(-90 * time.Second)
	equivalent[0].Assignment.TCPSince = now.Add(-2 * time.Hour)
	equivalent[0].Assignment.UDPSince = now.Add(-3 * time.Hour)
	equivalentKey, err := criticalCoveragePlanningKey(now, placement, equivalent, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	if equivalentKey != key {
		t.Fatalf("same activity/dwell buckets changed key: %s != %s", equivalentKey, key)
	}
	crossed := append([]scheduler.Client(nil), base...)
	crossed[0].LastTraffic = now.Add(-3 * time.Minute)
	crossedKey, err := criticalCoveragePlanningKey(now, placement, crossed, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	if crossedKey == key {
		t.Fatal("activity bucket transition did not invalidate key")
	}
}

func TestCriticalCoveragePlanningKeyInvalidatesOnlyStructuralChanges(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	clients := []scheduler.Client{{ID: "alice", Assignment: scheduler.Assignment{TCP: "route", UDP: "route"}}}
	candidates := []scheduler.Candidate{{
		ID: "route", Protocol: scheduler.ProtocolVLESS, RouteKey: "rk",
		TCPQualified: true, UDPQualified: true, ReserveEligible: true,
		ActiveEligible: true, ActiveFresh: true, FailureDomain: "domain-a", Score: 100,
	}}
	base, err := criticalCoveragePlanningKey(now, placement, clients, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]scheduler.Client, []scheduler.Candidate) ([]scheduler.Client, []scheduler.Candidate)
	}{
		{name: "domain", mutate: func(c []scheduler.Client, p []scheduler.Candidate) ([]scheduler.Client, []scheduler.Candidate) {
			p[0].FailureDomain = "domain-b"
			return c, p
		}},
		{name: "assignment", mutate: func(c []scheduler.Client, p []scheduler.Candidate) ([]scheduler.Client, []scheduler.Candidate) {
			c[0].Assignment.TCP = "other"
			return c, p
		}},
		{name: "client set", mutate: func(c []scheduler.Client, p []scheduler.Candidate) ([]scheduler.Client, []scheduler.Candidate) {
			return append(c, scheduler.Client{ID: "bob"}), p
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedClients := append([]scheduler.Client(nil), clients...)
			changedCandidates := append([]scheduler.Candidate(nil), candidates...)
			changedClients, changedCandidates = test.mutate(changedClients, changedCandidates)
			key, keyErr := criticalCoveragePlanningKey(
				now, placement, changedClients, changedCandidates, 16,
			)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			if key == base {
				t.Fatalf("structural %s change retained key", test.name)
			}
		})
	}

	changed := append([]scheduler.Candidate(nil), candidates...)
	changed[0].TCPQualified = false
	changed[0].UDPQualified = false
	changed[0].ReserveEligible = false
	changed[0].ActiveEligible = false
	changed[0].ActiveFresh = false
	changed[0].CircuitOpen = true
	changed[0].Retiring = true
	changed[0].QoEStatus = qoe.StatusDegraded
	changed[0].QoEFresh = false
	equivalent, err := criticalCoveragePlanningKey(now, placement, clients, changed, 16)
	if err != nil {
		t.Fatal(err)
	}
	if equivalent != base {
		t.Fatal("mutable candidate evidence changed planning key")
	}
}

func TestCriticalCoveragePlanningKeyIgnoresNonDecisionObservationChurn(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	placement := scheduler.New(scheduler.PolicyDefaults())
	candidates := []scheduler.Candidate{{
		ID: "route", Protocol: scheduler.ProtocolVLESS,
		TCPQualified: true, UDPQualified: true,
		// Active sequence/time churn is irrelevant while the candidate cannot
		// be selected as a reserve; only derived eligibility/proof is keyed.
		ReserveEligible: false, ActiveEligible: false, ActiveFresh: false,
	}}
	base, err := criticalCoveragePlanningKey(now, placement, nil, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	candidates[0].ActiveEligible = true
	candidates[0].ActiveFresh = true
	candidates[0].QoEEffective = 9 * time.Second
	candidates[0].QoEFresh = true
	equivalent, err := criticalCoveragePlanningKey(now, placement, nil, candidates, 16)
	if err != nil {
		t.Fatal(err)
	}
	if equivalent != base {
		t.Fatalf("non-decision observation churn changed key: %s != %s", equivalent, base)
	}
}

func TestActiveCriticalPlanCandidateCountDecodesTorAndExcludesDNS(t *testing.T) {
	plan := dataplane.DesiredPlan{Clients: []dataplane.ClientRoute{
		{ClientID: "alice", TCPOutbound: "tor-a-profile-1-client-alice", DNSOutbound: "dns-a"},
		{ClientID: "bob", TCPOutbound: "tor-a-profile-1-client-bob", UDPOutbound: "vless-b"},
	}}
	if got := activeCriticalPlanCandidateCount(plan); got != 2 {
		t.Fatalf("critical candidate count=%d want tor-a+vless-b", got)
	}
}

func TestEngineActiveTargetsIncludeBoundedProspectiveReserveUntilProofTransition(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "prospective", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
		{name: "not-working", kind: sources.KindVLESS, score: 200, tcp: true, udp: true, failureDomain: "domain-c"},
	})
	working := []store.Candidate{candidates["primary"], candidates["prospective"]}
	for _, candidate := range working {
		for success := 0; success < 2; success++ {
			if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 100, At: now.Add(time.Duration(success) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := database.ReplaceWorkingPool(ctx, []string{
		candidates["primary"].Fingerprint,
		candidates["prospective"].Fingerprint,
	}, nil); err != nil {
		t.Fatal(err)
	}
	setEngineActiveObservationAt(t, database, candidates["primary"], now)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
	)
	targets, err := engine.ActiveTargets(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]ActiveTarget, len(targets))
	for _, target := range targets {
		if _, duplicate := byID[target.Candidate.ID]; duplicate {
			t.Fatalf("duplicate target for TCP/UDP candidate %q: %+v",
				target.Candidate.ID, targets)
		}
		byID[target.Candidate.ID] = target
	}
	if len(byID) != 2 || byID[candidates["primary"].ID].TriggerPlacementOnSuccess ||
		!byID[candidates["prospective"].ID].TriggerPlacementOnSuccess {
		t.Fatalf("active targets before proof=%+v", targets)
	}
	if byID[candidates["primary"].ID].Role != ActiveTargetCritical ||
		byID[candidates["prospective"].ID].Role != ActiveTargetProspective {
		t.Fatalf("active target role catalog=%+v", targets)
	}
	if got, want := byID[candidates["prospective"].ID].ProofFreshAfter,
		now.Add(-2*time.Minute); !got.Equal(want) {
		t.Fatalf("prospective proof cutoff=%s want=%s", got, want)
	}
	if got, want := byID[candidates["primary"].ID].ProofFreshAfter,
		now.Add(-2*time.Minute); !got.Equal(want) {
		t.Fatalf("critical proof cutoff=%s want=%s", got, want)
	}
	if _, exists := byID[candidates["not-working"].ID]; exists {
		t.Fatalf("non-working candidate was probed prospectively: %+v", targets)
	}

	setEngineActiveObservationAt(t, database, candidates["prospective"], now.Add(time.Second))
	targets, err = engine.ActiveTargets(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	byID = make(map[string]ActiveTarget, len(targets))
	for _, target := range targets {
		byID[target.Candidate.ID] = target
	}
	if byID[candidates["prospective"].ID].TriggerPlacementOnSuccess {
		t.Fatalf("successful active proof retriggered placement: %+v", targets)
	}
	if got, want := byID[candidates["prospective"].ID].ProofFreshAfter,
		now.Add(time.Second-2*time.Minute); !got.Equal(want) {
		t.Fatalf("proof-satisfied capacity cutoff=%s want=%s", got, want)
	}
}

func TestEngineActiveTargetsBootstrapProspectiveCoverForBlockedAssignments(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false, "", "",
	)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)

	targets, err := engine.ActiveTargets(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("blocked assignment bootstrap targets=%d want=2: %+v", len(targets), targets)
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if target.Role != ActiveTargetCritical || target.TriggerPlacementOnSuccess {
			t.Fatalf("bootstrap target is not critical: %+v", target)
		}
		seen[target.Candidate.ID] = true
	}
	for _, name := range []string{"primary", "reserve"} {
		if !seen[candidates[name].ID] {
			t.Fatalf("bootstrap omitted %s candidate: %+v", name, targets)
		}
	}
}

func TestEngineActiveTargetsBootstrapProspectiveCoverForLegacyPlanWithoutReserves(
	t *testing.T,
) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	specs := []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	}
	for index := 0; index < 18; index++ {
		specs = append(specs, engineQoECandidateSpec{
			name: fmt.Sprintf("standby-%02d", index), kind: sources.KindVLESS,
			score: 80 - float64(index), tcp: true, udp: true,
			failureDomain: fmt.Sprintf("standby-domain-%02d", index),
		})
	}
	database, candidates := newEngineQoEFixture(t, now, specs)
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)

	targets, err := engine.ActiveTargets(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 || len(targets) > 4 {
		t.Fatalf("legacy reserve bootstrap targets=%d want=1..4: %+v", len(targets), targets)
	}
	for _, target := range targets {
		if target.Role != ActiveTargetCritical || target.TriggerPlacementOnSuccess {
			t.Fatalf("legacy bootstrap target is not retained critical capacity: %+v", target)
		}
	}
	engine.bootstrapCoverageMu.Lock()
	bootstrap := engine.bootstrapCoverageSearch
	engine.bootstrapCoverageMu.Unlock()
	if bootstrap == nil || !bootstrap.completed {
		t.Fatal("legacy plan without reserves did not retain prospective coverage cache")
	}
}

func TestEngineActiveTargetsKeepServingTargetsWhenBlockedCoverIsImpossible(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)

	targets, err := engine.ActiveTargets(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.Candidate.ID == candidates["primary"].ID &&
			target.Role == ActiveTargetCritical {
			return
		}
	}
	t.Fatalf("impossible UDP cover suppressed serving TCP target: %+v", targets)
}

func TestEngineActiveProofFreshnessSpansPipelinedFailoverWindow(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	engine := NewEngine(
		nil, nil, nil, nil, nil,
		WithActiveProbeInterval(300*time.Millisecond),
		WithActiveProofFreshness(5*time.Second),
		WithActiveFailureFreshness(1975*time.Millisecond),
	)
	observedAt := now.Add(-3300 * time.Millisecond)
	if !engine.reserveActiveObservationFresh(now, observedAt) {
		t.Fatal("proof expired before the configured end-to-end failover window")
	}
	if engine.activeHardFailureObservationFresh(now, observedAt) {
		t.Fatal("hard failure remained fresh beyond its configured recency window")
	}
}

func TestEngineKeepsReserveProofAcrossApplyWindow(t *testing.T) {
	ctx := context.Background()
	base := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, base, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, base, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", base, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	at := base.Add(time.Second)
	setEngineActiveObservationAt(t, database, candidates["primary"], at)

	staleEngine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
		WithActiveProofFreshness(600*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := staleEngine.Cycle(ctx, at); err == nil {
		t.Fatal("short proof window unexpectedly survived the apply interval")
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
		WithActiveProofFreshness(1975*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, at); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 ||
		agent.plans[0].Clients[0].TCPReserveOutbound == "" ||
		agent.plans[0].Clients[0].UDPReserveOutbound == "" {
		t.Fatalf("plan did not retain both reserves: %+v", agent.plans)
	}
}

func TestEngineActiveTargetsKeepAppliedReserveAfterItBecomesIneligible(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	reserveID := candidateIDFromHandler(
		agent.plans[0].Clients[0].TCPReserveOutbound, "alice",
	)
	if reserveID == "" {
		t.Fatalf("applied route has no reserve: %+v", agent.plans[0].Clients[0])
	}
	reserve := engineCandidateByID(t, candidates, reserveID)
	observation, err := database.ReserveCandidateObservation(
		ctx, reserve, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, reserve, observation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("reserve hard failure commit=%+v err=%v", commit, err)
	}
	targets, err := engine.ActiveTargets(ctx, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.Candidate.ID == reserveID {
			return
		}
	}
	t.Fatalf("ineligible applied reserve %q disappeared from targets: %+v",
		reserveID, targets)
}

func TestEngineActiveTargetsRetainsProspectiveCoverUntilNormalization(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	coverageCtx, cancelCoverage := context.WithCancel(context.Background())
	t.Cleanup(cancelCoverage)
	engine.bootstrapCoverageMu.Lock()
	engine.bootstrapCoverageSearch = &criticalCoverageSession{
		key: "repair-cover", completed: true,
		completedIDs: []string{candidates["primary"].ID, candidates["reserve"].ID},
		ctx:          coverageCtx, cancel: cancelCoverage,
	}
	engine.bootstrapCoverageMu.Unlock()

	if _, err := engine.ActiveTargets(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	engine.bootstrapCoverageMu.Lock()
	retained := engine.bootstrapCoverageSearch
	engine.bootstrapCoverageMu.Unlock()
	if retained == nil || !retained.completed {
		t.Fatal("active target refresh discarded the prospective repair cover")
	}
}

func TestEngineLegacyOverlimitActiveTargetsUseProspectiveCoveragePool(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 18)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	staleNow := now.Add(3 * time.Minute)
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.ActiveCardinalityReady(context.Background(), staleNow); err == nil {
		t.Fatal("legacy overlimit plan unexpectedly passed cardinality gate")
	}
	targets, err := engine.ActiveTargets(context.Background(), staleNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 || len(targets) > 16 {
		t.Fatalf("bootstrap targets=%d want 1..16", len(targets))
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if target.Role != ActiveTargetCritical || seen[target.Candidate.ID] {
			t.Fatalf("invalid bootstrap target=%+v duplicate=%v", target, seen[target.Candidate.ID])
		}
		seen[target.Candidate.ID] = true
	}
}

func TestEngineLegacyOverlimitActiveTargetsRejectImpossibleProspectiveCover(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 17)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(time.Minute),
	)
	if err := seed.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	for clientIndex := 0; clientIndex < 17; clientIndex++ {
		clientID := fmt.Sprintf("client-%02d", clientIndex)
		for candidateIndex := 0; candidateIndex < 17; candidateIndex++ {
			if candidateIndex == clientIndex {
				continue
			}
			placement.Exclude(
				clientID, candidates[fmt.Sprintf("route-%02d", candidateIndex)].ID,
				now.Add(time.Hour),
			)
		}
	}
	engine := NewEngine(
		database, &engineAgent{}, nil, placement, []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	_, err := engine.ActiveTargets(context.Background(), now.Add(3*time.Minute))
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) || coverageErr.Limit != 16 {
		t.Fatalf("impossible prospective bootstrap error=%v", err)
	}
}

func TestProspectiveCoverageCachesCompletedIDsAndRevalidatesEvidenceOrCardinalityChanges(
	t *testing.T,
) {
	now := time.Unix(1_900_000_000, 0)
	clients := []scheduler.Client{{
		ID: "alice", Assignment: scheduler.Assignment{TCP: "route-000", UDP: "route-000"},
	}}
	candidates := make([]scheduler.Candidate, 0, 200)
	for index := 0; index < 200; index++ {
		candidates = append(candidates, scheduler.Candidate{
			ID: fmt.Sprintf("route-%03d", index), Protocol: scheduler.ProtocolVLESS,
			RouteKey:      fmt.Sprintf("route-key-%03d", index),
			FailureDomain: fmt.Sprintf("domain-%03d", index),
			Score:         float64(200 - index), TCPQualified: true, UDPQualified: true,
			ReserveEligible: true,
		})
	}
	engine := NewEngine(
		nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(16),
	)
	var calls atomic.Int32
	engine.bootstrapCoverageEvaluate = func(
		ctx context.Context,
		at time.Time,
		placement *scheduler.Scheduler,
		clients []scheduler.Client,
		pool []scheduler.Candidate,
		required []string,
	) (criticalCoverageEvaluation, error) {
		if calls.Add(1) == 1 {
			select {
			case <-time.After(470 * time.Millisecond):
			case <-ctx.Done():
				return criticalCoverageEvaluation{}, ctx.Err()
			}
		}
		return evaluateProspectiveCriticalCoverage(
			ctx, at, placement, clients, pool, required,
		)
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	var cover []scheduler.Candidate
	slicesUsed := 0
	for slice := 0; slice < 5; slice++ {
		slicesUsed++
		var err error
		cover, err = engine.cappedProspectiveScheduleCandidates(
			context.Background(), now, placement, clients, candidates,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			t.Fatal(err)
		}
	}
	if len(cover) == 0 || len(cover) > 16 {
		t.Fatalf("completed prospective cover=%d calls=%d", len(cover), calls.Load())
	}
	if slicesUsed < 2 {
		t.Fatal("near-budget prospective planning did not resume across slices")
	}
	completedCalls := calls.Load()

	proofOnly := append([]scheduler.Candidate(nil), candidates...)
	for index := range proofOnly {
		proofOnly[index].ActiveEligible = true
		proofOnly[index].ActiveFresh = true
	}
	if cached, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now.Add(100*time.Millisecond), placement, clients, proofOnly,
	); err != nil || len(cached) != len(cover) || calls.Load() != completedCalls+1 {
		t.Fatalf("proof-only cache revalidation result=%d calls=%d/%d err=%v",
			len(cached), calls.Load(), completedCalls+1, err)
	}
	completedCalls = calls.Load()
	var exactCalls atomic.Int32
	engine.coverageEvaluate = func(
		context.Context, time.Time, *scheduler.Scheduler,
		[]scheduler.Client, []scheduler.Candidate, []string,
	) (criticalCoverageEvaluation, error) {
		exactCalls.Add(1)
		return criticalCoverageEvaluation{satisfied: map[string]bool{
			"alice:tcp:primary": true,
			"alice:udp:primary": true,
			"alice:tcp:reserve": true,
			"alice:udp:reserve": true,
		}}, nil
	}
	if exact, err := engine.cappedScheduleCandidates(
		context.Background(), now.Add(100*time.Millisecond), placement, clients, proofOnly,
	); err != nil || len(exact) != len(cover) {
		t.Fatalf("exact cached bootstrap cover=%d err=%v", len(exact), err)
	}
	if exactCalls.Load() != 1 {
		t.Fatalf("exact cached bootstrap validations=%d want 1", exactCalls.Load())
	}
	engine.coverageEvaluate = nil

	changed := append([]scheduler.Candidate(nil), proofOnly...)
	covered := make(map[string]bool, len(cover))
	for _, candidate := range cover {
		covered[candidate.ID] = true
	}
	for index := range changed {
		if covered[changed[index].ID] {
			changed[index].ReserveEligible = false
		}
	}
	if _, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now.Add(100*time.Millisecond), placement, clients, changed,
	); err != nil && !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatal(err)
	}
	if calls.Load() == completedCalls {
		t.Fatal("degraded completed cover was not revalidated")
	}
	afterEligibilityChange := calls.Load()
	if _, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, placement, clients, candidates[:16],
	); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	); err != nil && !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
		t.Fatal(err)
	}
	if calls.Load() == afterEligibilityChange {
		t.Fatal("normalized cardinality did not invalidate completed bootstrap cover")
	}
}

func TestExactCoverageRejectsIncompleteProspectiveCachedPool(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	clients := []scheduler.Client{{ID: "alice"}}
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID: fmt.Sprintf("route-%03d", index), Protocol: scheduler.ProtocolVLESS,
			RouteKey:      fmt.Sprintf("route-key-%03d", index),
			FailureDomain: fmt.Sprintf("domain-%03d", index),
			Score:         float64(200 - index), TCPQualified: true, UDPQualified: true,
			ReserveEligible: true, ActiveEligible: true, ActiveFresh: true,
		}
	}
	engine := NewEngine(
		nil, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithActiveCriticalRouteLimit(2),
	)
	requirements := criticalCoverageRequirements(clients)
	complete := func(witness ...string) criticalCoverageEvaluation {
		satisfied := make(map[string]bool, len(requirements))
		for _, requirement := range requirements {
			satisfied[requirement] = true
		}
		return criticalCoverageEvaluation{satisfied: satisfied, witnessIDs: witness}
	}
	engine.bootstrapCoverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		if len(pool) == len(candidates) {
			return complete(candidates[0].ID, candidates[1].ID), nil
		}
		return complete(), nil
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	prospective, err := engine.cappedProspectiveScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{prospective[0].ID, prospective[1].ID}; !slices.Equal(got, []string{candidates[0].ID, candidates[1].ID}) {
		t.Fatalf("prospective pool=%v", got)
	}

	var exactCalls atomic.Int32
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, pool []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		exactCalls.Add(1)
		present := make(map[string]bool, len(pool))
		for _, candidate := range pool {
			present[candidate.ID] = true
		}
		if len(pool) == len(candidates) {
			return complete(candidates[2].ID, candidates[3].ID), nil
		}
		if present[candidates[2].ID] && present[candidates[3].ID] {
			return complete(), nil
		}
		incomplete := complete()
		delete(incomplete.satisfied, "alice:udp:reserve")
		return incomplete, nil
	}
	exact, err := engine.cappedScheduleCandidates(
		context.Background(), now, placement, clients, candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{exact[0].ID, exact[1].ID}; !slices.Equal(got, []string{candidates[2].ID, candidates[3].ID}) {
		t.Fatalf("exact pool=%v want [%s %s]", got, candidates[2].ID, candidates[3].ID)
	}
	if exactCalls.Load() < 3 {
		t.Fatalf("exact evaluations=%d want cached validation plus replanning", exactCalls.Load())
	}
}

func TestScheduleCandidatesWaitsForCachedProspectiveProofWithoutSubsetSearch(
	t *testing.T,
) {
	now := time.Unix(1_900_000_000, 0)
	clients := []scheduler.Client{{ID: "alice"}}
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID: fmt.Sprintf("route-%03d", index), Protocol: scheduler.ProtocolVLESS,
			RouteKey:      fmt.Sprintf("route-key-%03d", index),
			FailureDomain: fmt.Sprintf("domain-%03d", index),
			Score:         float64(200 - index), TCPQualified: true, UDPQualified: true,
			ReserveEligible: true,
		}
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(
		nil, nil, nil, placement, nil,
		WithActiveCriticalRouteLimit(16),
	)
	key, err := criticalCoveragePlanningKeyWithProofMode(
		now, placement, clients, candidates, 16, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	engine.bootstrapCoverageSearch = &criticalCoverageSession{
		key: key, completed: true,
		completedIDs: []string{candidates[0].ID, candidates[1].ID},
	}
	var evaluations atomic.Int32
	engine.coverageEvaluate = func(
		ctx context.Context, at time.Time, selector *scheduler.Scheduler,
		clients []scheduler.Client, pool []scheduler.Candidate, required []string,
	) (criticalCoverageEvaluation, error) {
		evaluations.Add(1)
		return evaluateCriticalCoverage(
			ctx, at, selector, clients, pool, required,
		)
	}

	_, err = engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) {
		t.Fatalf("missing active proof error=%v", err)
	}
	if got := evaluations.Load(); got != 2 {
		t.Fatalf("active coverage evaluations=%d want full-pool+cached-cover only", got)
	}
}

func TestScheduleCandidatesBuildsProspectiveCoverBeforeExactSubsetSearch(
	t *testing.T,
) {
	now := time.Unix(1_900_000_000, 0)
	clients := []scheduler.Client{{ID: "alice"}}
	candidates := make([]scheduler.Candidate, 200)
	for index := range candidates {
		candidates[index] = scheduler.Candidate{
			ID: fmt.Sprintf("route-%03d", index), Protocol: scheduler.ProtocolVLESS,
			RouteKey:      fmt.Sprintf("route-key-%03d", index),
			FailureDomain: fmt.Sprintf("domain-%03d", index),
			Score:         float64(200 - index), TCPQualified: true, UDPQualified: true,
			ReserveEligible: true,
		}
	}
	placement := scheduler.New(scheduler.PolicyDefaults())
	engine := NewEngine(
		nil, nil, nil, placement, nil,
		WithActiveCriticalRouteLimit(16),
	)
	var exactEvaluations atomic.Int32
	engine.coverageEvaluate = func(
		_ context.Context, _ time.Time, _ *scheduler.Scheduler,
		_ []scheduler.Client, _ []scheduler.Candidate, _ []string,
	) (criticalCoverageEvaluation, error) {
		exactEvaluations.Add(1)
		return criticalCoverageEvaluation{satisfied: map[string]bool{}}, nil
	}

	_, err := engine.scheduleCandidatesForCycle(
		context.Background(), now, placement, clients, candidates,
	)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) || !coverageErr.SearchExhausted {
		t.Fatalf("missing active proof error=%v", err)
	}
	if got := exactEvaluations.Load(); got != 2 {
		t.Fatalf("active coverage evaluations=%d want full-pool+prospective-cover only", got)
	}
	engine.bootstrapCoverageMu.Lock()
	prospective := engine.bootstrapCoverageSearch
	engine.bootstrapCoverageMu.Unlock()
	if prospective == nil || !prospective.completed || len(prospective.completedIDs) == 0 {
		t.Fatalf("prospective cover was not retained: %+v", prospective)
	}
}

func TestEngineHardFailureSupersedesLowerPendingPlanThenRecomputesIt(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	initial := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("1.1.1.1"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := initial.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	agent.applyErr = errors.New("pending apply failed")
	current := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := current.Cycle(ctx, now.Add(time.Second)); err == nil {
		t.Fatal("resolver change did not leave a pending desired generation")
	}
	pending, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.DesiredGeneration != 2 || pending.AppliedGeneration != 1 {
		t.Fatalf("pending state=%+v", pending)
	}
	if pending.DesiredReason != string(PlacementPeriodic) {
		t.Fatalf("pending reason=%q", pending.DesiredReason)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	failed := engineCandidateByID(t, candidates, assignment.TCPOutbound)
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, now.Add(2*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}
	agent.applyErr = nil
	if err := current.CycleForReason(
		ctx, now.Add(3*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 3 || agent.plans[2].Generation != 3 {
		t.Fatalf("hard cycle replayed lower pending bytes before failover: generations=%v",
			enginePlanGenerations(agent.plans))
	}
	hardResolverFound := false
	for _, outbound := range agent.plans[2].Outbounds {
		if outbound.Protocol != dataplane.ProtocolDNS {
			continue
		}
		_, resolver := engineDNSConfig(t, outbound.Config)
		if resolver == "1.1.1.1" {
			hardResolverFound = true
		}
	}
	if !hardResolverFound {
		t.Fatalf("hard plan was not derived from the applied plan: %+v", agent.plans[2])
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 3 || state.AppliedGeneration != 3 ||
		state.DesiredReason != string(PlacementHardFailure) {
		t.Fatalf("hard supersession state=%+v", state)
	}
	if err := current.Cycle(ctx, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 4 || agent.plans[3].Generation != 4 {
		t.Fatalf("lower reason was not recomputed after hard: generations=%v",
			enginePlanGenerations(agent.plans))
	}
	state, err = database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredReason != string(PlacementPeriodic) {
		t.Fatalf("recomputed lower reason=%q", state.DesiredReason)
	}
}

func TestEngineHardFailureRetryReassertsItsOwnPendingGeneration(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	failure, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], failure, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	agent.applyErr = errors.New("hard apply response lost")
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err == nil {
		t.Fatal("hard apply fault did not leave a pending generation")
	}
	pending, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.DesiredGeneration != 2 || pending.AppliedGeneration != 1 ||
		pending.DesiredReason != string(PlacementHardFailure) {
		t.Fatalf("pending hard state=%+v", pending)
	}
	agent.applyErr = nil
	if err := engine.CycleForReason(
		ctx, now.Add(3*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if got := enginePlanGenerations(agent.plans); !reflect.DeepEqual(got, []int64{1, 2, 2}) {
		t.Fatalf("hard retry generations=%v", got)
	}
	settled, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settled.DesiredGeneration != 2 || settled.AppliedGeneration != 2 ||
		settled.DesiredReason != string(PlacementHardFailure) {
		t.Fatalf("settled hard state=%+v", settled)
	}
}

func TestEngineHardFailureDoesNotApplyPendingPlanWhosePrimaryFailed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
		{name: "fallback", kind: sources.KindVLESS, score: 80, tcp: true, failureDomain: "domain-c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	markHardFailed := func(candidate store.Candidate, at time.Time) {
		t.Helper()
		reservation, err := database.ReserveCandidateObservation(
			ctx, candidate, store.ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
			ctx, candidate, reservation, at,
		); err != nil || !commit.Accepted {
			t.Fatalf("hard failure commit=%+v err=%v", commit, err)
		}
	}
	markHardFailed(candidates["primary"], now.Add(time.Second))
	agent.applyErr = errors.New("hard apply response lost")
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err == nil {
		t.Fatal("hard apply fault did not leave a pending generation")
	}
	pendingRoute := agent.plans[len(agent.plans)-1].Clients[0]
	pendingPrimaryID := candidateIDFromHandler(pendingRoute.TCPOutbound, "alice")
	markHardFailed(engineCandidateByID(t, candidates, pendingPrimaryID), now.Add(3*time.Second))
	agent.applyErr = nil
	if err := engine.CycleForReason(
		ctx, now.Add(3*time.Minute), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if got := enginePlanGenerations(agent.plans); !reflect.DeepEqual(got, []int64{1, 2, 3}) {
		t.Fatalf("stale pending generation reached gateway: %v", got)
	}
	finalRoute := agent.plans[len(agent.plans)-1].Clients[0]
	if got := candidateIDFromHandler(finalRoute.TCPOutbound, "alice"); got != candidates["fallback"].ID {
		t.Fatalf("stale applied TCP primary was not replaced: %s", got)
	}
	if got := candidateIDFromHandler(finalRoute.UDPOutbound, "alice"); got != candidates["primary"].ID {
		t.Fatalf("UDP without a replacement did not keep last-known-good: %s", got)
	}
}

func TestEngineStartupNormalizationSettlesSafePendingHardPlanWithoutReserve(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	agent.applyErr = errors.New("hard apply response lost")
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err == nil {
		t.Fatal("hard apply fault did not leave a pending generation")
	}
	agent.applyErr = nil
	err = engine.NormalizeActiveCriticalRoutes(ctx, now.Add(3*time.Second))
	if !isActiveCriticalCoverageError(err) {
		t.Fatalf("normalization error=%v want missing reserve coverage", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.DesiredGeneration != 2 || state.AppliedGeneration != 2 {
		t.Fatalf("safe pending hard plan remained stranded: %+v", state)
	}
}

func TestEngineHardFailureKeepsLastKnownGoodRouteWithoutReplacement(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("initial plans=%v", enginePlanGenerations(agent.plans))
	}
	initialPlan := agent.plans[0]
	initialAssignment := engineQoEAssignment(t, database, "alice")
	failed := candidates["primary"]
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}

	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("hard failure without replacement applied generations=%v",
			enginePlanGenerations(agent.plans))
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != initialPlan.Generation ||
		state.AppliedGeneration != initialPlan.Generation {
		t.Fatalf("hard failure without replacement advanced state=%+v", state)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != initialAssignment.TCPOutbound ||
		assignment.UDPOutbound != initialAssignment.UDPOutbound ||
		!assignment.TCPSince.Equal(initialAssignment.TCPSince) ||
		!assignment.UDPSince.Equal(initialAssignment.UDPSince) {
		t.Fatalf("last-known-good assignment changed: before=%+v after=%+v",
			initialAssignment, assignment)
	}
}

func TestEngineHardFailurePreservesEveryDNSOutboundWhileUsingMappedReserve(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	initialEngine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("1.1.1.1"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := initialEngine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	initialPlan := agent.plans[0]
	initialRoute := initialPlan.Clients[0]
	failedID := candidateIDFromHandler(initialRoute.TCPOutbound, "alice")
	failed := engineCandidateByID(t, candidates, failedID)
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}
	current := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := current.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 2 || agent.plans[1].Generation != 2 {
		t.Fatalf("route-only failover generations=%v",
			enginePlanGenerations(agent.plans))
	}
	hard := agent.plans[1]
	if !reflect.DeepEqual(initialPlan.Outbounds, hard.Outbounds) {
		t.Fatalf("hard generation changed outbound set: before=%+v after=%+v",
			initialPlan.Outbounds, hard.Outbounds)
	}
	for _, outbound := range hard.Outbounds {
		if outbound.Protocol != dataplane.ProtocolDNS {
			continue
		}
		_, resolver := engineDNSConfig(t, outbound.Config)
		if resolver != "1.1.1.1" {
			t.Fatalf("hard generation rewrote existing DNS: %+v", outbound)
		}
	}
	if hard.Clients[0].TCPOutbound != initialRoute.TCPReserveOutbound {
		t.Fatalf("hard failover did not use mapped reserve: %+v", hard.Clients[0])
	}
	if target, _ := engineDNSConfig(
		t, engineOutboundByID(t, hard, hard.Clients[0].DNSOutbound).Config,
	); target != hard.Clients[0].TCPOutbound {
		t.Fatalf("hard route DNS target=%q route=%+v", target, hard.Clients[0])
	}
}

func TestRewritePlanDNSRepairsLegacyPlanWithMissingDNS(t *testing.T) {
	legacy := dataplane.DesiredPlan{
		Generation: 4,
		Outbounds: []dataplane.Outbound{
			{ID: "primary", Protocol: dataplane.ProtocolVLESS},
			{ID: "reserve", Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "primary",
			TCPReserveOutbound: "reserve", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	rewritten, matches, err := rewritePlanDNS(legacy, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if matches || rewritten.Clients[0].DNSOutbound == "" ||
		dnsHandlerForClientTarget("alice", "reserve", rewritten.Outbounds) == "" {
		t.Fatalf("legacy DNS was not rebuilt for active and reserve: %+v", rewritten)
	}
	if rewritten.Clients[0].TCPOutbound != "primary" ||
		rewritten.Clients[0].TCPReserveOutbound != "reserve" ||
		!sameEngineNonDNSOutboundSet(legacy.Outbounds, rewritten.Outbounds) {
		t.Fatalf("legacy DNS repair changed route identity: %+v", rewritten)
	}
}

func TestRewritePlanDNSUsesCandidateSelectedResolverPool(t *testing.T) {
	plan := dataplane.DesiredPlan{
		Generation: 4,
		Outbounds: []dataplane.Outbound{
			{ID: "primary", Protocol: dataplane.ProtocolVLESS},
			{ID: "reserve", Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "primary",
			TCPReserveOutbound: "reserve", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	resolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	rewritten, matches, err := rewritePlanDNSWithResolvers(plan, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("plan without DNS unexpectedly matched resolver pool")
	}
	for _, targetID := range []string{"primary", "reserve"} {
		dnsID := dnsHandlerForClientTarget("alice", targetID, rewritten.Outbounds)
		_, gotResolver := engineDNSConfig(t, engineOutboundByID(t, rewritten, dnsID).Config)
		wantResolver, err := dataplane.SelectDNSResolver(targetID, resolvers)
		if err != nil {
			t.Fatal(err)
		}
		if gotResolver != wantResolver {
			t.Fatalf("target %s resolver=%s want=%s", targetID, gotResolver, wantResolver)
		}
	}
}

func TestRewritePlanDNSRejectsAndPrunesUnreferencedExtraDNS(t *testing.T) {
	base := dataplane.DesiredPlan{
		Generation: 4,
		Outbounds: []dataplane.Outbound{
			{ID: "primary", Protocol: dataplane.ProtocolVLESS},
			{ID: "reserve", Protocol: dataplane.ProtocolVLESS},
		},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", TCPOutbound: "primary",
			TCPReserveOutbound: "reserve", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	exact, _, err := rewritePlanDNS(base, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	extra, err := dataplane.BuildDNSOutbound(
		"stale-client", base.Outbounds[0], "9.9.9.9",
	)
	if err != nil {
		t.Fatal(err)
	}
	withExtra := exact
	withExtra.Outbounds = append(
		append([]dataplane.Outbound(nil), exact.Outbounds...), extra,
	)
	rewritten, matches, err := rewritePlanDNS(withExtra, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("plan with unreferenced DNS was accepted as an exact DNS set")
	}
	if !sameEngineOutboundSet(exact.Outbounds, rewritten.Outbounds) {
		t.Fatalf("extra DNS was not pruned: exact=%+v rewritten=%+v",
			exact.Outbounds, rewritten.Outbounds)
	}

	withDuplicate := exact
	for _, outbound := range exact.Outbounds {
		if outbound.Protocol == dataplane.ProtocolDNS {
			withDuplicate.Outbounds = append(
				append([]dataplane.Outbound(nil), exact.Outbounds...), outbound,
			)
			break
		}
	}
	rewritten, matches, err = rewritePlanDNS(withDuplicate, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if matches || !sameEngineOutboundSet(exact.Outbounds, rewritten.Outbounds) {
		t.Fatalf("duplicate DNS count was accepted or not pruned: matches=%v rewritten=%+v",
			matches, rewritten.Outbounds)
	}
}

func TestEngineHardFailureRetriesInventoryCASWithoutColdApply(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	failed := candidates["primary"]
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}
	var mutate sync.Once
	attempts := 0
	engine.beforeDesiredPlanSave = func() {
		attempts++
		mutate.Do(func() {
			if err := database.ReplaceCandidates(
				ctx, failed.SourceID, []store.CandidateInput{
					{
						Kind: sources.KindVLESS, Label: "primary",
						Fingerprint:   "primary",
						Payload:       "vless://changed-primary@example.net:443",
						FailureDomain: "domain-a", RouteKey: "route-primary",
					},
					{
						Kind: sources.KindVLESS, Label: "reserve",
						Fingerprint:   "reserve",
						Payload:       "vless://changed-reserve@example.net:443",
						FailureDomain: "domain-b", RouteKey: "route-reserve",
					},
				},
			); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(agent.plans) != 2 {
		t.Fatalf("hard CAS retry attempts=%d applied generations=%v",
			attempts, enginePlanGenerations(agent.plans))
	}
}

func TestEngineHardFailureSurvivesTemporaryPreDesiredFailureAndRepeatedDown(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	failed := candidates["primary"]
	failure, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, failure, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}

	attempts := 0
	engine.beforeDesiredPlanSave = func() {
		attempts++
		rows, err := database.ListCandidateHealth(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.CandidateID != failed.ID {
				continue
			}
			row.Score += float64(attempts)
			row.UpdatedAt = now.Add(time.Duration(attempts+1) * time.Second)
			if err := database.SaveCandidateHealth(ctx, row); err != nil {
				t.Fatal(err)
			}
			return
		}
		t.Fatalf("failed candidate %q health missing", failed.ID)
	}
	err = engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	)
	if !errors.Is(err, store.ErrCandidateInventoryChanged) || attempts != 3 {
		t.Fatalf("temporary pre-desired failure err=%v attempts=%d", err, attempts)
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 1 || state.AppliedGeneration != 1 ||
		len(agent.plans) != 1 {
		t.Fatalf("temporary attempt leaked plan: state=%+v generations=%v",
			state, enginePlanGenerations(agent.plans))
	}

	repeatedDown, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, failed, repeatedDown,
		store.ActiveObservationOutcome{Available: false, ProofSuccess: false},
		now.Add(5*time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("repeated down commit=%+v err=%v", commit, err)
	}
	engine.beforeDesiredPlanSave = nil
	if err := engine.CycleForReason(
		ctx, now.Add(6*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 2 || agent.plans[1].Generation != 2 ||
		candidateIDFromHandler(agent.plans[1].Clients[0].TCPOutbound, "alice") !=
			candidates["reserve"].ID {
		t.Fatalf("hard failure was lost before retry: generations=%v plan=%+v",
			enginePlanGenerations(agent.plans), agent.plans[len(agent.plans)-1])
	}
}

func TestEngineDetectsOnlyFreshAssignedHardFailureAtStartup(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "other", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	observation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], observation, now,
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	engine := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithActiveProbeInterval(300*time.Millisecond),
		WithActiveProofFreshness(5*time.Second),
		WithActiveFailureFreshness(1975*time.Millisecond),
	)
	fresh, err := engine.HasFreshAssignedHardFailure(ctx, now.Add(1500*time.Millisecond))
	if err != nil || !fresh {
		t.Fatalf("fresh assigned failure=%v err=%v", fresh, err)
	}
	fresh, err = engine.HasFreshAssignedHardFailure(ctx, now.Add(3300*time.Millisecond))
	if err != nil || fresh {
		t.Fatalf("stale assigned failure=%v err=%v", fresh, err)
	}
}

func TestEngineRestartSyncUsesExistingWarmProfileForExactMappedTorReserve(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "tor-reserve", kind: sources.KindTorBridge, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	warm := torpool.Profile{
		Slot: 1, CandidateID: candidates["tor-reserve"].ID,
		SocksAddr: "127.0.0.1:19051", Role: "warm",
	}
	initialProfiles := NewTorCoordinator(&resyncTorProfileRemote{
		authoritative: []torpool.Profile{warm},
	})
	if err := initialProfiles.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	initialEngine := NewEngine(
		database, agent, initialProfiles, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := initialEngine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	initial := agent.plans[0]
	mappedReserve := initial.Clients[0].TCPReserveOutbound
	wantReserve := torProfileOutboundID(
		candidates["tor-reserve"].ID, warm, "alice",
	)
	if mappedReserve != wantReserve {
		t.Fatalf("initial mapped Tor reserve=%q want=%q", mappedReserve, wantReserve)
	}

	observation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], observation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("primary hard failure commit=%+v err=%v", commit, err)
	}

	restartedProfiles := NewTorCoordinator(&resyncTorProfileRemote{
		local: []torpool.Profile{{
			Slot: 9, CandidateID: candidates["tor-reserve"].ID,
			SocksAddr: "127.0.0.1:19999", Role: "warm",
		}},
		authoritative: []torpool.Profile{warm},
	})
	if profiles := restartedProfiles.Profiles(); len(profiles) != 0 {
		t.Fatalf("restart trusted process-local profiles before sync: %+v", profiles)
	}
	if err := restartedProfiles.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	restartedEngine := NewEngine(
		database, agent, restartedProfiles, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
		WithActiveProbeInterval(time.Minute),
	)
	if err := restartedEngine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 2 {
		t.Fatalf("restart hard plans=%v", enginePlanGenerations(agent.plans))
	}
	hard := agent.plans[1]
	if hard.Clients[0].BlockTCP ||
		hard.Clients[0].TCPOutbound != mappedReserve ||
		hard.Clients[0].TCPReserveOutbound != "" {
		t.Fatalf("restart did not promote exact mapped Tor reserve: %+v", hard.Clients[0])
	}
}

func TestEngineHardFailureRebuildsMappedTorFromCurrentLiveProfile(t *testing.T) {
	for _, test := range []struct {
		name     string
		newSlot  int
		newSocks string
	}{
		{name: "reslotted", newSlot: 2, newSocks: "127.0.0.1:19052"},
		{name: "socks address changed", newSlot: 1, newSocks: "127.0.0.1:29051"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_900_000_000, 0)
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
				{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
				{name: "tor-reserve", kind: sources.KindTorBridge, score: 90, tcp: true, failureDomain: "domain-b"},
			})
			qualifyEngineReserveCandidates(t, database, now, candidates)
			putEngineQoEClient(
				t, database, "alice", "10.44.0.2/32", now, false,
				candidates["primary"].ID, "",
			)
			torSlot := 1
			torSocks := "127.0.0.1:19051"
			profiles := profileProviderFunc(func() []torpool.Profile {
				return []torpool.Profile{{
					Slot: torSlot, CandidateID: candidates["tor-reserve"].ID,
					SocksAddr: torSocks, Role: "warm",
				}}
			})
			agent := &engineAgent{}
			engine := NewEngine(
				database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()),
				[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("9.9.9.9"),
				WithActiveProbeInterval(time.Minute),
			)
			if err := engine.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}
			initial := agent.plans[0]
			if initial.Clients[0].TCPReserveOutbound != torProfileOutboundID(
				candidates["tor-reserve"].ID,
				torpool.Profile{Slot: 1, SocksAddr: torSocks},
				"alice",
			) {
				t.Fatalf("initial Tor reserve=%+v", initial.Clients[0])
			}
			observation, err := database.ReserveCandidateObservation(
				ctx, candidates["primary"], store.ObservationActive,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
				ctx, candidates["primary"], observation, now.Add(time.Second),
			); err != nil || !commit.Accepted {
				t.Fatalf("hard failure commit=%+v err=%v", commit, err)
			}
			torSlot = test.newSlot
			torSocks = test.newSocks
			if err := engine.CycleForReason(
				ctx, now.Add(2*time.Second), PlacementHardFailure,
			); err != nil {
				t.Fatal(err)
			}
			if len(agent.plans) != 2 {
				t.Fatalf("hard plans=%v", enginePlanGenerations(agent.plans))
			}
			hard := agent.plans[1]
			wantHandler := torProfileOutboundID(
				candidates["tor-reserve"].ID,
				torpool.Profile{Slot: test.newSlot, SocksAddr: test.newSocks},
				"alice",
			)
			if hard.Clients[0].BlockTCP ||
				hard.Clients[0].TCPOutbound != wantHandler ||
				hard.Clients[0].DNSOutbound == "" ||
				hard.Clients[0].TCPReserveOutbound != "" {
				t.Fatalf("current live Tor profile was not rebuilt: want=%q route=%+v",
					wantHandler, hard.Clients[0])
			}
			if reflect.DeepEqual(initial.Outbounds, hard.Outbounds) {
				t.Fatalf("hard path did not materialize the current Tor profile")
			}
		})
	}
}

func TestEngineHardFailurePromotesOnlyAppliedMappedReserveWithoutColdAdd(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: false, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 70, tcp: true, udp: true, failureDomain: "domain-b"},
		{name: "cold", kind: sources.KindVLESS, score: 60, tcp: true, udp: true, failureDomain: "domain-c"},
		{name: "udp-primary", kind: sources.KindVLESS, score: 95, udp: true, failureDomain: "domain-d"},
		{name: "bob-primary", kind: sources.KindVLESS, score: 95, tcp: true, udp: true, failureDomain: "domain-e"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	setEngineActiveObservationAt(t, database, candidates["cold"], now.Add(-10*time.Minute))
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["udp-primary"].ID,
	)
	putEngineQoEClient(
		t, database, "bob", "10.44.0.3/32", now, false,
		candidates["bob-primary"].ID, candidates["bob-primary"].ID,
	)
	adapter := &recordingEngineAdapter{}
	reconciler, err := dataplane.NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent := &reconcilerEngineAgent{reconciler: reconciler}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("initial plans=%d", len(agent.plans))
	}
	initial := agent.plans[0]
	if rewritten, matches, err := rewritePlanDNS(initial, "9.9.9.9"); err != nil || !matches {
		t.Fatalf("fresh plan unexpectedly needs DNS rewrite: matches=%v err=%v\ninitial=%+v\nrewritten=%+v",
			matches, err, initial, rewritten)
	}
	initialAdds := append([]string(nil), adapter.adds...)
	initialDrains := append([]string(nil), adapter.drains...)
	initialRemoves := append([]string(nil), adapter.removes...)
	initialRouteReplacements := adapter.routeReplacements
	initialRoutes := make(map[string]dataplane.ClientRoute, len(initial.Clients))
	for _, route := range initial.Clients {
		initialRoutes[route.ClientID] = route
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["primary"].ID ||
		assignment.UDPOutbound != candidates["udp-primary"].ID {
		t.Fatalf("initial assignment=%+v", assignment)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	restarted := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	results := make(chan error, 2)
	for attempt := 0; attempt < 2; attempt++ {
		go func() {
			results <- restarted.CycleForReason(
				ctx, now.Add(2*time.Second), PlacementHardFailure,
			)
		}()
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(agent.plans) != 2 {
		t.Fatalf("hard plans=%d", len(agent.plans))
	}
	hard := agent.plans[1]
	if len(adapter.adds) != len(initialAdds) {
		t.Fatalf("hard failover performed cold AddOutbound: before=%v after=%v", initialAdds, adapter.adds)
	}
	if !reflect.DeepEqual(adapter.drains, initialDrains) ||
		!reflect.DeepEqual(adapter.removes, initialRemoves) {
		t.Fatalf("hard failover changed outbounds: drains=%v removes=%v",
			adapter.drains, adapter.removes)
	}
	if adapter.routeReplacements != initialRouteReplacements+1 {
		t.Fatalf("route replacements=%d want=%d", adapter.routeReplacements, initialRouteReplacements+1)
	}
	if !reflect.DeepEqual(initial.Outbounds, hard.Outbounds) {
		t.Fatalf("hard generation changed outbounds:\ninitial=%+v\nhard=%+v",
			initial.Outbounds, hard.Outbounds)
	}
	hardRoutes := make(map[string]dataplane.ClientRoute, len(hard.Clients))
	for _, route := range hard.Clients {
		hardRoutes[route.ClientID] = route
	}
	initialRoute, hardRoute := initialRoutes["alice"], hardRoutes["alice"]
	if hardRoute.TCPOutbound != initialRoute.TCPReserveOutbound ||
		hardRoute.TCPReserveOutbound != "" || hardRoute.BlockTCP ||
		hardRoute.UDPOutbound != initialRoute.UDPOutbound ||
		hardRoute.UDPReserveOutbound != initialRoute.UDPReserveOutbound ||
		hardRoute.BlockUDP != initialRoute.BlockUDP {
		t.Fatalf("hard route did not promote only failed TCP: before=%+v after=%+v", initialRoute, hardRoute)
	}
	if hardRoutes["bob"] != initialRoutes["bob"] {
		t.Fatalf("healthy client route changed: before=%+v after=%+v", initialRoutes["bob"], hardRoutes["bob"])
	}
	target, _ := engineDNSConfig(t, engineOutboundByID(t, hard, hardRoute.DNSOutbound).Config)
	if target != hardRoute.TCPOutbound {
		t.Fatalf("promoted DNS target=%q route=%+v", target, hardRoute)
	}
	assignment = engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidateIDFromHandler(initialRoute.TCPReserveOutbound, "alice") ||
		assignment.UDPOutbound != candidates["udp-primary"].ID {
		t.Fatalf("hard assignment=%+v", assignment)
	}
	if reserve, ok, err := database.AppliedReserveForFailure(
		ctx, "alice", store.RouteTransportTCP, assignment.TCPOutbound,
	); err != nil || ok || reserve != "" {
		t.Fatalf("critical generation unexpectedly replenished reserve=%q ok=%v err=%v", reserve, ok, err)
	}
}

func TestEngineHardFailureUsesFreshDynamicFallbackWhenMappedReserveIsStale(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "mapped", kind: sources.KindVLESS, score: 70, tcp: true, failureDomain: "domain-b"},
		{name: "alternative", kind: sources.KindVLESS, score: 60, tcp: true, failureDomain: "domain-c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	adapter := &recordingEngineAdapter{}
	reconciler, err := dataplane.NewReconciler(
		adapter, filepath.Join(t.TempDir(), "applied.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	agent := &reconcilerEngineAgent{reconciler: reconciler}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	initial := agent.plans[0]
	initialRoute := initial.Clients[0]
	mappedCandidateID := candidateIDFromHandler(
		initialRoute.TCPReserveOutbound, "alice",
	)
	if mappedCandidateID == "" {
		t.Fatalf("initial route has no mapped reserve: %+v", initialRoute)
	}
	setEngineActiveObservationAt(
		t, database, engineCandidateByID(t, candidates, mappedCandidateID),
		now.Add(-10*time.Minute),
	)
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	addsBefore := len(adapter.adds)
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 2 || len(adapter.adds) <= addsBefore {
		t.Fatalf("hard fallback plans=%d adds_before=%d adds_after=%d",
			len(agent.plans), addsBefore, len(adapter.adds))
	}
	hard := agent.plans[1]
	hardRoute := hard.Clients[0]
	if hardRoute.BlockTCP || hardRoute.TCPOutbound == "" ||
		hardRoute.DNSOutbound == "" || hardRoute.TCPReserveOutbound != "" {
		t.Fatalf("dynamic fallback was not published: %+v", hardRoute)
	}
	fallbackID := candidateIDFromHandler(hardRoute.TCPOutbound, "alice")
	if fallbackID == "" || fallbackID == candidates["primary"].ID ||
		fallbackID == mappedCandidateID {
		t.Fatalf("fallback=%q primary=%q stale_mapped=%q route=%+v",
			fallbackID, candidates["primary"].ID, mappedCandidateID, hardRoute)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != fallbackID {
		t.Fatalf("dynamic fallback assignment=%+v want=%q", assignment, fallbackID)
	}
}

func TestHardFailureEmergencyCandidatesRetainFailedRouteContext(t *testing.T) {
	failed := scheduler.Candidate{
		ID: "failed", FailureDomain: "domain-a", TCPQualified: true,
	}
	working := scheduler.Candidate{
		ID: "working", FailureDomain: "domain-b", TCPQualified: true,
	}
	snapshot := routeCandidateSnapshot{
		allByID: map[string]scheduler.Candidate{
			failed.ID:  failed,
			working.ID: working,
		},
		placementCandidates: []scheduler.Candidate{working},
	}

	candidates := hardFailureEmergencyCandidates("failed", snapshot)
	if len(candidates) != 2 || candidates[0].ID != "working" ||
		candidates[1].ID != "failed" {
		t.Fatalf("emergency candidates=%+v", candidates)
	}
}

func TestEngineHardFailureUsesClientScopedReserveDNSForSharedVLESSTarget(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 10, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	for index, clientID := range []string{"alice", "bob"} {
		putEngineQoEClient(
			t, database, clientID, fmt.Sprintf("10.44.0.%d/32", index+2),
			now, false, candidates["primary"].ID, "",
		)
	}
	adapter := &recordingEngineAdapter{}
	reconciler, err := dataplane.NewReconciler(
		adapter, filepath.Join(t.TempDir(), "applied.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	agent := &reconcilerEngineAgent{reconciler: reconciler}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	initial := agent.plans[0]
	initialRoutes := make(map[string]dataplane.ClientRoute, len(initial.Clients))
	expectedDNS := make(map[string]string, len(initial.Clients))
	for _, route := range initial.Clients {
		initialRoutes[route.ClientID] = route
		if route.TCPReserveOutbound != candidates["reserve"].ID {
			t.Fatalf("%s reserve=%q want shared %q", route.ClientID, route.TCPReserveOutbound, candidates["reserve"].ID)
		}
		expectedDNS[route.ClientID] = engineDNSHandlerForClientTarget(
			t, initial, route.ClientID, route.TCPReserveOutbound,
		)
	}
	if expectedDNS["alice"] == expectedDNS["bob"] {
		t.Fatalf("client-scoped reserve DNS collided: %v", expectedDNS)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	hardRoutes := make(map[string]dataplane.ClientRoute)
	for _, route := range agent.plans[1].Clients {
		hardRoutes[route.ClientID] = route
	}
	for _, clientID := range []string{"alice", "bob"} {
		if hardRoutes[clientID].TCPOutbound != candidates["reserve"].ID ||
			hardRoutes[clientID].DNSOutbound != expectedDNS[clientID] {
			t.Fatalf("%s hard route=%+v expected DNS=%q",
				clientID, hardRoutes[clientID], expectedDNS[clientID])
		}
	}
}

func TestEngineHardSignalIgnoresOldCurrentNegativeActiveOutcome(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 10, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	before := engineQoEAssignment(t, database, "alice")
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := database.CommitCandidateActiveObservation(
		ctx, candidates["primary"], reservation, false, now.Add(-10*time.Minute),
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("old active outcome commit=%+v err=%v", commit, err)
	}
	if err := engine.CycleForReason(
		ctx, now.Add(time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	after := engineQoEAssignment(t, database, "alice")
	if len(agent.plans) != 1 || after != before {
		t.Fatalf("old active failure reacted to unrelated hard signal: plans=%d before=%+v after=%+v",
			len(agent.plans), before, after)
	}
}

func TestEnginePartialActiveDegradationNeverBecomesPersistedHardFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, "",
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := database.CommitCandidateActiveOutcome(
		ctx, candidates["primary"], reservation,
		store.ActiveObservationOutcome{Available: true, ProofSuccess: false},
		now.Add(time.Second),
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("partial active commit=%+v err=%v", commit, err)
	}
	if hard, err := engine.HasFreshAssignedHardFailure(ctx, now.Add(2*time.Second)); err != nil || hard {
		t.Fatalf("partial degradation startup hard=%v err=%v", hard, err)
	}
	before := engineQoEAssignment(t, database, "alice")
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementHardFailure,
	); err != nil {
		t.Fatal(err)
	}
	after := engineQoEAssignment(t, database, "alice")
	if len(agent.plans) != 1 || after != before {
		t.Fatalf("partial degradation moved on unrelated hard event: plans=%d before=%+v after=%+v",
			len(agent.plans), before, after)
	}
}

func TestEngineKeepsAssignedDrainingCandidateUntilReplacementIsUsable(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "assigned", kind: sources.KindVLESS, score: 90, tcp: true, udp: true},
		{name: "replacement", kind: sources.KindVLESS, score: 80},
	})
	assigned := candidates["assigned"]
	replacement := candidates["replacement"]
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		assigned.ID, assigned.ID,
	)
	if err := database.ReplaceCandidates(
		ctx,
		assigned.SourceID,
		[]store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "replacement",
			Fingerprint: "replacement",
			Payload:     "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls",
		}},
		15*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 {
		t.Fatalf("plans=%+v", agent.plans)
	}
	route := agent.plans[0].Clients[0]
	if route.TCPOutbound != assigned.ID || route.UDPOutbound != assigned.ID ||
		route.TCPOutbound == replacement.ID {
		t.Fatalf("draining assignment was not preserved: %+v", route)
	}
}

func TestEngineRetriesWhenInventoryChangesBeforeDesiredPlanPersistence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *store.Store, map[string]store.Candidate)
	}{
		{
			name: "selected candidate drains",
			mutate: func(
				t *testing.T,
				database *store.Store,
				candidates map[string]store.Candidate,
			) {
				selected := candidates["selected"]
				if err := database.ReplaceCandidates(
					context.Background(),
					selected.SourceID,
					[]store.CandidateInput{{
						Kind: sources.KindVLESS, Label: "replacement",
						Fingerprint: "replacement",
						Payload:     "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls",
					}},
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "selected source disables",
			mutate: func(
				t *testing.T,
				database *store.Store,
				candidates map[string]store.Candidate,
			) {
				selected := candidates["selected"]
				if err := database.UpdateSource(
					context.Background(),
					selected.SourceID,
					"disabled",
					false,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_800_000_000, 0)
			database, candidates := newEngineQoEFixture(
				t,
				now,
				[]engineQoECandidateSpec{
					{
						name: "selected", kind: sources.KindVLESS,
						score: 100, tcp: true, udp: true,
					},
					{
						name: "replacement", kind: sources.KindVLESS,
						score: 90, tcp: true, udp: true,
					},
				},
			)
			putEngineQoEClient(
				t, database, "alice", "10.44.0.2/32", now, true, "", "",
			)
			var once sync.Once
			agent := &engineAgent{}
			engine := NewEngine(
				database, agent, nil,
				scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
			)
			engine.beforeDesiredPlanSave = func() {
				once.Do(func() { test.mutate(t, database, candidates) })
			}
			if err := engine.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}
			state, err := database.LoadPlanState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(
				state.DesiredPlan,
				[]byte(candidates["selected"].ID),
			) {
				t.Fatalf("stale selected route persisted: %s", state.DesiredPlan)
			}
			assignment := engineQoEAssignment(t, database, "alice")
			if assignment.TCPOutbound == candidates["selected"].ID ||
				assignment.UDPOutbound == candidates["selected"].ID {
				t.Fatalf("stale selected assignment persisted: %+v", assignment)
			}
			if len(agent.plans) != 1 {
				t.Fatalf("stale attempt reached agent: plans=%+v", agent.plans)
			}
		})
	}
}

func TestEngineInventoryRetriesDoNotManufactureSchedulerSnapshots(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(
		t,
		now,
		[]engineQoECandidateSpec{
			{
				name: "old", kind: sources.KindVLESS,
				score: 60, tcp: true,
			},
			{
				name: "better", kind: sources.KindVLESS,
				score: 100, tcp: true,
			},
		},
	)
	policy := scheduler.PolicyDefaults()
	policy.RequiredSnapshots = 3
	clientID := ""
	probePolicy := policy
	probePolicy.RequiredSnapshots = 1
	for index := 0; index < 1000; index++ {
		candidateClientID := fmt.Sprintf("streak-client-%d", index)
		result := scheduler.New(probePolicy).Schedule(
			now,
			[]scheduler.Client{{
				ID: candidateClientID, LastTraffic: now,
				Assignment: scheduler.Assignment{
					TCP:      candidates["old"].ID,
					TCPSince: now.Add(-time.Hour),
				},
			}},
			[]scheduler.Candidate{
				{
					ID: candidates["old"].ID, Protocol: scheduler.ProtocolVLESS,
					Score: 60, TCPQualified: true,
				},
				{
					ID: candidates["better"].ID, Protocol: scheduler.ProtocolVLESS,
					Score: 100, TCPQualified: true,
				},
			},
		)
		if result.Assignments[candidateClientID].TCP ==
			candidates["better"].ID {
			clientID = candidateClientID
			break
		}
	}
	if clientID == "" {
		t.Fatal("could not find deterministic client preferring better route")
	}
	putEngineQoEClient(
		t, database, clientID, "10.44.0.2/32", now, true,
		candidates["old"].ID, "",
	)
	placement := scheduler.New(policy)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, placement, []byte("secret"),
	)
	attempt := 0
	engine.beforeDesiredPlanSave = func() {
		attempt++
		if attempt > 2 {
			return
		}
		if err := database.ReplaceCandidates(
			ctx,
			candidates["old"].SourceID,
			[]store.CandidateInput{
				{
					Kind: sources.KindVLESS, Label: "old",
					Fingerprint: "old",
					Payload:     "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls",
				},
				{
					Kind: sources.KindVLESS, Label: "better",
					Fingerprint: "better",
					Payload:     "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls",
				},
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	assignment := engineQoEAssignment(t, database, clientID)
	if assignment.TCPOutbound != candidates["old"].ID {
		t.Fatalf("inventory retries manufactured three scheduler snapshots: %+v",
			assignment)
	}
	if attempt != 2 {
		t.Fatalf("attempts=%d want 2 (second equivalent stale refresh is unrelated)", attempt)
	}
}

func TestEngineDoesNotPublishWhenSchedulerPreviewCASConflicts(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, _ := newEngineQoEFixture(
		t, now, []engineQoECandidateSpec{{
			name: "selected", kind: sources.KindVLESS,
			score: 100, tcp: true, udp: true,
		}},
	)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, "", "")
	placement := scheduler.New(scheduler.PolicyDefaults())
	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, placement, []byte("secret"))
	attempts := 0
	engine.beforeDesiredPlanSave = func() {
		attempts++
		placement.Exclude(
			"alice", fmt.Sprintf("concurrent-%d", attempts), now.Add(time.Hour),
		)
	}
	err := engine.Cycle(ctx, now)
	if !errors.Is(err, scheduler.ErrPreviewChanged) {
		t.Fatalf("Cycle error=%v want scheduler preview conflict", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if attempts != 3 || state.DesiredGeneration != 0 || len(agent.plans) != 0 {
		t.Fatalf("attempts=%d desired=%d agent_plans=%d",
			attempts, state.DesiredGeneration, len(agent.plans))
	}
}

func TestEngineFailedDesiredPublishDoesNotCommitSchedulerPreview(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "old", kind: sources.KindVLESS, score: 60, tcp: true},
		{name: "better", kind: sources.KindVLESS, score: 100, tcp: true},
	})
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		candidates["old"].ID, "",
	)
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: candidates["old"].ID,
		TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	policy := scheduler.PolicyDefaults()
	policy.RequiredSnapshots = 2
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(policy), []byte("secret"),
		WithQoEEnabled(false),
	)
	cycleCtx, cancelCycle := context.WithCancel(ctx)
	var cancel sync.Once
	engine.afterSchedulerPreviewPrepare = func() {
		cancel.Do(cancelCycle)
	}
	if err := engine.Cycle(cycleCtx, now); err == nil {
		t.Fatal("forced desired publish failure returned success")
	}
	state, err := database.LoadPlanState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 0 || len(agent.plans) != 0 {
		t.Fatalf("failed desired publish leaked state: desired=%d plans=%d",
			state.DesiredGeneration, len(agent.plans))
	}
	engine.afterSchedulerPreviewPrepare = nil
	if err := engine.Cycle(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["old"].ID {
		t.Fatalf("failed publish manufactured hysteresis streak: %+v", assignment)
	}
	if err := engine.Cycle(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["better"].ID {
		t.Fatalf("second durable scheduler snapshot did not move: %+v", assignment)
	}
}

func TestEngineSameSemanticEvidenceChangeCannotCommitSchedulerPreview(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "applied"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_800_000_000, 0)
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
				{name: "old", kind: sources.KindVLESS, score: 60, tcp: true},
				{name: "better", kind: sources.KindVLESS, score: 100, tcp: true},
			})
			putEngineQoEClient(
				t, database, "alice", "10.44.0.2/32", now, true,
				candidates["old"].ID, "",
			)
			if err := database.SetAssignment(ctx, store.AssignmentRecord{
				ClientID: "alice", TCPOutbound: candidates["old"].ID,
				TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			policy := scheduler.PolicyDefaults()
			policy.RequiredSnapshots = 3
			agent := &engineAgent{}
			if pending {
				agent.applyErr = errors.New("initial apply failed")
			}
			engine := NewEngine(
				database, agent, nil, scheduler.New(policy), []byte("secret"),
				WithQoEEnabled(false),
			)
			initialErr := engine.Cycle(ctx, now)
			if pending {
				if initialErr == nil {
					t.Fatal("initial cycle did not leave pending desired plan")
				}
				agent.applyErr = nil
			} else if initialErr != nil {
				t.Fatal(initialErr)
			}
			mutations := 0
			engine.beforeSameSemanticCommit = func() {
				mutations++
				if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
					CandidateID:  candidates["old"].ID,
					Score:        60 + float64(mutations),
					TCPQualified: true, Available: true,
					UpdatedAt: now.Add(time.Duration(mutations) * time.Second),
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := engine.Cycle(ctx, now.Add(time.Minute))
			if !errors.Is(err, store.ErrCandidateEvidenceChanged) {
				t.Fatalf("same-semantic evidence race error=%v", err)
			}
			if mutations != 3 {
				t.Fatalf("same-semantic mutation attempts=%d want=3", mutations)
			}
			engine.beforeSameSemanticCommit = nil
			if err := database.RecordActivity(ctx, "alice", now.Add(2*time.Minute), 2, 2); err != nil {
				t.Fatal(err)
			}
			if err := engine.Cycle(ctx, now.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["old"].ID {
				t.Fatalf("failed evidence validation committed streak: %+v", assignment)
			}
			if err := database.RecordActivity(ctx, "alice", now.Add(3*time.Minute), 3, 3); err != nil {
				t.Fatal(err)
			}
			if err := engine.Cycle(ctx, now.Add(3*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["better"].ID {
				t.Fatalf("third durable snapshot did not move: %+v", assignment)
			}
		})
	}
}

func TestEngineSchedulerCommitLockIsReleasedBeforeDataplaneApply(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, _ := newEngineQoEFixture(t, now, []engineQoECandidateSpec{{
		name: "selected", kind: sources.KindVLESS, score: 100, tcp: true,
	}})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, "", "")
	placement := scheduler.New(scheduler.PolicyDefaults())
	agent := &engineAgent{
		applyStarted: make(chan struct{}), releaseApply: make(chan struct{}),
	}
	engine := NewEngine(database, agent, nil, placement, []byte("secret"))
	done := make(chan error, 1)
	go func() { done <- engine.Cycle(ctx, now) }()
	select {
	case <-agent.applyStarted:
	case <-time.After(time.Second):
		t.Fatal("dataplane Apply did not start")
	}
	excluded := make(chan struct{})
	go func() {
		placement.Exclude("alice", "concurrent", now.Add(time.Hour))
		close(excluded)
	}()
	select {
	case <-excluded:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("scheduler owner mutex remained held over dataplane Apply")
	}
	close(agent.releaseApply)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEngineTorPlanFailsTemporaryWithoutPublishWhileMutationIsInFlight(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{{
		name: "tor", kind: sources.KindTorBridge, score: 100, tcp: true,
	}})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, "", "")
	remote := &blockingTorProfileRemote{
		profiles: []torpool.Profile{{
			Slot: 0, Role: "warm", CandidateID: candidates["tor"].ID,
			SocksAddr: "127.0.0.1:19050",
		}},
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	mutationDone := make(chan error, 1)
	go func() { _, err := coordinator.ExploreNext(ctx); mutationDone <- err }()
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("Tor mutation did not reach remote")
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, coordinator, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	err := engine.Cycle(ctx, now)
	if !errors.Is(err, store.ErrCandidateEvidenceChanged) {
		t.Fatalf("Tor in-flight Cycle error=%v want temporary evidence conflict", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.DesiredGeneration != 0 || len(agent.plans) != 0 {
		t.Fatalf("unstable Tor plan published: desired=%d plans=%d",
			state.DesiredGeneration, len(agent.plans))
	}
	close(remote.release)
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
}

func TestEngineDoesNotPublishWhenReferencedRoutingEvidenceKeepsChanging(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(
		t, now, []engineQoECandidateSpec{{
			name: "selected", kind: sources.KindVLESS,
			score: 100, tcp: true, udp: true,
		}},
	)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, "", "")
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	attempts := 0
	engine.beforeDesiredPlanSave = func() {
		attempts++
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID:  candidates["selected"].ID,
			Score:        100 + float64(attempts),
			TCPQualified: true, UDPQualified: true, Available: true,
			UpdatedAt: now.Add(time.Duration(attempts) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	err := engine.Cycle(ctx, now)
	if !errors.Is(err, store.ErrCandidateEvidenceChanged) {
		t.Fatalf("Cycle error=%v want evidence conflict", err)
	}
	state, loadErr := database.LoadPlanState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if attempts != 3 || state.DesiredGeneration != 0 || len(agent.plans) != 0 {
		t.Fatalf("attempts=%d desired=%d agent_plans=%d",
			attempts, state.DesiredGeneration, len(agent.plans))
	}
}

func TestEnginePlacementCommitsDuringMonotonicActiveProofRefresh(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(
		t, now, []engineQoECandidateSpec{{
			name: "selected", kind: sources.KindVLESS,
			score: 100, tcp: true, udp: true,
		}},
	)
	selected := candidates["selected"]
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true, "", "",
	)
	seed, err := database.ReserveCandidateObservation(
		ctx, selected, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := database.CommitCandidateActiveOutcome(
		ctx, selected, seed, store.ActiveObservationOutcome{
			Available: true, ProofSuccess: true,
		}, now,
	); err != nil || !commit.Accepted {
		t.Fatalf("seed active proof=%+v err=%v", commit, err)
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
		WithActiveProofFreshness(15*time.Second),
	)
	attempts := 0
	engine.beforeDesiredPlanSave = func() {
		attempts++
		reservation, err := database.ReserveCandidateObservation(
			ctx, selected, store.ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := database.CommitCandidateActiveOutcome(
			ctx, selected, reservation, store.ActiveObservationOutcome{
				Available: true, ProofSuccess: true,
			}, now.Add(time.Duration(attempts)*time.Second),
		)
		if err != nil || !commit.Accepted {
			t.Fatalf("refresh attempt %d commit=%+v err=%v", attempts, commit, err)
		}
	}
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatalf("monotonic active proof refresh blocked cycle: %v", err)
	}
	if attempts != 1 || len(agent.plans) != 1 {
		t.Fatalf("refresh attempts=%d applied plans=%d", attempts, len(agent.plans))
	}
}

func TestEngineVLESSHardFailureApplyDoesNotWaitForBlockedTorMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, failureDomain: "domain-b"},
		{name: "unrelated-tor", kind: sources.KindTorBridge, score: 80, tcp: true, failureDomain: "domain-c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		candidates["primary"].ID, "",
	)
	putEngineQoEClient(
		t, database, "bob", "10.44.0.3/32", now, true,
		candidates["unrelated-tor"].ID, "",
	)
	remote := &blockingTorProfileRemote{
		profiles: []torpool.Profile{{
			Slot: 0, Role: "warm", CandidateID: candidates["unrelated-tor"].ID,
			SocksAddr: "127.0.0.1:19050",
		}},
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, coordinator, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithDNSResolver("9.9.9.9"), WithActiveProbeInterval(time.Minute),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidates["primary"], store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, candidates["primary"], reservation, now.Add(time.Second),
	); err != nil || !commit.Accepted {
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	mutationDone := make(chan error, 1)
	go func() { _, err := coordinator.ExploreNext(ctx); mutationDone <- err }()
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("Tor mutation did not block in remote")
	}
	agent.applyStarted = make(chan struct{})
	hardDone := make(chan error, 1)
	go func() {
		hardDone <- engine.CycleForReason(
			ctx, now.Add(2*time.Second), PlacementHardFailure,
		)
	}()
	select {
	case <-agent.applyStarted:
	case <-time.After(1900 * time.Millisecond):
		t.Fatal("VLESS hard Apply waited behind blocked Tor mutation")
	}
	select {
	case err := <-hardDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("VLESS hard cycle did not complete")
	}
	close(remote.release)
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
}

func TestEngineMovesAssignmentOffRetiringTorBeforeProfileRelease(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput(
		"tor-bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	)
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{
		{
			Kind: sources.KindTorBridge, Label: "retiring", Fingerprint: "retiring",
			Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			Kind: sources.KindTorBridge, Label: "replacement", Fingerprint: "replacement",
			Payload: "Bridge 192.0.2.2:443 1123456789ABCDEF0123456789ABCDEF01234567",
		},
	}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, listed[0].ID)
	ids := make(map[string]string, len(candidates))
	now := time.Unix(1_800_000_000, 0)
	for _, candidate := range candidates {
		ids[candidate.Fingerprint] = candidate.ID
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: 100,
			TCPQualified: true, Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer-a",
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: ids["retiring"],
		TCPSince: now.Add(-time.Minute), UDPSince: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{
			{
				Slot: 0, CandidateID: ids["retiring"],
				SocksAddr: "127.0.0.1:19050", Role: "warm", Retiring: true,
			},
			{
				Slot: 1, CandidateID: ids["replacement"],
				SocksAddr: "127.0.0.1:19051", Role: "warm",
			},
		}
	})
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	agent := &engineAgent{applyStarted: applyStarted, releaseApply: releaseApply}
	engine := NewEngine(
		database, agent, profiles,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	done := make(chan error, 1)
	go func() {
		done <- engine.Cycle(ctx, now)
	}()
	select {
	case <-applyStarted:
	case <-time.After(time.Second):
		t.Fatal("dataplane apply did not start")
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != ids["retiring"] {
		t.Fatalf("replacement published before dataplane apply: %+v", assignments)
	}
	close(releaseApply)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assignments, err = database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != ids["replacement"] {
		t.Fatalf("assignments=%+v", assignments)
	}
	if len(agent.plans) != 1 ||
		!strings.Contains(agent.plans[0].Clients[0].TCPOutbound, ids["replacement"]) {
		t.Fatalf("plans=%+v", agent.plans)
	}
}

func TestEngineClearsPausedAssignmentOnlyAfterRouteRemovalApplies(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "paused", Name: "Paused", Address: "10.44.0.2/32",
		PublicKey: "peer-a", Paused: true,
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "paused", TCPOutbound: "old-tor",
		TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	agent := &engineAgent{applyStarted: applyStarted, releaseApply: releaseApply}
	engine := NewEngine(
		database, agent, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	done := make(chan error, 1)
	go func() {
		done <- engine.Cycle(ctx, now)
	}()
	select {
	case <-applyStarted:
	case err := <-done:
		if err != nil {
			t.Fatalf("cycle failed before dataplane apply: %v", err)
		}
		t.Fatal("cycle completed without dataplane apply")
	}
	assignments, err := database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != "old-tor" {
		t.Fatalf("paused assignment cleared before route removal: %+v", assignments)
	}
	close(releaseApply)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assignments, err = database.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 ||
		assignments[0].TCPOutbound != "" ||
		assignments[0].UDPOutbound != "" {
		t.Fatalf("paused assignment survived route removal: %+v", assignments)
	}
}

func TestEnginePersistsEmptyAssignmentWhenFailClosed(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	_ = database.PutClient(ctx, store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer-a"}, "private config")
	_ = database.SetAssignment(ctx, store.AssignmentRecord{ClientID: "alice", TCPOutbound: "stale", UDPOutbound: "stale", TCPSince: now, UDPSince: now})
	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	assignments, _ := database.ListAssignments(ctx)
	if len(assignments) != 1 || assignments[0].TCPOutbound != "" || assignments[0].UDPOutbound != "" {
		t.Fatalf("assignments=%+v", assignments)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 ||
		!agent.plans[0].Clients[0].BlockTCP || !agent.plans[0].Clients[0].BlockUDP {
		t.Fatalf("plans=%+v", agent.plans)
	}
}

func TestEngineActiveCriticalCapacityRejectsEmptyPlanBeforePublish(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer-a",
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: "safe-old", UDPOutbound: "safe-old",
		TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithActiveCriticalRouteLimit(16),
	)
	err = engine.Cycle(ctx, now)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) || !coverageErr.SearchExhausted {
		t.Fatalf("Cycle error=%v", err)
	}
	assignments, loadErr := database.ListAssignments(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(assignments) != 1 || assignments[0].TCPOutbound != "safe-old" ||
		assignments[0].UDPOutbound != "safe-old" || len(agent.plans) != 0 {
		t.Fatalf("coverage loss mutated safe state assignments=%+v plans=%d",
			assignments, len(agent.plans))
	}
}

func TestEngineQoEFailoverProceedsWithoutCompleteReserveCoverage(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "broken", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "replacement", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineCandidateSet(t, database, now, []store.Candidate{
		candidates["broken"], candidates["replacement"],
	})
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		candidates["broken"].ID, candidates["broken"].ID,
	)
	for index := 2; index >= 0; index-- {
		state, _, err := database.RecordCandidateQoE(
			ctx, candidates["broken"], qoe.Observation{
				At:        now.Add(-time.Duration(index) * time.Second),
				ErrorCode: qoe.ReasonRouteTimeout,
			}, qoe.DefaultPolicy(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 && state.Status != qoe.StatusDegraded {
			t.Fatalf("broken status=%s", state.Status)
		}
	}
	seedEngineQoEState(
		t, database, candidates["replacement"], qoe.StatusHealthy, 2*time.Second, now,
	)
	setEngineActiveObservationAt(t, database, candidates["replacement"], now)

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.CycleForReason(ctx, now, PlacementQoEDegraded); err != nil {
		t.Fatalf("QoE failover was blocked by reserve coverage: %v", err)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["replacement"].ID ||
		assignment.UDPOutbound != candidates["replacement"].ID {
		t.Fatalf("assignment=%+v want replacement", assignment)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("applied plans=%d want 1", len(agent.plans))
	}
}

func TestDegradedQualityDoesNotBypassIncompleteReserveCoverage(t *testing.T) {
	clients := []scheduler.Client{{
		ID: "alice",
		Assignment: scheduler.Assignment{
			TCP: "slow",
		},
	}}
	candidates := []scheduler.Candidate{
		{
			ID: "slow", TCPQualified: true, QoEStatus: qoe.StatusDegraded,
			QoEReason: "qoe_throughput",
		},
		{
			ID: "fast", TCPQualified: true, QoEStatus: qoe.StatusHealthy,
			QoEFresh: true, QoEEffective: time.Second,
		},
	}
	if canRecoverDegradedAssignedTransport(clients, candidates) {
		t.Fatal("ordinary quality degradation bypassed incomplete reserve coverage")
	}
}

func TestEngineCapacityReadyTracksCurrentReserveProofWithoutPublishing(t *testing.T) {
	database, candidates, now := newEngineActiveCriticalLimitFixture(t, 2)
	putEngineActiveCriticalLimitClients(t, database, candidates, now)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	ctx := context.Background()
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.CapacityReady(ctx, now.Add(time.Second)); err != nil {
		t.Fatalf("fresh applied capacity=%v", err)
	}
	broken := candidates["route-01"]
	observation, err := database.ReserveCandidateObservation(
		ctx, broken, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, commitErr := database.CommitCandidateActiveHardFailureObservation(
		ctx, broken, observation, now.Add(2*time.Second),
	); commitErr != nil || !commit.Accepted {
		t.Fatalf("hard observation commit=%+v error=%v", commit, commitErr)
	}
	err = engine.CapacityReady(ctx, now.Add(2*time.Second))
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) || len(agent.plans) != 1 {
		t.Fatalf("stale reserve readiness=%v plans=%d", err, len(agent.plans))
	}
}

func TestEngineCapacityReadyUsesSharedReserveQoEAndClientExclusions(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*testing.T, *Engine, *store.Store, store.Candidate, time.Time)
		wantReady bool
	}{
		{name: "eligible", wantReady: true},
		{name: "qoe degraded", mutate: func(
			t *testing.T, _ *Engine, database *store.Store, reserve store.Candidate, now time.Time,
		) {
			seedEngineQoEState(t, database, reserve, qoe.StatusDegraded, 4*time.Second, now)
		}},
		{name: "client excluded", mutate: func(
			_ *testing.T, engine *Engine, _ *store.Store, reserve store.Candidate, now time.Time,
		) {
			engine.scheduler.Exclude("client-00", reserve.ID, now.Add(time.Hour))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, candidates, now := newEngineActiveCriticalLimitFixture(t, 2)
			putEngineActiveCriticalLimitClients(t, database, candidates, now)
			agent := &engineAgent{}
			engine := NewEngine(
				database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
				WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
			)
			ctx := context.Background()
			if err := engine.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}
			if len(agent.plans) != 1 || len(agent.plans[0].Clients) == 0 {
				t.Fatalf("plans=%v", agent.plans)
			}
			var clientRoute dataplane.ClientRoute
			for _, route := range agent.plans[0].Clients {
				if route.ClientID == "client-00" {
					clientRoute = route
					break
				}
			}
			reserveID := candidateIDFromHandler(clientRoute.TCPReserveOutbound, "client-00")
			reserve := engineCandidateByID(t, candidates, reserveID)
			if test.mutate != nil {
				test.mutate(t, engine, database, reserve, now.Add(time.Second))
			}
			err := engine.CapacityReady(ctx, now.Add(2*time.Second))
			if test.wantReady && err != nil {
				t.Fatalf("eligible capacity=%v", err)
			}
			if !test.wantReady {
				var coverageErr *ActiveCriticalCoveragePlanError
				if !errors.As(err, &coverageErr) {
					t.Fatalf("invalid reserve readiness=%v", err)
				}
			}
		})
	}
}

func TestEngineCapacityReadyKeepsAdmissibleAppliedReserveAcrossWinnerChurn(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-primary"},
		{name: "applied-reserve", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-applied"},
		{name: "new-winner", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-new"},
	})
	initial := []store.Candidate{candidates["primary"], candidates["applied-reserve"]}
	full := append(append([]store.Candidate(nil), initial...), candidates["new-winner"])
	clientID := engineReserveWinnerChurnClientID(t, candidates["primary"], initial, full)
	qualifyEngineCandidateSet(t, database, now, initial)
	putEngineQoEClient(
		t, database, clientID, "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithActiveProbeInterval(300*time.Millisecond),
		WithActiveProofFreshness(5*time.Second),
		WithActiveFailureFreshness(1975*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 {
		t.Fatalf("applied plans=%+v", agent.plans)
	}
	applied := agent.plans[0].Clients[0]
	appliedReserve := candidateIDFromHandler(applied.TCPReserveOutbound, clientID)
	if appliedReserve != candidates["applied-reserve"].ID {
		t.Fatalf("applied reserve=%q want=%q", appliedReserve, candidates["applied-reserve"].ID)
	}

	qualifyEngineCandidateSet(t, database, now.Add(time.Second), full)
	checkAt := now.Add(2 * time.Second)
	snapshot, err := engine.loadRouteCandidateSnapshot(ctx, checkAt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := engine.scheduler.ReadView().SelectReserves(
		checkAt, clientID,
		scheduler.Assignment{TCP: candidates["primary"].ID, UDP: candidates["primary"].ID},
		snapshot.placementCandidates,
	)
	if selected.TCP != candidates["new-winner"].ID || selected.TCP == appliedReserve {
		t.Fatalf("current reserve=%q applied=%q new=%q",
			selected.TCP, appliedReserve, candidates["new-winner"].ID)
	}
	if err := engine.CapacityReady(ctx, checkAt); err != nil {
		t.Fatalf("admissible applied reserve rejected after winner churn: %v", err)
	}
	if err := engine.Cycle(ctx, checkAt); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("admissible applied reserve was republished after winner churn: plans=%d", len(agent.plans))
	}
}

func TestEngineCapacityReadyRejectsAppliedReserveBelowFullUniverseQualityTier(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-primary"},
		{name: "applied-reserve", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-applied"},
		{name: "much-better", kind: sources.KindVLESS, score: 200, tcp: true, udp: true, failureDomain: "domain-better"},
	})
	initial := []store.Candidate{candidates["primary"], candidates["applied-reserve"]}
	full := append(append([]store.Candidate(nil), initial...), candidates["much-better"])
	qualifyEngineCandidateSet(t, database, now, initial)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithActiveProbeInterval(300*time.Millisecond),
		WithActiveProofFreshness(5*time.Second),
		WithActiveFailureFreshness(1975*time.Millisecond),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 {
		t.Fatalf("applied plans=%+v", agent.plans)
	}
	applied := agent.plans[0].Clients[0]
	appliedReserve := candidateIDFromHandler(applied.TCPReserveOutbound, "alice")
	if appliedReserve != candidates["applied-reserve"].ID {
		t.Fatalf("applied reserve=%q want=%q", appliedReserve, candidates["applied-reserve"].ID)
	}

	qualifyEngineCandidateSet(t, database, now.Add(time.Second), full)
	health, err := database.ListCandidateHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range health {
		if row.CandidateID != candidates["much-better"].ID {
			continue
		}
		row.Score = 200
		row.UpdatedAt = now.Add(time.Second)
		if err := database.SaveCandidateHealth(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	checkAt := now.Add(2 * time.Second)
	snapshot, err := engine.loadRouteCandidateSnapshot(ctx, checkAt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := engine.scheduler.ReadView().SelectReserves(
		checkAt, "alice",
		scheduler.Assignment{TCP: candidates["primary"].ID, UDP: candidates["primary"].ID},
		snapshot.placementCandidates,
	)
	if selected.TCP != candidates["much-better"].ID {
		t.Fatalf("full-universe winner=%q want=%q", selected.TCP, candidates["much-better"].ID)
	}
	err = engine.CapacityReady(ctx, checkAt)
	var coverageErr *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverageErr) ||
		!slices.Contains(coverageErr.Unsatisfied, "alice:tcp:reserve") ||
		!slices.Contains(coverageErr.Unsatisfied, "alice:udp:reserve") {
		t.Fatalf("below-tier applied reserve readiness=%v", err)
	}
	if err := engine.Cycle(ctx, checkAt); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 2 {
		t.Fatalf("below-tier applied reserve was not replaced: plans=%d", len(agent.plans))
	}
	replacement := candidateIDFromHandler(
		agent.plans[1].Clients[0].TCPReserveOutbound, "alice",
	)
	if replacement != candidates["much-better"].ID {
		t.Fatalf("replacement reserve=%q want=%q", replacement, candidates["much-better"].ID)
	}
}

func TestEngineCapacityReadyKeepsSevenStaggeredCriticalProofsAcrossWinnerChurn(t *testing.T) {
	ctx := context.Background()
	base := time.Unix(1_900_000_000, 0)
	specs := make([]engineQoECandidateSpec, 0, 8)
	for index := 0; index < 8; index++ {
		name := fmt.Sprintf("route-%02d", index)
		specs = append(specs, engineQoECandidateSpec{
			name: name, kind: sources.KindVLESS, score: 100,
			tcp: true, udp: true, failureDomain: "domain-" + name,
		})
	}
	database, candidates := newEngineQoEFixture(t, base, specs)
	initial := make([]store.Candidate, 0, 7)
	full := make([]store.Candidate, 0, 8)
	for index := 0; index < 8; index++ {
		candidate := candidates[fmt.Sprintf("route-%02d", index)]
		full = append(full, candidate)
		if index < 7 {
			initial = append(initial, candidate)
		}
	}
	churnClientID := engineReserveWinnerChurnClientID(t, initial[0], initial, full)
	qualifyEngineCandidateSet(t, database, base, initial)
	for index, candidate := range initial {
		clientID := fmt.Sprintf("capacity-client-%02d", index)
		if index == 0 {
			clientID = churnClientID
		}
		putEngineQoEClient(
			t, database, clientID, fmt.Sprintf("10.44.0.%d/32", index+2),
			base, false, candidate.ID, candidate.ID,
		)
	}
	const limit = 7
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false), WithActiveProbeInterval(300*time.Millisecond),
		WithActiveProofFreshness(5*time.Second),
		WithActiveFailureFreshness(1975*time.Millisecond),
		WithActiveCriticalRouteLimit(limit),
	)
	if err := engine.Cycle(ctx, base); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("applied plans=%+v", agent.plans)
	}
	appliedPlan := agent.plans[0]
	criticalIDs := make(map[string]bool)
	var churnRoute dataplane.ClientRoute
	for _, route := range appliedPlan.Clients {
		if route.ClientID == churnClientID {
			churnRoute = route
		}
		if route.BlockTCP || route.BlockUDP || route.TCPOutbound == "" ||
			route.UDPOutbound == "" || route.TCPReserveOutbound == "" ||
			route.UDPReserveOutbound == "" {
			t.Fatalf("invalid applied critical route=%+v", route)
		}
		for _, handler := range []string{
			route.TCPOutbound, route.UDPOutbound,
			route.TCPReserveOutbound, route.UDPReserveOutbound,
		} {
			if candidateID := candidateIDFromHandler(handler, route.ClientID); candidateID != "" {
				criticalIDs[candidateID] = true
			}
		}
	}
	if len(criticalIDs) != 7 || len(criticalIDs) > limit {
		t.Fatalf("applied critical IDs=%d limit=%d plan=%+v", len(criticalIDs), limit, appliedPlan)
	}
	if churnRoute.ClientID == "" {
		t.Fatalf("churn client %q missing from plan", churnClientID)
	}

	sweepStart := base.Add(10 * time.Second)
	qualifyEngineCandidateSet(t, database, sweepStart, full)
	criticalList := make([]string, 0, len(criticalIDs))
	for candidateID := range criticalIDs {
		criticalList = append(criticalList, candidateID)
	}
	sort.Strings(criticalList)
	for index, candidateID := range criticalList {
		setEngineActiveObservationAt(
			t, database, engineCandidateByID(t, candidates, candidateID),
			sweepStart.Add(time.Duration(index)*550*time.Millisecond),
		)
	}
	checkAt := sweepStart.Add(3300 * time.Millisecond)
	snapshot, err := engine.loadRouteCandidateSnapshot(ctx, checkAt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.placementCandidates) != 8 || len(snapshot.placementCandidates) <= limit {
		t.Fatalf("candidate universe=%d limit=%d", len(snapshot.placementCandidates), limit)
	}
	earliest, latest := checkAt, time.Time{}
	for _, candidateID := range criticalList {
		health, exists := snapshot.healthByID[candidateID]
		if !exists || !engine.reserveActiveObservationFresh(checkAt, health.ActiveObservedAt) {
			t.Fatalf("critical proof %q is missing or stale: %+v", candidateID, health)
		}
		observedAt := health.ActiveObservedAt
		if observedAt.Before(earliest) {
			earliest = observedAt
		}
		if observedAt.After(latest) {
			latest = observedAt
		}
	}
	if latest.Sub(earliest) < 3300*time.Millisecond {
		t.Fatalf("critical proof sweep span=%s want at least 3.3s", latest.Sub(earliest))
	}
	appliedPrimary := candidateIDFromHandler(churnRoute.TCPOutbound, churnClientID)
	appliedReserve := candidateIDFromHandler(churnRoute.TCPReserveOutbound, churnClientID)
	selected := engine.scheduler.ReadView().SelectReserves(
		checkAt, churnClientID,
		scheduler.Assignment{TCP: appliedPrimary, UDP: appliedPrimary},
		snapshot.placementCandidates,
	)
	if selected.TCP != full[7].ID || selected.TCP == appliedReserve {
		t.Fatalf("current reserve=%q applied=%q new=%q", selected.TCP, appliedReserve, full[7].ID)
	}
	if err := engine.CapacityReady(ctx, checkAt); err != nil {
		t.Fatalf("staggered applied readiness after winner churn: %v", err)
	}
}

func TestEngineKeepsTorTCPWhenNoVLESSUDPExists(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	preview := sources.PreviewInput("tor-bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567")
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	if err := database.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{{
		Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor-only",
		Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, listed[0].ID)
	now := time.Unix(1_800_000_000, 0)
	_ = database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: candidates[0].ID, Score: 100, TCPQualified: true, Available: true, UpdatedAt: now,
	})
	_ = database.PutClient(ctx, store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer-a",
	}, "private config")
	agent := &engineAgent{}
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{{Slot: 0, CandidateID: candidates[0].ID, SocksAddr: "127.0.0.1:19050", Role: "warm"}}
	})
	engine := NewEngine(database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	route := agent.plans[0].Clients[0]
	if route.TCPOutbound == "" || route.BlockTCP || route.UDPOutbound != "" || !route.BlockUDP {
		t.Fatalf("route=%+v", route)
	}
}

func TestEngineCriticalCapacityKeepsTorTCPWhenUDPIsStaticallyImpossible(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "tor", kind: sources.KindTorBridge, score: 100, tcp: true},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, "", "")
	profiles := staticProfileProvider{{
		Slot: 0, CandidateID: candidates["tor"].ID,
		SocksAddr: "127.0.0.1:19050", Role: "warm",
	}}
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	if err := seed.Cycle(ctx, now); err != nil {
		t.Fatalf("seed blocked plan: %v", err)
	}
	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
		WithActiveCriticalRouteLimit(16),
	)

	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatalf("degraded availability cycle: %v", err)
	}
	if len(agent.plans) != 1 || len(agent.plans[0].Clients) != 1 {
		t.Fatalf("plans=%+v", agent.plans)
	}
	route := agent.plans[0].Clients[0]
	if route.TCPOutbound == "" || route.BlockTCP ||
		route.UDPOutbound != "" || !route.BlockUDP {
		t.Fatalf("degraded route=%+v", route)
	}
	if err := engine.CapacityReady(ctx, now); err == nil {
		t.Fatal("degraded primary-only plan reported full capacity ready")
	}
}

func TestEngineCriticalCapacityGivesNewClientBestEffortRouteWhenFullCoverIsImpossible(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "tor", kind: sources.KindTorBridge, score: 100, tcp: true},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	profiles := staticProfileProvider{{
		Slot: 0, CandidateID: candidates["tor"].ID,
		SocksAddr: "127.0.0.1:19050", Role: "warm",
	}}
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, "", "")
	seed := NewEngine(
		database, &engineAgent{}, profiles, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	if err := seed.Cycle(ctx, now); err != nil {
		t.Fatalf("seed serving plan: %v", err)
	}
	putEngineQoEClient(t, database, "bob", "10.44.0.3/32", now, false, "", "")

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
		WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now.Add(time.Second)); err != nil {
		t.Fatalf("new-client degraded availability cycle: %v", err)
	}
	if len(agent.plans) != 1 {
		t.Fatalf("plans=%+v", agent.plans)
	}
	for _, route := range agent.plans[0].Clients {
		if route.TCPOutbound == "" || route.BlockTCP || !route.BlockUDP {
			t.Fatalf("degraded route=%+v", route)
		}
	}
}

func TestEngineStartupNormalizationKeepsLastKnownGoodWhenPoolMembershipIsUnqualified(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "current", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "unverified", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["current"].ID, candidates["current"].ID,
	)
	seedAgent := &engineAgent{}
	seedEngine := NewEngine(
		database, seedAgent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	if err := seedEngine.Cycle(ctx, now); err != nil {
		t.Fatalf("seed plan: %v", err)
	}

	unverified := candidates["unverified"]
	if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
		Fingerprint: unverified.Fingerprint, CandidateID: unverified.ID,
		SourceID: unverified.SourceID, Full: true, Success: false,
		ErrorCode: "active_hard_failure", At: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("make replacement unverified: %v", err)
	}
	if err := database.ReplaceWorkingPool(
		ctx,
		[]string{unverified.Fingerprint},
		[]string{candidates["current"].Fingerprint},
	); err != nil {
		t.Fatalf("replace working pool: %v", err)
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	err := engine.CycleForReason(ctx, now.Add(2*time.Second), PlacementStartupNormalization)
	if err != nil {
		t.Fatalf("retain last-known-good plan: %v", err)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["current"].ID ||
		assignment.UDPOutbound != candidates["current"].ID {
		t.Fatalf("last-known-good assignment changed: %+v", assignment)
	}
	if len(agent.plans) > 1 {
		t.Fatalf("unexpected retained plans=%+v", agent.plans)
	}
	if len(agent.plans) == 1 {
		if len(agent.plans[0].Clients) != 1 {
			t.Fatalf("retained plan=%+v", agent.plans[0])
		}
		route := agent.plans[0].Clients[0]
		if route.BlockTCP || route.BlockUDP ||
			candidateIDFromHandler(route.TCPOutbound, "alice") != candidates["current"].ID ||
			candidateIDFromHandler(route.UDPOutbound, "alice") != candidates["current"].ID {
			t.Fatalf("last-known-good route was not retained: %+v", route)
		}
	}
}

func TestEngineStartupNormalizationDoesNotMigrateServingAssignmentForCapacity(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "current", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "replacement", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-b"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["current"].ID, candidates["current"].ID,
	)
	seed := NewEngine(
		database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	if err := seed.Cycle(ctx, now); err != nil {
		t.Fatalf("seed plan: %v", err)
	}

	if err := database.ReplaceWorkingPool(
		ctx,
		[]string{candidates["replacement"].Fingerprint},
		[]string{candidates["current"].Fingerprint},
	); err != nil {
		t.Fatalf("replace working pool: %v", err)
	}

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false),
	)
	if err := engine.CycleForReason(
		ctx, now.Add(2*time.Second), PlacementStartupNormalization,
	); err != nil {
		t.Fatalf("capacity normalization: %v", err)
	}
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["current"].ID ||
		assignment.UDPOutbound != candidates["current"].ID {
		t.Fatalf("capacity event migrated serving assignment: %+v", assignment)
	}
}

func TestBoundedDegradedAvailabilityCandidatesPreferServingAndUsableRoutes(t *testing.T) {
	candidates := []scheduler.Candidate{
		{ID: "cold-tor", Protocol: scheduler.ProtocolTor, Score: 100},
		{ID: "warm-tor", Protocol: scheduler.ProtocolTor, TCPQualified: true, Score: 70},
		{ID: "dual", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, Score: 90},
		{ID: "serving", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, Score: 10},
	}
	selected := boundedDegradedAvailabilityCandidates(
		[]scheduler.Client{{
			ID: "alice", Assignment: scheduler.Assignment{TCP: "serving"},
		}},
		candidates, 2,
	)
	ids := make([]string, 0, len(selected))
	for _, candidate := range selected {
		ids = append(ids, candidate.ID)
	}
	if !reflect.DeepEqual(ids, []string{"serving", "dual"}) {
		t.Fatalf("degraded candidates=%v want serving+dual", ids)
	}
}

func TestEngineQoEUsesTwoMinuteFreshnessForActiveAssignedCandidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "slow", kind: sources.KindVLESS, score: 100, tcp: true},
		{name: "fast", kind: sources.KindVLESS, score: 90, tcp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow"].ID, "")
	putEngineQoEClient(t, database, "bob", "10.44.0.3/32", now, true, candidates["fast"].ID, "")
	seedEngineQoEState(t, database, candidates["slow"], qoe.StatusDegraded, 4*time.Second, now)
	seedEngineQoEState(t, database, candidates["fast"], qoe.StatusHealthy, time.Second, now.Add(-3*time.Minute))

	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["slow"].ID {
		t.Fatalf("active candidate with stale QoE triggered move: %+v", assignment)
	}
}

func TestEngineQualityOptimizationDoesNotPromoteUnmeasuredTarget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "current", kind: sources.KindVLESS, score: 60, tcp: true},
		{name: "unmeasured", kind: sources.KindVLESS, score: 100, tcp: true},
	})
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		candidates["current"].ID, "",
	)
	ageEngineQoEAssignment(t, database, "alice", now.Add(-time.Hour))
	seedEngineQoEState(
		t, database, candidates["current"], qoe.StatusHealthy, time.Second, now,
	)

	engine := NewEngine(
		database, &engineAgent{}, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	runEngineQoEPlacementSnapshots(t, engine, now, 3)
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["current"].ID {
		t.Fatalf("unmeasured quality target received traffic: %+v", assignment)
	}
}

func TestEngineApplicationGateDegradationFailsOverImmediately(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "blocked", kind: sources.KindVLESS, score: 100, tcp: true},
		{name: "working", kind: sources.KindVLESS, score: 90, tcp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["blocked"].ID, "")
	seedEngineQoEState(t, database, candidates["working"], qoe.StatusHealthy, 2*time.Second, now)
	for index := 2; index >= 0; index-- {
		state, _, err := database.RecordCandidateQoE(context.Background(), candidates["blocked"], qoe.Observation{
			At: now.Add(-time.Duration(index) * time.Second), ErrorCode: qoe.ReasonApplicationGates,
		}, qoe.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 && (state.Status != qoe.StatusDegraded || state.LastReason != qoe.ReasonApplicationGates) {
			t.Fatalf("blocked state=%+v", state)
		}
	}

	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	if err := engine.CycleForReason(context.Background(), now, PlacementQoEDegraded); err != nil {
		t.Fatal(err)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["working"].ID {
		t.Fatalf("application gate did not fail over: %+v", assignment)
	}
}

func TestEngineNonPeriodicCyclesDoNotInitiateQualityUpgrade(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "current", kind: sources.KindVLESS, score: 60, tcp: true},
		{name: "better", kind: sources.KindVLESS, score: 100, tcp: true},
	})
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, true,
		candidates["current"].ID, "",
	)
	ageEngineQoEAssignment(t, database, "alice", now.Add(-time.Hour))
	seedEngineQoEState(
		t, database, candidates["current"], qoe.StatusHealthy, 2*time.Second, now,
	)
	seedEngineQoEState(
		t, database, candidates["better"], qoe.StatusHealthy, time.Second, now,
	)

	engine := NewEngine(
		database, &engineAgent{}, nil,
		scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
	)
	for snapshot := 0; snapshot < scheduler.PolicyDefaults().RequiredSnapshots; snapshot++ {
		if err := engine.CycleForReason(
			context.Background(), now.Add(time.Duration(snapshot)*time.Second),
			PlacementPromotion,
		); err != nil {
			t.Fatal(err)
		}
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["current"].ID {
		t.Fatalf("promotion trigger initiated unrelated quality upgrade: %+v", assignment)
	}
}

func TestEngineQoEUsesTenMinuteFreshnessForStandbyCandidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "slow", kind: sources.KindVLESS, score: 100, tcp: true},
		{name: "standby", kind: sources.KindVLESS, score: 90, tcp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow"].ID, "")
	ageEngineQoEAssignment(t, database, "alice", now.Add(-time.Hour))
	seedEngineQoEState(t, database, candidates["slow"], qoe.StatusDegraded, 4*time.Second, now)
	seedEngineQoEState(t, database, candidates["standby"], qoe.StatusHealthy, time.Second, now.Add(-9*time.Minute))

	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	runEngineQoEPlacementSnapshots(t, engine, now, 3)
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["standby"].ID {
		t.Fatalf("fresh standby candidate was not selected: %+v", assignment)
	}
}

func TestEngineQoEMovesBothNetworksToQualifiedFasterVLESS(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "slow", kind: sources.KindVLESS, score: 100, tcp: true, udp: true},
		{name: "fast", kind: sources.KindVLESS, score: 90, tcp: true, udp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow"].ID, candidates["slow"].ID)
	ageEngineQoEAssignment(t, database, "alice", now.Add(-time.Hour))
	seedEngineQoEState(t, database, candidates["slow"], qoe.StatusDegraded, 4*time.Second, now)
	seedEngineQoEState(t, database, candidates["fast"], qoe.StatusHealthy, time.Second, now)

	agent := &engineAgent{}
	engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	runEngineQoEPlacementSnapshots(t, engine, now, 3)
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["fast"].ID || assignment.UDPOutbound != candidates["fast"].ID {
		t.Fatalf("assignments=%+v", assignment)
	}
}

func TestEngineQoEMovesTorTCPWithoutChangingVLESSUDP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "slow-tor", kind: sources.KindTorBridge, score: 100, tcp: true},
		{name: "fast-tor", kind: sources.KindTorBridge, score: 90, tcp: true},
		{name: "udp", kind: sources.KindVLESS, score: 80, udp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow-tor"].ID, candidates["udp"].ID)
	ageEngineQoEAssignment(t, database, "alice", now.Add(-time.Hour))
	seedEngineQoEState(t, database, candidates["slow-tor"], qoe.StatusDegraded, 4*time.Second, now)
	seedEngineQoEState(t, database, candidates["fast-tor"], qoe.StatusHealthy, time.Second, now)
	profiles := profileProviderFunc(func() []torpool.Profile {
		return []torpool.Profile{
			{Slot: 0, CandidateID: candidates["slow-tor"].ID, SocksAddr: "127.0.0.1:19050", Role: "warm"},
			{Slot: 1, CandidateID: candidates["fast-tor"].ID, SocksAddr: "127.0.0.1:19051", Role: "warm"},
		}
	})

	agent := &engineAgent{}
	engine := NewEngine(database, agent, profiles, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
	runEngineQoEPlacementSnapshots(t, engine, now, 3)
	assignment := engineQoEAssignment(t, database, "alice")
	if assignment.TCPOutbound != candidates["fast-tor"].ID || assignment.UDPOutbound != candidates["udp"].ID {
		t.Fatalf("assignments=%+v", assignment)
	}
}

func TestEngineQoEDisabledTreatsPersistedDegradedCandidateAsOrdinaryQualified(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "degraded", kind: sources.KindVLESS, score: 100, tcp: true},
	})
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, "", "")
	seedEngineQoEState(t, database, candidates["degraded"], qoe.StatusDegraded, 4*time.Second, now)

	agent := &engineAgent{}
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
		WithQoEEnabled(false),
	)
	if err := engine.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["degraded"].ID {
		t.Fatalf("disabled QoE excluded ordinary qualified candidate: %+v", assignment)
	}
}

func TestEngineQoEFutureLastValidAtIsNotFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name              string
		alternativeActive bool
	}{
		{name: "active", alternativeActive: true},
		{name: "idle standby"},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
				{name: "slow", kind: sources.KindVLESS, score: 100, tcp: true},
				{name: "alternative", kind: sources.KindVLESS, score: 90, tcp: true},
			})
			putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow"].ID, "")
			if test.alternativeActive {
				putEngineQoEClient(t, database, "bob", "10.44.0.3/32", now, true, candidates["alternative"].ID, "")
			}
			seedEngineQoEState(t, database, candidates["slow"], qoe.StatusDegraded, 4*time.Second, now)
			seedEngineQoEState(t, database, candidates["alternative"], qoe.StatusHealthy, time.Second, now.Add(time.Minute))

			agent := &engineAgent{}
			engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
			if err := engine.Cycle(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["slow"].ID {
				t.Fatalf("future QoE timestamp triggered emergency move: %+v", assignment)
			}
		})
	}
}

func TestEngineQoERetainsAssignmentForStaleOrInsufficientAlternative(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name              string
		currentEffective  time.Duration
		targetEffective   time.Duration
		targetLastValidAt time.Time
	}{
		{name: "stale", currentEffective: 4 * time.Second, targetEffective: time.Second, targetLastValidAt: now.Add(-11 * time.Minute)},
		{name: "less than one point five times faster", currentEffective: 2900 * time.Millisecond, targetEffective: 2 * time.Second, targetLastValidAt: now},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
				{name: "slow", kind: sources.KindVLESS, score: 100, tcp: true},
				{name: "alternative", kind: sources.KindVLESS, score: 90, tcp: true},
			})
			putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, true, candidates["slow"].ID, "")
			seedEngineQoEState(t, database, candidates["slow"], qoe.StatusDegraded, test.currentEffective, now)
			seedEngineQoEState(t, database, candidates["alternative"], qoe.StatusHealthy, test.targetEffective, test.targetLastValidAt)

			agent := &engineAgent{}
			engine := NewEngine(database, agent, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"))
			if err := engine.Cycle(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if assignment := engineQoEAssignment(t, database, "alice"); assignment.TCPOutbound != candidates["slow"].ID {
				t.Fatalf("assignment=%+v", assignment)
			}
		})
	}
}

func TestEngineAppliesFailureDomainCircuitUntilExactOpenBoundary(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name            string
		openedAt        time.Time
		wantAlternative bool
	}{
		{
			name:            "before boundary",
			openedAt:        now.Add(-10*time.Minute + time.Second),
			wantAlternative: true,
		},
		{
			name:     "at boundary",
			openedAt: now.Add(-10 * time.Minute),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
				{
					name: "domain-a", kind: sources.KindVLESS, score: 100, tcp: true,
					failureDomain: "failure-domain-a",
				},
				{
					name: "domain-b", kind: sources.KindVLESS, score: 90, tcp: true,
					failureDomain: "failure-domain-b",
				},
			})
			putEngineQoEClient(
				t, database, "alice", "10.44.0.2/32", now, true,
				candidates["domain-a"].ID, "",
			)
			for _, candidateID := range []string{"opaque-a", "opaque-b", "opaque-c"} {
				if _, err := database.RecordFailureDomainFailure(
					ctx, "failure-domain-a", candidateID, test.openedAt,
				); err != nil {
					t.Fatal(err)
				}
			}

			agent := &engineAgent{}
			engine := NewEngine(
				database, agent, nil,
				scheduler.New(scheduler.PolicyDefaults()), []byte("secret"),
				WithQoEEnabled(false),
			)
			if err := engine.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}
			assignment := engineQoEAssignment(t, database, "alice")
			want := candidates["domain-a"].ID
			if test.wantAlternative {
				want = candidates["domain-b"].ID
			}
			if assignment.TCPOutbound != want {
				t.Fatalf("assignment=%+v want=%q", assignment, want)
			}
		})
	}
}

type engineQoECandidateSpec struct {
	name          string
	kind          sources.Kind
	score         float64
	tcp, udp      bool
	failureDomain string
}

func newEngineQoEFixture(t *testing.T, now time.Time, specs []engineQoECandidateSpec) (*store.Store, map[string]store.Candidate) {
	t.Helper()
	ctx := context.Background()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	preview := sources.PreviewInput("vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	inputs := make([]store.CandidateInput, 0, len(specs))
	for _, spec := range specs {
		payload := "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls"
		if spec.kind == sources.KindTorBridge {
			payload = "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"
		}
		inputs = append(inputs, store.CandidateInput{
			Kind: spec.kind, Label: spec.name, Fingerprint: spec.name, Payload: payload,
			RouteKey: "route-" + spec.name, FailureDomain: spec.failureDomain,
		})
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]store.Candidate, len(rows))
	specByName := make(map[string]engineQoECandidateSpec, len(specs))
	for _, spec := range specs {
		specByName[spec.name] = spec
	}
	for _, candidate := range rows {
		byName[candidate.Label] = candidate
		spec := specByName[candidate.Label]
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Score: spec.score,
			TCPQualified: spec.tcp, UDPQualified: spec.udp,
			Available: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return database, byName
}

func newEngineActiveCriticalLimitFixture(
	t *testing.T,
	count int,
) (*store.Store, map[string]store.Candidate, time.Time) {
	t.Helper()
	now := time.Unix(1_900_000_000, 0)
	specs := make([]engineQoECandidateSpec, 0, count)
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("route-%02d", index)
		specs = append(specs, engineQoECandidateSpec{
			name: name, kind: sources.KindVLESS, score: 100,
			tcp: true, udp: true, failureDomain: "domain-" + name,
		})
	}
	database, candidates := newEngineQoEFixture(t, now, specs)
	qualifyEngineReserveCandidates(t, database, now, candidates)
	return database, candidates, now
}

func putEngineActiveCriticalLimitClients(
	t *testing.T,
	database *store.Store,
	candidates map[string]store.Candidate,
	now time.Time,
) {
	t.Helper()
	putEngineActiveCriticalLimitClientCount(t, database, candidates, now, len(candidates))
}

func putEngineActiveCriticalLimitClientCount(
	t *testing.T,
	database *store.Store,
	candidates map[string]store.Candidate,
	now time.Time,
	count int,
) {
	t.Helper()
	ctx := context.Background()
	for index := 0; index < count; index++ {
		clientID := fmt.Sprintf("client-%02d", index)
		candidate := candidates[fmt.Sprintf("route-%02d", index)]
		if err := database.PutClient(ctx, store.ClientRecord{
			ID: clientID, Name: clientID,
			Address:   fmt.Sprintf("10.44.0.%d/32", index+2),
			PublicKey: "peer-" + clientID,
		}, "private-"+clientID); err != nil {
			t.Fatal(err)
		}
		if err := database.SetAssignment(ctx, store.AssignmentRecord{
			ClientID: clientID, TCPOutbound: candidate.ID, UDPOutbound: candidate.ID,
			TCPSince: now, UDPSince: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func qualifyEngineReserveCandidates(
	t *testing.T,
	database *store.Store,
	now time.Time,
	candidates map[string]store.Candidate,
) {
	t.Helper()
	ctx := context.Background()
	activeFingerprints := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		for success := 0; success < 2; success++ {
			if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 100, At: now.Add(time.Duration(success) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
		activeFingerprints = append(activeFingerprints, candidate.Fingerprint)
	}
	if err := database.ReplaceWorkingPool(ctx, activeFingerprints, nil); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		reservation, err := database.ReserveCandidateObservation(
			ctx, candidate, store.ObservationActive,
		)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := database.CommitCandidateActiveObservation(
			ctx, candidate, reservation, true, now,
		)
		if err != nil || !commit.Accepted {
			t.Fatalf("active candidate %s commit=%+v err=%v", candidate.ID, commit, err)
		}
	}
}

func qualifyEngineCandidateSet(
	t *testing.T,
	database *store.Store,
	at time.Time,
	candidates []store.Candidate,
) {
	t.Helper()
	ctx := context.Background()
	activeFingerprints := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		for success := 0; success < 2; success++ {
			if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, Success: true,
				Score: 100, At: at.Add(time.Duration(success-1) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
		activeFingerprints = append(activeFingerprints, candidate.Fingerprint)
	}
	if err := database.ReplaceWorkingPool(ctx, activeFingerprints, nil); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		setEngineActiveObservationAt(t, database, candidate, at)
	}
}

func engineReserveWinnerChurnClientID(
	t *testing.T,
	primary store.Candidate,
	before, after []store.Candidate,
) string {
	t.Helper()
	convert := func(rows []store.Candidate) []scheduler.Candidate {
		result := make([]scheduler.Candidate, 0, len(rows))
		for _, candidate := range rows {
			result = append(result, scheduler.Candidate{
				ID: candidate.ID, Protocol: scheduler.ProtocolVLESS,
				RouteKey: candidate.RouteKey, Score: 100,
				TCPQualified: true, UDPQualified: true, ReserveEligible: true,
				ActiveEligible: true, ActiveFresh: true,
				FailureDomain: candidate.FailureDomain,
			})
		}
		return result
	}
	assignment := scheduler.Assignment{TCP: primary.ID, UDP: primary.ID}
	selector := scheduler.New(scheduler.PolicyDefaults())
	beforeCandidates := convert(before)
	afterCandidates := convert(after)
	newCandidateID := after[len(after)-1].ID
	for index := 0; index < 100_000; index++ {
		clientID := fmt.Sprintf("capacity-churn-%05d", index)
		applied := selector.SelectReserves(
			time.Unix(1_900_000_000, 0), clientID, assignment, beforeCandidates,
		)
		current := selector.SelectReserves(
			time.Unix(1_900_000_001, 0), clientID, assignment, afterCandidates,
		)
		if applied.TCP != "" && current.TCP == newCandidateID && current.TCP != applied.TCP {
			return clientID
		}
	}
	t.Fatalf("could not find deterministic winner churn to %q", newCandidateID)
	return ""
}

func setEngineActiveObservationAt(
	t *testing.T,
	database *store.Store,
	candidate store.Candidate,
	at time.Time,
) {
	t.Helper()
	ctx := context.Background()
	reservation, err := database.ReserveCandidateObservation(
		ctx, candidate, store.ObservationActive,
	)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := database.CommitCandidateActiveObservation(
		ctx, candidate, reservation, true, at,
	)
	if err != nil || !commit.Accepted {
		t.Fatalf("active candidate %s commit=%+v err=%v", candidate.ID, commit, err)
	}
}

func engineCandidateByID(
	t *testing.T,
	candidates map[string]store.Candidate,
	candidateID string,
) store.Candidate {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.ID == candidateID {
			return candidate
		}
	}
	t.Fatalf("candidate %q not found in %+v", candidateID, candidates)
	return store.Candidate{}
}

func enginePlanCriticalCandidateCount(plan dataplane.DesiredPlan) int {
	ids := make(map[string]struct{})
	for _, route := range plan.Clients {
		for _, handler := range []string{
			route.TCPOutbound, route.UDPOutbound,
			route.TCPReserveOutbound, route.UDPReserveOutbound,
		} {
			if candidateID := candidateIDFromHandler(handler, route.ClientID); candidateID != "" {
				ids[candidateID] = struct{}{}
			}
		}
	}
	return len(ids)
}

func engineCriticalCountPlan(generation int64, count int) dataplane.DesiredPlan {
	plan := dataplane.DesiredPlan{
		Generation: generation, DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("critical-%02d", index)
		plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{
			ID: id, Protocol: dataplane.ProtocolVLESS, Config: json.RawMessage(`{}`),
		})
		plan.Clients = append(plan.Clients, dataplane.ClientRoute{
			ClientID: fmt.Sprintf("client-%02d", index), TCPOutbound: id,
			BlockUDP: true,
		})
	}
	return plan
}

func engineDNSConfig(t *testing.T, encoded json.RawMessage) (string, string) {
	t.Helper()
	var config struct {
		Settings struct {
			RewriteAddress string `json:"rewriteAddress"`
		} `json:"settings"`
		StreamSettings struct {
			Sockopt struct {
				DialerProxy string `json:"dialerProxy"`
			} `json:"sockopt"`
		} `json:"streamSettings"`
		ProxySettings struct {
			Tag string `json:"tag"`
		} `json:"proxySettings"`
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	target := config.StreamSettings.Sockopt.DialerProxy
	if target == "" {
		target = config.ProxySettings.Tag
	}
	return target, config.Settings.RewriteAddress
}

func engineDNSHandlerForClientTarget(
	t *testing.T,
	plan dataplane.DesiredPlan,
	clientID, targetID string,
) string {
	t.Helper()
	target := engineOutboundByID(t, plan, targetID)
	for _, outbound := range plan.Outbounds {
		if outbound.Protocol != dataplane.ProtocolDNS {
			continue
		}
		proxyTarget, resolver := engineDNSConfig(t, outbound.Config)
		if proxyTarget != targetID {
			continue
		}
		expected, err := dataplane.BuildDNSOutbound(clientID, target, resolver)
		if err != nil {
			t.Fatal(err)
		}
		if expected.ID == outbound.ID {
			return outbound.ID
		}
	}
	t.Fatalf("client %q DNS for target %q not found", clientID, targetID)
	return ""
}

func engineOutboundByID(
	t *testing.T,
	plan dataplane.DesiredPlan,
	id string,
) dataplane.Outbound {
	t.Helper()
	for _, outbound := range plan.Outbounds {
		if outbound.ID == id {
			return outbound
		}
	}
	t.Fatalf("outbound %q not found in %+v", id, plan.Outbounds)
	return dataplane.Outbound{}
}

func sameEngineOutboundSet(left, right []dataplane.Outbound) bool {
	if len(left) != len(right) {
		return false
	}
	byID := make(map[string]dataplane.Outbound, len(left))
	for _, outbound := range left {
		byID[outbound.ID] = outbound
	}
	for _, outbound := range right {
		other, exists := byID[outbound.ID]
		if !exists || other.Protocol != outbound.Protocol ||
			!bytes.Equal(other.Config, outbound.Config) {
			return false
		}
	}
	return true
}

func sameEngineNonDNSOutboundSet(left, right []dataplane.Outbound) bool {
	withoutDNS := func(outbounds []dataplane.Outbound) []dataplane.Outbound {
		result := make([]dataplane.Outbound, 0, len(outbounds))
		for _, outbound := range outbounds {
			if outbound.Protocol != dataplane.ProtocolDNS {
				result = append(result, outbound)
			}
		}
		return result
	}
	return sameEngineOutboundSet(withoutDNS(left), withoutDNS(right))
}

func enginePlanGenerations(plans []dataplane.DesiredPlan) []int64 {
	result := make([]int64, 0, len(plans))
	for _, plan := range plans {
		result = append(result, plan.Generation)
	}
	return result
}

func putEngineQoEClient(
	t *testing.T,
	database *store.Store,
	clientID, address string,
	now time.Time,
	active bool,
	tcp, udp string,
) {
	t.Helper()
	ctx := context.Background()
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: clientID, Name: clientID, Address: address, PublicKey: "peer-" + clientID,
	}, "private config"); err != nil {
		t.Fatal(err)
	}
	if active {
		if err := database.RecordActivity(ctx, clientID, now, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := database.RecordActivity(ctx, clientID, now, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: clientID, TCPOutbound: tcp, UDPOutbound: udp,
		TCPSince: now.Add(-time.Minute), UDPSince: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
}

func seedEngineQoEState(
	t *testing.T,
	database *store.Store,
	candidate store.Candidate,
	status qoe.Status,
	effective time.Duration,
	lastValidAt time.Time,
) {
	t.Helper()
	count := 5
	throughput := 100.0
	if status == qoe.StatusDegraded {
		count = 3
		throughput = 0.1
	}
	for index := count - 1; index >= 0; index-- {
		observation := qoe.Observation{
			At:      lastValidAt.Add(-time.Duration(index) * time.Second),
			Success: true, TTFB: effective, ThroughputMbps: throughput,
		}
		state, _, err := database.RecordCandidateQoE(context.Background(), candidate, observation, qoe.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 && state.Status != status {
			t.Fatalf("candidate %s status=%s, want %s", candidate.ID, state.Status, status)
		}
	}
}

func engineQoEAssignment(t *testing.T, database *store.Store, clientID string) store.AssignmentRecord {
	t.Helper()
	assignments, err := database.ListAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range assignments {
		if assignment.ClientID == clientID {
			return assignment
		}
	}
	t.Fatalf("assignment for %s not found: %+v", clientID, assignments)
	return store.AssignmentRecord{}
}

func ageEngineQoEAssignment(
	t *testing.T,
	database *store.Store,
	clientID string,
	since time.Time,
) {
	t.Helper()
	assignment := engineQoEAssignment(t, database, clientID)
	assignment.TCPSince = since
	assignment.UDPSince = since
	if err := database.SetAssignment(context.Background(), assignment); err != nil {
		t.Fatal(err)
	}
}

func runEngineQoEPlacementSnapshots(
	t *testing.T,
	engine *Engine,
	now time.Time,
	count int,
) {
	t.Helper()
	for snapshot := 0; snapshot < count; snapshot++ {
		if err := engine.Cycle(
			context.Background(), now.Add(time.Duration(snapshot)*time.Second),
		); err != nil {
			t.Fatal(err)
		}
	}
}

type engineAgent struct {
	plans        []dataplane.DesiredPlan
	applyStarted chan struct{}
	releaseApply chan struct{}
	applyErr     error
}

type recordingEngineAdapter struct {
	adds              []string
	drains            []string
	removes           []string
	routeReplacements int
}

func (adapter *recordingEngineAdapter) AddOutbound(
	_ context.Context,
	outbound dataplane.Outbound,
) error {
	adapter.adds = append(adapter.adds, outbound.ID)
	return nil
}

func (*recordingEngineAdapter) RouteClient(context.Context, dataplane.ClientRoute) error {
	return nil
}

func (adapter *recordingEngineAdapter) ReplaceRoutes(
	_ context.Context,
	_ []dataplane.ClientRoute,
) error {
	adapter.routeReplacements++
	return nil
}

func (adapter *recordingEngineAdapter) DrainOutbound(_ context.Context, id string) error {
	adapter.drains = append(adapter.drains, id)
	return nil
}
func (adapter *recordingEngineAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.removes = append(adapter.removes, id)
	return nil
}

type reconcilerEngineAgent struct {
	reconciler *dataplane.Reconciler
	plans      []dataplane.DesiredPlan
}

func (agent *reconcilerEngineAgent) Apply(
	ctx context.Context,
	plan dataplane.DesiredPlan,
) error {
	agent.plans = append(agent.plans, plan)
	return agent.reconciler.Apply(ctx, plan)
}

func (*reconcilerEngineAgent) Activity(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

func (agent *engineAgent) Apply(_ context.Context, plan dataplane.DesiredPlan) error {
	agent.plans = append(agent.plans, plan)
	if agent.applyStarted != nil {
		close(agent.applyStarted)
	}
	if agent.releaseApply != nil {
		<-agent.releaseApply
	}
	return agent.applyErr
}
func (agent *engineAgent) Activity(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

type serializedCycleAgent struct {
	mu           sync.Mutex
	plans        []dataplane.DesiredPlan
	applyEntered chan int
	releaseFirst chan struct{}
}

func (agent *serializedCycleAgent) Apply(_ context.Context, plan dataplane.DesiredPlan) error {
	agent.mu.Lock()
	agent.plans = append(agent.plans, plan)
	call := len(agent.plans)
	agent.mu.Unlock()
	agent.applyEntered <- call
	if call == 1 {
		<-agent.releaseFirst
	}
	return nil
}

func (agent *serializedCycleAgent) Activity(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

func (agent *serializedCycleAgent) ApplyCalls() int {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return len(agent.plans)
}

type profileProviderFunc func() []torpool.Profile

func (function profileProviderFunc) Profiles() []torpool.Profile { return function() }

func TestEngineExcludesRussianEgressWhenDisallowed(t *testing.T) {
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
	// Simulate candidate_health in DB for all three candidates as qualified
	for _, c := range candidates {
		_ = database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
			CandidateID:  c.ID,
			Score:        90,
			TCPQualified: true,
			UDPQualified: true,
			Available:    true,
			UpdatedAt:    now,
		})
	}

	// With DisallowRUEgress enabled
	engine := NewEngine(
		database, nil, nil, scheduler.New(scheduler.PolicyDefaults()), nil,
		WithDisallowRUEgress(true),
	)

	snapshot, err := engine.loadRouteCandidateSnapshotWithProfiles(
		context.Background(), now, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(snapshot.placementCandidates) != 1 {
		t.Fatalf("expected 1 placement candidate (Germany), got %d: %+v", len(snapshot.placementCandidates), snapshot.placementCandidates)
	}
	if snapshot.placementCandidates[0].ID != candidates["vless-de"].ID {
		t.Fatalf("expected Germany candidate in placementCandidates, got %s", snapshot.placementCandidates[0].ID)
	}

	ruCand := snapshot.allByID[candidates["vless-ru"].ID]
	if ruCand.TCPQualified || ruCand.UDPQualified || ruCand.ReserveEligible {
		t.Fatalf("Russia candidate should not be qualified/reserve eligible: %+v", ruCand)
	}

	yandexCand := snapshot.allByID[candidates["vless-yandex"].ID]
	if yandexCand.TCPQualified || yandexCand.UDPQualified || yandexCand.ReserveEligible {
		t.Fatalf("CIDR-Yandex candidate should not be qualified/reserve eligible: %+v", yandexCand)
	}
}
