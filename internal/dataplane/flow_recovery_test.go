package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

type recoveryAdapter struct {
	recordingAdapter
	registry    *xrayflow.Registry
	unavailable bool
	lostReply   bool
	failSources map[string]bool
}

func (a *recoveryAdapter) FlowSnapshot(ctx context.Context) (xrayflow.Snapshot, error) {
	a.operations = append(a.operations, "flow:snapshot")
	if a.unavailable {
		return xrayflow.Snapshot{}, errors.New("unavailable")
	}
	return a.registry.Snapshot(), nil
}
func (a *recoveryAdapter) ResetFlow(ctx context.Context, q xrayflow.ResetRequest) (int, error) {
	a.operations = append(a.operations, "flow:reset")
	if a.unavailable {
		return 0, errors.New("unavailable")
	}
	if a.failSources[q.Source] {
		return 0, errors.New("unavailable")
	}
	n, err := a.registry.Reset(ctx, q)
	if a.lostReply {
		a.lostReply = false
		return 0, errors.New("reply lost")
	}
	return n, err
}

func TestRecoveryLostReplyRetainsWatermarkAcrossReopen(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	path := filepath.Join(t.TempDir(), "applied.json")
	r, _ := NewReconciler(a, path)
	old, next, scopes := recoveryPlans()
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	closed := 0
	_, finish := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed++ })
	defer finish()
	a.lostReply = true
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatal(err)
	}
	if closed != 1 || len(r.applied.PendingFlowRecoveries) != 1 {
		t.Fatal("lost response not retained")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		DesiredPlan
		Digest string `json:"digest"`
	}
	if !strings.Contains(string(data), "pending_flow_recoveries") {
		t.Fatal("missing new local metadata")
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	if digest, _ := legacy.DesiredPlan.digest(); digest != legacy.Digest {
		t.Fatal("rollback route digest changed")
	}
	freshClosed := false
	_, finishFresh := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { freshClosed = true })
	defer finishFresh()
	reopened, err := NewReconciler(a, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Rehydrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RetryFlowRecoveries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if freshClosed || len(reopened.applied.PendingFlowRecoveries) != 0 {
		t.Fatal("replay recaptured fresh same-tag session")
	}
}

func TestRecoveryRequiresPreviouslyAppliedServingRoute(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	r, _ := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	_, next, scopes := recoveryPlans()
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err == nil {
		t.Fatal("recovery admitted without any previously applied route")
	}
	if len(a.operations) != 0 {
		t.Fatal("invalid first-generation recovery reached adapter")
	}
}

func TestRecoveryCoreRestartDropsOldTokenWithoutRecapture(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry(), failSources: map[string]bool{"10.44.0.2": true}}
	r, _ := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	old, next, scopes := recoveryPlans()
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatal(err)
	}
	a.registry = xrayflow.NewRegistry()
	a.failSources = nil
	closed := false
	_, finish := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed = true })
	defer finish()
	if err := r.RetryFlowRecoveries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if closed || len(r.applied.PendingFlowRecoveries) != 0 {
		t.Fatal("new core flow touched by old intent")
	}
}

func TestRecoveryUnreachableScopeDoesNotStarveOtherClients(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry(), failSources: make(map[string]bool)}
	r, _ := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	old, next, _ := recoveryPlans()
	old.Clients, next.Clients = nil, nil
	var scopes []FlowRecovery
	closed := false
	for i := 0; i < flowRecoveryBatch+1; i++ {
		id, source := fmt.Sprintf("client%d", i), fmt.Sprintf("10.44.0.%d", i+2)
		old.Clients = append(old.Clients, ClientRoute{ClientID: id, SourceCIDR: source + "/32", TCPOutbound: "old", BlockUDP: true})
		next.Clients = append(next.Clients, ClientRoute{ClientID: id, SourceCIDR: source + "/32", TCPOutbound: "new", BlockUDP: true})
		scopes = append(scopes, FlowRecovery{ClientID: id, SourceCIDR: source + "/32", FailedOutbound: "old", ReplacementOutbound: "new"})
		if i < flowRecoveryBatch {
			a.failSources[source] = true
		} else {
			_, finish := a.registry.Track(t.Context(), "old", source, "tcp", func() { closed = true })
			defer finish()
		}
	}
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatal(err)
	}
	_ = r.RetryFlowRecoveries(t.Context())
	if !closed {
		t.Fatal("first failed scopes starved later client")
	}
}

func recoveryPlans() (DesiredPlan, DesiredPlan, []FlowRecovery) {
	old := DesiredPlan{Generation: 1, Outbounds: []Outbound{{ID: "old", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old", UDPOutbound: "old"}}, DirectSuffixes: []string{".ru"}, FailClosed: true}
	next := DesiredPlan{Generation: 2, Outbounds: []Outbound{{ID: "new", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", UDPOutbound: "new"}}, DirectSuffixes: []string{".ru"}, FailClosed: true}
	return old, next, []FlowRecovery{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", FailedOutbound: "old", ReplacementOutbound: "new"}}
}

func TestRecoveryOnlyAfterSuccessfulReplacement(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	r, err := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	old, next, scopes := recoveryPlans()
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	closed := 0
	_, done := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed++ })
	defer done()
	a.routeError = errors.New("replacement failed")
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err == nil || closed != 0 {
		t.Fatal("failed apply reset old connection")
	}
	a.routeError = nil
	a.operations = nil
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("old flow not reset: %d", closed)
	}
	operations := strings.Join(a.operations, ",")
	if strings.Index(operations, "route:alice:new:new") > strings.Index(operations, "flow:reset") || !strings.Contains(operations, "flow:reset") {
		t.Fatalf("unsafe ordering: %s", operations)
	}
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil || closed != 1 {
		t.Fatal("same generation repeated reset")
	}
}

func TestRecoveryControlOutageKeepsNewRoutingAndRetriesDurably(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	path := filepath.Join(t.TempDir(), "applied.json")
	r, _ := NewReconciler(a, path)
	old, next, scopes := recoveryPlans()
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	closed := 0
	_, done := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed++ })
	defer done()
	a.unavailable = true
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatalf("control outage blocked traffic failover: %v", err)
	}
	if r.applied.Generation != 2 || closed != 0 {
		t.Fatal("new routing was not retained")
	}
	// Reopen the persisted gateway state while retaining the live core instance.
	reopened, err := NewReconciler(a, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Rehydrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.unavailable = false
	if err := reopened.RetryFlowRecoveries(t.Context()); err != nil || closed != 1 {
		t.Fatalf("durable retry closed=%d err=%v", closed, err)
	}
}

func TestOrdinaryMovesAndObsoleteRecoveryNeverResetHealthyFlows(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	r, _ := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	old, next, scopes := recoveryPlans()
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	closed := 0
	_, done := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed++ })
	defer done()
	ordinary := next
	if err := r.Apply(t.Context(), ordinary); err != nil || closed != 0 {
		t.Fatal("ordinary move reset accepted TCP")
	}
	// A stale reset intent cannot claim a source/client or old outbound that
	// was not serving this client in the previous applied generation.
	for _, mutate := range []func(*FlowRecovery){
		func(q *FlowRecovery) { q.SourceCIDR = "10.44.0.3/32" },
		func(q *FlowRecovery) { q.ClientID = "other" },
		func(q *FlowRecovery) { q.FailedOutbound = "unrelated" },
	} {
		bad := next
		bad.Generation = 3
		badScopes := append([]FlowRecovery(nil), scopes...)
		mutate(&badScopes[0])
		if err := r.ApplyWithRecovery(t.Context(), bad, badScopes); err == nil {
			t.Fatalf("unsafe scope accepted: %+v", badScopes)
		}
	}
}

func TestPendingRecoveryIsDroppedWhenClientReusesFailedRoute(t *testing.T) {
	a := &recoveryAdapter{registry: xrayflow.NewRegistry()}
	r, _ := NewReconciler(a, filepath.Join(t.TempDir(), "applied.json"))
	old, next, scopes := recoveryPlans()
	_ = r.Apply(t.Context(), old)
	a.unavailable = true
	if err := r.ApplyWithRecovery(t.Context(), next, scopes); err != nil {
		t.Fatal(err)
	}
	old.Generation = 3
	if err := r.Apply(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	closed := 0
	_, done := a.registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed++ })
	defer done()
	a.unavailable = false
	if err := r.RetryFlowRecoveries(t.Context()); err != nil || closed != 0 {
		t.Fatalf("stale recovery reset new healthy flow: %v", err)
	}
}
