package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func TestConcurrentPlanHTTPRequestsSerializeWholeReconcileTransaction(t *testing.T) {
	adapter := newHTTPControlledAdapter()
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, err := dataplane.NewReconciler(adapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewServer(reconciler, 64*1024))
	defer server.Close()
	if status, err := postPlan(server.URL, httpTestPlan(1, "g1")); err != nil || status != http.StatusNoContent {
		t.Fatalf("generation 1 status=%d error=%v", status, err)
	}

	type response struct {
		status int
		err    error
	}
	g2Result := make(chan response, 1)
	go func() {
		status, postErr := postPlan(server.URL, httpTestPlan(2, "g2"))
		g2Result <- response{status: status, err: postErr}
	}()
	select {
	case <-adapter.g2Entered:
	case <-time.After(time.Second):
		t.Fatal("generation 2 did not enter staged replacement")
	}
	g3Result := make(chan response, 1)
	go func() {
		status, postErr := postPlan(server.URL, httpTestPlan(3, "g3"))
		g3Result <- response{status: status, err: postErr}
	}()
	interleaved := false
	select {
	case <-adapter.g3Touched:
		interleaved = true
	case <-time.After(150 * time.Millisecond):
	}
	close(adapter.releaseG2)
	for generation, result := range map[int]<-chan response{2: g2Result, 3: g3Result} {
		got := <-result
		if got.err != nil || got.status != http.StatusNoContent {
			t.Fatalf("generation %d status=%d error=%v", generation, got.status, got.err)
		}
	}
	if interleaved {
		t.Fatal("generation 3 HTTP request touched dataplane during generation 2 transaction")
	}
	adapter.mu.Lock()
	missingReference := adapter.missingReference
	lastRoute := adapter.lastRoute
	adapter.mu.Unlock()
	if missingReference || lastRoute != "g3" {
		t.Fatalf("runtime missing_reference=%t last_route=%q", missingReference, lastRoute)
	}

	restarted, err := dataplane.NewReconciler(newHTTPControlledAdapter(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	restartedServer := httptest.NewServer(NewServer(restarted, 64*1024))
	defer restartedServer.Close()
	if status, err := postPlan(restartedServer.URL, httpTestPlan(2, "g2")); err != nil || status != http.StatusConflict {
		t.Fatalf("persisted stale generation status=%d error=%v want=%d", status, err, http.StatusConflict)
	}
}

func postPlan(serverURL string, plan dataplane.DesiredPlan) (int, error) {
	body, err := json.Marshal(plan)
	if err != nil {
		return 0, err
	}
	response, err := http.Post(serverURL+"/v1/plan", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func httpTestPlan(generation int64, outboundID string) dataplane.DesiredPlan {
	return dataplane.DesiredPlan{
		Generation: generation,
		Outbounds:  []dataplane.Outbound{{ID: outboundID, Protocol: dataplane.ProtocolVLESS}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: outboundID, UDPOutbound: outboundID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
}

type httpControlledAdapter struct {
	mu               sync.Mutex
	handlers         map[string]struct{}
	lastRoute        string
	missingReference bool
	g2Entered        chan struct{}
	releaseG2        chan struct{}
	g3Touched        chan struct{}
	g2Once           sync.Once
	g3Once           sync.Once
}

func newHTTPControlledAdapter() *httpControlledAdapter {
	return &httpControlledAdapter{
		handlers:  make(map[string]struct{}),
		g2Entered: make(chan struct{}),
		releaseG2: make(chan struct{}),
		g3Touched: make(chan struct{}),
	}
}

func (adapter *httpControlledAdapter) AddOutbound(_ context.Context, outbound dataplane.Outbound) error {
	adapter.mu.Lock()
	adapter.handlers[outbound.ID] = struct{}{}
	adapter.mu.Unlock()
	if outbound.ID == "g3" {
		adapter.g3Once.Do(func() { close(adapter.g3Touched) })
	}
	return nil
}

func (*httpControlledAdapter) RouteClient(context.Context, dataplane.ClientRoute) error {
	return nil
}

func (adapter *httpControlledAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []dataplane.ClientRoute,
	desired []dataplane.ClientRoute,
	_ []dataplane.ClientRoute,
) error {
	target := desired[0].TCPOutbound
	adapter.mu.Lock()
	if _, exists := adapter.handlers[target]; !exists {
		adapter.missingReference = true
	}
	adapter.mu.Unlock()
	if target == "g2" {
		adapter.g2Once.Do(func() { close(adapter.g2Entered) })
		<-adapter.releaseG2
	}
	adapter.mu.Lock()
	if _, exists := adapter.handlers[target]; !exists {
		adapter.missingReference = true
	}
	adapter.lastRoute = target
	adapter.mu.Unlock()
	return nil
}

func (*httpControlledAdapter) DrainOutbound(context.Context, string) error {
	return nil
}

func (adapter *httpControlledAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	delete(adapter.handlers, id)
	return nil
}
