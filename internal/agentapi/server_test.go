package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAgentAPIAppliesVersionedPlan(t *testing.T) {
	applier := &recordingApplier{}
	handler := NewServer(applier, 64*1024)
	plan := dataplane.DesiredPlan{
		Generation:     7,
		Outbounds:      []dataplane.Outbound{{ID: "vless", Protocol: dataplane.ProtocolVLESS}},
		Clients:        []dataplane.ClientRoute{{ClientID: "alice", TCPOutbound: "vless", UDPOutbound: "vless"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	body, _ := json.Marshal(plan)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(applier.plans) != 1 || applier.plans[0].Generation != 7 {
		t.Fatalf("plans=%+v", applier.plans)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusOK || !bytes.Contains(healthResponse.Body.Bytes(), []byte(`"api_version":"v1"`)) {
		t.Fatalf("health status=%d body=%s", healthResponse.Code, healthResponse.Body.String())
	}
}

func TestAgentAPIReturnsRetryableStatusWhileRuntimeRecovers(t *testing.T) {
	handler := NewServer(applierFunc(func(context.Context, dataplane.DesiredPlan) error {
		return fmt.Errorf("wrapped: %w", dataplane.ErrRuntimeRecovering)
	}), 64*1024)
	plan := dataplane.DesiredPlan{
		Generation:     7,
		Outbounds:      []dataplane.Outbound{{ID: "vless", Protocol: dataplane.ProtocolVLESS}},
		Clients:        []dataplane.ClientRoute{{ClientID: "alice", TCPOutbound: "vless", UDPOutbound: "vless"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	body, _ := json.Marshal(plan)
	request := httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s want=%d", response.Code, response.Body.String(), http.StatusServiceUnavailable)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(dataplane.ErrRuntimeRecovering.Error())) {
		t.Fatalf("response omitted non-secret recovery error: %s", response.Body.String())
	}
}

func TestAgentAPIReturnsMarkedRetryableStatusForTemporaryApplyFailure(t *testing.T) {
	handler := NewServer(applierFunc(func(context.Context, dataplane.DesiredPlan) error {
		return fmt.Errorf("reconcile routes: %w",
			dataplane.MarkTemporary(errors.New("xray route API unavailable")))
	}), 64*1024)
	body, _ := json.Marshal(dataplane.DesiredPlan{Generation: 7})
	request := httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s want=%d",
			response.Code, response.Body.String(), http.StatusServiceUnavailable)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"retryable":true`)) ||
		!bytes.Contains(response.Body.Bytes(), []byte("xray route API unavailable")) {
		t.Fatalf("response omitted retry marker or cause: %s", response.Body.String())
	}
}

func TestAgentAPIKeepsPermanentApplyFailureNonRetryable(t *testing.T) {
	handler := NewServer(applierFunc(func(context.Context, dataplane.DesiredPlan) error {
		return errors.New("invalid desired plan")
	}), 64*1024)
	body, _ := json.Marshal(dataplane.DesiredPlan{Generation: 7})
	request := httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		bytes.Contains(response.Body.Bytes(), []byte(`"retryable":true`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAgentHealthWaitsForManagedDataplane(t *testing.T) {
	runtime := runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{
		Status: "starting",
		Epoch:  3,
	}}
	handler := NewServer(
		&recordingApplier{},
		1024,
		WithReadiness(func(context.Context) error {
			return errors.New("xray APIs are not listening")
		}),
		WithProbeRuntime(runtime),
	)
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"probe_runtime":{"status":"starting","epoch":3`)) {
		t.Fatalf("starting health omitted probe runtime: %s", response.Body.String())
	}
}

func TestAgentHealthIncludesOnlyNonSecretProbeRuntimeSnapshot(t *testing.T) {
	runtime := runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{
		Status:            "ready",
		Epoch:             7,
		RSSBytes:          123456,
		FDCount:           42,
		CompletedProbes:   19,
		RecycleCount:      2,
		LastRecycleReason: "probe_limit",
	}}
	handler := NewServer(
		&recordingApplier{},
		1024,
		WithProbeRuntime(runtime),
	)
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Status       string                `json:"status"`
		APIVersion   string                `json:"api_version"`
		ProbeRuntime proberuntime.Snapshot `json:"probe_runtime"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != "ok" || payload.APIVersion != "v1" ||
		payload.ProbeRuntime != runtime.snapshot {
		t.Fatalf("health payload=%+v", payload)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"candidate"`),
		[]byte(`"payload"`),
		[]byte(`"endpoint"`),
		[]byte(`"api_address"`),
		[]byte(`"config_path"`),
	} {
		if bytes.Contains(response.Body.Bytes(), forbidden) {
			t.Fatalf("health leaked forbidden field %s: %s", forbidden, response.Body.String())
		}
	}
}

func TestAgentHealthIncludesDedicatedActiveProbeRuntimeSnapshot(t *testing.T) {
	probeRuntime := runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{
		Status: "ready", Epoch: 7, CompletedProbes: 19,
	}}
	activeRuntime := runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{
		Status: "ready", Epoch: 3, CompletedProbes: 411,
	}}
	handler := NewServer(
		&recordingApplier{},
		1024,
		WithProbeRuntime(probeRuntime),
		WithActiveProbeRuntime(activeRuntime),
	)
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		ProbeRuntime       proberuntime.Snapshot `json:"probe_runtime"`
		ActiveProbeRuntime proberuntime.Snapshot `json:"active_probe_runtime"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProbeRuntime != probeRuntime.snapshot ||
		payload.ActiveProbeRuntime != activeRuntime.snapshot {
		t.Fatalf("health payload=%+v", payload)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"candidate"`), []byte(`"payload"`), []byte(`"endpoint"`),
		[]byte(`"api_address"`), []byte(`"config_path"`),
	} {
		if bytes.Contains(response.Body.Bytes(), forbidden) {
			t.Fatalf("health leaked forbidden field %s: %s", forbidden, response.Body.String())
		}
	}
}

func TestAgentAPIExposesReadOnlyWireGuardActivity(t *testing.T) {
	provider := activityProviderFunc(func(context.Context) ([]wireguard.PeerActivity, error) {
		return []wireguard.PeerActivity{{PublicKey: "peer-a", RXBytes: 10, TXBytes: 20}}, nil
	})
	handler := NewServer(&recordingApplier{}, 1024, WithActivityProvider(provider))
	request := httptest.NewRequest(http.MethodGet, "/v1/activity", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"public_key":"peer-a"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAgentAPIProvisionsAndPausesWireGuardPeer(t *testing.T) {
	manager := &peerManagerRecorder{}
	handler := NewServer(&recordingApplier{}, 4096, WithPeerManager(manager))
	create := httptest.NewRequest(http.MethodPost, "/v1/peers", bytes.NewBufferString(`{"name":"phone","address":"10.44.0.3/32"}`))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated || !bytes.Contains(createResponse.Body.Bytes(), []byte(`"config":"wg-config"`)) {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	state := httptest.NewRequest(http.MethodPost, "/v1/peer-state", bytes.NewBufferString(`{"peer":{"name":"phone","address":"10.44.0.3/32","public_key":"public"},"paused":true}`))
	stateResponse := httptest.NewRecorder()
	handler.ServeHTTP(stateResponse, state)
	if stateResponse.Code != http.StatusNoContent || !manager.paused {
		t.Fatalf("state status=%d manager=%+v", stateResponse.Code, manager)
	}
}

func TestAgentAPIReconcilesTorProfiles(t *testing.T) {
	manager := &profileManagerRecorder{}
	handler := NewServer(&recordingApplier{}, 4096, WithProfileManager(manager))
	request := httptest.NewRequest(http.MethodPost, "/v1/profiles/reconcile", bytes.NewBufferString(`{"candidates":[{"id":"bridge","bridge":"Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567","score":90,"qualified":true}]}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(manager.candidates) != 1 {
		t.Fatalf("status=%d manager=%+v", response.Code, manager)
	}
}

func TestAgentAPIRejectsUnknownFields(t *testing.T) {
	applier := &recordingApplier{}
	handler := NewServer(applier, 1024)
	request := httptest.NewRequest(http.MethodPost, "/v1/plan", bytes.NewBufferString(`{"generation":1,"unknown":true}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(applier.plans) != 0 {
		t.Fatalf("status=%d plans=%+v", response.Code, applier.plans)
	}
}

type recordingApplier struct{ plans []dataplane.DesiredPlan }

func (applier *recordingApplier) Apply(_ context.Context, plan dataplane.DesiredPlan) error {
	applier.plans = append(applier.plans, plan)
	return nil
}

type applierFunc func(context.Context, dataplane.DesiredPlan) error

func (function applierFunc) Apply(ctx context.Context, plan dataplane.DesiredPlan) error {
	return function(ctx, plan)
}

type activityProviderFunc func(context.Context) ([]wireguard.PeerActivity, error)

func (function activityProviderFunc) Snapshot(ctx context.Context) ([]wireguard.PeerActivity, error) {
	return function(ctx)
}

type runtimeSnapshotProvider struct {
	snapshot proberuntime.Snapshot
}

func (provider runtimeSnapshotProvider) Snapshot() proberuntime.Snapshot {
	return provider.snapshot
}

type peerManagerRecorder struct{ paused bool }

func (*peerManagerRecorder) Create(_ context.Context, name, address string) (wireguard.Peer, string, error) {
	return wireguard.Peer{Name: name, Address: address, PublicKey: "public"}, "wg-config", nil
}

type profileManagerRecorder struct{ candidates []torpool.Candidate }

func (manager *profileManagerRecorder) Reconcile(_ context.Context, candidates []torpool.Candidate) ([]torpool.Profile, error) {
	manager.candidates = candidates
	return []torpool.Profile{{CandidateID: candidates[0].ID}}, nil
}
func (*profileManagerRecorder) Profiles() []torpool.Profile { return nil }
func (*profileManagerRecorder) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return nil, nil
}
func (manager *peerManagerRecorder) SetPaused(_ context.Context, _ wireguard.Peer, paused bool) error {
	manager.paused = paused
	return nil
}

type fakeGeoManager struct {
	status  GeoAssetStatus
	updated bool
	forced  bool
}

func (f *fakeGeoManager) Status() GeoAssetStatus {
	return f.status
}

func (f *fakeGeoManager) UpdateConfig(enabled, autoUpdate bool, geoIPURL, geoSiteURL string, updateInterval time.Duration) error {
	f.updated = true
	f.status.Enabled = enabled
	f.status.AutoUpdate = autoUpdate
	if geoIPURL != "" {
		f.status.GeoIPURL = geoIPURL
	}
	if geoSiteURL != "" {
		f.status.GeoSiteURL = geoSiteURL
	}
	if updateInterval > 0 {
		f.status.UpdateInterval = updateInterval.String()
	}
	return nil
}

func (f *fakeGeoManager) ForceUpdate(ctx context.Context) error {
	f.forced = true
	return nil
}

func TestAgentAPIGeoEndpoints(t *testing.T) {
	geo := &fakeGeoManager{
		status: GeoAssetStatus{
			Enabled:        true,
			AutoUpdate:     true,
			GeoIPURL:       "https://example.com/geoip.dat",
			GeoSiteURL:     "https://example.com/geosite.dat",
			UpdateInterval: "24h0m0s",
			GeoIPExists:    true,
			GeoIPSize:      1000,
		},
	}
	server := NewServer(&recordingApplier{}, 1024, WithGeoManager(geo))

	// Test GET /v1/geo
	req := httptest.NewRequest(http.MethodGet, "/v1/geo", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/geo status=%d", rec.Code)
	}
	var status GeoAssetStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.GeoIPSize != 1000 {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Test POST /v1/geo/update
	updateBody := `{"geoip_url":"https://new.example.com/geoip.dat","force":true}`
	req = httptest.NewRequest(http.MethodPost, "/v1/geo/update", bytes.NewBufferString(updateBody))
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/geo/update status=%d", rec.Code)
	}
	if !geo.updated || !geo.forced || geo.status.GeoIPURL != "https://new.example.com/geoip.dat" {
		t.Fatalf("geo update not applied: %+v", geo)
	}
}
