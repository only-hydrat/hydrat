package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestClientPortalReturnsTCPAndUDPAssignments(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	if err := database.PutClient(context.Background(), store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer",
	}, "[Interface]\nPrivateKey = secret\n"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
		ClientID: "alice", TCPOutbound: "tor-fast", UDPOutbound: "vless-fast", TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	reassigner := &reassignRecorder{}
	handler := New(ServerConfig{Store: database, AdminPassword: "admin", Reassigner: reassigner})

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.RemoteAddr = "10.44.0.2:54321"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &me)
	if me["assignment"] != "tor-fast" || me["tcp_assignment"] != "tor-fast" || me["udp_assignment"] != "vless-fast" {
		t.Fatalf("me=%+v", me)
	}

	reassignRequest := httptest.NewRequest(http.MethodPost, "/api/me/reassign", nil)
	reassignRequest.RemoteAddr = "10.44.0.2:54321"
	reassignRequest.Header.Set("X-Hydrat-Action", "reassign")
	reassignResponse := httptest.NewRecorder()
	handler.ServeHTTP(reassignResponse, reassignRequest)
	if reassignResponse.Code != http.StatusAccepted || reassigner.clientID != "alice" {
		t.Fatalf("reassign status=%d client=%s", reassignResponse.Code, reassigner.clientID)
	}
}

func TestClientPortalReturnsCandidateLabelAndKind(t *testing.T) {
	database := testStore(t)
	now := time.Now()
	if err := database.PutClient(context.Background(), store.ClientRecord{
		ID: "bob", Name: "Bob", Address: "10.44.0.3/32", PublicKey: "peer-bob",
	}, "config"); err != nil {
		t.Fatal(err)
	}
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls#Sweden-Proxy\nBridge 192.0.2.2:443 0123456789ABCDEF0123456789ABCDEF01234567")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listedSources, _ := database.ListSources(context.Background())
	if err := database.ReplaceCandidates(context.Background(), listedSources[0].ID, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "Sweden-Proxy", Fingerprint: "fp-vless", Payload: "vless://id@example.net:443?security=tls#Sweden-Proxy"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.ReplaceCandidates(context.Background(), listedSources[1].ID, []store.CandidateInput{
		{Kind: sources.KindTorBridge, Label: "Tor-Bridge-1", Fingerprint: "fp-tor", Payload: "Bridge 192.0.2.2:443 0123456789ABCDEF0123456789ABCDEF01234567"},
	}); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(context.Background(), "")
	var vlessID, torID string
	for _, c := range candidates {
		if c.Kind == sources.KindVLESS {
			vlessID = c.ID
		} else if c.Kind == sources.KindTorBridge {
			torID = c.ID
		}
	}
	if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
		ClientID: "bob", TCPOutbound: vlessID, UDPOutbound: vlessID, TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.RemoteAddr = "10.44.0.3:12345"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &me)
	if me["tcp_label"] != "Sweden-Proxy" || me["tcp_kind"] != "vless" {
		t.Errorf("tcp details=%+v, want Sweden-Proxy/vless", me)
	}
	if me["udp_label"] != "Sweden-Proxy" || me["udp_kind"] != "vless" {
		t.Errorf("udp details=%+v, want Sweden-Proxy/vless", me)
	}

	// Test Tor TCP assignment
	if err := database.SetAssignment(context.Background(), store.AssignmentRecord{
		ClientID: "bob", TCPOutbound: torID, UDPOutbound: "", TCPSince: now, UDPSince: now,
	}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	_ = json.Unmarshal(response.Body.Bytes(), &me)
	if me["tcp_label"] != "Tor-Bridge-1" || me["tcp_kind"] != "tor_bridge" {
		t.Errorf("tor tcp details=%+v, want Tor-Bridge-1/tor_bridge", me)
	}
}

func TestClientIdentityRequiresTrustedGatewayToken(t *testing.T) {
	database := testStore(t)
	if err := database.PutClient(context.Background(), store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer",
	}, "config"); err != nil {
		t.Fatal(err)
	}
	handler := New(ServerConfig{
		Store: database, AdminPassword: "admin", InternalToken: "trusted-token",
	})
	forged := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	forged.RemoteAddr = "172.30.0.10:40000"
	forged.Header.Set("X-Hydrat-Internal-Token", "wrong")
	forged.Header.Set("X-Hydrat-Client-IP", "10.44.0.2")
	forgedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forgedResponse, forged)
	if forgedResponse.Code != http.StatusNotFound {
		t.Fatalf("forged status=%d body=%s", forgedResponse.Code, forgedResponse.Body.String())
	}

	trusted := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	trusted.RemoteAddr = "172.30.0.10:40000"
	trusted.Header.Set("X-Hydrat-Internal-Token", "trusted-token")
	trusted.Header.Set("X-Hydrat-Client-IP", "10.44.0.2")
	trustedResponse := httptest.NewRecorder()
	handler.ServeHTTP(trustedResponse, trusted)
	if trustedResponse.Code != http.StatusOK {
		t.Fatalf("trusted status=%d body=%s", trustedResponse.Code, trustedResponse.Body.String())
	}
}

func TestRequestSource(t *testing.T) {
	server := New(ServerConfig{InternalToken: "trusted-token"}).(*Server)
	for _, test := range []struct {
		name, remote, token, clientIP, want string
	}{
		{"direct", "192.0.2.10:40000", "", "", "192.0.2.10"},
		{"untrusted header", "192.0.2.10:40000", "wrong", "10.44.0.2", "192.0.2.10"},
		{"trusted client", "172.30.0.10:40000", "trusted-token", "10.44.0.2", "10.44.0.2"},
		{"malformed trusted client", "172.30.0.10:40000", "trusted-token", "not-an-ip", "172.30.0.10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-Hydrat-Internal-Token", test.token)
			request.Header.Set("X-Hydrat-Client-IP", test.clientIP)
			if got := server.requestSource(request); got != test.want {
				t.Fatalf("source=%q want=%q", got, test.want)
			}
		})
	}
}

func TestGatewayClientsHaveIndependentLimiterBudgets(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "secret", InternalToken: "trusted-token"})
	handler.(*Server).auth = newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	for attempt := 0; attempt < maxAdminFailures; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
		request.RemoteAddr = "172.30.0.10:40000"
		request.Header.Set("X-Hydrat-Internal-Token", "trusted-token")
		request.Header.Set("X-Hydrat-Client-IP", "10.44.0.2")
		request.Header.Set("X-Hydrat-Admin-Password", "wrong")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt=%d status=%d", attempt+1, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
	request.RemoteAddr = "172.30.0.10:40000"
	request.Header.Set("X-Hydrat-Internal-Token", "trusted-token")
	request.Header.Set("X-Hydrat-Client-IP", "10.44.0.3")
	request.Header.Set("X-Hydrat-Admin-Password", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("second client status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminClientConfigAndQRNeverAppearInList(t *testing.T) {
	database := testStore(t)
	_ = database.PutClient(context.Background(), store.ClientRecord{
		ID: "alice", Name: "Alice", Address: "10.44.0.2/32", PublicKey: "peer",
	}, "[Interface]\nPrivateKey = secret\n")
	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})

	listed := adminRequest(t, handler, http.MethodGet, "/api/admin/clients", "admin", nil)
	if listed.Code != http.StatusOK || bytes.Contains(listed.Body.Bytes(), []byte("PrivateKey")) {
		t.Fatalf("unsafe list status=%d body=%s", listed.Code, listed.Body.String())
	}
	config := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/alice/config", "admin", nil)
	if config.Code != http.StatusOK || !bytes.Contains(config.Body.Bytes(), []byte("PrivateKey")) {
		t.Fatalf("config status=%d body=%s", config.Code, config.Body.String())
	}
	qr := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/alice/qr", "admin", nil)
	if qr.Code != http.StatusOK || !bytes.HasPrefix(qr.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("QR status=%d content-type=%s prefix=%x", qr.Code, qr.Header().Get("Content-Type"), qr.Body.Bytes()[:min(8, qr.Body.Len())])
	}
}

func TestDashboardIsServedWithoutExternalAssets(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin"})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("Hydrat")) || bytes.Contains(response.Body.Bytes(), []byte("https://")) ||
		!bytes.Contains(response.Body.Bytes(), []byte(`id="source-input"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`id="admin-clients"`)) {
		t.Fatalf("dashboard status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminCreatePauseResumeRenameDeleteFlow(t *testing.T) {
	database := testStore(t)
	provisioner := &provisionRecorder{}
	clientChanges := make(chan struct{}, 8)
	handler := New(ServerConfig{
		Store: database, AdminPassword: "admin", Provisioner: provisioner,
		ClientChanges: clientChanges,
	})
	created := adminRequest(t, handler, http.MethodPost, "/api/admin/clients", "admin", map[string]string{"name": "phone"})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	for _, action := range []string{"pause", "resume"} {
		response := adminRequest(t, handler, http.MethodPost, "/api/admin/clients/phone/"+action, "admin", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
		}
	}
	patched := adminRequest(t, handler, http.MethodPatch, "/api/admin/clients/phone", "admin", map[string]any{"name": "phone", "paused": true})
	if patched.Code != http.StatusNoContent || provisioner.pauseCalls != 3 || !provisioner.lastPaused {
		t.Fatalf("patch status=%d provisioner=%+v", patched.Code, provisioner)
	}
	renamed := adminRequest(t, handler, http.MethodPost, "/api/admin/clients/phone/rename", "admin", map[string]string{"name": "tablet"})
	if renamed.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", renamed.Code, renamed.Body.String())
	}
	artifact := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/tablet/config.json", "admin", nil)
	if artifact.Code != http.StatusOK || !bytes.Contains(artifact.Body.Bytes(), []byte(`"config"`)) {
		t.Fatalf("artifact status=%d body=%s", artifact.Code, artifact.Body.String())
	}
	deleted := adminRequest(t, handler, http.MethodDelete, "/api/admin/clients/tablet", "admin", nil)
	if deleted.Code != http.StatusNoContent || provisioner.deleted != "tablet" {
		t.Fatalf("delete status=%d provisioner=%+v", deleted.Code, provisioner)
	}
	if got := len(clientChanges); got != 5 {
		t.Fatalf("client lifecycle signals=%d, want 5", got)
	}
}
func TestPortalServesNormalizedEndpointForExistingStoredProfiles(t *testing.T) {
	database := testStore(t)
	oldProfile := "[Interface]\nPrivateKey = secret-key-1\nAddress = 10.44.0.5/32\nDNS = 10.44.0.1\nMTU = 1420\n\n[Peer]\nPublicKey = server-pubkey-1\nEndpoint = 203.0.113.10\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	_ = database.PutClient(context.Background(), store.ClientRecord{
		ID: "client-with-endpoint", Name: "Phone", Address: "10.44.0.5/32", PublicKey: "pub1",
	}, oldProfile)

	noEndpointProfile := "[Interface]\nPrivateKey = secret-key-2\nAddress = 10.44.0.6/32\n"
	_ = database.PutClient(context.Background(), store.ClientRecord{
		ID: "client-no-endpoint", Name: "Laptop", Address: "10.44.0.6/32", PublicKey: "pub2",
	}, noEndpointProfile)

	handler := New(ServerConfig{
		Store:             database,
		AdminPassword:     "admin",
		WireGuardEndpoint: "203.0.113.10:51820",
	})

	// 1. Text config download
	configResp := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/client-with-endpoint/config", "admin", nil)
	if configResp.Code != http.StatusOK {
		t.Fatalf("config status=%d body=%s", configResp.Code, configResp.Body.String())
	}
	bodyText := configResp.Body.String()
	if !bytes.Contains([]byte(bodyText), []byte("Endpoint = 203.0.113.10:51820\n")) {
		t.Fatalf("config text missing normalized endpoint, got:\n%s", bodyText)
	}
	if bytes.Contains([]byte(bodyText), []byte("Endpoint = 203.0.113.10\n")) {
		t.Fatalf("config text still contains un-normalized IP-only endpoint:\n%s", bodyText)
	}
	if !bytes.Contains([]byte(bodyText), []byte("PrivateKey = secret-key-1")) ||
		!bytes.Contains([]byte(bodyText), []byte("Address = 10.44.0.5/32")) ||
		!bytes.Contains([]byte(bodyText), []byte("AllowedIPs = 0.0.0.0/0")) {
		t.Fatalf("config text corrupted other fields:\n%s", bodyText)
	}

	// 2. Config JSON download
	jsonResp := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/client-with-endpoint/config.json", "admin", nil)
	if jsonResp.Code != http.StatusOK {
		t.Fatalf("json status=%d body=%s", jsonResp.Code, jsonResp.Body.String())
	}
	var payload struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(jsonResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if !bytes.Contains([]byte(payload.Config), []byte("Endpoint = 203.0.113.10:51820\n")) {
		t.Fatalf("json config missing normalized endpoint, got:\n%s", payload.Config)
	}

	// 3. QR download
	qrResp := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/client-with-endpoint/qr", "admin", nil)
	if qrResp.Code != http.StatusOK || !bytes.HasPrefix(qrResp.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("qr status=%d prefix=%x", qrResp.Code, qrResp.Body.Bytes()[:min(8, qrResp.Body.Len())])
	}

	// 4. Verify stored profile in database was NOT overwritten
	storedInDB, err := database.ClientConfig(context.Background(), "client-with-endpoint")
	if err != nil {
		t.Fatalf("database ClientConfig: %v", err)
	}
	if storedInDB != oldProfile {
		t.Fatalf("stored database profile was mutated:\n%s\nwant original:\n%s", storedInDB, oldProfile)
	}

	// 5. Verify profile without Endpoint line is served completely unchanged
	noEndpointResp := adminRequest(t, handler, http.MethodGet, "/api/admin/clients/client-no-endpoint/config", "admin", nil)
	if noEndpointResp.Code != http.StatusOK {
		t.Fatalf("noEndpoint status=%d body=%s", noEndpointResp.Code, noEndpointResp.Body.String())
	}
	if noEndpointResp.Body.String() != noEndpointProfile {
		t.Fatalf("noEndpoint config was altered:\n%s\nwant:\n%s", noEndpointResp.Body.String(), noEndpointProfile)
	}
}

type reassignRecorder struct{ clientID string }

func (recorder *reassignRecorder) Reassign(_ context.Context, clientID string) error {
	recorder.clientID = clientID
	return nil
}

type provisionRecorder struct {
	deleted    string
	pauseCalls int
	lastPaused bool
}

func (recorder *provisionRecorder) Create(_ context.Context, name string) (store.ClientRecord, string, error) {
	return store.ClientRecord{ID: name, Name: name, Address: "10.44.0.3/32", PublicKey: "public"}, "[Interface]\nPrivateKey = private\n", nil
}

func (recorder *provisionRecorder) SetPaused(_ context.Context, _ store.ClientRecord, paused bool) error {
	recorder.pauseCalls++
	recorder.lastPaused = paused
	return nil
}
func (recorder *provisionRecorder) Delete(_ context.Context, client store.ClientRecord) error {
	recorder.deleted = client.Name
	return nil
}
