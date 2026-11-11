package portal

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestI2PPermissionAdminOnlyOptionalAndStatus(t *testing.T) {
	db := testStore(t)
	ctx := context.Background()
	if err := db.PutClient(ctx, store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "config"); err != nil {
		t.Fatal(err)
	}
	changes := make(chan struct{}, 10)
	h := New(ServerConfig{Store: db, AdminPassword: "admin", ClientChanges: changes})
	patch := func(body string, admin bool) int {
		r := httptest.NewRequest(http.MethodPatch, "/api/admin/clients/alice", strings.NewReader(body))
		if admin {
			r.Header.Set("X-Hydrat-Admin-Password", "admin")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := patch(`{"i2p_enabled":true}`, false); code != 401 {
		t.Fatal(code)
	}
	if code := patch(`{"i2p_enabled":true}`, true); code != 204 {
		t.Fatal(code)
	}
	if code := patch(`{"name":"renamed"}`, true); code != 204 {
		t.Fatal(code)
	}
	clients, _ := db.ListClients(ctx)
	if !clients[0].I2PEnabled || len(changes) != 1 {
		t.Fatal(clients, changes)
	}
	get := func() map[string]any {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.RemoteAddr = "10.44.0.2:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var v map[string]any
		json.Unmarshal(w.Body.Bytes(), &v)
		return v
	}
	if v := get(); v["i2p_status"] != "pending" {
		t.Fatal(v)
	}
	if code := patch(`{"i2p_enabled":false}`, true); code != 204 {
		t.Fatal(code)
	}
	if v := get(); v["i2p_status"] != "disabled" {
		t.Fatal(v)
	}
}
func TestI2PManagementNeverBypassesAdmin(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })
	h := New(ServerConfig{Store: testStore(t), AdminPassword: "admin", I2P: handler})
	for _, path := range []string{"/api/admin/i2p", "/api/admin/i2p/entries", "/api/admin/i2p/subscriptions/x/refresh"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 || called {
			t.Fatal("management exposed", path, w.Code)
		}
	}
}
