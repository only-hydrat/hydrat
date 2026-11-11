package portal

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnionPermissionAdminOnlyOptionalAndStatus(t *testing.T) {
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
	if code := patch(`{"onion_enabled":true}`, false); code != 401 {
		t.Fatal(code)
	}
	if code := patch(`{"onion_enabled":true}`, true); code != 204 {
		t.Fatal(code)
	}
	if code := patch(`{"name":"renamed"}`, true); code != 204 {
		t.Fatal(code)
	}
	clients, _ := db.ListClients(ctx)
	if !clients[0].OnionEnabled || len(changes) != 1 {
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
	if v := get(); v["onion_status"] != "pending" {
		t.Fatal(v)
	}
	if code := patch(`{"onion_enabled":false}`, true); code != 204 {
		t.Fatal(code)
	}
	if v := get(); v["onion_status"] != "disabled" {
		t.Fatal(v)
	}
}
func TestOnionStatusRequiresAppliedPermission(t *testing.T) {
	c := store.ClientRecord{ID: "a", OnionEnabled: true}
	for _, tc := range []struct {
		enabled bool
		out     string
		want    string
	}{{false, "", "pending"}, {true, "", "unavailable"}, {true, "tor", "ready"}} {
		if got := onionStatus(c, map[string]dataplane.ClientRoute{"a": {OnionEnabled: tc.enabled, OnionOutbound: tc.out}}); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	c.OnionEnabled = false
	if got := onionStatus(c, map[string]dataplane.ClientRoute{"a": {OnionEnabled: true, OnionOutbound: "tor"}}); got != "disabling" {
		t.Fatal(got)
	}
}
