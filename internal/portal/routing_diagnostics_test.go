package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestPolicyExcludedCandidateIsNotReportedAsWaitingForProbe(t *testing.T) {
	db := testStore(t)
	ctx := context.Background()
	_, err := db.ImportSources(ctx, sources.PreviewInput("https://example.net/subscription").Items)
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := db.ListSources(ctx)
	if err := db.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{{Kind: sources.KindVLESS, Label: "foreign label", Fingerprint: "ru-host", Payload: "vless://private-uuid@node.example.ru:443"}}); err != nil {
		t.Fatal(err)
	}
	server := New(ServerConfig{Store: db, AdminPassword: "admin", Routing: &fakeRoutingProvider{state: RoutingState{DisallowRUEgress: true}}})
	response := adminRequest(t, server, http.MethodGet, "/api/admin/candidates", "admin", nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "policy_ru_egress") {
		t.Fatalf("policy reason missing: %s", response.Body)
	}
	if strings.Contains(response.Body.String(), "private-uuid") {
		t.Fatal("diagnostics exposed credentials")
	}
	response = adminRequest(t, server, http.MethodGet, "/api/admin/system", "admin", nil)
	var body struct {
		Coverage map[string]int `json:"probe_coverage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Coverage["excluded_policy"] != 1 || body.Coverage["never_attempted"] != 0 {
		t.Fatalf("excluded route inflates backlog: %+v", body.Coverage)
	}
}
