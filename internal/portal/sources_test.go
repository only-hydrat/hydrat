package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestAdminSourcePreviewImportAndCRUD(t *testing.T) {
	database := testStore(t)
	changes := make(chan struct{}, 1)
	server := New(ServerConfig{Store: database, AdminPassword: "correct horse", SourceChanges: changes})

	secretURI := "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?security=tls#fast"
	preview := adminRequest(t, server, http.MethodPost, "/api/admin/sources/preview", "correct horse", map[string]string{"input": secretURI})
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	if strings.Contains(preview.Body.String(), "550e8400") {
		t.Fatalf("preview leaked source credential: %s", preview.Body.String())
	}

	imported := adminRequest(t, server, http.MethodPost, "/api/admin/sources/import", "correct horse", map[string]string{"input": secretURI})
	if imported.Code != http.StatusCreated {
		t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
	}
	select {
	case <-changes:
	default:
		t.Fatal("source import did not trigger refresh and qualification")
	}

	listed := adminRequest(t, server, http.MethodGet, "/api/admin/sources", "correct horse", nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "550e8400") {
		t.Fatalf("unsafe source list: status=%d body=%s", listed.Code, listed.Body.String())
	}
	var response struct {
		Sources []store.Source `json:"sources"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &response); err != nil || len(response.Sources) != 1 {
		t.Fatalf("decode list: %+v, %v", response, err)
	}
	id := response.Sources[0].ID

	updated := adminRequest(t, server, http.MethodPatch, "/api/admin/sources/"+id, "correct horse", map[string]any{"label": "Fast", "enabled": false})
	if updated.Code != http.StatusNoContent {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	deleted := adminRequest(t, server, http.MethodDelete, "/api/admin/sources/"+id, "correct horse", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestAdminSourceAPIRequiresPasswordAndLimitsBody(t *testing.T) {
	database := testStore(t)
	server := New(ServerConfig{Store: database, AdminPassword: "secret", MaxBodyBytes: 32})

	unauthorized := adminRequest(t, server, http.MethodGet, "/api/admin/sources", "wrong", nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	oversized := adminRequest(t, server, http.MethodPost, "/api/admin/sources/preview", "secret", map[string]string{"input": strings.Repeat("x", 100)})
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d body=%s", oversized.Code, oversized.Body.String())
	}
}

func TestAdminDeleteSourceUsesConfiguredStableRetirementGrace(t *testing.T) {
	database := testStore(t)
	ctx := context.Background()
	preview := sources.PreviewInput(
		"vless://delete@example.net:443?security=tls",
	)
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	if err := database.ReplaceCandidates(
		ctx,
		listed[0].ID,
		[]store.CandidateInput{{
			Kind: sources.KindVLESS, Label: "delete",
			Fingerprint: "delete", Payload: "vless://secret@example.net:443",
		}},
	); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, listed[0].ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	server := New(ServerConfig{
		Store: database, AdminPassword: "admin",
		RetirementGrace: 3 * time.Second,
	})
	before := time.Now().Unix()
	deleted := adminRequest(
		t, server, http.MethodDelete,
		"/api/admin/sources/"+listed[0].ID, "admin", nil,
	)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s",
			deleted.Code, deleted.Body.String())
	}
	candidate, err := database.CandidateForRetirement(
		ctx, candidates[0].ID,
	)
	if err != nil || candidate.DrainAfter == nil {
		t.Fatalf("draining candidate=%+v err=%v", candidate, err)
	}
	if *candidate.DrainAfter < before+3 ||
		*candidate.DrainAfter > time.Now().Unix()+3 {
		t.Fatalf("drain_after=%d outside configured 3s window",
			*candidate.DrainAfter)
	}
	stable := *candidate.DrainAfter
	repeated := adminRequest(
		t, server, http.MethodDelete,
		"/api/admin/sources/"+listed[0].ID, "admin", nil,
	)
	if repeated.Code != http.StatusNoContent {
		t.Fatalf("repeated delete status=%d body=%s",
			repeated.Code, repeated.Body.String())
	}
	candidate, err = database.CandidateForRetirement(
		ctx, candidates[0].ID,
	)
	if err != nil || candidate.DrainAfter == nil ||
		*candidate.DrainAfter != stable {
		t.Fatalf("repeated delete extended deadline: %+v err=%v",
			candidate, err)
	}
}

func TestServerDefaultsInvalidRetirementGraceForLegacyConstruction(t *testing.T) {
	for _, grace := range []time.Duration{
		0,
		-time.Second,
		500 * time.Millisecond,
	} {
		handler := New(ServerConfig{
			Store: testStore(t), RetirementGrace: grace,
		})
		server, ok := handler.(*Server)
		if !ok {
			t.Fatalf("handler type=%T", handler)
		}
		if server.retirementGrace != defaultRetirementGrace {
			t.Fatalf("grace=%s defaulted to %s",
				grace, server.retirementGrace)
		}
	}
}

func TestAdminCanRefreshSourceAndRotateTorExplorer(t *testing.T) {
	database := testStore(t)
	preview := sources.PreviewInput("vless://id@example.net:443?security=tls")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	refresher := &refreshRecorder{}
	profiles := &profileRecorder{}
	server := New(ServerConfig{Store: database, AdminPassword: "admin", Refresher: refresher, Profiles: profiles})
	refresh := adminRequest(t, server, http.MethodPost, "/api/admin/sources/"+listed[0].ID+"/refresh", "admin", nil)
	if refresh.Code != http.StatusOK || refresher.sourceID != listed[0].ID {
		t.Fatalf("refresh status=%d source=%s", refresh.Code, refresher.sourceID)
	}
	explore := adminRequest(t, server, http.MethodPost, "/api/admin/profiles/explore", "admin", nil)
	if explore.Code != http.StatusOK || profiles.rotations != 1 {
		t.Fatalf("explore status=%d rotations=%d", explore.Code, profiles.rotations)
	}
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func adminRequest(t *testing.T, handler http.Handler, method, path, password string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hydrat-Admin-Password", password)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type refreshRecorder struct{ sourceID string }

func (recorder *refreshRecorder) Source(_ context.Context, sourceID string) error {
	recorder.sourceID = sourceID
	return nil
}

type profileRecorder struct{ rotations int }

func (*profileRecorder) Profiles() []torpool.Profile { return nil }
func (recorder *profileRecorder) ExploreNext(context.Context) ([]torpool.Profile, error) {
	recorder.rotations++
	return nil, nil
}
