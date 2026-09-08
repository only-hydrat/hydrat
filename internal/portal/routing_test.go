package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
)

type fakeRoutingProvider struct {
	state        RoutingState
	updatedInput UpdateRoutingInput
	triggered    bool
	updateError  error
	triggerError error
}

func (f *fakeRoutingProvider) GetRouting(_ context.Context) (RoutingState, error) {
	return f.state, nil
}

func (f *fakeRoutingProvider) UpdateRouting(_ context.Context, input UpdateRoutingInput) (RoutingState, error) {
	if f.updateError != nil {
		return RoutingState{}, f.updateError
	}
	f.updatedInput = input
	f.state.DirectSuffixes = input.DirectSuffixes
	f.state.DirectDomains = input.DirectDomains
	if input.GeoRules != nil {
		f.state.GeoRules = GeoRulesView{
			Enabled:        input.GeoRules.Enabled,
			AutoUpdate:     input.GeoRules.AutoUpdate,
			GeoIPURL:       input.GeoRules.GeoIPURL,
			GeoSiteURL:     input.GeoRules.GeoSiteURL,
			UpdateInterval: input.GeoRules.UpdateInterval,
		}
	}
	return f.state, nil
}

func (f *fakeRoutingProvider) TriggerGeoUpdate(_ context.Context) (agentapi.GeoAssetStatus, error) {
	if f.triggerError != nil {
		return agentapi.GeoAssetStatus{}, f.triggerError
	}
	f.triggered = true
	f.state.GeoStatus.LastUpdate = time.Now()
	return f.state.GeoStatus, nil
}

func TestRoutingAdminEndpoints(t *testing.T) {
	initialState := RoutingState{
		DirectSuffixes: []string{".ru", ".su", ".xn--p1ai"},
		DirectDomains:  []string{"thecode.media", "habr.com"},
		GeoRules: GeoRulesView{
			Enabled:        true,
			AutoUpdate:     true,
			GeoIPURL:       "https://example.com/geoip.dat",
			GeoSiteURL:     "https://example.com/geosite.dat",
			UpdateInterval: "24h",
		},
		GeoStatus: agentapi.GeoAssetStatus{
			Enabled:     true,
			AutoUpdate:  true,
			GeoIPExists: true,
			GeoIPSize:   18000000,
		},
	}

	provider := &fakeRoutingProvider{state: initialState}
	handler := New(ServerConfig{
		Store:         testStore(t),
		AdminPassword: "secret-admin-pass",
		Routing:       provider,
	})

	t.Run("unauthorized access rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/routing", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("get routing state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/routing", nil)
		req.Header.Set("X-Hydrat-Admin-Password", "secret-admin-pass")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var state RoutingState
		if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(state.DirectSuffixes, initialState.DirectSuffixes) ||
			!reflect.DeepEqual(state.DirectDomains, initialState.DirectDomains) {
			t.Fatalf("unexpected state: %+v", state)
		}
	})

	t.Run("update routing validation rejects invalid inputs", func(t *testing.T) {
		invalidInputs := []string{
			`{"direct_suffixes": []}`,
			`{"direct_suffixes": ["bad"]}`,
			`{"direct_suffixes": [".ru"], "direct_domains": ["https://bad.com"]}`,
			`{"direct_suffixes": [".ru"], "direct_domains": ["bad.com:8080"]}`,
			`{"direct_suffixes": [".ru"], "direct_domains": ["ok.com"], "geo_rules": {"enabled": true, "auto_update": true, "geoip_url": "ftp://bad.com"}}`,
		}
		for _, body := range invalidInputs {
			req := httptest.NewRequest(http.MethodPut, "/api/admin/routing", bytes.NewBufferString(body))
			req.Header.Set("X-Hydrat-Admin-Password", "secret-admin-pass")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for input %s, got %d", body, rec.Code)
			}
		}
	})

	t.Run("update routing succeeds with valid input", func(t *testing.T) {
		updateBody := `{
			"direct_suffixes": [".ru", ".by"],
			"direct_domains": ["my-custom-service.org"],
			"geo_rules": {
				"enabled": true,
				"auto_update": true,
				"geoip_url": "https://custom-repo.com/geoip.dat",
				"geosite_url": "https://custom-repo.com/geosite.dat",
				"update_interval": "12h"
			}
		}`
		req := httptest.NewRequest(http.MethodPut, "/api/admin/routing", bytes.NewBufferString(updateBody))
		req.Header.Set("X-Hydrat-Admin-Password", "secret-admin-pass")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if !reflect.DeepEqual(provider.state.DirectSuffixes, []string{".ru", ".by"}) {
			t.Fatalf("suffixes not updated: %v", provider.state.DirectSuffixes)
		}
		if !reflect.DeepEqual(provider.state.DirectDomains, []string{"my-custom-service.org"}) {
			t.Fatalf("domains not updated: %v", provider.state.DirectDomains)
		}
		if provider.state.GeoRules.GeoIPURL != "https://custom-repo.com/geoip.dat" {
			t.Fatalf("geoip_url not updated: %s", provider.state.GeoRules.GeoIPURL)
		}
	})

	t.Run("trigger geo update succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/routing/geo/update", nil)
		req.Header.Set("X-Hydrat-Admin-Password", "secret-admin-pass")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if !provider.triggered {
			t.Fatal("expected trigger to be called")
		}
	})
}
