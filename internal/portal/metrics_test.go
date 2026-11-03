package portal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsEndpointDisabledByDefault(t *testing.T) {
	handler := New(ServerConfig{})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestMetricsEndpointCanBeEnabled(t *testing.T) {
	handler := New(ServerConfig{MetricsEnabled: true})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
}
