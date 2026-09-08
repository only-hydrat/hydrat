package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPortalProxyReplacesForgedIdentityHeaders(t *testing.T) {
	var upstreamRequest *http.Request
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamRequest = request.Clone(request.Context())
		upstreamRequest.Header = request.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			Header: make(http.Header),
		}, nil
	})
	handler, err := NewPortalProxy("http://controller:8080", "trusted-token", transport)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://10.44.0.1/api/me", nil)
	request.RemoteAddr = "10.44.0.2:54321"
	request.Header.Set(InternalTokenHeader, "forged-token")
	request.Header.Set(ClientIPHeader, "203.0.113.9")
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	if upstreamRequest == nil ||
		upstreamRequest.Header.Get(InternalTokenHeader) != "trusted-token" ||
		upstreamRequest.Header.Get(ClientIPHeader) != "10.44.0.2" {
		t.Fatalf("upstream headers=%v", upstreamRequest.Header)
	}
	if upstreamRequest.Header.Get("X-Forwarded-For") != "" {
		t.Fatalf("forged forwarded identity survived: %v", upstreamRequest.Header)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
