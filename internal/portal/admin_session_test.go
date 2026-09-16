package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestAdminSessionCreatesRevokesAndBearerAccess(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "secret"})

	request := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
	request.RemoteAddr = "192.0.2.10:40000"
	request.Header.Set("X-Hydrat-Admin-Password", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var session struct {
		Token             string `json:"token"`
		ExpiresIn         int    `json:"expires_in"`
		AbsoluteExpiresIn int    `json:"absolute_expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Token == "" || session.ExpiresIn != 1800 || session.AbsoluteExpiresIn != 28800 {
		t.Fatalf("session=%+v", session)
	}

	access := httptest.NewRequest(http.MethodGet, "/api/admin/profiles", nil)
	access.Header.Set("Authorization", "Bearer "+session.Token)
	accessResponse := httptest.NewRecorder()
	handler.ServeHTTP(accessResponse, access)
	if accessResponse.Code != http.StatusOK {
		t.Fatalf("bearer status=%d body=%s", accessResponse.Code, accessResponse.Body.String())
	}

	legacyDelete := httptest.NewRequest(http.MethodDelete, "/api/admin/session", nil)
	legacyDelete.Header.Set("X-Hydrat-Admin-Password", "secret")
	legacyDeleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyDeleteResponse, legacyDelete)
	if legacyDeleteResponse.Code != http.StatusUnauthorized {
		t.Fatalf("legacy delete status=%d body=%s", legacyDeleteResponse.Code, legacyDeleteResponse.Body.String())
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/session", nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+session.Token)
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}

	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, access)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestAdminMiddlewareBearerPrecedenceAndLegacyAccess(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "secret"})

	legacy := httptest.NewRequest(http.MethodGet, "/api/admin/profiles", nil)
	legacy.Header.Set("X-Hydrat-Admin-Password", "secret")
	legacyResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusOK {
		t.Fatalf("legacy status=%d body=%s", legacyResponse.Code, legacyResponse.Body.String())
	}

	for _, authorization := range []string{"", "Bearer invalid", "Basic secret"} {
		request := httptest.NewRequest(http.MethodGet, "/api/admin/profiles", nil)
		request.Header.Set("Authorization", authorization)
		request.Header.Set("X-Hydrat-Admin-Password", "secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"admin authentication required\"}\n" {
			t.Fatalf("authorization=%q status=%d body=%s", authorization, response.Code, response.Body.String())
		}
	}
}

func TestAdminSessionReturnsFailureStatuses(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	newHandler := func(auth *adminAuth) http.Handler {
		handler := New(ServerConfig{Store: testStore(t), AdminPassword: "secret"})
		handler.(*Server).auth = auth
		return handler
	}
	randomFailure := newHandler(newAdminAuthWith("secret", func() time.Time { return now }, errReader{errors.New("random failed")}))
	randomRequest := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
	randomRequest.Header.Set("X-Hydrat-Admin-Password", "secret")
	randomResponse := httptest.NewRecorder()
	randomFailure.ServeHTTP(randomResponse, randomRequest)
	if randomResponse.Code != http.StatusInternalServerError {
		t.Fatalf("random status=%d body=%s", randomResponse.Code, randomResponse.Body.String())
	}

	fullAuth := newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(nil))
	for index := 0; index < maxAdminSessions; index++ {
		fullAuth.sessions[[32]byte{byte(index), byte(index >> 8)}] = adminSession{createdAt: now, lastUsedAt: now}
	}
	capacityHandler := newHandler(fullAuth)
	capacityRequest := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
	capacityRequest.Header.Set("X-Hydrat-Admin-Password", "secret")
	capacityResponse := httptest.NewRecorder()
	capacityHandler.ServeHTTP(capacityResponse, capacityRequest)
	if capacityResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status=%d body=%s", capacityResponse.Code, capacityResponse.Body.String())
	}

	limitedHandler := newHandler(newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(make([]byte, 32))))
	for attempt := 0; attempt < maxAdminFailures; attempt++ {
		post := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
		post.RemoteAddr = "192.0.2.10:40000"
		post.Header.Set("X-Hydrat-Admin-Password", "wrong")
		response := httptest.NewRecorder()
		limitedHandler.ServeHTTP(response, post)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt=%d status=%d body=%s", attempt+1, response.Code, response.Body.String())
		}
	}
	limitedRequest := httptest.NewRequest(http.MethodPost, "/api/admin/session", nil)
	limitedRequest.RemoteAddr = "192.0.2.10:40000"
	limitedRequest.Header.Set("X-Hydrat-Admin-Password", "secret")
	limitedResponse := httptest.NewRecorder()
	limitedHandler.ServeHTTP(limitedResponse, limitedRequest)
	if retry, err := strconv.Atoi(limitedResponse.Header().Get("Retry-After")); limitedResponse.Code != http.StatusTooManyRequests || err != nil || retry < 1 {
		t.Fatalf("limited status=%d retry=%q body=%s", limitedResponse.Code, limitedResponse.Header().Get("Retry-After"), limitedResponse.Body.String())
	}

}
