package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceRejectsUnpublishedSelectionAndConcurrentInstall(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	service := &service{
		status: Status{
			Enabled:   true,
			Installed: Versions{Hydrat: "1.2.0"},
			Available: map[string]Offer{"hydrat": {Version: "1.2.1"}},
		},
		install: func(_ context.Context, name string, offer Offer) error {
			if name != "hydrat" || offer.Version != "1.2.1" {
				t.Errorf("unexpected install: %s %+v", name, offer)
			}
			close(started)
			<-release
			return nil
		},
	}
	handler := service.handler()
	request := func(body string, code int) {
		t.Helper()
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/v1/install", strings.NewReader(body)))
		if res.Code != code {
			t.Fatalf("install request returned %d, want %d (%s)", res.Code, code, res.Body)
		}
	}
	request(`{"component":"tor","version":"1.2.1"}`, http.StatusBadRequest)
	request(`{"component":"xray","version":"1.2.1"}`, http.StatusBadRequest)
	request(`{"component":"hydrat","version":"1.2.2"}`, http.StatusConflict)
	request(`{"component":"hydrat","version":"1.2.1","digest":"unchecked"}`, http.StatusBadRequest)
	request(`{"component":"hydrat","version":"1.2.1"}`, http.StatusAccepted)
	<-started
	request(`{"component":"hydrat","version":"1.2.1"}`, http.StatusConflict)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if !strings.Contains(res.Body.String(), `"state":"installing"`) {
		t.Fatalf("missing running state: %s", res.Body)
	}
}

func TestRefreshUnlocksRestoredRollbackWhenRoutesReturn(t *testing.T) {
	s := &service{
		ctx:            context.Background(),
		status:         Status{Result: Result{State: "rollback_waiting"}},
		finishRollback: func(context.Context) (bool, error) { return true, nil },
		check: func(context.Context) (Versions, map[string]Offer, error) {
			return Versions{Hydrat: "1.2.0"}, map[string]Offer{"hydrat": {Version: "1.2.1"}}, nil
		},
		install: func(context.Context, string, Offer) error { return nil },
	}
	s.refresh()
	for deadline := time.Now().Add(2 * time.Second); ; {
		s.mu.Lock()
		checking := s.status.Checking
		s.mu.Unlock()
		if !checking {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	res := httptest.NewRecorder()
	s.handler().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/v1/install", strings.NewReader(`{"component":"hydrat","version":"1.2.1"}`)))
	if res.Code != http.StatusAccepted {
		t.Fatalf("restored service remains locked: %d", res.Code)
	}
}
