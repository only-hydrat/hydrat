package portal

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestSystemSummarySeparatesHealthFromReadiness(t *testing.T) {
	health, ready := &healthCheckerStub{}, &healthCheckerStub{err: errors.New("reserve_not_ready")}
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin", Health: health, ControllerReadiness: ready})
	for _, tc := range []struct {
		healthErr, readyErr   error
		wantHealth, wantReady string
	}{
		{nil, errors.New("reserve_not_ready"), "ok", "controller unavailable: reserve_not_ready"},
		{nil, nil, "ok", "ok"},
		{errors.New("private agent error"), nil, "gateway agent unavailable", "gateway agent unavailable"},
	} {
		health.err, ready.err = tc.healthErr, tc.readyErr
		response := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
		var body struct {
			Health string `json:"health_status"`
			Ready  string `json:"readiness_status"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || body.Health != tc.wantHealth || body.Ready != tc.wantReady {
			t.Fatalf("status=%d body=%s", response.Code, response.Body)
		}
	}
}
