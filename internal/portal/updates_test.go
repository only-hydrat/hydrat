package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdaterRequiresAdminAndRejectsComponentInstall(t *testing.T) {
	handler := New(ServerConfig{AdminPassword: "secret"})
	for _, tc := range []struct {
		method, operation, password string
		want                        int
	}{
		{http.MethodGet, "status", "", http.StatusUnauthorized},
		{http.MethodPost, "check", "", http.StatusUnauthorized},
		{http.MethodPost, "install", "", http.StatusUnauthorized},
		{http.MethodPost, "install", "secret", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method, "/api/admin/updates/"+tc.operation, strings.NewReader(`{"component":"tor","version":"0.4.9.17"}`))
		req.Header.Set("X-Hydrat-Admin-Password", tc.password)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != tc.want {
			t.Errorf("%s %s returned %d, want %d", tc.method, tc.operation, res.Code, tc.want)
		}
	}
}
