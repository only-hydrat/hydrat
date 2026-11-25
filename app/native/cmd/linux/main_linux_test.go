package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestImportReturnsSafeLineIssues(t *testing.T) {
	app, err := device.OpenMobile(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	service := newDesktopAPI(app, nil, nil)
	request := httptest.NewRequest(http.MethodPost, "/sources/import", strings.NewReader("invalid raw text"))
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "unsupported source format") ||
		strings.Contains(response.Body.String(), "invalid raw text") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}

func TestDesktopSourceHWID(t *testing.T) {
	const defaultHWID = "default-device-001"
	const customHWID = "source-device-001"
	headers := make(chan string, 4)
	sub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("X-HWID")
		_, _ = io.WriteString(w, "vless://11111111-1111-1111-8111-111111111111@example.org:443?security=tls")
	}))
	defer sub.Close()
	app, err := device.OpenSingleDevice(t.Context(), t.TempDir(), sub.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err := app.SetHWID(defaultHWID); err != nil {
		t.Fatal(err)
	}
	service := newDesktopAPI(app, nil, nil)
	req := func(method, path, body, hwid string, code int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("X-Hydrat-Source-HWID", hwid)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		if response.Code != code {
			t.Fatalf("%s %s = %d, want %d", method, path, response.Code, code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive settings can be cached")
		}
		return response
	}
	expectHeader := func(want string) {
		t.Helper()
		select {
		case got := <-headers:
			if got != want {
				t.Errorf("subscription received %q, want %q", got, want)
			}
		default:
			t.Fatal("no request to subscription")
		}
	}
	url := sub.URL + "/list"
	response := req(http.MethodPost, "/sources/import", url, customHWID, 200)
	if strings.Contains(response.Body.String(), customHWID) {
		t.Fatal("import response contains HWID")
	}
	expectHeader(customHWID)
	path := "/sources/src_" + sources.PreviewInput(url).Items[0].Fingerprint + "/hwid"
	response = req(http.MethodGet, path, "", "", 200)
	var value struct{ HWID string }
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil || value.HWID != customHWID {
		t.Fatalf("editor did not return the source value: %v", err)
	}
	req(http.MethodPut, path, `{"HWID":"bad"}`, "", 400)
	req(http.MethodPut, path, `{}`, "", 400)
	req(http.MethodPut, path, `{"HWID":""}`, "", 200)
	expectHeader(defaultHWID)
}

func TestDesktopPreferencesIgnoreScreenPause(t *testing.T) {
	var value settings
	value.PauseOnScreenOff = true
	if normalizeSettings(value).PauseOnScreenOff {
		t.Fatal("desktop preferences enabled mobile power saving")
	}
}
