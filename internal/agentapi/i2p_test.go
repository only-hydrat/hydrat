package agentapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type i2pRoundTrip func(*http.Request) (*http.Response, error)

func (f i2pRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestI2PProxyPreservesPaginationAndRejectsOversizedResponse(t *testing.T) {
	for _, large := range []bool{false, true} {
		client := &Client{http: &http.Client{Transport: i2pRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.RawQuery != "offset=50&q=site" {
				t.Errorf("pagination lost: %s", r.URL)
			}
			body := `{"entries":[]}`
			if large {
				body = strings.Repeat("x", (2<<20)+1)
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		w := httptest.NewRecorder()
		client.I2PHandler().ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/i2p?offset=50&q=site", nil))
		if !large && (w.Code != 200 || w.Body.String() != `{"entries":[]}`) {
			t.Fatalf("normal response: %d %s", w.Code, w.Body.String())
		}
		if large && w.Code != 502 {
			t.Fatalf("oversized response silently returned as %d", w.Code)
		}
	}
}

func TestI2PExportCanExceedStatusLimit(t *testing.T) {
	body := strings.Repeat("x", 3<<20)
	client := &Client{http: &http.Client{Transport: i2pRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	w := httptest.NewRecorder()
	client.I2PHandler().ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/i2p/export", nil))
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("valid export truncated or rejected: status=%d size=%d", w.Code, w.Body.Len())
	}
}
