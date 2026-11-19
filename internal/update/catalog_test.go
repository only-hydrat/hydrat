package update

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestOffersUseOnlyStableHydratRelease(t *testing.T) {
	for _, tc := range []struct {
		body, current, want string
		code                int
		failed              bool
	}{
		{`{"tag_name":"v1.10.0"}`, "1.9.9", "1.10.0", http.StatusOK, false},
		{`{"tag_name":"v1.10.0"}`, "1.10.0", "", http.StatusOK, false},
		{`{"tag_name":"v1.10.0"}`, "dev", "", http.StatusOK, false},
		{`{"tag_name":"v1.10.0","draft":true}`, "1.9.9", "", http.StatusOK, true},
		{`{"tag_name":"v1.10.0","prerelease":true}`, "1.9.9", "", http.StatusOK, true},
		{`{"tag_name":"v1.10.0.1"}`, "1.9.9", "", http.StatusOK, true},
		{"", "1.9.9", "", http.StatusServiceUnavailable, true},
	} {
		client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != latestRelease {
				t.Fatalf("unexpected update source: %s", req.URL)
			}
			return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		offers, err := findOffers(context.Background(), client, Versions{Hydrat: tc.current})
		if (err != nil) != tc.failed || offers["hydrat"].Version != tc.want || len(offers) > 1 {
			t.Errorf("current %s, response %s: offers %v, error %v", tc.current, tc.body, offers, err)
		}
	}
}
