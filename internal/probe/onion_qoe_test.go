package probe

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestOnionQoEOnlyUsesRoutedOnionChecks(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	m := NewQoEMeasurer(QoEMeasurerConfig{ClientFactory: func(addr string) *http.Client {
		if addr != "127.0.0.1:19050" {
			t.Errorf("unexpected proxy %s", addr)
		}
		return &http.Client{Transport: qoeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Hostname(), ".onion") {
				t.Errorf("non onion request %s", r.URL.Host)
			}
			mu.Lock()
			calls++
			mu.Unlock()
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		})}
	}, DNSDirectCheck: func(context.Context, string) error { t.Error("direct DNS used"); return nil }})
	o := m.MeasureOnion(t.Context(), "bridge", "127.0.0.1:19050")
	if !o.Success || o.Infrastructure || len(o.ApplicationChecks) != 2 || calls != 2 || o.ComparisonPolicy != qoe.OnionComparisonPolicy {
		t.Fatalf("observation=%+v calls=%d", o, calls)
	}
}
func TestOnionQoETimeoutNeedsPeerConfirmation(t *testing.T) {
	m := NewQoEMeasurer(QoEMeasurerConfig{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })}
	}})
	o := m.MeasureOnion(t.Context(), "bridge", "proxy")
	if o.Success || !o.Infrastructure || !o.UnconfirmedHTTP || len(qoe.SafeHTTPChecks(o.ApplicationChecks)) != 2 {
		t.Fatalf("unconfirmed failure=%+v", o)
	}
	for _, c := range qoe.SafeHTTPChecks(o.ApplicationChecks) {
		if c.Service == "custom" {
			t.Fatal("onion diagnostics discarded")
		}
	}
}
