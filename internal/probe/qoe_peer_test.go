package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEHTTPFailuresNeverUseHostControlOrSuppressOtherRoutes(t *testing.T) {
	var direct, routed atomic.Int32
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) { routed.Add(1); return nil, errors.New("route timeout") })}
		},
		DirectClient: &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) { direct.Add(1); return nil, errors.New("blocked on host") })},
	})
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		observation := measurer.Measure(context.Background(), id, "socks")
		if observation.Success || !observation.Infrastructure {
			t.Fatalf("unconfirmed failure must be neutral: %+v", observation)
		}
	}
	if direct.Load() != 0 || routed.Load() != 5 {
		t.Fatalf("host HTTP=%d, routed checks=%d; want 0 and 5", direct.Load(), routed.Load())
	}
}

func TestQoERoutedTimeoutLeavesTimeForRawFailureAndCleanup(t *testing.T) {
	parent := context.Background()
	route := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{ClientFactory: func(string) *http.Client { return route }, Deadline: time.Second})
	got := measurer.Measure(parent, "route", "socks")
	if parent.Err() != nil || !got.Infrastructure || !got.UnconfirmedHTTP || got.ErrorCode != qoe.ReasonRouteTimeout {
		t.Fatalf("routed timeout was mistaken for RPC cancellation: %+v", got)
	}
}

func TestQoEApplicationResultsIncludeSuccessfulChecksWithoutHostHTTP(t *testing.T) {
	var controls int
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return qoeSuccessClient() }, SampleBytes: 65536,
		ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{YouTubeWeb: true, TelegramWeb: true, OpenAI401: true, Checks: []qoe.HTTPCheck{{Service: "youtube", OK: true}}}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult { controls++; return HTTPGateResult{} },
	})
	got := measurer.Measure(context.Background(), "a", "socks")
	if !got.Success || len(got.ApplicationChecks) == 0 || controls != 0 {
		t.Fatalf("observation=%+v host controls=%d", got, controls)
	}
}

func TestQoEComparisonPolicyFencesEndpointSizeDNSAndAcceptance(t *testing.T) {
	base := NewQoEMeasurer(QoEMeasurerConfig{}).comparisonPolicy
	for _, config := range []QoEMeasurerConfig{
		{Endpoint: "https://other.example/down"}, {SampleBytes: 65536}, {DNSResolver: "9.9.9.9"}, {Deadline: 20 * time.Second}, {ApplicationPolicy: "different status acceptance"},
	} {
		if got := NewQoEMeasurer(config).comparisonPolicy; got == base || len(got) != 64 {
			t.Fatalf("policy mismatch not fenced: %q", got)
		}
	}
}

func TestQoELocalSOCKSDialFailureIsInfrastructureNotComparableRouteFailure(t *testing.T) {
	client := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, Err: errors.New("local listener unavailable")}
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{ClientFactory: func(string) *http.Client { return client }})
	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")
	if !got.Infrastructure || got.UnconfirmedHTTP || got.ErrorCode != qoeProxyUnavailable {
		t.Fatalf("local probe socket failure blamed on route: %+v", got)
	}
}

func TestAvailabilityLocalSOCKSDialFailureCannotConfirmCandidateOutage(t *testing.T) {
	directChecks := 0
	measurer := NewQoEMeasurer(QoEMeasurerConfig{DNSResolver: "1.1.1.1", DNSRouteCheck: func(context.Context, string, string) error {
		return &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, Err: errors.New("local listener unavailable")}
	}, DNSDirectCheck: func(context.Context, string) error { directChecks++; return nil }})
	got := measurer.MeasureAvailability(context.Background(), "candidate", "127.0.0.1:1080")
	if !got.Infrastructure || got.ErrorCode != qoeProxyUnavailable || directChecks != 0 {
		t.Fatalf("checking socket failure confirmed candidate outage: %+v direct checks=%d", got, directChecks)
	}
}

func TestQoENativeTelegramFailureCannotHideBehindHealthyWeb(t *testing.T) {
	for _, code := range []string{"ok", "timeout", "budget_exhausted", "canceled", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return qoeSuccessClient() }, SampleBytes: 65536,
				ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
					return HTTPGateResult{YouTubeWeb: true, TelegramWeb: true, OpenAI401: true}
				},
				TelegramTransports: func(_ context.Context, address string) []qoe.HTTPCheck {
					if address != "candidate-socks" {
						t.Errorf("wrong route: %s", address)
					}
					return []qoe.HTTPCheck{{Service: "telegram_padded", Code: code, OK: code == "ok"}}
				},
			})
			got := measurer.Measure(context.Background(), "candidate", "candidate-socks")
			if code == "ok" {
				if !got.Success {
					t.Fatalf("healthy native transport: %+v", got)
				}
			} else if got.Success || !got.Infrastructure || got.UnconfirmedHTTP != (code == "timeout") {
				t.Fatalf("unsafe failure classification: %+v", got)
			}
			found := false
			for _, c := range got.ApplicationChecks {
				if c.Service == "telegram_padded" && c.Path == "route" {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing safe native diagnostic: %+v", got.ApplicationChecks)
			}
		})
	}
}

func TestQoEAvailabilityDoesNotRunNativeTelegram(t *testing.T) {
	calls := 0
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		DNSResolver: "1.1.1.1", DNSRouteCheck: func(context.Context, string, string) error { return nil },
		TelegramTransports: func(context.Context, string) []qoe.HTTPCheck { calls++; return nil },
	})
	if got := measurer.MeasureAvailability(context.Background(), "candidate", "socks"); !got.Success || calls != 0 {
		t.Fatalf("availability=%+v native calls=%d", got, calls)
	}
}

func TestQoENativePolicyCannotReuseWebOnlyEvidence(t *testing.T) {
	old := NewQoEMeasurer(QoEMeasurerConfig{}).comparisonPolicy
	native := NewQoEMeasurer(QoEMeasurerConfig{TelegramTransports: CheckTelegramTransports}).comparisonPolicy
	if old == native {
		t.Fatal("native and web-only evidence share a comparison policy")
	}
}

func TestQoENativeChecksRunAlongsideWebAndJoinBeforeReturn(t *testing.T) {
	nativeStarted := make(chan struct{})
	webFinished := make(chan struct{})
	nativeFinished := make(chan struct{})
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return qoeSuccessClient() }, SampleBytes: 65536,
		ApplicationGates: func(ctx context.Context, _ *http.Client) HTTPGateResult {
			select {
			case <-nativeStarted:
			case <-ctx.Done():
				t.Error("native not started concurrently")
			}
			close(webFinished)
			return HTTPGateResult{YouTubeWeb: true, TelegramWeb: true, OpenAI401: true}
		},
		TelegramTransports: func(ctx context.Context, _ string) []qoe.HTTPCheck {
			close(nativeStarted)
			select {
			case <-webFinished:
			case <-ctx.Done():
				t.Error("web check did not complete")
			}
			close(nativeFinished)
			return []qoe.HTTPCheck{{Service: "telegram_obfuscated", Code: "ok", OK: true}, {Service: "telegram_padded", Code: "ok", OK: true}}
		},
	})
	got := measurer.Measure(context.Background(), "candidate", "socks")
	if !got.Success {
		t.Fatalf("concurrent check: %+v", got)
	}
	select {
	case <-nativeFinished:
	default:
		t.Fatal("probe returned before native checks finished")
	}
}
