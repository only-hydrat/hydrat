package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
)

type closeTrackingTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
	closed    atomic.Int32
}

func (transport *closeTrackingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.roundTrip(request)
}

func (transport *closeTrackingTransport) CloseIdleConnections() {
	transport.closed.Add(1)
}

func TestLivenessClosesOwnedRouteClientAfterBothChecks(t *testing.T) {
	transport := &closeTrackingTransport{roundTrip: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	}}
	result := (Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: transport}
	}}).Observe(context.Background(), "127.0.0.1:11080")
	if !result.PrimaryOK || !result.ConfirmationOK || transport.closed.Load() != 1 {
		t.Fatalf("observation=%+v closes=%d", result, transport.closed.Load())
	}
}

func TestFullMeasurerClosesOwnedRouteClient(t *testing.T) {
	transport := &closeTrackingTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		status := http.StatusNoContent
		if request.URL.Host == "api.openai.com" {
			status = http.StatusUnauthorized
		}
		if request.URL.Host == "web.telegram.org" || request.URL.Host == "speed.cloudflare.com" {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(make([]byte, 1<<20))), Header: make(http.Header)}, nil
	}}
	_, err := (Measurer{
		ClientFactory: func(string) *http.Client { return &http.Client{Transport: transport} },
		MTProtoCheck:  func(context.Context, string) bool { return true },
		UDPCheck:      func(context.Context, string) bool { return true },
		Now:           time.Now,
	}).Measure(context.Background(), "127.0.0.1:11080", health.ProtocolVLESS)
	if err != nil || transport.closed.Load() != 1 {
		t.Fatalf("err=%v closes=%d", err, transport.closed.Load())
	}
}

func TestQoEMeasurerClosesRouteClientButNotDirectControlClient(t *testing.T) {
	route := &closeTrackingTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		if trace := httptrace.ContextClientTrace(request.Context()); trace != nil {
			trace.GotFirstResponseByte()
		}
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	}}
	direct := &closeTrackingTransport{roundTrip: route.roundTrip}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return &http.Client{Transport: route} },
		DirectClient:  &http.Client{Transport: direct}, SampleBytes: 65536,
	})
	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:11080")
	if !got.Success || route.closed.Load() != 1 || direct.closed.Load() != 0 {
		t.Fatalf("observation=%+v route closes=%d direct closes=%d", got, route.closed.Load(), direct.closed.Load())
	}
}

func TestRouteProbeClientsCloseAfterTransportFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*http.Client)
	}{
		{name: "liveness", run: func(client *http.Client) {
			_ = (Liveness{ClientFactory: func(string) *http.Client { return client }}).
				Observe(context.Background(), "127.0.0.1:11080")
		}},
		{name: "full", run: func(client *http.Client) {
			_, _ = (Measurer{
				ClientFactory: func(string) *http.Client { return client },
				MTProtoCheck:  func(context.Context, string) bool { return true },
				UDPCheck:      func(context.Context, string) bool { return true },
			}).Measure(context.Background(), "127.0.0.1:11080", health.ProtocolVLESS)
		}},
		{name: "qoe", run: func(client *http.Client) {
			direct := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if trace := httptrace.ContextClientTrace(request.Context()); trace != nil {
					trace.GotFirstResponseByte()
				}
				return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
			})}
			_ = NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return client },
				DirectClient:  direct, SampleBytes: 65536,
			}).Measure(context.Background(), "candidate", "127.0.0.1:11080")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &closeTrackingTransport{roundTrip: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("route failed")
			}}
			test.run(&http.Client{Transport: transport})
			if transport.closed.Load() != 1 {
				t.Fatalf("closes=%d", transport.closed.Load())
			}
		})
	}
}

func TestNativeRouteTransportsDisableKeepAlives(t *testing.T) {
	qoeMeasurer := NewQoEMeasurer(QoEMeasurerConfig{})
	clients := map[string]*http.Client{
		"liveness": (Liveness{}).client(context.Background(), "127.0.0.1:11080"),
		"full":     (Measurer{}).client("127.0.0.1:11080"),
		"qoe":      qoeMeasurer.routeClient("127.0.0.1:11080"),
	}
	for name, client := range clients {
		transport, ok := client.Transport.(*http.Transport)
		if !ok || !transport.DisableKeepAlives {
			t.Errorf("%s transport=%T disable_keep_alives=%t", name, client.Transport, ok && transport.DisableKeepAlives)
		}
		client.CloseIdleConnections()
	}
}
