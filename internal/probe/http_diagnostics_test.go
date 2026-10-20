package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestHTTPGateDiagnosticsIdentifyServiceWithoutURLs(t *testing.T) {
	client := &http.Client{Transport: gateRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "www.youtube.com" {
			return nil, &net.DNSError{Err: "private-token", Name: "private-host"}
		}
		return nil, context.DeadlineExceeded
	})}
	result := CheckHTTPGatesWithConfig(context.Background(), client, HTTPGateConfig{
		CustomGates: []CustomGateCheck{{Name: "private-token", URL: "https://private-host/private-token"}},
	})
	if len(result.Checks) != 6 {
		t.Fatalf("checks=%+v", result.Checks)
	}
	for _, check := range result.Checks {
		if strings.Contains(check.Service, "private") {
			t.Fatalf("unsafe service: %+v", check)
		}
		if check.Service == "youtube" && (check.Phase != "dns" || check.Code != "dns") {
			t.Fatalf("lost DNS cause: %+v", check)
		}
	}
}

func TestHTTPCheckDiagnosticsPreserveStatusAndBodyFailure(t *testing.T) {
	for _, status := range []int{204, 503} {
		result := CheckHTTPGates(context.Background(), gateClient(map[string]int{"www.youtube.com": status}))
		for _, check := range result.Checks {
			if check.Service == "youtube" && (check.Status != status || check.OK != (status == 204)) {
				t.Fatalf("check=%+v", check)
			}
		}
	}
}

func TestHTTPDiagnosticsTrackTLSAndBodyTimeout(t *testing.T) {
	client := &http.Client{Transport: gateRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		trace.TLSHandshakeStart()
		trace.TLSHandshakeDone(tls.ConnectionState{}, errors.New("private-token"))
		return nil, errors.New("private-token")
	})}
	got := checkStatusDetailed(context.Background(), client, "https://example.com", statusBelow400)
	if got.Phase != "tls" || got.Code != "tls" {
		t.Fatalf("TLS check=%+v", got)
	}
	client.Transport = gateRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: diagnosticErrorBody{}}, nil
	})
	got = checkStatusDetailed(context.Background(), client, "https://example.com", statusBelow400)
	if got.Phase != "body" || got.Code != "timeout" || got.Status != 200 {
		t.Fatalf("body check=%+v", got)
	}
}

type diagnosticErrorBody struct{}

func (diagnosticErrorBody) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (diagnosticErrorBody) Close() error             { return nil }

func TestGateDiagnosticsAlwaysRetainBuiltinsWithManyCustomGates(t *testing.T) {
	config := DefaultHTTPGateConfig()
	for range 40 {
		config.CustomGates = append(config.CustomGates, CustomGateCheck{Name: "private-token", URL: "https://example.com"})
	}
	got := CheckHTTPGatesWithConfig(context.Background(), gateClient(nil), config)
	if len(got.Checks) != 16 || got.Checks[3].Service != "youtube" || got.Checks[4].Service != "instagram" {
		t.Fatalf("checks=%+v", got.Checks)
	}
}

func TestHTTPDiagnosticsDistinguishAlreadyExhaustedBudget(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got := checkStatusDetailed(ctx, &http.Client{}, "https://example.invalid", statusBelow400)
	if got.OK || got.Phase != "request" || got.Code != "budget_exhausted" {
		t.Fatalf("check=%+v", got)
	}
}

func TestHTTPDiagnosticsIdentifyOnlyStalledServiceOverRealHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/youtube" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := CheckHTTPGatesWithConfig(ctx, server.Client(), HTTPGateConfig{
		YouTubeURL: server.URL + "/youtube", ChatGPTURL: server.URL + "/chatgpt", OpenAIURL: server.URL + "/openai", TelegramURL: server.URL + "/telegram", InstagramURL: server.URL + "/instagram",
	})
	if got.YouTubeWeb || !got.TelegramWeb || !got.ChatGPTWeb || !got.OpenAI401 || !got.InstagramWeb {
		t.Fatalf("gates=%+v", got)
	}
	for _, check := range got.Checks {
		if check.Service == "youtube" && (check.Phase != "headers" || check.Code != "timeout" || check.ElapsedMS < 50) {
			t.Fatalf("stall not identified: %+v", check)
		}
	}
}

func TestQoEApplicationDiagnosticsCarryRawRoutedResults(t *testing.T) {
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		SampleBytes: 4,
		ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: gateRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				httptrace.ContextClientTrace(r.Context()).GotFirstResponseByte()
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("test")), Header: http.Header{"Content-Length": []string{"4"}}, ContentLength: 4}, nil
			})}
		},
		ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{Checks: []qoe.HTTPCheck{{Service: "youtube", Phase: "headers", Code: "timeout", ElapsedMS: 3000}}}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{Checks: []qoe.HTTPCheck{{Service: "youtube", Phase: "status", Code: "http_status", Status: 503}}}
		},
	})
	got := measurer.Measure(context.Background(), "candidate", "unused")
	if !got.UnconfirmedHTTP || !got.Infrastructure || got.ErrorCode != qoeApplicationGates || len(got.ApplicationChecks) != 2 || got.ApplicationChecks[0].Path != "route" || got.ApplicationChecks[1].Path != "route" {
		t.Fatalf("observation=%+v", got)
	}
}
