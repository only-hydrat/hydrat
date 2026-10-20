package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestQoEDiagnosticsSurviveAgentHTTPAndSafeProjection(t *testing.T) {
	runner := probeRunnerFunc(func(context.Context, ProbeMode, ProbeRequest) (ProbeResponse, error) {
		return ProbeResponse{FailureClass: FailureInfrastructure, ErrorCode: "qoe_application_gates_unavailable", QoE: &qoe.Observation{ApplicationChecks: []qoe.HTTPCheck{
			{Path: "route", Service: "youtube", Phase: "headers", Code: "timeout", ElapsedMS: 3000},
			{Path: "private-token", Service: "private-token", Phase: "private-token", Code: "private-token"},
		}}}, nil
	})
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner))
	response, err := sendProbeHandler(context.Background(), handler, "/v1/probes/qoe", ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(response)
	_, details := ProbeFailureDetails(response, nil)
	if strings.Contains(string(encoded), "private-token") || strings.Contains(details, "private-token") || !strings.Contains(details, "route/youtube:headers:timeout:http_0:3000ms") {
		t.Fatalf("encoded=%s details=%s", encoded, details)
	}
}

func TestUnconfirmedQoEFailureSurvivesHTTPAsInfrastructure(t *testing.T) {
	policy := strings.Repeat("a", 64)
	runner := probeRunnerFunc(func(context.Context, ProbeMode, ProbeRequest) (ProbeResponse, error) {
		return ProbeResponse{FailureClass: FailureInfrastructure, ErrorCode: qoe.ReasonApplicationGates, QoE: &qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: policy, ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "timeout"}}}}, nil
	})
	response, err := sendProbeHandler(context.Background(), NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner)), "/v1/probes/qoe", ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"})
	if err != nil || response.FailureClass != FailureInfrastructure || response.Success || response.QoE == nil || !response.QoE.Infrastructure || !response.QoE.UnconfirmedHTTP || response.QoE.ComparisonPolicy != policy || response.QoE.ErrorCode != qoe.ReasonApplicationGates {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func TestQoEComparisonRejectsUnboundedOrPrivatePolicyMetadata(t *testing.T) {
	response := ProbeResponse{QoE: &qoe.Observation{UnconfirmedHTTP: true, ComparisonPolicy: "https://private-token.example/secret"}}
	response.sanitizeHTTPDiagnostics()
	encoded, _ := json.Marshal(response)
	if strings.Contains(string(encoded), "private-token") || response.QoE.UnconfirmedHTTP || !response.QoE.Infrastructure {
		t.Fatalf("unsafe comparison metadata: %s", encoded)
	}
}

func TestProbeClientSanitizesHTTPDiagnosticsFromUntrustedAgent(t *testing.T) {
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"candidate_id":"candidate","failure_class":"infrastructure","error_code":"qoe_application_gates_unavailable","qoe":{"application_checks":[{"service":"private-token","path":"private-token","phase":"private-token","code":"private-token","elapsed_ms":9999999,"status":999}]}}`))}, nil
	})})
	response, err := client.ProbeQoE(context.Background(), ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(response)
	if strings.Contains(string(encoded), "private-token") || response.QoE.ApplicationChecks[0].ElapsedMS != 600000 {
		t.Fatalf("response=%s", encoded)
	}
}

func TestProbeClientPreservesStructuredInfrastructureHTTPFailures(t *testing.T) {
	for _, status := range []int{503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(`{"candidate_id":"candidate","failure_class":"infrastructure","error_code":"worker_timeout"}`))}, nil
			})})
			response, err := client.ProbeFull(context.Background(), ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"})
			if err != nil || response.FailureClass != FailureInfrastructure || response.ErrorCode != "worker_timeout" {
				t.Fatalf("infrastructure cause lost: response=%+v err=%v", response, err)
			}
		})
	}
}

func TestBackgroundRuntimeBackoffRecoversWithoutBlockingCriticalProbes(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	posts, health, critical := 0, 0, 0
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, status := `{"candidate_id":"candidate","success":true}`, http.StatusOK
		switch request.URL.Path {
		case "/v1/health":
			health++
			body = `{"probe_runtime":{"status":"draining"}}`
			if health > 1 {
				body = `{"probe_runtime":{"status":"ready"}}`
			}
		case "/v1/probes/active-critical":
			critical++
		default:
			posts++
			if posts == 1 {
				status, body = 503, `{"candidate_id":"candidate","failure_class":"infrastructure","error_code":"probe_runtime_unavailable"}`
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	client.probeNow = func() time.Time { return now }
	request := ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"}
	for _, offset := range []time.Duration{0, time.Second, 5 * time.Second, 14 * time.Second, 15 * time.Second} {
		now = time.Unix(1_900_000_000, 0).Add(offset)
		if _, err := client.ProbeQoE(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ProbeActiveCritical(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if posts != 2 || health != 2 || critical != 5 {
		t.Fatalf("posts=%d health=%d critical=%d", posts, health, critical)
	}
}

func TestProbeFailureProjectionDoesNotLeakErrorText(t *testing.T) {
	secret := "vless://private-password@subscription.example/secret"
	code, details := ProbeFailureDetails(ProbeResponse{ErrorCode: secret, Diagnostics: &ProbeDiagnostics{Phase: secret, RuntimeStatus: secret, ElapsedMS: -1}}, fmt.Errorf("%s", secret))
	if code != "agent_transport" || strings.Contains(details, "secret") || strings.Contains(details, "subscription") {
		t.Fatalf("unsafe projection code=%s details=%s", code, details)
	}
}

func TestDrainingBackgroundRuntimeDoesNotBlockTorOrCriticalLane(t *testing.T) {
	runner := probeRunnerFunc(func(_ context.Context, _ ProbeMode, request ProbeRequest) (ProbeResponse, error) {
		return ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
	})
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner), WithCriticalActiveProbeRunner(runner, 4),
		WithProbeRuntime(runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{Status: "draining", Epoch: 4}}),
		WithActiveProbeRuntime(runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{Status: "ready", Epoch: 8}}))
	for _, test := range []struct{ path, kind string }{{"active-critical", "vless"}, {"qoe", string(sources.KindTorBridge)}} {
		request := ProbeRequest{CandidateID: "candidate", Kind: sources.Kind(test.kind), Payload: "secret"}
		response, err := sendProbeHandler(context.Background(), handler, "/v1/probes/"+test.path, request)
		if err != nil || !response.Success {
			t.Fatalf("%s blocked: %+v err=%v", test.path, response, err)
		}
		if test.path == "active-critical" && (response.Diagnostics == nil || response.Diagnostics.RuntimeEpoch != 8) {
			t.Fatalf("critical diagnostics used wrong runtime: %+v", response)
		}
	}
}

func TestProbeClientRejectsInvalidFailureClassAsInfrastructure(t *testing.T) {
	for _, body := range []string{`{"candidate_id":"candidate","failure_class":"invalid"}`, `{"candidate_id":"candidate","success":true,"failure_class":"infrastructure"}`} {
		client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})})
		response, err := client.ProbeFast(context.Background(), ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: "secret"})
		if err == nil {
			t.Fatalf("malformed result accepted as route evidence: %+v", response)
		}
		code, _ := ProbeFailureDetails(response, err)
		if code != "agent_response_invalid" {
			t.Fatalf("unexpected cause %s", code)
		}
	}
}

func TestBackgroundProbeRejectsDrainingRuntimeBeforeRunner(t *testing.T) {
	runner := newBlockingProbeRunner()
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner),
		WithProbeDeadlines(time.Millisecond, time.Millisecond, time.Millisecond),
		WithProbeRuntime(runtimeSnapshotProvider{snapshot: proberuntime.Snapshot{Status: "draining", Epoch: 4}}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/probes/full", bytes.NewBufferString(`{"candidate_id":"candidate","kind":"vless","payload":"secret"}`)))
	var response ProbeResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", recorder.Code)
	}
	if err != nil || response.FailureClass != FailureInfrastructure || response.ErrorCode != "probe_runtime_unavailable" {
		t.Fatalf("draining runtime accepted probe: response=%+v err=%v", response, err)
	}
	if runner.startedCount(ProbeModeFull) != 0 {
		t.Fatal("probe entered unavailable runtime")
	}
}
