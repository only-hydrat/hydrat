package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestProbeAPIKeepsActivePoolIndependentFromSaturatedFullPool(t *testing.T) {
	runner := newBlockingProbeRunner()
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests sync.WaitGroup
	for index := 0; index < 5; index++ {
		requests.Add(1)
		go func(index int) {
			defer requests.Done()
			_, _ = sendProbeHandler(ctx, handler, "/v1/probes/full", ProbeRequest{
				CandidateID: "candidate", Kind: "vless", Payload: "payload",
			})
		}(index)
	}
	runner.waitStarted(t, ProbeModeFull, 4)
	if got := runner.startedCount(ProbeModeFull); got != 4 {
		t.Fatalf("full workers=%d, want default 4", got)
	}

	activeDone := make(chan error, 1)
	go func() {
		_, err := sendProbeHandler(context.Background(), handler, "/v1/probes/active", ProbeRequest{
			CandidateID: "candidate", Kind: "vless", Payload: "payload",
		})
		activeDone <- err
	}()
	runner.waitStarted(t, ProbeModeActive, 1)
	runner.release(ProbeModeActive, 1)
	select {
	case err := <-activeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("active probe was starved by full probes")
	}
	cancel()
	runner.release(ProbeModeFull, 4)
	requests.Wait()
}

func TestProbeAPIKeepsCriticalActiveRunnerIndependentFromBackgroundActive(t *testing.T) {
	background := newBlockingProbeRunner()
	critical := newBlockingProbeRunner()
	handler := NewServer(
		&recordingApplier{}, 4096,
		WithProbeRunner(background),
		WithCriticalActiveProbeRunner(critical, 48),
		WithProbeWorkers(8, 4, 4),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests sync.WaitGroup
	for index := 0; index < 5; index++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			_, _ = sendProbeHandler(ctx, handler, "/v1/probes/active", ProbeRequest{
				CandidateID: "prospective", Kind: "vless", Payload: "payload",
			})
		}()
	}
	background.waitStarted(t, ProbeModeActive, 4)
	criticalDone := make(chan error, 1)
	go func() {
		_, err := sendProbeHandler(
			context.Background(), handler, "/v1/probes/active-critical",
			ProbeRequest{CandidateID: "assigned", Kind: "vless", Payload: "payload"},
		)
		criticalDone <- err
	}()
	critical.waitStarted(t, ProbeModeActiveCritical, 1)
	critical.release(ProbeModeActiveCritical, 1)
	select {
	case err := <-criticalDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("critical active probe was starved by background active lane")
	}
	cancel()
	background.release(ProbeModeActive, 4)
	requests.Wait()
}

func TestProbeAPIKeepsActivePoolIndependentFromSaturatedQoEPool(t *testing.T) {
	runner := newBlockingProbeRunner()
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests sync.WaitGroup
	for index := 0; index < 5; index++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			_, _ = sendProbeHandler(ctx, handler, "/v1/probes/qoe", ProbeRequest{
				CandidateID: "candidate", Kind: "vless", Payload: "payload",
			})
		}()
	}
	runner.waitStarted(t, ProbeModeQoE, 4)
	if got := runner.startedCount(ProbeModeQoE); got != 4 {
		t.Fatalf("QoE workers=%d, want default 4", got)
	}

	activeDone := make(chan error, 1)
	go func() {
		_, err := sendProbeHandler(context.Background(), handler, "/v1/probes/active", ProbeRequest{
			CandidateID: "candidate", Kind: "vless", Payload: "payload",
		})
		activeDone <- err
	}()
	runner.waitStarted(t, ProbeModeActive, 1)
	runner.release(ProbeModeActive, 1)
	select {
	case err := <-activeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("active probe was starved by QoE probes")
	}
	cancel()
	runner.release(ProbeModeQoE, 4)
	requests.Wait()
}

func TestProbeAPIKeepsQoEPoolIndependentFromSaturatedActivePool(t *testing.T) {
	runner := newBlockingProbeRunner()
	handler := NewServer(
		&recordingApplier{},
		4096,
		WithProbeRunner(runner),
		WithProbeWorkers(8, 4, 4),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests sync.WaitGroup
	for index := 0; index < 5; index++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			_, _ = sendProbeHandler(ctx, handler, "/v1/probes/active", ProbeRequest{
				CandidateID: "candidate", Kind: "vless", Payload: "payload",
			})
		}()
	}
	runner.waitStarted(t, ProbeModeActive, 4)
	if got := runner.startedCount(ProbeModeActive); got != 4 {
		t.Fatalf("active workers=%d, want configured 4", got)
	}

	qoeDone := make(chan error, 1)
	go func() {
		_, err := sendProbeHandler(context.Background(), handler, "/v1/probes/qoe", ProbeRequest{
			CandidateID: "candidate", Kind: "vless", Payload: "payload",
		})
		qoeDone <- err
	}()
	runner.waitStarted(t, ProbeModeQoE, 1)
	runner.release(ProbeModeQoE, 1)
	select {
	case err := <-qoeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("QoE probe was starved by active probes")
	}
	cancel()
	runner.release(ProbeModeActive, 4)
	requests.Wait()
}

func TestProbeAPIQoEResponseContainsObservationWithoutRequestPayload(t *testing.T) {
	const secretPayload = "vless://secret-route-payload"
	runner := probeRunnerFunc(func(_ context.Context, mode ProbeMode, request ProbeRequest) (ProbeResponse, error) {
		if mode != ProbeModeQoE {
			t.Fatalf("mode=%q, want QoE", mode)
		}
		return ProbeResponse{
			CandidateID: request.CandidateID,
			Success:     true,
			QoE: &qoe.Observation{
				Success: true, TTFB: 125 * time.Millisecond, Bytes: 65536, ThroughputMbps: 12.5,
			},
		}, nil
	})
	handler := NewServer(&recordingApplier{}, 4096, WithProbeRunner(runner))
	body, err := json.Marshal(ProbeRequest{CandidateID: "candidate", Kind: "vless", Payload: secretPayload})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/probes/qoe", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte(secretPayload)) || bytes.Contains(response.Body.Bytes(), []byte(`"payload"`)) {
		t.Fatalf("response repeated request payload: %s", response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	observation, ok := decoded["qoe"].(map[string]any)
	if !ok {
		t.Fatalf("response has no QoE observation: %s", response.Body.String())
	}
	if got := observation["Bytes"]; got != float64(65536) {
		t.Fatalf("QoE bytes=%v, want numeric 65536", got)
	}
	if got := observation["ThroughputMbps"]; got != 12.5 {
		t.Fatalf("QoE throughput=%v, want numeric 12.5", got)
	}
}

func TestProbeAPIRejectsOversizedAndUnknownPayloads(t *testing.T) {
	handler := NewServer(&recordingApplier{}, 128, WithProbeRunner(newBlockingProbeRunner()))
	oversized := httptest.NewRequest(http.MethodPost, "/v1/probes/fast", bytes.NewReader(make([]byte, 1024)))
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d", oversizedResponse.Code)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/v1/probes/fast", bytes.NewBufferString(`{"candidate_id":"id","kind":"vless","payload":"x","secret":true}`))
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown status=%d", unknownResponse.Code)
	}
}

func TestProbeAPIUsesTorSpecificDeadlines(t *testing.T) {
	runner := newBlockingProbeRunner()
	handler := NewServer(
		&recordingApplier{},
		4096,
		WithProbeRunner(runner),
		WithProbeDeadlines(20*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond),
		WithTorProbeDeadlines(250*time.Millisecond, 300*time.Millisecond),
	)

	_, vlessErr := sendProbeHandler(context.Background(), handler, "/v1/probes/fast", ProbeRequest{
		CandidateID: "vless", Kind: "vless", Payload: "payload",
	})
	if vlessErr != nil {
		t.Fatal(vlessErr)
	}

	torDone := make(chan error, 1)
	go func() {
		_, err := sendProbeHandler(context.Background(), handler, "/v1/probes/fast", ProbeRequest{
			CandidateID: "tor", Kind: "tor_bridge", Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
		})
		torDone <- err
	}()
	runner.waitStarted(t, ProbeModeFast, 2)
	select {
	case err := <-torDone:
		t.Fatalf("Tor request used VLESS deadline: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	runner.release(ProbeModeFast, 1)
	if err := <-torDone; err != nil {
		t.Fatal(err)
	}
}

func TestProbeDeadlineOptionsComposeWithoutResettingTor(t *testing.T) {
	server := &Server{probeDeadlines: defaultProbeDeadlines()}
	WithTorProbeDeadlines(250*time.Millisecond, 300*time.Millisecond)(server)
	WithProbeDeadlines(20*time.Millisecond, 30*time.Millisecond, 40*time.Millisecond)(server)

	if got := server.probeDeadlines.forRequest(ProbeModeFast, "tor_bridge"); got != 250*time.Millisecond {
		t.Fatalf("Tor fast deadline=%s, want 250ms", got)
	}
	if got := server.probeDeadlines.forRequest(ProbeModeFull, "tor_bridge"); got != 300*time.Millisecond {
		t.Fatalf("Tor full deadline=%s, want 300ms", got)
	}
}

func TestQoEProbeOptionsComposeWithoutChangingLegacyPoolsOrDeadlines(t *testing.T) {
	server := &Server{probeLimits: newProbeLimits(8, 4, 16), probeDeadlines: defaultProbeDeadlines()}
	WithQoEProbeWorkers(2)(server)
	WithQoEProbeDeadline(45 * time.Second)(server)
	WithProbeWorkers(3, 5, 7)(server)
	WithProbeDeadlines(11*time.Second, 12*time.Second, 13*time.Second)(server)

	if got := cap(server.probeLimits.qoe); got != 2 {
		t.Fatalf("QoE workers=%d, want 2", got)
	}
	if got := cap(server.probeLimits.fast); got != 3 {
		t.Fatalf("fast workers=%d, want 3", got)
	}
	if got := server.probeDeadlines.forMode(ProbeModeQoE); got != 45*time.Second {
		t.Fatalf("QoE deadline=%s, want 45s", got)
	}
	if got := server.probeDeadlines.forMode(ProbeModeActive); got != 13*time.Second {
		t.Fatalf("active deadline=%s, want 13s", got)
	}
}

func TestQoEProbeWorkerOptionCannotExceedAgentHardLimit(t *testing.T) {
	server := &Server{probeLimits: newProbeLimits(8, 4, 16)}
	WithQoEProbeWorkers(99)(server)
	if got := cap(server.probeLimits.qoe); got != 4 {
		t.Fatalf("QoE workers=%d, want hard limit 4", got)
	}
}

func TestDefaultTorProbeDeadlinesMatchApprovedLiveDefaults(t *testing.T) {
	deadlines := defaultProbeDeadlines()
	if got := deadlines.forRequest(ProbeModeFast, "tor_bridge"); got != 5*time.Minute {
		t.Fatalf("Tor fast deadline=%s, want 5m", got)
	}
	if got := deadlines.forRequest(ProbeModeFull, "tor_bridge"); got != 6*time.Minute {
		t.Fatalf("Tor full deadline=%s, want 6m", got)
	}
	if got := deadlines.forRequest(ProbeModeActive, "tor_bridge"); got != 10*time.Second {
		t.Fatalf("Tor active deadline=%s, want 10s", got)
	}
}

func sendProbeHandler(ctx context.Context, handler http.Handler, endpoint string, payload ProbeRequest) (ProbeResponse, error) {
	body, _ := json.Marshal(payload)
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return ProbeResponse{}, fmt.Errorf("HTTP %d: %s", response.Code, response.Body.String())
	}
	var result ProbeResponse
	err := json.NewDecoder(response.Body).Decode(&result)
	return result, err
}

type blockingProbeRunner struct {
	mu            sync.Mutex
	started       map[ProbeMode]int
	releaseByMode map[ProbeMode]chan struct{}
}

func newBlockingProbeRunner() *blockingProbeRunner {
	return &blockingProbeRunner{
		started: make(map[ProbeMode]int),
		releaseByMode: map[ProbeMode]chan struct{}{
			ProbeModeFast: make(chan struct{}, 16), ProbeModeFull: make(chan struct{}, 16), ProbeModeActive: make(chan struct{}, 16),
			ProbeModeActiveCritical: make(chan struct{}, 64),
			ProbeModeQoE:            make(chan struct{}, 16),
		},
	}
}

type probeRunnerFunc func(context.Context, ProbeMode, ProbeRequest) (ProbeResponse, error)

func (function probeRunnerFunc) Probe(ctx context.Context, mode ProbeMode, request ProbeRequest) (ProbeResponse, error) {
	return function(ctx, mode, request)
}

func (runner *blockingProbeRunner) Probe(ctx context.Context, mode ProbeMode, request ProbeRequest) (ProbeResponse, error) {
	runner.mu.Lock()
	runner.started[mode]++
	runner.mu.Unlock()
	select {
	case <-runner.releaseByMode[mode]:
		return ProbeResponse{CandidateID: request.CandidateID, Success: true}, nil
	case <-ctx.Done():
		return ProbeResponse{}, ctx.Err()
	}
}

func (runner *blockingProbeRunner) waitStarted(t *testing.T, mode ProbeMode, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runner.startedCount(mode) >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s started=%d, want %d", mode, runner.startedCount(mode), count)
}

func (runner *blockingProbeRunner) startedCount(mode ProbeMode) int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.started[mode]
}

func (runner *blockingProbeRunner) release(mode ProbeMode, count int) {
	for index := 0; index < count; index++ {
		runner.releaseByMode[mode] <- struct{}{}
	}
}
