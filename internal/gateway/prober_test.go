package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestVLESSQoEUsesDedicatedPrioritySlot(t *testing.T) {
	runner := &recordingProbeXrayRunner{}
	control := probexray.New("xray", "127.0.0.1:10086", 20, runner)
	control.Reset(7)
	measurer := &recordingQoEMeasurer{observation: qoe.Observation{
		Success: true, Bytes: 65536, ThroughputMbps: 10,
	}}
	prober := &Prober{
		control:        control,
		runtime:        &recordingProbeRuntime{epoch: 7},
		cleanupTimeout: time.Second,
		qoe:            measurer,
		portBase:       11080,
		fullSlots:      slotPool(fullSlotStart, fullSlotCount),
		fastSlots:      slotPool(fastSlotStart, fastSlotCount),
		activeSlots:    slotPool(activeSlotStart, activeSlotCount),
		qoeSlots:       slotPool(qoeSlotStart, qoeSlotCount),
	}
	for range fullSlotCount {
		<-prober.fullSlots
	}

	response, err := prober.Probe(context.Background(), agentapi.ProbeModeQoE, agentapi.ProbeRequest{
		CandidateID: "candidate",
		Kind:        sources.KindVLESS,
		Payload:     "vless://id@example.net:443?type=raw&security=reality&pbk=public-key&sni=example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.QoE == nil {
		t.Fatalf("response=%+v", response)
	}
	calls := measurer.callsSnapshot()
	if len(calls) != 1 || calls[0].candidateID != "candidate" || calls[0].socksAddr != "127.0.0.1:11096" {
		t.Fatalf("QoE calls=%+v", calls)
	}
	stdin := runner.stdinSnapshot()
	if !strings.Contains(stdin, `"tag":"probe-outbound-16"`) ||
		!strings.Contains(stdin, `"inboundTag":["probe-slot-16"]`) {
		t.Fatalf("QoE slot was not configured in dedicated range: %s", stdin)
	}
}

func TestBackgroundActiveVLESSCarriesRoutedDNSAvailability(t *testing.T) {
	runner := &recordingProbeXrayRunner{}
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, runner)
	control.Reset(3)
	availability := probe.NewQoEMeasurer(probe.QoEMeasurerConfig{
		DNSResolvers: []string{"1.1.1.1"},
		DNSRouteCheck: func(context.Context, string, string) error {
			return errors.New("routed DNS blocked")
		},
		DNSDirectCheck: func(context.Context, string) error { return nil },
	})
	prober, err := NewProber(
		control, &recordingProbeRuntime{epoch: 3}, time.Second,
		probe.Measurer{}, probe.Liveness{ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: probeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}
		}}, availability, nil, 11080,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := prober.Probe(
		context.Background(), agentapi.ProbeModeActive, vlessProbeRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.QoE == nil ||
		response.QoE.ErrorCode != qoe.ReasonDNSRoute || response.QoE.Infrastructure {
		t.Fatalf("response=%+v", response)
	}
}

func TestNewProberRequiresRuntimeAndCleanupTimeout(t *testing.T) {
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, &recordingProbeXrayRunner{})
	runtime := &recordingProbeRuntime{epoch: 1}
	for _, test := range []struct {
		name           string
		runtime        ProbeRuntime
		cleanupTimeout time.Duration
	}{
		{name: "runtime", cleanupTimeout: time.Second},
		{name: "cleanup timeout", runtime: runtime},
	} {
		t.Run(test.name, func(t *testing.T) {
			prober, err := NewProber(
				control,
				test.runtime,
				test.cleanupTimeout,
				probe.Measurer{},
				probe.Liveness{},
				nil,
				nil,
				11080,
			)
			if err == nil || prober != nil {
				t.Fatalf("NewProber()=(%v, %v), want validation error", prober, err)
			}
		})
	}
}

func TestActiveCriticalEndpointMutatesFortyEightSlotVLESSControl(t *testing.T) {
	runner := &recordingProbeXrayRunner{}
	control := probexray.New(
		"xray", "127.0.0.1:10087", 48, runner,
	)
	control.Reset(1)
	runtime := &recordingProbeRuntime{epoch: 1}
	availability := probe.NewQoEMeasurer(probe.QoEMeasurerConfig{
		DNSResolvers:  []string{"1.1.1.1"},
		DNSRouteCheck: func(context.Context, string, string) error { return nil },
	})
	prober, err := NewCriticalActiveProber(
		control,
		runtime,
		time.Second,
		probe.Liveness{ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: probeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}
		}},
		nil,
		12080,
		48,
		availability,
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := agentapi.NewServer(
		nil,
		0,
		agentapi.WithCriticalActiveProbeRunner(prober, 48),
		agentapi.WithProbeDeadlines(time.Second, time.Second, time.Second),
	)
	body, err := json.Marshal(vlessProbeRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/probes/active-critical",
		bytes.NewReader(body),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("active-critical status=%d body=%s", response.Code, response.Body.String())
	}
	var result agentapi.ProbeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || !result.Observation.PrimaryOK ||
		!result.Observation.ConfirmationOK || result.QoE == nil || !result.QoE.Success {
		t.Fatalf("active-critical response=%+v", result)
	}
	stdin := runner.stdinSnapshot()
	if !strings.Contains(stdin, `"tag":"probe-outbound-0"`) ||
		!strings.Contains(stdin, `"inboundTag":["probe-slot-0"]`) {
		t.Fatalf("48-slot active-critical control was not mutated: %s", stdin)
	}
}

func TestActiveAvailabilityLeavesResponseReserveAndJoins(t *testing.T) {
	measurer := &blockingAvailabilityMeasurer{returned: make(chan struct{})}
	prober := &Prober{qoe: measurer}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	check := prober.startAvailabilityCheck(ctx, "candidate", "127.0.0.1:12080")
	observation := awaitAvailabilityCheck(check)
	if observation == nil || !observation.Infrastructure {
		t.Fatalf("availability observation=%+v", observation)
	}
	select {
	case <-measurer.returned:
	default:
		t.Fatal("availability goroutine was not joined")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("availability consumed parent response reserve: %v", err)
	}
}

func TestCriticalActiveVLESSRouteCacheReusesConfiguredCandidateWithoutClearing(t *testing.T) {
	runner := &criticalActiveCacheRunner{}
	control := probexray.New("xray", "127.0.0.1:10087", 2, runner)
	control.Reset(1)
	addresses := &criticalActiveAddressRecorder{}
	prober, err := NewCriticalActiveProber(
		control, &recordingProbeRuntime{epoch: 1}, time.Second,
		addresses.liveness(), nil, 12080, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := vlessProbeRequest()
	for range 2 {
		response, err := prober.Probe(
			context.Background(), agentapi.ProbeModeActiveCritical, request,
		)
		if err != nil || !response.Success {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	if calls := runner.adoCount(); calls != 1 {
		t.Fatalf("active outbound configure calls=%d want=1", calls)
	}
	if got := addresses.snapshot(); len(got) != 2 || got[0] != got[1] {
		t.Fatalf("critical-active SOCKS addresses=%v want stable candidate slot", got)
	}
	if body := runner.lastRoutingBody(); !strings.Contains(body, `"ruleTag":"probe-route-0"`) {
		t.Fatalf("critical-active route was cleared after observation: %s", body)
	}
}

func TestCriticalActiveVLESSRouteCacheSingleFlightsConcurrentCandidateSetup(t *testing.T) {
	runner := newBlockingCriticalActiveCacheRunner()
	control := probexray.New("xray", "127.0.0.1:10087", 2, runner)
	control.Reset(1)
	addresses := &criticalActiveAddressRecorder{}
	prober, err := NewCriticalActiveProber(
		control, &recordingProbeRuntime{epoch: 1}, time.Second,
		addresses.liveness(), nil, 12080, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	probeCandidate := func() {
		response, err := prober.Probe(
			context.Background(), agentapi.ProbeModeActiveCritical, vlessProbeRequest(),
		)
		if err == nil && !response.Success {
			err = errors.New("critical-active probe did not succeed")
		}
		results <- err
	}
	go probeCandidate()
	select {
	case <-runner.firstADOStarted:
	case <-time.After(time.Second):
		t.Fatal("first candidate setup did not start")
	}
	go probeCandidate()
	close(runner.releaseFirstADO)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls := runner.adoCount(); calls != 1 {
		t.Fatalf("concurrent same-candidate configure calls=%d want=1", calls)
	}
	if got := addresses.snapshot(); len(got) != 2 || got[0] != got[1] {
		t.Fatalf("concurrent same-candidate SOCKS addresses=%v want one slot", got)
	}
}

func TestCriticalActiveVLESSRouteCacheReconfiguresPayloadAndEpoch(t *testing.T) {
	runner := &criticalActiveCacheRunner{}
	control := probexray.New("xray", "127.0.0.1:10087", 1, runner)
	control.Reset(1)
	runtime := &recordingProbeRuntime{epoch: 1}
	addresses := &criticalActiveAddressRecorder{}
	prober, err := NewCriticalActiveProber(
		control, runtime, time.Second, addresses.liveness(), nil, 12080, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := vlessProbeRequest()
	probeCandidate := func(request agentapi.ProbeRequest) {
		t.Helper()
		response, err := prober.Probe(
			context.Background(), agentapi.ProbeModeActiveCritical, request,
		)
		if err != nil || !response.Success {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	probeCandidate(request)
	probeCandidate(request)
	request.Payload += "&flow=xtls-rprx-vision"
	probeCandidate(request)
	control.Reset(2)
	runtime.mu.Lock()
	runtime.epoch = 2
	runtime.mu.Unlock()
	probeCandidate(request)
	if calls := runner.adoCount(); calls != 3 {
		t.Fatalf("configure calls=%d want initial+payload+epoch", calls)
	}
}

func TestCriticalActiveVLESSRouteCacheRetriesFailedSetupWithoutPublishingSuccess(t *testing.T) {
	configureErr := errors.New("configure failed")
	runner := &criticalActiveCacheRunner{failNextADO: configureErr}
	control := probexray.New("xray", "127.0.0.1:10087", 1, runner)
	control.Reset(1)
	addresses := &criticalActiveAddressRecorder{}
	prober, err := NewCriticalActiveProber(
		control, &recordingProbeRuntime{epoch: 1}, time.Second,
		addresses.liveness(), nil, 12080, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := prober.Probe(
		context.Background(), agentapi.ProbeModeActiveCritical, vlessProbeRequest(),
	)
	if !errors.Is(err, configureErr) || response.Success {
		t.Fatalf("failed setup response=%+v err=%v", response, err)
	}
	response, err = prober.Probe(
		context.Background(), agentapi.ProbeModeActiveCritical, vlessProbeRequest(),
	)
	if err != nil || !response.Success {
		t.Fatalf("retried setup response=%+v err=%v", response, err)
	}
	if calls := runner.adoCount(); calls != 2 {
		t.Fatalf("configure calls=%d want failed attempt+retry", calls)
	}
	if got := addresses.snapshot(); len(got) != 1 {
		t.Fatalf("liveness calls=%v want only successful setup", got)
	}
}

func TestCriticalActiveRouteCacheEvictsOnlyIdleEntry(t *testing.T) {
	cache := newCriticalActiveRouteCache(2)
	setup := func(context.Context, int) (error, error) { return nil, nil }
	var keyA, keyB, keyC [32]byte
	keyA[0], keyB[0], keyC[0] = 1, 2, 3

	slotA, releaseA, _, err := cache.acquire(
		context.Background(), 1, "candidate-a", keyA, setup,
	)
	if err != nil {
		t.Fatal(err)
	}
	slotB, releaseB, _, err := cache.acquire(
		context.Background(), 1, "candidate-b", keyB, setup,
	)
	if err != nil {
		t.Fatal(err)
	}
	if slotA == slotB {
		t.Fatalf("live candidates share slot=%d", slotA)
	}

	releaseA()
	slotC, releaseC, _, err := cache.acquire(
		context.Background(), 1, "candidate-c", keyC, setup,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseB()
	defer releaseC()
	if slotC != slotA {
		t.Fatalf("evicted slot=%d want idle slot=%d; live slot=%d", slotC, slotA, slotB)
	}
}

func TestCriticalActiveRouteCacheNoFreeSlotHonorsContextDeadline(t *testing.T) {
	cache := newCriticalActiveRouteCache(1)
	setup := func(context.Context, int) (error, error) { return nil, nil }
	var keyA, keyB [32]byte
	keyA[0], keyB[0] = 1, 2
	_, releaseA, _, err := cache.acquire(
		context.Background(), 1, "candidate-a", keyA, setup,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelWait()
	started := time.Now()
	_, _, cleanupErr, err := cache.acquire(
		waitCtx, 1, "candidate-b", keyB,
		func(context.Context, int) (error, error) {
			t.Fatal("setup ran while the only slot was in use")
			return nil, nil
		},
	)
	if cleanupErr != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanupErr=%v err=%v want context deadline", cleanupErr, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("no-free-slot wait ignored bounded context: %s", elapsed)
	}
}

func TestVLESSProbeClearsSlotBeforeReleasingRuntimeLease(t *testing.T) {
	order := &callOrder{}
	fixture := newLeaseAwareProber(t, order, leaseProbeOptions{
		observation: qoe.Observation{Success: true},
	})
	fixture.runtime.onRelease = func() {
		if got := len(fixture.prober.qoeSlots); got != qoeSlotCount-1 {
			t.Errorf("slot returned before runtime release: available=%d", got)
		}
	}

	response, err := fixture.prober.Probe(
		context.Background(),
		agentapi.ProbeModeQoE,
		vlessProbeRequest(),
	)
	if err != nil || !response.Success {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if got := order.String(); got != "acquire,configure,measure,clear,release" {
		t.Fatalf("order=%s", got)
	}
	if fixture.runtime.acquireCalls != 1 || fixture.runtime.releaseCalls != 1 {
		t.Fatalf(
			"runtime calls acquire=%d release=%d",
			fixture.runtime.acquireCalls,
			fixture.runtime.releaseCalls,
		)
	}
	if got := len(fixture.prober.qoeSlots); got != qoeSlotCount {
		t.Fatalf("slot was not returned after cleanup: available=%d", got)
	}
}

func TestVLESSProbeClearsOnEveryExitPath(t *testing.T) {
	configureFailure := errors.New("configure failed")
	clearFailure := errors.New("clear failed")
	tests := []struct {
		name             string
		options          leaseProbeOptions
		context          func() (context.Context, context.CancelFunc)
		wantOrder        string
		wantError        error
		notWantError     error
		wantClass        agentapi.FailureClass
		wantReleaseError error
	}{
		{
			name: "success",
			options: leaseProbeOptions{
				observation: qoe.Observation{Success: true},
			},
			wantOrder: "acquire,configure,measure,clear,release",
		},
		{
			name: "candidate failure",
			options: leaseProbeOptions{
				observation: qoe.Observation{ErrorCode: "qoe_route_timeout"},
			},
			wantOrder: "acquire,configure,measure,clear,release",
			wantClass: agentapi.FailureCandidate,
		},
		{
			name: "request timeout",
			options: leaseProbeOptions{
				measure: canceledQoEMeasure,
			},
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 15*time.Millisecond)
			},
			wantOrder: "acquire,configure,measure,clear,release",
			wantClass: agentapi.FailureInfrastructure,
		},
		{
			name: "request cancellation",
			options: leaseProbeOptions{
				measure: canceledQoEMeasure,
			},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(15*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantOrder: "acquire,configure,measure,clear,release",
			wantClass: agentapi.FailureInfrastructure,
		},
		{
			name: "configure failure",
			options: leaseProbeOptions{
				configureErr: configureFailure,
			},
			wantOrder: "acquire,configure,clear,release",
			wantError: configureFailure,
		},
		{
			name: "clear failure",
			options: leaseProbeOptions{
				observation: qoe.Observation{Success: true},
				clearErr:    clearFailure,
			},
			wantOrder:        "acquire,configure,measure,clear,release",
			wantError:        clearFailure,
			wantReleaseError: clearFailure,
		},
		{
			name: "clear failure overrides configure failure",
			options: leaseProbeOptions{
				configureErr: configureFailure,
				clearErr:     clearFailure,
			},
			wantOrder:        "acquire,configure,clear,release",
			wantError:        clearFailure,
			notWantError:     configureFailure,
			wantReleaseError: clearFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			order := &callOrder{}
			fixture := newLeaseAwareProber(t, order, test.options)
			ctx, cancel := context.WithCancel(context.Background())
			if test.context != nil {
				cancel()
				ctx, cancel = test.context()
			}
			defer cancel()

			response, err := fixture.prober.Probe(
				ctx,
				agentapi.ProbeModeQoE,
				vlessProbeRequest(),
			)
			if test.wantError == nil && err != nil {
				t.Fatalf("Probe error=%v", err)
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("Probe error=%v, want %v", err, test.wantError)
			}
			if test.notWantError != nil && errors.Is(err, test.notWantError) {
				t.Fatalf("Probe error=%v retained lower-precedence %v", err, test.notWantError)
			}
			if response.FailureClass != test.wantClass {
				t.Fatalf("response=%+v, want failure class %q", response, test.wantClass)
			}
			if got := order.String(); got != test.wantOrder {
				t.Fatalf("order=%s, want %s", got, test.wantOrder)
			}
			if fixture.runtime.acquireCalls != 1 || fixture.runtime.releaseCalls != 1 {
				t.Fatalf(
					"runtime calls acquire=%d release=%d",
					fixture.runtime.acquireCalls,
					fixture.runtime.releaseCalls,
				)
			}
			if len(fixture.runtime.cleanupErrors) != 1 ||
				!errors.Is(fixture.runtime.cleanupErrors[0], test.wantReleaseError) {
				t.Fatalf(
					"release cleanup errors=%v, want %v",
					fixture.runtime.cleanupErrors,
					test.wantReleaseError,
				)
			}
			if fixture.runner.cleanupContextErr != nil {
				t.Fatalf("cleanup inherited request cancellation: %v", fixture.runner.cleanupContextErr)
			}
			assertCleanupDeadline(t, fixture.runner.cleanupDeadline, fixture.prober.cleanupTimeout)
		})
	}
}

func TestVLESSProbeCleanupUsesConfiguredTimeout(t *testing.T) {
	order := &callOrder{}
	fixture := newLeaseAwareProber(t, order, leaseProbeOptions{
		observation: qoe.Observation{Success: true},
		blockClear:  true,
	})
	fixture.prober.cleanupTimeout = 25 * time.Millisecond

	started := time.Now()
	response, err := fixture.prober.Probe(
		context.Background(),
		agentapi.ProbeModeQoE,
		vlessProbeRequest(),
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Probe error=%v, want cleanup deadline exceeded; response=%+v", err, response)
	}
	if elapsed := time.Since(started); elapsed < fixture.prober.cleanupTimeout {
		t.Fatalf("cleanup returned after %s, before configured %s", elapsed, fixture.prober.cleanupTimeout)
	}
	if len(fixture.runtime.cleanupErrors) != 1 ||
		!errors.Is(fixture.runtime.cleanupErrors[0], context.DeadlineExceeded) {
		t.Fatalf("release cleanup errors=%v", fixture.runtime.cleanupErrors)
	}
	if got := order.String(); got != "acquire,configure,measure,clear,release" {
		t.Fatalf("order=%s", got)
	}
}

func TestVLESSProbeRuntimeDrainIsInfrastructureFailure(t *testing.T) {
	order := &callOrder{}
	const epoch = 7
	runner := &lifecycleProbeXrayRunner{
		order: order,
		slot:  fastSlotStart,
	}
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, runner)
	control.Reset(epoch)
	leaseCtx, cancelLease := context.WithCancel(context.Background())
	defer cancelLease()
	runtime := &recordingProbeRuntime{
		order:        order,
		epoch:        epoch,
		leaseContext: leaseCtx,
	}
	var cancelOnce sync.Once
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: probeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			cancelOnce.Do(cancelLease)
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
	}}
	prober := &Prober{
		control:        control,
		runtime:        runtime,
		cleanupTimeout: 200 * time.Millisecond,
		liveness:       liveness,
		portBase:       11080,
		fullSlots:      slotPool(fullSlotStart, fullSlotCount),
		fastSlots:      slotPool(fastSlotStart, fastSlotCount),
		activeSlots:    slotPool(activeSlotStart, activeSlotCount),
		qoeSlots:       slotPool(qoeSlotStart, qoeSlotCount),
	}

	response, err := prober.Probe(
		context.Background(),
		agentapi.ProbeModeFast,
		vlessProbeRequest(),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("response=%+v error=%v, want runtime cancellation", response, err)
	}
	if response.FailureClass != agentapi.FailureNone {
		t.Fatalf("runtime drain became candidate failure: %+v", response)
	}
	if got := order.String(); got != "acquire,configure,clear,release" {
		t.Fatalf("order=%s", got)
	}
	if runtime.releaseCalls != 1 || len(runtime.cleanupErrors) != 1 ||
		runtime.cleanupErrors[0] != nil {
		t.Fatalf("release calls=%d cleanup=%v", runtime.releaseCalls, runtime.cleanupErrors)
	}
}

func TestVLESSFullProbeRuntimeDrainIsInfrastructureFailure(t *testing.T) {
	order := &callOrder{}
	const epoch = 7
	runner := &lifecycleProbeXrayRunner{
		order: order,
		slot:  fullSlotStart,
	}
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, runner)
	control.Reset(epoch)
	leaseCtx, cancelLease := context.WithCancel(context.Background())
	defer cancelLease()
	runtime := &recordingProbeRuntime{
		order:        order,
		epoch:        epoch,
		leaseContext: leaseCtx,
	}
	var cancelOnce sync.Once
	measurer := probe.Measurer{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: probeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			cancelOnce.Do(cancelLease)
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
	}}
	prober := &Prober{
		control:        control,
		runtime:        runtime,
		cleanupTimeout: 200 * time.Millisecond,
		measurer:       measurer,
		portBase:       11080,
		fullSlots:      slotPool(fullSlotStart, fullSlotCount),
		fastSlots:      slotPool(fastSlotStart, fastSlotCount),
		activeSlots:    slotPool(activeSlotStart, activeSlotCount),
		qoeSlots:       slotPool(qoeSlotStart, qoeSlotCount),
	}

	response, err := prober.Probe(
		context.Background(),
		agentapi.ProbeModeFull,
		vlessProbeRequest(),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("response=%+v error=%v, want runtime cancellation", response, err)
	}
	if response.FailureClass != agentapi.FailureNone {
		t.Fatalf("runtime drain became candidate failure: %+v", response)
	}
	if got := order.String(); got != "acquire,configure,clear,release" {
		t.Fatalf("order=%s", got)
	}
	if runtime.releaseCalls != 1 || len(runtime.cleanupErrors) != 1 ||
		runtime.cleanupErrors[0] != nil {
		t.Fatalf("release calls=%d cleanup=%v", runtime.releaseCalls, runtime.cleanupErrors)
	}
}

func TestVLESSFullProbeUsesQUICForStandardVision(t *testing.T) {
	runner := &recordingProbeXrayRunner{}
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, runner)
	control.Reset(7)
	quicChecks := 0
	client := &http.Client{Transport: probeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusOK
		if request.URL.Host == "api.openai.com" {
			status = http.StatusUnauthorized
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(make([]byte, 1024*1024))),
			Header:     make(http.Header),
		}, nil
	})}
	prober := &Prober{
		control: control, runtime: &recordingProbeRuntime{epoch: 7}, cleanupTimeout: time.Second,
		measurer: probe.Measurer{
			ClientFactory: func(string) *http.Client { return client },
			MTProtoCheck:  func(context.Context, string) bool { return true },
			UDPCheck: func(context.Context, string) bool {
				quicChecks++
				return false
			},
		},
		portBase: 11080, fullSlots: slotPool(fullSlotStart, fullSlotCount),
		fastSlots: slotPool(fastSlotStart, fastSlotCount), activeSlots: slotPool(activeSlotStart, activeSlotCount),
		qoeSlots: slotPool(qoeSlotStart, qoeSlotCount),
	}
	request := vlessProbeRequest()
	request.Payload = " \t" + request.Payload + "&flow=xtls-rprx-vision\n"
	response, err := prober.Probe(context.Background(), agentapi.ProbeModeFull, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Evaluation.UDPQualified || quicChecks != 1 {
		t.Fatalf("response=%+v QUIC checks=%d", response, quicChecks)
	}
}

func TestVLESSProbeClearsAndRepanics(t *testing.T) {
	panicValue := errors.New("measurement panic")
	clearFailure := errors.New("clear failed during panic")
	for _, test := range []struct {
		name     string
		clearErr error
	}{
		{name: "clear succeeds"},
		{name: "clear fails", clearErr: clearFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := &callOrder{}
			fixture := newLeaseAwareProber(t, order, leaseProbeOptions{
				clearErr: test.clearErr,
				measure: func(context.Context, string, string) qoe.Observation {
					panic(panicValue)
				},
			})

			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = fixture.prober.Probe(
					context.Background(),
					agentapi.ProbeModeQoE,
					vlessProbeRequest(),
				)
			}()
			if recovered != panicValue {
				t.Fatalf("recovered=%v, want original panic %v", recovered, panicValue)
			}
			if got := order.String(); got != "acquire,configure,measure,clear,release" {
				t.Fatalf("order=%s", got)
			}
			if fixture.runtime.releaseCalls != 1 ||
				len(fixture.runtime.cleanupErrors) != 1 ||
				!errors.Is(fixture.runtime.cleanupErrors[0], test.clearErr) {
				t.Fatalf(
					"runtime releases=%d cleanup=%v",
					fixture.runtime.releaseCalls,
					fixture.runtime.cleanupErrors,
				)
			}
			if got := len(fixture.prober.qoeSlots); got != qoeSlotCount {
				t.Fatalf("slot was not returned after panic: available=%d", got)
			}
		})
	}
}

func TestTorProbeDoesNotAcquireRuntime(t *testing.T) {
	runtime := &recordingProbeRuntime{epoch: 7}
	manager := &recordingTorProbeManager{explorer: "tor"}
	prober := testTorProber(manager, probe.Liveness{})
	prober.runtime = runtime
	prober.qoe = qoeMeasurerFunc(func(context.Context, string, string) qoe.Observation {
		return qoe.Observation{Success: true}
	})

	response, err := prober.Probe(
		context.Background(),
		agentapi.ProbeModeQoE,
		torProbeRequest("tor"),
	)
	if err != nil || !response.Success {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if runtime.acquireCalls != 0 || runtime.releaseCalls != 0 {
		t.Fatalf(
			"Tor touched probe runtime: acquire=%d release=%d",
			runtime.acquireCalls,
			runtime.releaseCalls,
		)
	}
}

func TestVLESSQoEUsesTransportAwareMeasurement(t *testing.T) {
	fixture := newLeaseAwareProber(t, &callOrder{}, leaseProbeOptions{})
	measurer := &recordingVLESSQoEMeasurer{}
	fixture.prober.qoe = measurer
	response, err := fixture.prober.Probe(
		context.Background(), agentapi.ProbeModeQoE, vlessProbeRequest(),
	)
	if err != nil || !response.Success {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if measurer.vlessCalls != 1 || measurer.genericCalls != 0 {
		t.Fatalf("VLESS calls=%d generic calls=%d", measurer.vlessCalls, measurer.genericCalls)
	}
}

func TestQoEProbeResponseClassifiesObservationWithoutRawError(t *testing.T) {
	tests := []struct {
		name        string
		observation qoe.Observation
		wantClass   agentapi.FailureClass
	}{
		{name: "success", observation: qoe.Observation{Success: true}},
		{name: "candidate", observation: qoe.Observation{ErrorCode: "qoe_route_timeout"}, wantClass: agentapi.FailureCandidate},
		{name: "infrastructure", observation: qoe.Observation{Infrastructure: true, ErrorCode: "qoe_endpoint_unavailable"}, wantClass: agentapi.FailureInfrastructure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := qoeProbeResponse("candidate", test.observation)
			if response.Success != test.observation.Success || response.FailureClass != test.wantClass ||
				response.ErrorCode != test.observation.ErrorCode || response.QoE == nil || *response.QoE != test.observation {
				t.Fatalf("response=%+v", response)
			}
			if strings.Contains(response.ErrorCode, "dial tcp") {
				t.Fatalf("response leaked raw error text: %+v", response)
			}
		})
	}
}

func TestFullProbeResponseReportsQualificationFailure(t *testing.T) {
	metrics := healthyProbeMetrics()
	metrics.OpenAI401 = false

	response := fullProbeResponse("candidate", metrics, health.ProtocolVLESS)

	if response.Success || response.FailureClass != agentapi.FailureCandidate || response.ErrorCode != "openai_api_failed" {
		t.Fatalf("response=%+v", response)
	}
}

func TestFullProbeResponseSucceedsWithoutFailureMetadata(t *testing.T) {
	response := fullProbeResponse("candidate", healthyProbeMetrics(), health.ProtocolVLESS)

	if !response.Success || response.FailureClass != agentapi.FailureNone || response.ErrorCode != "" {
		t.Fatalf("response=%+v", response)
	}
}

func healthyProbeMetrics() health.Metrics {
	return health.Metrics{
		SuccessRatio: 1, Latency: 50 * time.Millisecond, ThroughputMbps: 100,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true,
		TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}
}

type qoeMeasureCall struct {
	candidateID string
	socksAddr   string
}

type recordingQoEMeasurer struct {
	mu          sync.Mutex
	calls       []qoeMeasureCall
	observation qoe.Observation
}

func (measurer *recordingQoEMeasurer) Measure(_ context.Context, candidateID, socksAddr string) qoe.Observation {
	measurer.mu.Lock()
	defer measurer.mu.Unlock()
	measurer.calls = append(measurer.calls, qoeMeasureCall{candidateID: candidateID, socksAddr: socksAddr})
	return measurer.observation
}

func (measurer *recordingQoEMeasurer) callsSnapshot() []qoeMeasureCall {
	measurer.mu.Lock()
	defer measurer.mu.Unlock()
	return append([]qoeMeasureCall(nil), measurer.calls...)
}

type recordingProbeXrayRunner struct {
	mu    sync.Mutex
	stdin []string
}

type criticalActiveCacheRunner struct {
	mu              sync.Mutex
	adoCalls        int
	routingBodies   []string
	failNextADO     error
	firstADOStarted chan struct{}
	releaseFirstADO chan struct{}
	startOnce       sync.Once
}

func newBlockingCriticalActiveCacheRunner() *criticalActiveCacheRunner {
	return &criticalActiveCacheRunner{
		firstADOStarted: make(chan struct{}),
		releaseFirstADO: make(chan struct{}),
	}
}

func (runner *criticalActiveCacheRunner) Run(
	ctx context.Context,
	stdin string,
	_ string,
	args ...string,
) error {
	if len(args) < 2 {
		return nil
	}
	switch args[1] {
	case "ado":
		runner.mu.Lock()
		runner.adoCalls++
		call := runner.adoCalls
		failure := runner.failNextADO
		runner.failNextADO = nil
		started := runner.firstADOStarted
		release := runner.releaseFirstADO
		runner.mu.Unlock()
		if call == 1 && started != nil {
			runner.startOnce.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return failure
	case "adrules":
		runner.mu.Lock()
		runner.routingBodies = append(runner.routingBodies, stdin)
		runner.mu.Unlock()
	}
	return nil
}

func (runner *criticalActiveCacheRunner) adoCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.adoCalls
}

func (runner *criticalActiveCacheRunner) lastRoutingBody() string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.routingBodies) == 0 {
		return ""
	}
	return runner.routingBodies[len(runner.routingBodies)-1]
}

type criticalActiveAddressRecorder struct {
	mu        sync.Mutex
	addresses []string
}

func (recorder *criticalActiveAddressRecorder) liveness() probe.Liveness {
	return probe.Liveness{ClientFactory: func(address string) *http.Client {
		recorder.mu.Lock()
		recorder.addresses = append(recorder.addresses, address)
		recorder.mu.Unlock()
		return &http.Client{Transport: probeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		})}
	}}
}

func (recorder *criticalActiveAddressRecorder) snapshot() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]string(nil), recorder.addresses...)
}

func (runner *recordingProbeXrayRunner) Run(_ context.Context, stdin, _ string, _ ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.stdin = append(runner.stdin, stdin)
	return nil
}

func (runner *recordingProbeXrayRunner) stdinSnapshot() string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return strings.Join(runner.stdin, "\n")
}

type leaseProbeOptions struct {
	observation  qoe.Observation
	measure      func(context.Context, string, string) qoe.Observation
	configureErr error
	clearErr     error
	blockClear   bool
}

type blockingAvailabilityMeasurer struct {
	returned chan struct{}
}

func (*blockingAvailabilityMeasurer) Measure(
	context.Context, string, string,
) qoe.Observation {
	return qoe.Observation{}
}

func (measurer *blockingAvailabilityMeasurer) MeasureAvailability(
	ctx context.Context, _, _ string,
) qoe.Observation {
	<-ctx.Done()
	close(measurer.returned)
	return qoe.Observation{Infrastructure: true, ErrorCode: "availability_timeout"}
}

type leaseProbeFixture struct {
	prober  *Prober
	runtime *recordingProbeRuntime
	runner  *lifecycleProbeXrayRunner
}

func newLeaseAwareProber(
	t *testing.T,
	order *callOrder,
	options leaseProbeOptions,
) leaseProbeFixture {
	t.Helper()
	const epoch = 7
	runner := &lifecycleProbeXrayRunner{
		order:        order,
		slot:         qoeSlotStart,
		configureErr: options.configureErr,
		clearErr:     options.clearErr,
		blockClear:   options.blockClear,
	}
	control := probexray.New("xray", "127.0.0.1:10086", TotalProbeSlots, runner)
	control.Reset(epoch)
	runtime := &recordingProbeRuntime{order: order, epoch: epoch}
	measure := options.measure
	if measure == nil {
		measure = func(context.Context, string, string) qoe.Observation {
			return options.observation
		}
	}
	prober := &Prober{
		control:        control,
		runtime:        runtime,
		cleanupTimeout: 200 * time.Millisecond,
		qoe: qoeMeasurerFunc(func(
			ctx context.Context,
			candidateID string,
			socksAddress string,
		) qoe.Observation {
			order.Add("measure")
			if got := ctx.Value(leaseContextKey{}); got != "lease" {
				t.Errorf("measurement context marker=%v, want lease context", got)
			}
			return measure(ctx, candidateID, socksAddress)
		}),
		portBase:    11080,
		fullSlots:   slotPool(fullSlotStart, fullSlotCount),
		fastSlots:   slotPool(fastSlotStart, fastSlotCount),
		activeSlots: slotPool(activeSlotStart, activeSlotCount),
		qoeSlots:    slotPool(qoeSlotStart, qoeSlotCount),
	}
	return leaseProbeFixture{prober: prober, runtime: runtime, runner: runner}
}

type leaseContextKey struct{}

type recordingProbeRuntime struct {
	mu            sync.Mutex
	order         *callOrder
	epoch         uint64
	leaseContext  context.Context
	acquireCalls  int
	releaseCalls  int
	cleanupErrors []error
	onRelease     func()
}

func (runtime *recordingProbeRuntime) Acquire(ctx context.Context) (*proberuntime.Lease, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.acquireCalls++
	if runtime.order != nil {
		runtime.order.Add("acquire")
	}
	leaseContext := ctx
	if runtime.leaseContext != nil {
		leaseContext = runtime.leaseContext
	}
	return &proberuntime.Lease{
		Epoch:   runtime.epoch,
		Context: context.WithValue(leaseContext, leaseContextKey{}, "lease"),
	}, nil
}

func (runtime *recordingProbeRuntime) Release(lease *proberuntime.Lease, cleanupErr error) {
	runtime.mu.Lock()
	runtime.releaseCalls++
	runtime.cleanupErrors = append(runtime.cleanupErrors, cleanupErr)
	onRelease := runtime.onRelease
	runtime.mu.Unlock()
	if runtime.order != nil {
		runtime.order.Add("release")
	}
	if onRelease != nil {
		onRelease()
	}
}

func (runtime *recordingProbeRuntime) Snapshot() proberuntime.Snapshot {
	return proberuntime.Snapshot{Status: "ready", Epoch: runtime.epoch}
}

type lifecycleProbeXrayRunner struct {
	mu                sync.Mutex
	order             *callOrder
	slot              int
	configureErr      error
	clearErr          error
	blockClear        bool
	cleanupContextErr error
	cleanupDeadline   time.Time
}

func (runner *lifecycleProbeXrayRunner) Run(
	ctx context.Context,
	stdin string,
	_ string,
	args ...string,
) error {
	if len(args) < 2 {
		return nil
	}
	switch args[1] {
	case "ado":
		runner.order.Add("configure")
		return runner.configureErr
	case "adrules":
		routeTag := fmt.Sprintf(`"ruleTag":"probe-route-%d"`, runner.slot)
		if strings.Contains(stdin, routeTag) {
			return nil
		}
		runner.order.Add("clear")
		runner.mu.Lock()
		runner.cleanupContextErr = ctx.Err()
		runner.cleanupDeadline, _ = ctx.Deadline()
		block := runner.blockClear
		clearErr := runner.clearErr
		runner.mu.Unlock()
		if block {
			<-ctx.Done()
			return ctx.Err()
		}
		return clearErr
	default:
		return nil
	}
}

type callOrder struct {
	mu    sync.Mutex
	calls []string
}

func (order *callOrder) Add(call string) {
	order.mu.Lock()
	defer order.mu.Unlock()
	order.calls = append(order.calls, call)
}

func (order *callOrder) String() string {
	order.mu.Lock()
	defer order.mu.Unlock()
	return strings.Join(order.calls, ",")
}

type qoeMeasurerFunc func(context.Context, string, string) qoe.Observation

func (function qoeMeasurerFunc) Measure(
	ctx context.Context,
	candidateID string,
	socksAddress string,
) qoe.Observation {
	return function(ctx, candidateID, socksAddress)
}

type recordingVLESSQoEMeasurer struct {
	genericCalls int
	vlessCalls   int
}

func (measurer *recordingVLESSQoEMeasurer) Measure(
	context.Context, string, string,
) qoe.Observation {
	measurer.genericCalls++
	return qoe.Observation{Success: true}
}

func (measurer *recordingVLESSQoEMeasurer) MeasureVLESS(
	context.Context, string, string, string,
) qoe.Observation {
	measurer.vlessCalls++
	return qoe.Observation{Success: true}
}

func canceledQoEMeasure(ctx context.Context, _, _ string) qoe.Observation {
	<-ctx.Done()
	return qoe.Observation{
		Infrastructure: true,
		ErrorCode:      "qoe_measurement_canceled",
	}
}

type probeRoundTripFunc func(*http.Request) (*http.Response, error)

func (function probeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func assertCleanupDeadline(t *testing.T, deadline time.Time, timeout time.Duration) {
	t.Helper()
	if deadline.IsZero() {
		t.Fatal("cleanup context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > timeout || remaining < timeout-100*time.Millisecond {
		t.Fatalf("cleanup deadline remaining=%s, want approximately %s", remaining, timeout)
	}
}

func vlessProbeRequest() agentapi.ProbeRequest {
	return agentapi.ProbeRequest{
		CandidateID: "candidate",
		Kind:        sources.KindVLESS,
		Payload:     "vless://id@example.net:443?type=raw&security=reality&pbk=public-key&sni=example.com",
	}
}

var _ qoeMeasurer = (*probe.QoEMeasurer)(nil)
