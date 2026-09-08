package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestTorFastProbeRetriesUntilSOCKSRouteIsLive(t *testing.T) {
	manager := &recordingTorProbeManager{}
	var attempts atomic.Int32
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			if attempts.Add(1) <= 4 {
				return nil, errors.New("Tor circuit is not ready")
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})}
	}}
	prober := testTorProber(manager, liveness)

	response, err := prober.Probe(context.Background(), agentapi.ProbeModeFast, torProbeRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Success || manager.callCount() != 1 || attempts.Load() < 5 {
		t.Fatalf("response=%+v calls=%d attempts=%d", response, manager.callCount(), attempts.Load())
	}
}

func TestTorActiveProbeReportsCompleteLivenessFailureWithoutRetry(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "first"}
	var attempts atomic.Int32
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts.Add(1)
			return nil, errors.New("Tor circuit cannot carry traffic")
		})}
	}}
	prober := testTorProber(manager, liveness)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := prober.Probe(ctx, agentapi.ProbeModeActive, torProbeRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Success || response.FailureClass != agentapi.FailureCandidate ||
		response.ErrorCode != "liveness_failed" || attempts.Load() != 2 {
		t.Fatalf("response=%+v attempts=%d", response, attempts.Load())
	}
}

func TestActiveTorDeadlineIsInfrastructureNotCandidateFailure(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "first"}
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
	}}
	prober := testTorProber(manager, liveness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	liveness.ClientFactory = func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			cancel()
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
	}
	prober.liveness = liveness
	response, err := prober.Probe(ctx, agentapi.ProbeModeActiveCritical, torProbeRequest("first"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("response=%+v err=%v want cancellation", response, err)
	}
	if response.FailureClass == agentapi.FailureCandidate {
		t.Fatalf("deadline became candidate failure: %+v", response)
	}
}

func TestTorQoEUsesWarmProfileWithoutExplorer(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "tor"}
	measurer := &recordingQoEMeasurer{observation: qoe.Observation{
		Success: true, Bytes: 65536, ThroughputMbps: 8,
	}}
	prober := testTorProber(manager, probe.Liveness{})
	prober.qoe = measurer

	response, err := prober.Probe(context.Background(), agentapi.ProbeModeQoE, torProbeRequest("tor"))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.QoE == nil {
		t.Fatalf("response=%+v", response)
	}
	if manager.callCount() != 0 {
		t.Fatalf("QoE probe used Tor explorer: calls=%d", manager.callCount())
	}
	calls := measurer.callsSnapshot()
	if len(calls) != 1 || calls[0].candidateID != "tor" || calls[0].socksAddr != "127.0.0.1:19050" {
		t.Fatalf("QoE calls=%+v", calls)
	}
}

func TestTorQoERejectsExplorerProfileWithoutMeasurement(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "explorer"}
	measurer := &recordingQoEMeasurer{observation: qoe.Observation{Success: true}}
	prober := testTorProber(manager, probe.Liveness{})
	prober.qoe = measurer

	response, err := prober.Probe(
		context.Background(),
		agentapi.ProbeModeQoE,
		torProbeRequest("explorer"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.Success || response.FailureClass != agentapi.FailureCandidate ||
		response.ErrorCode != "tor_profile_unavailable" || response.QoE != nil {
		t.Fatalf("response=%+v", response)
	}
	if calls := measurer.callsSnapshot(); len(calls) != 0 {
		t.Fatalf("QoE measurement used explorer profile: calls=%+v", calls)
	}
	if manager.callCount() != 0 {
		t.Fatalf("QoE probe created Tor explorer: calls=%d", manager.callCount())
	}
}

func TestTorQoEDiscardsMeasurementWhenWarmProfileChanges(t *testing.T) {
	tests := []struct {
		name   string
		change func(*mutableTorProbeManager)
	}{
		{
			name: "exited",
			change: func(manager *mutableTorProbeManager) {
				manager.setExited(true)
			},
		},
		{
			name: "replaced",
			change: func(manager *mutableTorProbeManager) {
				manager.replaceProfile(torpool.Profile{
					Slot: 1, CandidateID: "tor", SocksAddr: "127.0.0.1:19051", Role: "warm",
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newMutableTorProbeManager(torpool.Profile{
				Slot: 0, CandidateID: "tor", SocksAddr: "127.0.0.1:19050", Role: "warm",
			})
			measurer := &blockingQoEMeasurer{
				started:     make(chan struct{}),
				release:     make(chan struct{}),
				observation: qoe.Observation{Success: true, Bytes: 65536, ThroughputMbps: 8},
			}
			prober := testTorProber(manager, probe.Liveness{})
			prober.qoe = measurer
			type result struct {
				response agentapi.ProbeResponse
				err      error
			}
			done := make(chan result, 1)
			go func() {
				response, err := prober.Probe(
					context.Background(),
					agentapi.ProbeModeQoE,
					torProbeRequest("tor"),
				)
				done <- result{response: response, err: err}
			}()

			select {
			case <-measurer.started:
			case <-time.After(time.Second):
				t.Fatal("QoE measurement did not start")
			}
			test.change(manager)
			close(measurer.release)

			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				response := result.response
				if response.Success || response.FailureClass != agentapi.FailureCandidate ||
					response.ErrorCode != "tor_process_exited" || response.QoE != nil {
					t.Fatalf("nominal QoE success was not discarded: response=%+v", response)
				}
			case <-time.After(time.Second):
				t.Fatal("QoE probe did not finish")
			}
		})
	}
}

func TestTorActiveProbeReportsProcessExitDuringLiveness(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "first"}
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			manager.clearExplorer()
			return nil, errors.New("Tor process exited")
		})}
	}}
	prober := testTorProber(manager, liveness)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := prober.Probe(ctx, agentapi.ProbeModeActive, torProbeRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != "tor_process_exited" {
		t.Fatalf("response=%+v", response)
	}
}

func TestTorActiveProbeReportsAlreadyExitedProcess(t *testing.T) {
	prober := testTorProber(&exitedTorProbeManager{}, liveTorLiveness())

	response, err := prober.Probe(context.Background(), agentapi.ProbeModeActive, torProbeRequest("exited"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != "tor_process_exited" {
		t.Fatalf("response=%+v", response)
	}
}

func TestTorActiveProbeTreatsMissingRuntimeProfileAsInfrastructure(t *testing.T) {
	prober := testTorProber(&recordingTorProbeManager{}, liveTorLiveness())

	response, err := prober.Probe(
		context.Background(),
		agentapi.ProbeModeActiveCritical,
		torProbeRequest("not-materialized"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.Success ||
		response.FailureClass != agentapi.FailureInfrastructure ||
		response.ErrorCode != "tor_profile_unavailable" {
		t.Fatalf("response=%+v", response)
	}
}

func TestTorFullProbeReportsProcessExitDuringMeasurement(t *testing.T) {
	manager := &recordingTorProbeManager{}
	measurer := probe.Measurer{
		ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
				manager.clearExplorer()
				return nil, errors.New("Tor process exited")
			})}
		},
		MTProtoCheck: func(context.Context, string) bool { return false },
	}
	prober := testTorProber(manager, liveTorLiveness())
	prober.measurer = measurer

	response, err := prober.Probe(context.Background(), agentapi.ProbeModeFull, torProbeRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != "tor_process_exited" {
		t.Fatalf("response=%+v", response)
	}
}

func TestTorDiscoveryProbesOwnExplorerSerially(t *testing.T) {
	manager := &recordingTorProbeManager{}
	release := make(chan struct{})
	var blocked atomic.Bool
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			if blocked.CompareAndSwap(false, true) {
				<-release
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})}
	}}
	prober := testTorProber(manager, liveness)
	results := make(chan error, 2)
	go func() {
		_, err := prober.Probe(context.Background(), agentapi.ProbeModeFast, torProbeRequest("first"))
		results <- err
	}()
	waitTorCalls(t, manager, 1)
	go func() {
		_, err := prober.Probe(context.Background(), agentapi.ProbeModeFast, torProbeRequest("second"))
		results <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if manager.callCount() != 1 {
		t.Fatalf("second explorer started before first released: calls=%d", manager.callCount())
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if manager.callCount() != 2 {
		t.Fatalf("calls=%d", manager.callCount())
	}
}

func TestCanceledTorProbeDoesNotReplaceExplorer(t *testing.T) {
	manager := &recordingTorProbeManager{}
	release := make(chan struct{})
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			<-release
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})}
	}}
	prober := testTorProber(manager, liveness)
	firstDone := make(chan error, 1)
	go func() {
		_, err := prober.Probe(context.Background(), agentapi.ProbeModeFast, torProbeRequest("first"))
		firstDone <- err
	}()
	waitTorCalls(t, manager, 1)

	ctx, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, err := prober.Probe(ctx, agentapi.ProbeModeFast, torProbeRequest("second"))
		secondDone <- err
	}()
	cancel()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("second error=%v", err)
	}
	if manager.callCount() != 1 {
		t.Fatalf("canceled probe mutated explorer: calls=%d", manager.callCount())
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestAcquireTorProbeRejectsAlreadyCanceledContextWithoutLeakingLease(t *testing.T) {
	prober := testTorProber(&recordingTorProbeManager{}, probe.Liveness{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	release, err := prober.acquireTorProbe(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if release != nil {
		t.Fatal("canceled acquisition returned a release function")
	}

	acquireCtx, acquireCancel := context.WithTimeout(context.Background(), time.Second)
	defer acquireCancel()
	release, err = prober.acquireTorProbe(acquireCtx)
	if err != nil {
		t.Fatalf("lease was leaked: %v", err)
	}
	release()
}

func TestTorProbeCanceledAfterAcquireDoesNotReplaceExplorer(t *testing.T) {
	manager := &recordingTorProbeManager{explorer: "existing"}
	prober := testTorProber(manager, liveTorLiveness())
	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelOnDeadlineContext{Context: baseCtx, cancel: cancel}

	_, err := prober.Probe(ctx, agentapi.ProbeModeFast, torProbeRequest("replacement"))
	if manager.callCount() != 0 || manager.currentExplorer() != "existing" {
		t.Fatalf("calls=%d explorer=%q", manager.callCount(), manager.currentExplorer())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestTorProbeReleasesLeaseAfterProbeCandidateError(t *testing.T) {
	manager := &recordingTorProbeManager{err: errors.New("probe candidate failed")}
	prober := testTorProber(manager, liveTorLiveness())

	if _, err := prober.Probe(context.Background(), agentapi.ProbeModeFast, torProbeRequest("first")); err == nil {
		t.Fatal("expected probe candidate error")
	}
	manager.setError(nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := prober.Probe(ctx, agentapi.ProbeModeFast, torProbeRequest("second"))
	if err != nil {
		t.Fatalf("lease was not released after error: %v", err)
	}
	if !response.Success {
		t.Fatalf("response=%+v", response)
	}
}

func TestTorProbeReleasesLeaseAfterReadinessCancellation(t *testing.T) {
	manager := &recordingTorProbeManager{}
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("Tor circuit is not ready")
		})}
	}}
	prober := testTorProber(manager, liveness)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	response, err := prober.Probe(ctx, agentapi.ProbeModeFast, torProbeRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != "tor_bootstrap_timeout" {
		t.Fatalf("response=%+v", response)
	}

	acquireCtx, acquireCancel := context.WithTimeout(context.Background(), time.Second)
	defer acquireCancel()
	release, err := prober.acquireTorProbe(acquireCtx)
	if err != nil {
		t.Fatalf("lease was leaked after readiness cancellation: %v", err)
	}
	release()
}

func TestTorProbeReportsExitedProcessWithoutWaitingForBootstrapDeadline(t *testing.T) {
	manager := &exitedTorProbeManager{}
	liveness := probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("SOCKS listener unavailable")
		})}
	}}
	prober := testTorProber(manager, liveness)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := time.Now()
	response, err := prober.Probe(ctx, agentapi.ProbeModeFast, torProbeRequest("exited"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != "tor_process_exited" {
		t.Fatalf("response=%+v", response)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("exited Tor process was reported after %v", elapsed)
	}
}

type exitedTorProbeManager struct{}

func (*exitedTorProbeManager) ProbeCandidate(
	_ context.Context,
	candidate torpool.Candidate,
) (torpool.Profile, error) {
	return torpool.Profile{
		Slot: 3, CandidateID: candidate.ID,
		SocksAddr: "127.0.0.1:19053", Role: "explorer",
	}, nil
}

func (*exitedTorProbeManager) Profiles() []torpool.Profile { return nil }

func (*exitedTorProbeManager) ProfileStatus(candidateID string) (torpool.ProfileStatus, bool) {
	return torpool.ProfileStatus{
		Profile: torpool.Profile{
			Slot: 3, CandidateID: candidateID,
			SocksAddr: "127.0.0.1:19053", Role: "explorer",
		},
		Exited: true,
	}, true
}

type mutableTorProbeManager struct {
	mu     sync.Mutex
	status torpool.ProfileStatus
}

func newMutableTorProbeManager(profile torpool.Profile) *mutableTorProbeManager {
	return &mutableTorProbeManager{status: torpool.ProfileStatus{Profile: profile}}
}

func (*mutableTorProbeManager) ProbeCandidate(
	context.Context,
	torpool.Candidate,
) (torpool.Profile, error) {
	return torpool.Profile{}, errors.New("unexpected Tor explorer probe")
}

func (manager *mutableTorProbeManager) Profiles() []torpool.Profile {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return []torpool.Profile{manager.status.Profile}
}

func (manager *mutableTorProbeManager) ProfileStatus(string) (torpool.ProfileStatus, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.status, true
}

func (manager *mutableTorProbeManager) setExited(exited bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.Exited = exited
}

func (manager *mutableTorProbeManager) replaceProfile(profile torpool.Profile) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status = torpool.ProfileStatus{Profile: profile}
}

type blockingQoEMeasurer struct {
	started     chan struct{}
	release     chan struct{}
	observation qoe.Observation
}

func (measurer *blockingQoEMeasurer) Measure(
	context.Context,
	string,
	string,
) qoe.Observation {
	close(measurer.started)
	<-measurer.release
	return measurer.observation
}

type recordingTorProbeManager struct {
	mu       sync.Mutex
	calls    []string
	explorer string
	err      error
}

func (manager *recordingTorProbeManager) ProbeCandidate(
	_ context.Context,
	candidate torpool.Candidate,
) (torpool.Profile, error) {
	manager.mu.Lock()
	manager.calls = append(manager.calls, candidate.ID)
	manager.explorer = candidate.ID
	err := manager.err
	manager.mu.Unlock()
	if err != nil {
		return torpool.Profile{}, err
	}
	return torpool.Profile{
		Slot:        3,
		CandidateID: candidate.ID,
		SocksAddr:   "127.0.0.1:19053",
		Role:        "explorer",
	}, nil
}

func (manager *recordingTorProbeManager) Profiles() []torpool.Profile {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.explorer == "" {
		return nil
	}
	return []torpool.Profile{{
		Slot: 3, CandidateID: manager.explorer,
		SocksAddr: "127.0.0.1:19053", Role: "explorer",
	}}
}

func (manager *recordingTorProbeManager) ProfileStatus(
	candidateID string,
) (torpool.ProfileStatus, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.explorer == "" || manager.explorer != candidateID {
		return torpool.ProfileStatus{}, false
	}
	return torpool.ProfileStatus{
		Profile: torpool.Profile{
			Slot: 3, CandidateID: manager.explorer,
			SocksAddr: torSOCKSAddress(manager.explorer), Role: torProfileRole(manager.explorer),
		},
	}, true
}

func torSOCKSAddress(candidateID string) string {
	if candidateID == "tor" {
		return "127.0.0.1:19050"
	}
	return "127.0.0.1:19053"
}

func torProfileRole(candidateID string) string {
	if candidateID == "tor" {
		return "warm"
	}
	return "explorer"
}

func (manager *recordingTorProbeManager) callCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return len(manager.calls)
}

func (manager *recordingTorProbeManager) currentExplorer() string {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.explorer
}

func (manager *recordingTorProbeManager) setError(err error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.err = err
}

func (manager *recordingTorProbeManager) clearExplorer() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.explorer = ""
}

type cancelOnDeadlineContext struct {
	context.Context
	cancel context.CancelFunc
}

func (ctx *cancelOnDeadlineContext) Deadline() (time.Time, bool) {
	ctx.cancel()
	return time.Time{}, false
}

type torRoundTripFunc func(*http.Request) (*http.Response, error)

func (function torRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func liveTorLiveness() probe.Liveness {
	return probe.Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: torRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})}
	}}
}

func testTorProber(manager TorProbeManager, liveness probe.Liveness) *Prober {
	lease := make(chan struct{}, 1)
	lease <- struct{}{}
	return &Prober{
		tor: manager, liveness: liveness,
		torProbeLease: lease, torRetryInterval: time.Millisecond,
	}
}

func torProbeRequest(id string) agentapi.ProbeRequest {
	return agentapi.ProbeRequest{
		CandidateID: id,
		Kind:        sources.KindTorBridge,
		Payload:     "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	}
}

func waitTorCalls(t *testing.T, manager *recordingTorProbeManager, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.callCount() >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("calls=%d, want %d", manager.callCount(), count)
}
