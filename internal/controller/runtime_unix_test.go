//go:build unix

package controller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

func TestRuntimeRetriesTemporaryHTTPApplyAndRetainsHardReason(t *testing.T) {
	runner := &temporaryRouteRunner{failRoutes: 1}
	adapter := xrayapi.NewAdapter(
		"xray", "127.0.0.1:10085", "9.9.9.9", runner,
	)
	reconciler, err := dataplane.NewReconciler(
		adapter, t.TempDir()+"/applied.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	client := agentapi.NewClient(serveRuntimeAgent(
		t, agentapi.NewServer(reconciler, 64*1024),
	))
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{{
			ID: "primary", Protocol: dataplane.ProtocolVLESS,
			Config: []byte(`{"protocol":"vless"}`),
		}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "primary", UDPOutbound: "primary",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	attempts := 0
	runtime := Runtime{
		Place: func(
			ctx context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			err := client.Apply(ctx, plan)
			if err == nil {
				cancel()
			}
			return err
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("temporary HTTP apply was not retried")
	}
	if attempts != 2 || runner.RouteCalls() != 2 {
		t.Fatalf("hard attempts=%d xray route calls=%d want 2/2",
			attempts, runner.RouteCalls())
	}
}

func TestRuntimeUnixHTTPHardFailurePreemptsStartupNormalizationWithinEnvelope(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "domain-a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "domain-b"},
		{name: "replacement", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "domain-c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(
		t, database, "alice", "10.44.0.2/32", now, false,
		candidates["primary"].ID, candidates["primary"].ID,
	)
	applier := newWallClockHTTPApplier()
	agent := agentapi.NewClient(serveRuntimeAgent(t, agentapi.NewServer(
		applier, 64*1024, agentapi.WithActivityProvider(emptyActivityProvider{}),
	)))
	engine := NewEngine(
		database, agent, nil, scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"), WithQoEEnabled(false), WithDNSResolver("1.1.1.1"),
		WithActiveProbeInterval(time.Minute), WithActiveCriticalRouteLimit(16),
	)
	if err := engine.Cycle(ctx, now); err != nil {
		t.Fatal(err)
	}
	engine.dnsResolvers = []string{"9.9.9.9"}

	hardFailures := NewHardFailureMailbox()
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	reasons := make(chan PlacementReason, 16)
	var writerMu sync.Mutex
	writers, maximumWriters := 0, 0
	unready := make(chan error, 1)
	ready := make(chan struct{}, 1)
	coverageErr := &ActiveCriticalCoveragePlanError{
		Limit: 16, Unsatisfied: []string{"startup:normalization"},
		SearchExhausted: true,
	}
	runtime := Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return coverageErr },
		RecoveryReady:    engine.ActiveCardinalityReady,
		CapacityReady:    engine.CapacityReady,
		Qualify: func(context.Context, time.Time) error {
			return store.ErrCandidateInventoryChanged
		},
		Place: func(ctx context.Context, at time.Time, reason PlacementReason) error {
			writerMu.Lock()
			writers++
			if writers > maximumWriters {
				maximumWriters = writers
			}
			writerMu.Unlock()
			defer func() {
				writerMu.Lock()
				writers--
				writerMu.Unlock()
			}()
			reasons <- reason
			return engine.CycleForReason(ctx, at, reason)
		},
		HardFailureEvents:          hardFailures,
		Unready:                    func(err error) { unready <- err },
		Ready:                      func() { ready <- struct{}{} },
		PlacementPreemptTimeout:    100 * time.Millisecond,
		NormalizationRetryInterval: time.Hour,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             time.Hour,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runtimeCtx) }()
	select {
	case err := <-unready:
		if !errors.Is(err, ErrActiveCriticalCoverageExceeded) {
			cancelRuntime()
			t.Fatalf("startup unready=%v", err)
		}
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup normalization did not keep readiness red")
	}
	select {
	case <-applier.lowerStarted:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup-normalization HTTP apply did not block")
	}
	assignment := engineQoEAssignment(t, database, "alice")
	failed := engineCandidateByID(t, candidates, assignment.TCPOutbound)
	probeStartedAt := time.Now()
	observation, err := database.ReserveCandidateObservation(
		ctx, failed, store.ObservationActive,
	)
	if err != nil {
		cancelRuntime()
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(
		ctx, failed, observation, time.Now(),
	); err != nil || !commit.Accepted {
		cancelRuntime()
		t.Fatalf("hard failure commit=%+v err=%v", commit, err)
	}
	detectedAt := time.Now()
	event, err := NewHardFailureEvent(
		failed.ID, probeStartedAt, detectedAt, 950*time.Millisecond,
	)
	if err != nil {
		cancelRuntime()
		t.Fatal(err)
	}
	hardFailures.Publish(event)
	select {
	case <-applier.hardDone:
	case <-time.After(950 * time.Millisecond):
		cancelRuntime()
		t.Fatal("hard HTTP apply exceeded its 950ms budget")
	}
	hardElapsed := time.Since(probeStartedAt)
	select {
	case <-ready:
		cancelRuntime()
		t.Fatal("hard success alone turned readiness green")
	default:
	}
	select {
	case <-applier.recomputeDone:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("startup normalization was not recomputed after hard apply")
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		cancelRuntime()
		t.Fatal("fresh startup normalization did not restore readiness")
	}
	var state store.PlanState
	settleDeadline := time.Now().Add(500 * time.Millisecond)
	for {
		state, err = database.LoadPlanState(ctx)
		if err != nil {
			cancelRuntime()
			t.Fatal(err)
		}
		if state.AppliedGeneration == 4 {
			break
		}
		if time.Now().After(settleDeadline) {
			cancelRuntime()
			t.Fatalf("recomputed generation did not settle: desired=%d applied=%d reason=%s",
				state.DesiredGeneration, state.AppliedGeneration, state.DesiredReason)
		}
		time.Sleep(time.Millisecond)
	}
	totalElapsed := time.Since(probeStartedAt)
	cancelRuntime()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if hardElapsed >= 950*time.Millisecond || totalElapsed >= 2*time.Second {
		t.Fatalf("wall envelope hard=%s total=%s", hardElapsed, totalElapsed)
	}
	preemptionGap := applier.PreemptionGap()
	if preemptionGap < 0 || preemptionGap > 100*time.Millisecond {
		t.Fatalf("normalization cancellation to hard Apply gap=%s", preemptionGap)
	}
	if maximum := applier.MaximumConcurrency(); maximum != 1 {
		t.Fatalf("HTTP apply max concurrency=%d", maximum)
	}
	writerMu.Lock()
	gotMaximumWriters := maximumWriters
	writerMu.Unlock()
	if gotMaximumWriters != 1 {
		t.Fatalf("Engine writer max concurrency=%d", gotMaximumWriters)
	}
	if generations := applier.Generations(); !reflect.DeepEqual(
		generations, []int64{1, 2, 3, 4},
	) {
		t.Fatalf("HTTP apply generations=%v", generations)
	}
	if state.DesiredGeneration != 4 || state.AppliedGeneration != 4 ||
		state.DesiredReason != string(PlacementStartupNormalization) {
		t.Fatalf("final plan state=%+v", state)
	}
	seen := make([]PlacementReason, 0, len(reasons))
	for len(reasons) > 0 {
		seen = append(seen, <-reasons)
	}
	if len(seen) != 3 || seen[0] != PlacementStartupNormalization ||
		seen[1] != PlacementHardFailure || seen[2] != PlacementStartupNormalization {
		t.Fatalf("placement reasons=%v", seen)
	}
	t.Logf(
		"wall-clock cancel-to-hard=%s hard=%s total-through-recompute=%s",
		preemptionGap, hardElapsed, totalElapsed,
	)
}

func TestRuntimeDoesNotRetryPermanentHTTPValidationFailure(t *testing.T) {
	runner := &temporaryRouteRunner{}
	adapter := xrayapi.NewAdapter(
		"xray", "127.0.0.1:10085", "9.9.9.9", runner,
	)
	reconciler, err := dataplane.NewReconciler(
		adapter, t.TempDir()+"/applied.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	client := agentapi.NewClient(serveRuntimeAgent(
		t, agentapi.NewServer(reconciler, 64*1024),
	))
	invalid := dataplane.DesiredPlan{
		Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	hardFailures := make(chan struct{}, 1)
	firstAttempt := make(chan struct{})
	attempts := 0
	runtime := Runtime{
		Place: func(
			ctx context.Context, _ time.Time, reason PlacementReason,
		) error {
			if reason != PlacementHardFailure {
				return nil
			}
			attempts++
			if attempts == 1 {
				close(firstAttempt)
			}
			return client.Apply(ctx, invalid)
		},
		HardFailures:          hardFailures,
		PlacementRetryBase:    5 * time.Millisecond,
		PlacementRetryMax:     10 * time.Millisecond,
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        time.Hour,
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	hardFailures <- struct{}{}
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("permanent validation failure was not attempted")
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	waitRuntimeDone(t, done)
	if attempts != 1 || runner.RouteCalls() != 0 {
		t.Fatalf("permanent failure attempts=%d xray route calls=%d",
			attempts, runner.RouteCalls())
	}
}

func TestRuntimeActiveProbeAllowsResponseAfterServerDeadline(t *testing.T) {
	const serverDeadline = 5 * time.Millisecond
	socketPath := serveRuntimeAgent(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/probes/active" {
			t.Errorf("unexpected request path %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(serverDeadline + 5*time.Millisecond)
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"candidate_id":"active","success":true}`)
	}))
	agent := agentapi.NewClient(
		socketPath,
		agentapi.WithClientProbeDeadlines(
			time.Second,
			time.Second,
			serverDeadline,
			time.Second,
			time.Second,
		),
	)
	activeResult := make(chan error, 1)
	var resultOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := Runtime{
		Active: func(ctx context.Context, _ time.Time) error {
			_, err := agent.ProbeActive(ctx, agentapi.ProbeRequest{
				CandidateID: "active", Kind: "vless", Payload: "payload",
			})
			resultOnce.Do(func() {
				activeResult <- err
				cancel()
			})
			return err
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        20 * time.Millisecond,
		ActiveDeadline:        agentapi.ProbeRequestTimeout(serverDeadline),
	}
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()

	select {
	case err := <-activeResult:
		waitRuntimeDone(t, done)
		if err != nil {
			t.Fatalf("active response inside controller slack was canceled: %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("active probe did not finish")
	}
}

func TestRuntimeActiveProbeHonorsExternalCancellation(t *testing.T) {
	started := make(chan struct{})
	socketPath := serveRuntimeAgent(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	agent := agentapi.NewClient(
		socketPath,
		agentapi.WithClientProbeDeadlines(
			time.Second,
			time.Second,
			500*time.Millisecond,
			time.Second,
			time.Second,
		),
	)
	activeResult := make(chan error, 1)
	var resultOnce sync.Once
	runtime := Runtime{
		Active: func(ctx context.Context, _ time.Time) error {
			_, err := agent.ProbeActive(ctx, agentapi.ProbeRequest{
				CandidateID: "active", Kind: "vless", Payload: "payload",
			})
			resultOnce.Do(func() {
				activeResult <- err
			})
			return err
		},
		SourceRefreshInterval: time.Hour,
		QualificationInterval: time.Hour,
		PlacementInterval:     time.Hour,
		ActiveInterval:        20 * time.Millisecond,
		ActiveDeadline:        agentapi.ProbeRequestTimeout(500 * time.Millisecond),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.Start(ctx)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		waitRuntimeDone(t, done)
		t.Fatal("active probe did not start")
	}

	start := time.Now()
	cancel()
	select {
	case err := <-activeResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active probe error=%v, want external cancellation", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("external cancellation took %s", elapsed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("active probe ignored external cancellation")
	}
	waitRuntimeDone(t, done)
}
