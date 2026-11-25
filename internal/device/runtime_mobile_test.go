package device

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

type mobileTestTunnel struct {
	testTunnel
	fast, full    atomic.Int64
	activeStarted chan struct{}
	allowActive   <-chan struct{}
	failedID      string
}

func (tunnel *mobileTestTunnel) ProbeFast(_ context.Context, req agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	tunnel.fast.Add(1)
	if req.CandidateID == tunnel.failedID {
		return failedMobileProbe(req), nil
	}
	return agentapi.ProbeResponse{CandidateID: req.CandidateID, Success: true}, nil
}

func (tunnel *mobileTestTunnel) ProbeFull(_ context.Context, req agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	tunnel.full.Add(1)
	if req.CandidateID == tunnel.failedID {
		return failedMobileProbe(req), nil
	}
	return agentapi.ProbeResponse{
		CandidateID: req.CandidateID, Success: true,
		Evaluation: health.Evaluation{Score: 98, TCPQualified: true, UDPQualified: true},
	}, nil
}

func (tunnel *mobileTestTunnel) ProbeActive(ctx context.Context, req agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	select {
	case tunnel.activeStarted <- struct{}{}:
	default:
	}
	select {
	case <-tunnel.allowActive:
		if req.CandidateID == tunnel.failedID {
			return failedMobileProbe(req), nil
		}
		return agentapi.ProbeResponse{
			CandidateID: req.CandidateID, Success: true,
			Observation: health.Observation{PrimaryOK: true, ConfirmationOK: true},
		}, nil
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	}
}

func (tunnel *mobileTestTunnel) ProbeActiveCritical(ctx context.Context, req agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return tunnel.ProbeActive(ctx, req)
}

func (tunnel *mobileTestTunnel) ProbeQoE(_ context.Context, req agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{CandidateID: req.CandidateID, FailureClass: agentapi.FailureInfrastructure}, nil
}

func failedMobileProbe(req agentapi.ProbeRequest) agentapi.ProbeResponse {
	return agentapi.ProbeResponse{CandidateID: req.CandidateID, FailureClass: agentapi.FailureCandidate, ErrorCode: "liveness_failed"}
}

func TestMobileIdleProbeScheduling(t *testing.T) {
	app := &App{}
	now := time.Now()
	var lastTraffic time.Time
	activeCalls, qualityCalls := 0, 0
	active := func(context.Context, time.Time) error { activeCalls++; return nil }
	quality := func(context.Context, time.Time) error { qualityCalls++; return nil }
	active, quality = app.mobileIdleProbes(func() time.Time { return lastTraffic }, active, quality)
	run := func(at time.Time) {
		t.Helper()
		if err := active(t.Context(), at); err != nil {
			t.Fatal(err)
		}
		if err := quality(t.Context(), at); err != nil {
			t.Fatal(err)
		}
	}

	run(now)
	if activeCalls != 1 || qualityCalls != 1 {
		t.Fatal("screen-off startup must still find a route")
	}
	app.route.Store(&dataplane.ClientRoute{TCPOutbound: "vless-active", BlockUDP: true})
	for offset := 4 * time.Second; offset <= time.Minute; offset += 4 * time.Second {
		run(now.Add(offset))
	}
	if activeCalls != 3 || qualityCalls != 1 {
		t.Fatalf("idle active/quality cycles = %d/%d, want 3/1", activeCalls, qualityCalls)
	}

	lastTraffic = now.Add(time.Minute)
	run(now.Add(64 * time.Second))
	if activeCalls != 4 || qualityCalls != 1 {
		t.Fatal("background traffic must restore fast liveness without starting QoE scans")
	}
	lastTraffic = time.Time{}
	app.SetScreenInteractive(true)
	run(now.Add(68 * time.Second))
	if activeCalls != 5 || qualityCalls != 2 {
		t.Fatal("turning the screen on must restore normal checks")
	}
	app.SetScreenInteractive(false)
	app.route.Store(&dataplane.ClientRoute{BlockTCP: true, BlockUDP: true})
	run(now.Add(72 * time.Second))
	if activeCalls != 6 || qualityCalls != 3 {
		t.Fatal("a blocked plan must still run recovery checks")
	}
}

func TestMobileDefersOnlyRoutineQualificationWithScreenOff(t *testing.T) {
	app := &App{}
	now := time.Now()
	app.route.Store(&dataplane.ClientRoute{TCPOutbound: "vless-active", BlockUDP: true})
	if !app.deferMobileQualification(now, now.Add(-15*time.Second), false) ||
		app.deferMobileQualification(now, now.Add(-time.Minute), false) ||
		app.deferMobileQualification(now, now.Add(-15*time.Second), true) {
		t.Fatal("screen-off qualification must run at least once a minute and immediately for recovery")
	}
	app.SetScreenInteractive(true)
	if app.deferMobileQualification(now, now, false) {
		t.Fatal("qualification must resume after waking the screen")
	}
	app.SetScreenInteractive(false)
	app.route.Store(nil)
	if app.deferMobileQualification(now, now, false) {
		t.Fatal("qualification must run without a route")
	}
}

func TestMobileReconnectRequiresFreshProofAndReusesThePool(t *testing.T) {
	dir := t.TempDir()
	app, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		input := fmt.Sprintf("vless://e2ffdef7-5fdd-4ad5-99da-c8a83ae64d5d@route-%d.example.net:443?security=tls#route-%d", i, i)
		if _, err := app.Import(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func(app *App, gate chan struct{}, failedID string) (*mobileTestTunnel, func()) {
		t.Helper()
		tunnel := &mobileTestTunnel{
			testTunnel:    testTunnel{plans: make(chan dataplane.DesiredPlan, 16)},
			activeStarted: make(chan struct{}, 1), allowActive: gate, failedID: failedID,
		}
		session, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- app.RunMobile(session, tunnel) }()
		return tunnel, syncStop(t, stop, done)
	}
	waitForRoute := func(tunnel *mobileTestTunnel) dataplane.ClientRoute {
		t.Helper()
		for {
			select {
			case plan := <-tunnel.plans:
				if route := plan.Clients[0]; !route.BlockTCP && !route.BlockUDP {
					for ctx.Err() == nil {
						state, err := app.database.LoadPlanState(ctx)
						if err != nil {
							t.Fatal(err)
						}
						if state.AppliedGeneration >= plan.Generation {
							return route
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			case <-ctx.Done():
				t.Fatal("mobile session did not install a usable route")
			}
		}
	}

	gate := make(chan struct{})
	close(gate)
	first, stopFirst := connect(app, gate, "")
	firstRoute := waitForRoute(first)
	stopFirst()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	app, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	gate = make(chan struct{})
	second, stopSecond := connect(app, gate, "")
	defer stopSecond()
	select {
	case <-second.activeStarted:
	case <-ctx.Done():
		t.Fatal("mobile reconnect did not probe the saved routes")
	}
	select {
	case plan := <-second.plans:
		if !plan.Clients[0].BlockTCP || !plan.Clients[0].BlockUDP {
			t.Fatal("mobile reconnect installed routes before obtaining current proof")
		}
	default:
	}
	if second.fast.Load() != 0 || second.full.Load() != 0 {
		t.Fatalf("reconnect rediscovered the warmed pool: fast=%d full=%d", second.fast.Load(), second.full.Load())
	}
	close(gate)
	secondRoute := waitForRoute(second)
	if secondRoute.TCPOutbound != firstRoute.TCPOutbound || secondRoute.UDPOutbound != firstRoute.UDPOutbound {
		t.Fatalf("preferred routes were not retained: before=%v after=%v", firstRoute, secondRoute)
	}
	stopSecond()
	id := sources.CandidateIDFromHandler(secondRoute.TCPOutbound, profileID)
	candidates, err := app.database.ListRoutableCandidates(ctx, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	var primary store.Candidate
	for _, candidate := range candidates {
		if candidate.ID == id {
			primary = candidate
		}
	}
	reservation, err := app.database.ReserveCandidateObservation(ctx, primary, store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.database.CommitCandidateActiveHardFailureObservation(ctx, primary, reservation, time.Now()); err != nil {
		t.Fatal(err)
	}
	if pending, err := app.database.PendingRouteRecoveries(ctx); err != nil || len(pending) == 0 {
		t.Fatalf("expected prior tunnel's recovery debt, got %v, %v", pending, err)
	}
	third, stopThird := connect(app, gate, id)
	defer stopThird()
	if replacement := waitForRoute(third); replacement.TCPOutbound == secondRoute.TCPOutbound {
		t.Fatal("mobile session reinstalled the failed primary")
	}
	if pending, err := app.database.PendingRouteRecoveries(ctx); err != nil || len(pending) != 0 {
		t.Fatalf("fresh tunnel should settle old recovery debt, got %v, %v", pending, err)
	}
}

func syncStop(t *testing.T, stop context.CancelFunc, done <-chan error) func() {
	return sync.OnceFunc(func() {
		t.Helper()
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}
