package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

type testTunnel struct {
	TunnelBackend
	plans chan dataplane.DesiredPlan
}

func (tunnel *testTunnel) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, _ []dataplane.FlowRecovery) error {
	select {
	case tunnel.plans <- plan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (tunnel *testTunnel) LastTraffic() time.Time                                   { return time.Now() }
func (tunnel *testTunnel) FetchProfiles(context.Context) ([]torpool.Profile, error) { return nil, nil }
func (tunnel *testTunnel) ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error) {
	return nil, nil
}
func (tunnel *testTunnel) ExploreNext(context.Context) ([]torpool.Profile, error) { return nil, nil }
func (tunnel *testTunnel) ProbeFast(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	return agentapi.ProbeResponse{}, errors.New("unexpected probe")
}

func TestStartWithoutProvenCandidatePublishesFailClosedPlan(t *testing.T) {
	app, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	backend := &testTunnel{plans: make(chan dataplane.DesiredPlan, 3)}
	session := app.session(backend)
	if err := session.engine.Cycle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case plan := <-backend.plans:
		if !plan.FailClosed || len(plan.Clients) != 1 || !plan.Clients[0].BlockTCP || !plan.Clients[0].BlockUDP ||
			plan.Clients[0].SourceCIDR != TunnelCIDR {
			t.Fatalf("unexpected startup plan: %+v", plan)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestRunCanStartWithoutASubscriptionAndStopsOnCancellation(t *testing.T) {
	app, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	backend := &testTunnel{plans: make(chan dataplane.DesiredPlan, 5)}
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, backend) }()
	select {
	case err := <-done:
		t.Fatalf("connection stopped during startup: %v", err)
	case plan := <-backend.plans:
		if !plan.FailClosed || len(plan.Clients) != 1 || !plan.Clients[0].BlockTCP || !plan.Clients[0].BlockUDP {
			t.Fatalf("empty inventory applied an open route: %+v", plan)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	status, err := app.Status(context.Background())
	if err != nil || status.Running || status.Connected {
		t.Fatalf("status after stop = %+v, %v", status, err)
	}
}

func TestNewTunnelInstallsThePersistedPlanAgain(t *testing.T) {
	app, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var generation int64
	for range 2 {
		backend := &testTunnel{plans: make(chan dataplane.DesiredPlan, 2)}
		engine := app.session(backend).engine
		now := time.Now()
		if err := engine.Cycle(ctx, now); err != nil {
			t.Fatal(err)
		}
		select {
		case plan := <-backend.plans:
			if plan.Generation <= generation || !plan.FailClosed {
				t.Fatalf("new tunnel received generation %d after %d", plan.Generation, generation)
			}
			generation = plan.Generation
		default:
			t.Fatal("new tunnel received no plan")
		}
		if err := engine.Cycle(ctx, now); err != nil {
			t.Fatal(err)
		}
		select {
		case plan := <-backend.plans:
			t.Fatalf("unchanged plan applied twice in one session: generation %d", plan.Generation)
		default:
		}
	}
}
