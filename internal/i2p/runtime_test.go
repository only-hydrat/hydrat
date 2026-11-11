package i2p

import (
	"context"
	"testing"
	"time"
)

type testRouter struct {
	starts, stops int
	transit       int
	ready         bool
}

func (r *testRouter) Start(context.Context) error { r.starts++; return nil }
func (r *testRouter) Stop(context.Context) error  { r.stops++; return nil }
func (r *testRouter) Inspect(context.Context) (RouterStatus, error) {
	return RouterStatus{Ready: r.ready, Transit: r.transit}, nil
}
func TestRuntimeIdleAndSafety(t *testing.T) {
	ctx := t.Context()
	now := time.Unix(1900000000, 0)
	r := &testRouter{ready: true}
	m := NewRuntime(r, 2*time.Hour)
	if err := m.Tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	if r.starts != 0 {
		t.Fatal("idle router started")
	}
	if err := m.Wake(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := m.Wake(ctx, now); err != nil {
		t.Fatal(err)
	}
	if r.starts != 1 {
		t.Fatal("duplicate start")
	}
	if err := m.Tick(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.stops != 1 {
		t.Fatal("background status checks prolonged warmup")
	}
	if err := m.Wake(ctx, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.transit = 1
	if err := m.Tick(ctx, now.Add(3*time.Hour)); err == nil {
		t.Fatal("transit accepted")
	}
	if m.Status().State != "error" || r.stops != 2 {
		t.Fatal("unsafe router was not stopped")
	}
}
func TestRuntimeNeverSleepsWithUsersAndTrafficResetsTimer(t *testing.T) {
	ctx := t.Context()
	now := time.Unix(1900000000, 0)
	r := &testRouter{ready: true}
	m := NewRuntime(r, time.Minute)
	release, err := m.Acquire(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.stops != 0 {
		t.Fatal("active stream interrupted")
	}
	release(now.Add(time.Hour))
	if err := m.Tick(ctx, now.Add(time.Hour+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if r.stops != 1 {
		t.Fatal("completed stream never slept")
	}
}
func TestClosedRuntimeCannotBeRestartedByLateRequest(t *testing.T) {
	r := &testRouter{}
	m := NewRuntime(r, time.Hour)
	if err := m.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.Wake(t.Context(), time.Now()); err == nil || r.starts != 0 {
		t.Fatal("late request restarted closed supervisor")
	}
}
