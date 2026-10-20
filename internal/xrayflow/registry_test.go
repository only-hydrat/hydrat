package xrayflow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestResetIsScopedAndFenced(t *testing.T) {
	r := NewRegistry()
	var old, otherClient, healthyRoute, fresh atomic.Int32
	ctx, finish := r.Track(context.Background(), "failed", "10.44.0.2", "tcp", func() { old.Add(1) })
	defer finish()
	_, finishOther := r.Track(context.Background(), "failed", "10.44.0.3", "tcp", func() { otherClient.Add(1) })
	defer finishOther()
	_, finishHealthy := r.Track(context.Background(), "healthy", "10.44.0.2", "tcp", func() { healthyRoute.Add(1) })
	defer finishHealthy()
	snapshot := r.Snapshot()
	_, finishFresh := r.Track(context.Background(), "failed", "10.44.0.2", "tcp", func() { fresh.Add(1) })
	defer finishFresh()
	req := ResetRequest{Snapshot: snapshot, Outbound: "failed", Source: "10.44.0.2"}
	for attempt := 0; attempt < 2; attempt++ {
		closed, err := r.Reset(context.Background(), req)
		if err != nil || closed != 1-attempt {
			t.Fatalf("attempt%d closed=%d err=%v", attempt, closed, err)
		}
	}
	if old.Load() != 1 || ctx.Err() != context.Canceled {
		t.Fatal("old session was not canceled exactly once")
	}
	if otherClient.Load()+healthyRoute.Load()+fresh.Load() != 0 {
		t.Fatal("reset touched another client, healthy route or post-snapshot session")
	}
	if r.Snapshot().Active != 3 {
		t.Fatalf("closed flow retained: %+v", r.Snapshot())
	}
}

func TestResetRejectsStaleInstanceAndInvalidScope(t *testing.T) {
	r := NewRegistry()
	var closed atomic.Int32
	_, finish := r.Track(context.Background(), "route", "10.44.0.2", "tcp", func() { closed.Add(1) })
	defer finish()
	valid := ResetRequest{Snapshot: r.Snapshot(), Outbound: "route", Source: "10.44.0.2"}
	stale := valid
	stale.Snapshot = NewRegistry().Snapshot()
	if _, err := r.Reset(context.Background(), stale); !errors.Is(err, ErrStaleInstance) {
		t.Fatalf("old process token accepted: %v", err)
	}
	for _, change := range []func(*ResetRequest){
		func(q *ResetRequest) { q.Source = "" },
		func(q *ResetRequest) { q.Source = "0.0.0.0/0" },
		func(q *ResetRequest) { q.Source = "::ffff:10.44.0.2" },
		func(q *ResetRequest) { q.Outbound = "" },
		func(q *ResetRequest) { q.Outbound = "*" },
		func(q *ResetRequest) { q.Snapshot.BeforeID++ },
	} {
		q := valid
		change(&q)
		if _, err := r.Reset(context.Background(), q); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid scope accepted: %+v err=%v", q, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Reset(ctx, valid); !errors.Is(err, context.Canceled) || closed.Load() != 0 {
		t.Fatalf("canceled request mutated state: err=%v closed=%d", err, closed.Load())
	}
}

func TestResetCallbacksRunOutsideLock(t *testing.T) {
	r := NewRegistry()
	_, finish := r.Track(context.Background(), "route", "10.44.0.2", "tcp", func() {
		_ = r.Snapshot()
		_, done := r.Track(context.Background(), "new", "10.44.0.3", "tcp", func() {})
		done()
	})
	defer finish()
	if n, err := r.Reset(t.Context(), ResetRequest{Snapshot: r.Snapshot(), Outbound: "route", Source: "10.44.0.2"}); n != 1 || err != nil {
		t.Fatalf("closed=%d err=%v", n, err)
	}
}

func TestRegistryConcurrentLifecycleDoesNotRetainFinishedFlows(t *testing.T) {
	r := NewRegistry()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 100; j++ {
				_, finish := r.Track(t.Context(), "route", "10.44.0.2", "tcp", func() {})
				_, _ = r.Reset(t.Context(), ResetRequest{Snapshot: r.Snapshot(), Outbound: "route", Source: "10.44.0.2"})
				finish()
				finish()
			}
		})
	}
	workers.Wait()
	if r.Snapshot().Active != 0 {
		t.Fatal("registry retains completed sessions")
	}
}

func TestRegistryDoesNotTrackUDPOrInvalidSource(t *testing.T) {
	r := NewRegistry()
	for _, input := range []struct{ source, network string }{{"10.44.0.2", "udp"}, {"", "tcp"}, {"example.com", "tcp"}} {
		ctx, finish := r.Track(t.Context(), "route", input.source, input.network, func() { t.Error("unexpected reset") })
		finish()
		if ctx != t.Context() || r.Snapshot().Active != 0 {
			t.Fatal("non-TCP or unattributed flow was tracked")
		}
	}
}
