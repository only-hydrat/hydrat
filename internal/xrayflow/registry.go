package xrayflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sync"
)

type flow struct {
	outbound, source string
	cancel           context.CancelFunc
	interrupt        func()
}

// Registry retains only live TCP dispatches, including those whose outbound
// handler was removed while accepted sessions were still running.
type Registry struct {
	mu       sync.Mutex
	instance string
	next     uint64
	flows    map[uint64]flow
}

func NewRegistry() *Registry {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("flow registry entropy unavailable")
	}
	return &Registry{instance: hex.EncodeToString(nonce[:]), flows: make(map[uint64]flow)}
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Snapshot{Instance: r.instance, BeforeID: r.next, Active: len(r.flows)}
}

func (r *Registry) Track(ctx context.Context, outbound, source, network string, interrupt func()) (context.Context, func()) {
	address, err := netip.ParseAddr(source)
	if network != "tcp" || err != nil || !address.Is4() || !validTag(outbound) || interrupt == nil || ctx.Err() != nil {
		return ctx, func() {}
	}
	child, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.next++
	id := r.next
	r.flows[id] = flow{outbound: outbound, source: address.String(), cancel: cancel, interrupt: interrupt}
	r.mu.Unlock()
	return child, func() {
		r.mu.Lock()
		delete(r.flows, id)
		r.mu.Unlock()
		cancel()
	}
}

func (r *Registry) Reset(ctx context.Context, q ResetRequest) (int, error) {
	if err := q.Validate(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return 0, err
	}
	if q.Snapshot.Instance != r.instance {
		r.mu.Unlock()
		return 0, ErrStaleInstance
	}
	if q.Snapshot.BeforeID > r.next {
		r.mu.Unlock()
		return 0, ErrInvalidRequest
	}
	// ponytail: O(live flows) scan under one mutex; shard by outbound only if
	// measurements show reset contention. No historical flow index is retained.
	var closing []flow
	for id, f := range r.flows {
		if id <= q.Snapshot.BeforeID && f.outbound == q.Outbound && f.source == q.Source {
			closing = append(closing, f)
			delete(r.flows, id)
		}
	}
	r.mu.Unlock()
	for _, f := range closing {
		f.cancel()
		f.interrupt()
	}
	return len(closing), nil
}
