package onion

import (
	"context"
	"errors"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Runtime owns the persistent address namespace. A lost book cannot silently
// reassign addresses cached by clients; restore the book with gateway state.
type Runtime struct {
	allocationMu     sync.Mutex
	allocations      map[netip.Addr]allocationBudget
	globalAllocation allocationBudget
	Mappings         *Mappings
	Policy           func() []dataplane.ClientRoute
	Profiles         func() []torpool.Profile
	lock             *os.File
	mu               sync.Mutex
}

func NewRuntime(path string) (*Runtime, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("onion address book already owned")
	}
	marker := path + ".initialized"
	if _, err := os.Stat(marker); err == nil {
		if _, err := os.Stat(path); err != nil {
			return nil, errors.New("onion address book missing; restore gateway state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	book, err := OpenMappings(path, "198.18.0.0/15", 1024)
	if err != nil {
		return nil, err
	}
	if err := book.save(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, err
	}
	ok = true
	return &Runtime{Mappings: book, lock: lock, allocations: make(map[netip.Addr]allocationBudget)}, nil
}
func (r *Runtime) Close() { r.lock.Close() }
func (r *Runtime) Allowed(source netip.Addr) bool {
	if r.Policy == nil {
		return false
	}
	for _, route := range r.Policy() {
		p, err := netip.ParsePrefix(route.SourceCIDR)
		if err == nil && p.Contains(source) && route.OnionEnabled && route.OnionOutbound != "" {
			return true
		}
	}
	return false
}
func profileControl(p torpool.Profile) Control {
	return Control{Socket: filepath.Join(p.DataDir, "control.sock"), CookieFile: filepath.Join(p.DataDir, "control_auth_cookie")}
}
func (r *Runtime) Prepare(ctx context.Context, p torpool.Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := profileControl(p)
	if err := c.Ready(ctx); err != nil {
		return err
	}
	for host, ip := range r.Mappings.Snapshot() {
		if err := c.Map(ctx, ip, host); err != nil {
			return err
		}
	}
	return nil
}
func (r *Runtime) Install(ctx context.Context, ip, host string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Profiles == nil {
		return errors.New("onion profiles unavailable")
	}
	profiles := r.Profiles()
	count := 0
	// Include warming profiles: publication of readiness must never race a new
	// address mapping. The separate DNS budget bounds this work.
	for _, p := range profiles {
		if p.Role != "warm" {
			continue
		}
		count++
		if err := profileControl(p).Map(ctx, ip, host); err != nil {
			return err
		}
	}
	if count == 0 {
		return errors.New("onion profiles unavailable")
	}
	return nil
}

type allocationBudget struct {
	tokens float64
	at     time.Time
}

func (b *allocationBudget) take(now time.Time, burst, perSecond float64) bool {
	if b.at.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*perSecond)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Existing names remain usable during a burst. Rate and memory limits apply
// only to new allocations; quotas contain client IPs, never browsing names.
func (r *Runtime) Resolve(source netip.Addr, host string) (netip.Addr, error) {
	name, err := Normalize(host)
	if err != nil {
		return netip.Addr{}, err
	}
	r.allocationMu.Lock()
	defer r.allocationMu.Unlock()
	if ip, ok := r.Mappings.lookup(name); ok {
		return ip, nil
	}
	now := time.Now()
	budget, exists := r.allocations[source]
	if !exists && len(r.allocations) >= 1024 {
		for ip, b := range r.allocations {
			if now.Sub(b.at) > time.Hour {
				delete(r.allocations, ip)
			}
		}
		if len(r.allocations) >= 1024 {
			return netip.Addr{}, errors.New("onion allocation quota full")
		}
	}
	allowed := budget.take(now, 8, 1.0/6)
	r.allocations[source] = budget
	if !allowed || !r.globalAllocation.take(now, 16, 1) {
		return netip.Addr{}, errors.New("onion allocation rate limited")
	}
	return r.Mappings.Resolve(name)
}
