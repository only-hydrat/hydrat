package i2p

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"io"
	"net/netip"
	"time"
)

// Access derives permissions only from the reconciler's applied snapshot.
// Availability is fixed before routing starts; a legacy onion collision disables
// I2P without changing the existing onion namespace.
type Access struct {
	Policy                   func() []dataplane.ClientRoute
	Available                bool
	Control                  SupervisorClient
	previous                 map[string]bool
	pendingWake, pendingStop bool
	retry                    time.Time
}

func (a *Access) Grants() []Grant {
	var grants []Grant
	if !a.Available || a.Policy == nil {
		return grants
	}
	for _, r := range a.Policy() {
		p, err := netip.ParsePrefix(r.SourceCIDR)
		if err == nil && p.IsSingleIP() && p.Addr().Is4() && r.I2PEnabled && r.I2POutbound != "" && r.I2PToken != "" {
			grants = append(grants, Grant{User: r.ClientID, Password: r.I2PToken, Source: p.Addr()})
		}
	}
	return grants
}

type SupervisorClient interface {
	Do(context.Context, string, string, io.Reader) ([]byte, error)
}

// sync runs in the sole policy watcher. Applied permissions are recorded even
// when a supervisor reply is lost, so revocation still stops a possible process.
func (a *Access) sync(ctx context.Context, now time.Time) {
	next := map[string]bool{}
	for _, g := range a.Grants() {
		next[g.User] = true
		if !a.previous[g.User] {
			a.pendingWake = true
		}
	}
	if len(next) == 0 && len(a.previous) > 0 {
		a.pendingStop = true
		a.pendingWake = false
		a.retry = time.Time{}
	}
	// A delayed stop belongs to the old empty policy. A new grant supersedes
	// it, even if that client's traffic already woke the runtime independently.
	if len(next) > 0 && a.pendingStop {
		a.pendingStop = false
		a.retry = time.Time{}
	}
	a.previous = next
	if now.Before(a.retry) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if a.pendingStop {
		if _, err := a.Control.Do(ctx, "POST", "/stop", nil); err != nil {
			a.retry = now.Add(time.Minute)
			return
		}
		a.pendingStop = false
	}
	if a.pendingWake && len(next) > 0 {
		if _, err := a.Control.Do(ctx, "POST", "/wake", nil); err != nil {
			a.retry = now.Add(time.Minute)
			return
		}
		a.pendingWake = false
	}
}
func (a *Access) Watch(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			a.sync(ctx, now)
		}
	}
}
