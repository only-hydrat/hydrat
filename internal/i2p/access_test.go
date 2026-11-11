package i2p

import (
	"context"
	"errors"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestAccessGrantsOnlyAppliedI2PClients(t *testing.T) {
	routes := []dataplane.ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", I2PEnabled: true, I2POutbound: "i2p-a", I2PToken: "secret"}, {ClientID: "b", SourceCIDR: "10.44.0.3/32", OnionEnabled: true}, {ClientID: "c", SourceCIDR: "10.44.0.4/32", I2PEnabled: false, I2POutbound: "old", I2PToken: "secret"}}
	a := &Access{Policy: func() []dataplane.ClientRoute { return routes }, Available: true}
	grants := a.Grants()
	if len(grants) != 1 || grants[0].User != "a" || grants[0].Source != netip.MustParseAddr("10.44.0.2") {
		t.Fatal(grants)
	}
	a.Available = false
	if len(a.Grants()) != 0 {
		t.Fatal("conflicting namespace allowed")
	}
}

type accessControl struct {
	wake, stop int
	fail       bool
}

func (c *accessControl) Do(_ context.Context, _ string, path string, _ io.Reader) ([]byte, error) {
	if path == "/wake" {
		c.wake++
		if c.fail {
			return nil, errors.New("lost reply")
		}
	}
	if path == "/stop" {
		c.stop++
	}
	return nil, nil
}
func TestAccessRevokesEvenAfterLostWarmupReply(t *testing.T) {
	allowed := true
	c := &accessControl{fail: true}
	a := &Access{Available: true, Control: c, Policy: func() []dataplane.ClientRoute {
		if !allowed {
			return nil
		}
		return []dataplane.ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", I2PEnabled: true, I2POutbound: "i2p-a", I2PToken: "secret"}}
	}}
	now := time.Unix(1900000000, 0)
	a.sync(t.Context(), now)
	allowed = false
	a.sync(t.Context(), now.Add(time.Second))
	if c.wake != 1 || c.stop != 1 {
		t.Fatal("possibly started router not stopped", c)
	}
}
