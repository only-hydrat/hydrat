package onion

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeOwnershipAndLostState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "onion.json")
	r, err := NewRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntime(path); err == nil {
		t.Fatal("duplicate owner accepted")
	}
	r.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntime(path); err == nil {
		t.Fatal("lost address book accepted")
	}
}
func TestRuntimeUsesAppliedClientPolicy(t *testing.T) {
	r, err := NewRuntime(filepath.Join(t.TempDir(), "onion.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	routes := []dataplane.ClientRoute{{ClientID: "a", SourceCIDR: "10.8.0.2/32", OnionEnabled: true, OnionOutbound: "tor-a"}}
	r.Policy = func() []dataplane.ClientRoute { return routes }
	if !r.Allowed(netip.MustParseAddr("10.8.0.2")) || r.Allowed(netip.MustParseAddr("10.8.0.3")) {
		t.Fatal("permission boundary")
	}
	routes[0].OnionEnabled = false
	if r.Allowed(netip.MustParseAddr("10.8.0.2")) {
		t.Fatal("revoked permission")
	}
	if err := r.Install(context.Background(), "198.18.0.1", testHost(1)); err == nil {
		t.Fatal("missing profiles accepted")
	}
}

func TestRuntimeBoundsNewNamesWithoutBlockingCachedNames(t *testing.T) {
	r, err := NewRuntime(filepath.Join(t.TempDir(), "book.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	source := netip.MustParseAddr("10.44.0.2")
	for i := 0; i < 8; i++ {
		if _, err := r.Resolve(source, testHost(byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Resolve(source, testHost(9)); err == nil {
		t.Fatal("unbounded new-name allocation")
	}
	if _, err := r.Resolve(source, testHost(1)); err != nil {
		t.Fatal("cached name rate limited")
	}
	if _, err := r.Resolve(netip.MustParseAddr("10.44.0.3"), testHost(9)); err != nil {
		t.Fatal("other client's budget consumed")
	}
}
