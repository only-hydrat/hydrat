package platform_test

import (
	"context"
	"errors"
	"testing"

	"github.com/only-hydrat/hydrat/internal/gateway"
	"github.com/only-hydrat/hydrat/internal/i2p"
	"github.com/only-hydrat/hydrat/internal/onion"
	"github.com/only-hydrat/hydrat/internal/platform"
	"github.com/only-hydrat/hydrat/internal/retainedlog"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func TestWindowsFacilitiesReturnTypedErrors(t *testing.T) {
	ctx := context.Background()
	checks := map[string]func() error{
		"gateway":          func() error { return (gateway.ExecRunner{}).Run(ctx, "nft") },
		"wireguard":        func() error { _, err := (wireguard.ExecInputRunner{}).RunInput(ctx, "", "wg"); return err },
		"activity":         func() error { _, err := (wireguard.ExecRunner{}).Output(ctx, "wg"); return err },
		"xray":             func() error { return (xrayapi.ExecRunner{}).Run(ctx, "", "xray") },
		"tor":              func() error { _, err := (torpool.ExecRunner{}).Start(ctx, "tor"); return err },
		"i2p":              func() error { return (&i2p.ExecRouter{}).Start(ctx) },
		"i2p client":       func() error { _, err := (i2p.ControlClient{}).Do(ctx, "GET", "/status", nil); return err },
		"i2p supervisor":   func() error { return i2p.ServeSupervisor(ctx, "", "", "") },
		"i2p lock":         func() error { _, err := i2p.OpenBook(t.TempDir() + "/book"); return err },
		"onion lock":       func() error { _, err := onion.NewRuntime(t.TempDir() + "/book"); return err },
		"logs":             func() error { _, err := retainedlog.Open(retainedlog.Config{}); return err },
		"log directory":    func() error { return retainedlog.PrepareDirectory("", 0, 0) },
		"flow socket":      func() error { _, err := xrayflow.Listen("", nil); return err },
		"socket transport": func() error { _, err := platform.DialUnix(ctx, nil, ""); return err },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			var unsupported *platform.UnsupportedError
			if err := check(); !errors.As(err, &unsupported) {
				t.Fatalf("error=%v; want *platform.UnsupportedError", err)
			}
		})
	}
}
