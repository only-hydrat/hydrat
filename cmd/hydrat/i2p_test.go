package main

import (
	"github.com/only-hydrat/hydrat/internal/config"
	"testing"
)

func TestI2PBridgePreservesConfiguredServices(t *testing.T) {
	for _, kind := range []string{"background probes", "active probes", "serving Tor", "probe Tor", "API"} {
		t.Run(kind, func(t *testing.T) {
			cfg := config.Defaults()
			switch kind {
			case "background probes":
				cfg.Xray.ProbeSocksPortBase = 19440
			case "active probes":
				cfg.Xray.ActiveSocksPortBase = 19447
			case "serving Tor":
				cfg.Tor.SocksPortBase = 19447
			case "probe Tor":
				cfg.Tor.ProbeSocksPortBase = 19447
			case "API":
				cfg.Xray.APIAddress = "127.0.0.1:19447"
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal("previously valid config rejected", err)
			}
			listener, err := listenI2PBridge(cfg)
			if listener != nil {
				listener.Close()
				t.Fatal("optional I2P stole configured service port")
			}
			if err == nil {
				t.Fatal("missing conflict reason")
			}
		})
	}
}
