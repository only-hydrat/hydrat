package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func TestWindowsCommandsValidateConfigBeforeRejectingGateway(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	t.Setenv("WIREGUARD_ENDPOINT", "gateway.example:51820")
	for _, command := range []string{"agent", "controller"} {
		t.Run(command, func(t *testing.T) {
			os.Args = []string{"hydrat", command, "--config", filepath.Join("..", "..", "config", "config.yml")}
			var unsupported *platform.UnsupportedError
			if err := run(); !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "hydrat is a Linux gateway") {
				t.Fatalf("error=%v", err)
			}
			invalid := filepath.Join(t.TempDir(), "invalid.yml")
			if err := os.WriteFile(invalid, []byte("wireguard: ["), 0600); err != nil {
				t.Fatal(err)
			}
			os.Args = []string{"hydrat", command, "--config", invalid}
			if err := run(); err == nil || errors.As(err, &unsupported) {
				t.Fatalf("invalid config error=%v", err)
			}
		})
	}
}
