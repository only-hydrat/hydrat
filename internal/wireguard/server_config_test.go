package wireguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureServerConfigGeneratesPrivateKeyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard", "wg0.conf")
	runner := &managerRunner{outputs: map[string]string{"wg genkey": "server-private\n"}}

	if err := EnsureServerConfig(context.Background(), path, "10.44.0.0/24", 51820, runner); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	for _, expected := range []string{
		"Address = 10.44.0.1/24",
		"ListenPort = 51820",
		"PrivateKey = server-private",
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("config does not contain %q:\n%s", expected, config)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 600", info.Mode().Perm())
	}

	runner.outputs["wg genkey"] = "replacement\n"
	if err := EnsureServerConfig(context.Background(), path, "10.44.0.0/24", 51820, runner); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "replacement") {
		t.Fatal("existing server private key was replaced")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("wg genkey calls=%d, want 1", len(runner.calls))
	}
}

func TestEnsureServerConfigRejectsInvalidNetwork(t *testing.T) {
	err := EnsureServerConfig(context.Background(), filepath.Join(t.TempDir(), "wg0.conf"), "not-a-network", 51820, &managerRunner{})
	if err == nil {
		t.Fatal("invalid WireGuard network was accepted")
	}
}
