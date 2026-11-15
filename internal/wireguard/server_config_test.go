package wireguard

import (
	"context"
	"path/filepath"
	"testing"
)

func TestEnsureServerConfigRejectsInvalidNetwork(t *testing.T) {
	err := EnsureServerConfig(context.Background(), filepath.Join(t.TempDir(), "wg0.conf"), "not-a-network", 51820, &managerRunner{})
	if err == nil {
		t.Fatal("invalid WireGuard network was accepted")
	}
}
