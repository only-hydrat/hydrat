//go:build unix

package secretbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKeyCreatesStablePrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "master.key")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != KeySize || !bytes.Equal(first, second) {
		t.Fatalf("unstable key: first=%d bytes second=%d bytes", len(first), len(second))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
}
