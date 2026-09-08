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

func TestSealOpenUsesAssociatedSourceIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeySize)
	box, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Seal("source-a", []byte("vless://secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plaintext, err := box.Open("source-a", ciphertext)
	if err != nil || string(plaintext) != "vless://secret" {
		t.Fatalf("open = %q, %v", plaintext, err)
	}
	if _, err := box.Open("source-b", ciphertext); err == nil {
		t.Fatal("ciphertext opened with wrong source identity")
	}
}
