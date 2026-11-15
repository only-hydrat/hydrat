package secretbox

import (
	"bytes"
	"testing"
)

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
