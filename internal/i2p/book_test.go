package i2p

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestBookDoesNotSilentlyReplaceDestinationOrReuseIP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "book.json")
	b, err := OpenBook(p)
	if err != nil {
		t.Fatal(err)
	}
	a := strings.Repeat("a", 52) + ".b32.i2p"
	z := strings.Repeat("b", 51) + "a.b32.i2p"
	if err := b.Put("test.i2p", a, "manual", false); err != nil {
		t.Fatal(err)
	}
	ip, _, err := b.Resolve("test.i2p")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put("test.i2p", z, "feed", false); err == nil {
		t.Fatal("silent replacement")
	}
	if err := b.Put("test.i2p", z, "manual", true); err != nil {
		t.Fatal(err)
	}
	next, _, err := b.Resolve("test.i2p")
	if err != nil || next == ip {
		t.Fatal("IP was reused", err)
	}
	if _, err := b.Reverse(ip); err == nil {
		t.Fatal("retired destination accessible")
	}
	b.Close()
	restored, err := OpenBook(p)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := restored.Resolve("test.i2p")
	if err != nil || got != next {
		t.Fatal("mapping did not survive restart")
	}
}
func TestBookRejectsUnsafeNames(t *testing.T) {
	b, err := OpenBook(filepath.Join(t.TempDir(), "book.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.com", "127.0.0.1", "a..i2p", "foo.i2p\r\n", "foo/i2p"} {
		if _, _, err := b.Resolve(name); err == nil {
			t.Fatal(name)
		}
	}
}
func TestBookPreservesManualOwnership(t *testing.T) {
	b, _ := OpenBook(filepath.Join(t.TempDir(), "book.json"))
	d := strings.Repeat("a", 52) + ".b32.i2p"
	if err := b.Put("test.i2p", d, "manual", false); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("test.i2p", d, "feed", false); err != nil {
		t.Fatal(err)
	}
	if b.List()[0].Source != "manual" {
		t.Fatal("feed took ownership of manual record")
	}
}
func TestBookRejectsRewoundAllocator(t *testing.T) {
	p := filepath.Join(t.TempDir(), "book.json")
	b, _ := OpenBook(p)
	b.Resolve(strings.Repeat("a", 52) + ".b32.i2p")
	b.state.Next = 1
	b.save()
	b.Close()
	if _, err := OpenBook(p); err == nil {
		t.Fatal("rewound allocator permits IP reuse")
	}
}
func TestPublicDestinationSurvivesExport(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString(make([]byte, 387))
	b, _ := OpenBook(filepath.Join(t.TempDir(), "book"))
	if err := b.ApplyImport(b.Preview("test.i2p="+raw), "manual", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Export(), raw) {
		t.Fatal("hosts.txt lost original Destination")
	}
}
func TestB32NameCannotBeRetargeted(t *testing.T) {
	b, _ := OpenBook(filepath.Join(t.TempDir(), "book"))
	a := strings.Repeat("a", 52) + ".b32.i2p"
	z := strings.Repeat("b", 51) + "a.b32.i2p"
	if err := b.Put(a, z, "manual", true); err == nil {
		t.Fatal("b32 was retargeted")
	}
}
func TestBookRejectsConcurrentOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "book")
	b, err := OpenBook(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if other, err := OpenBook(path); err == nil {
		other.Close()
		t.Fatal("concurrent book writer admitted")
	}
}
