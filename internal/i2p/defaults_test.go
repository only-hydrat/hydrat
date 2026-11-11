package i2p

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultHostsSeedOncePreservesOwnershipAndDeletions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "book.json")
	b, err := OpenBook(path)
	if err != nil {
		t.Fatal(err)
	}
	manual := strings.Repeat("a", 52) + ".b32.i2p"
	if err := b.Put("i2pforum.i2p", manual, "manual", false); err != nil {
		t.Fatal(err)
	}
	ip, _, err := b.Resolve("i2pforum.i2p")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SeedDefaultHosts(); err != nil {
		t.Fatal(err)
	}
	if len(b.List()) != 71 {
		t.Fatalf("entries=%d", len(b.List()))
	}
	same, dest, err := b.Resolve("i2pforum.i2p")
	if err != nil || same != ip || dest != manual {
		t.Fatalf("manual mapping changed: %v %s %v", same, dest, err)
	}
	if _, _, err := b.Resolve("forum.i2p"); err == nil {
		t.Fatal("invented alias")
	}
	if err := b.Delete("i2p-projekt.i2p"); err != nil {
		t.Fatal(err)
	}
	b.Close()
	b, err = OpenBook(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.SeedDefaultHosts(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Resolve("i2p-projekt.i2p"); err == nil {
		t.Fatal("deleted default restored")
	}
}

func TestDefaultHostsFreshBookAndCapacity(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			b, err := OpenBook(filepath.Join(t.TempDir(), "book.json"))
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if full {
				for i := 0; i < MaxEntries; i++ {
					n := fmt.Sprintf("manual-%d.i2p", i)
					b.state.Entries[n] = Entry{Name: n, Destination: strings.Repeat("a", 52) + ".b32.i2p", Source: "manual"}
				}
			}
			if err := b.SeedDefaultHosts(); err != nil {
				t.Fatal(err)
			}
			want := 71
			if full {
				want = MaxEntries
			}
			if len(b.List()) != want || len(b.state.Mappings) != 0 || b.state.Next != 1 {
				t.Fatal("seed changed capacity or mappings")
			}
			if !full {
				if _, _, err := b.Resolve("i2pforum.i2p"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDefaultHostsPersistenceFailureFailsClosed(t *testing.T) {
	b, err := OpenBook(filepath.Join(t.TempDir(), "book.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	// Rename cannot replace a directory: deterministic even when tests run as root.
	b.path = filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(b.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := b.SeedDefaultHosts(); err == nil {
		t.Fatal("ignored persistence failure")
	}
	if _, _, err := b.Resolve("i2pforum.i2p"); err == nil {
		t.Fatal("served unsaved defaults")
	}
	if err := b.SeedDefaultHosts(); err == nil {
		t.Fatal("failed book reused")
	}
}
