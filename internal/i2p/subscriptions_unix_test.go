//go:build unix

package i2p

import (
	"strings"
	"testing"
)

func TestImportPreviewAndSubscriptionConflicts(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book")
	if err != nil {
		t.Fatal(err)
	}
	destination := strings.Repeat("a", 52) + ".b32.i2p"
	p := b.Preview("good.i2p=" + destination + "\nbad.test=" + destination + "\n")
	if p.Valid != 1 || len(p.Errors) != 1 {
		t.Fatal(p)
	}
	if err := b.ApplyImport(p, "feed", false); err == nil {
		t.Fatal("invalid batch accepted")
	}
	p = b.Preview("good.i2p=" + destination + "\n")
	if err := b.ApplyImport(p, "feed", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Export(), "good.i2p=") {
		t.Fatal("export lost entry")
	}
}
