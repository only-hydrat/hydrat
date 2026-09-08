package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestImportSourcesEncryptsPayloadAndDeduplicates(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "hydrat.db")
	box, err := secretbox.New(bytes.Repeat([]byte{0x37}, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(dbPath, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	secret := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality#fast"
	preview := sources.PreviewInput(secret + "\n" + strings.Replace(secret, "#fast", "#other", 1))
	result, err := db.ImportSources(ctx, preview.Items)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Skipped != 1 {
		t.Fatalf("import result = %+v", result)
	}

	listed, err := db.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Kind != sources.KindVLESS || !listed[0].Enabled {
		t.Fatalf("listed sources = %+v", listed)
	}
	if strings.Contains(listed[0].Label, "11111111") {
		t.Fatalf("safe source leaked credential: %+v", listed[0])
	}
	payload, err := db.SourcePayload(ctx, listed[0].ID)
	if err != nil || payload != secret {
		t.Fatalf("payload = %q, %v", payload, err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("11111111-1111")) || bytes.Contains(raw, []byte("vless://")) {
		t.Fatal("database contains plaintext source credential")
	}
}

func TestImportSourcesIsIdempotentAcrossRequests(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(bytes.Repeat([]byte{0x19}, secretbox.KeySize))
	db, err := Open(filepath.Join(t.TempDir(), "hydrat.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	items := sources.PreviewInput("tor-source https://bridges.example/list.txt").Items

	first, err := db.ImportSources(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.ImportSources(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	if first.Imported != 1 || second.Imported != 0 || second.Skipped != 1 {
		t.Fatalf("unexpected results: first=%+v second=%+v", first, second)
	}
}
