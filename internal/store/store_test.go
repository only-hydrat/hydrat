package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestImportSourcesRestoresPendingDeletion(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(bytes.Repeat([]byte{0x21}, secretbox.KeySize))
	db, err := Open(filepath.Join(t.TempDir(), "hydrat.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	items := sources.PreviewInput("vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#fast").Items
	if _, err := db.ImportSources(ctx, items); err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListSources(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	id := listed[0].ID
	input := CandidateInput{Kind: sources.KindVLESS, Label: "fast", Fingerprint: "fast", Payload: items[0].Payload}
	if err := db.ReplaceCandidates(ctx, id, []CandidateInput{input}); err != nil {
		t.Fatal(err)
	}
	candidates, err := db.ListCandidates(ctx, id)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	if err := db.DeleteSource(ctx, id, time.Second); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.LoadCandidateRetirementSnapshot(ctx, candidates[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	result, err := db.ImportSources(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListSources(ctx)
	if err != nil || len(listed) != 1 || listed[0].ID != id || !listed[0].Enabled || listed[0].PendingDelete {
		t.Fatalf("restored source=%+v err=%v", listed, err)
	}
	if result.Imported != 0 || result.Restored != 1 || result.Skipped != 0 {
		t.Fatalf("restore result=%+v", result)
	}
	if listed[0].CandidateCount != 0 {
		t.Fatalf("unrefreshed candidate count=%d", listed[0].CandidateCount)
	}
	if routable, err := db.ListCandidates(ctx, id); err != nil || len(routable) != 0 {
		t.Fatalf("unrefreshed candidates=%+v err=%v", routable, err)
	}
	epoch, err := db.InventoryEpoch(ctx)
	if err != nil || epoch != snapshot.InventoryEpoch+1 {
		t.Fatalf("restore epoch=%d snapshot=%d err=%v", epoch, snapshot.InventoryEpoch, err)
	}
	retired, err := db.AdvanceCandidateRetirement(ctx, candidates[0].ID, snapshot.DesiredGeneration,
		snapshot.InventoryEpoch, snapshot.TorSemanticDigest, time.Now().Add(2*time.Second), time.Second)
	if err != nil || retired.Changed {
		t.Fatalf("stale retirement advanced=%+v err=%v", retired, err)
	}
	if err := db.ReplaceCandidates(ctx, id, []CandidateInput{input}); err != nil {
		t.Fatalf("refresh restored source: %v", err)
	}
	active, err := db.ListCandidates(ctx, id)
	if err != nil || len(active) != 1 || active[0].ID != candidates[0].ID || active[0].Lifecycle != CandidateLifecycleActive {
		t.Fatalf("refreshed candidates=%+v err=%v", active, err)
	}
	duplicate, err := db.ImportSources(ctx, items)
	if err != nil || duplicate.Imported != 0 || duplicate.Skipped != 1 {
		t.Fatalf("active duplicate=%+v err=%v", duplicate, err)
	}
}
