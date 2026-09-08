package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeoUpdaterUpdateOnceSuccess(t *testing.T) {
	tempDir := t.TempDir()

	geoipPayload := strings.Repeat("GEOIP-DATA-SAMPLE-PAYLOAD-", 10)
	geositePayload := strings.Repeat("GEOSITE-DATA-SAMPLE-PAYLOAD-", 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(geoipPayload))
		case "/geosite.dat":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(geositePayload))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	updater, err := NewGeoUpdater(GeoUpdaterConfig{
		Enabled:    true,
		AutoUpdate: true,
		GeoIPURL:   server.URL + "/geoip.dat",
		GeoSiteURL: server.URL + "/geosite.dat",
		TargetDir:  tempDir,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := updater.UpdateOnce(context.Background()); err != nil {
		t.Fatalf("UpdateOnce failed: %v", err)
	}

	geoipContent, err := os.ReadFile(filepath.Join(tempDir, "geoip.dat"))
	if err != nil {
		t.Fatalf("read geoip.dat: %v", err)
	}
	if string(geoipContent) != geoipPayload {
		t.Fatalf("geoip content mismatch: got %d bytes, want %d", len(geoipContent), len(geoipPayload))
	}

	geositeContent, err := os.ReadFile(filepath.Join(tempDir, "geosite.dat"))
	if err != nil {
		t.Fatalf("read geosite.dat: %v", err)
	}
	if string(geositeContent) != geositePayload {
		t.Fatalf("geosite content mismatch: got %d bytes, want %d", len(geositeContent), len(geositePayload))
	}

	// Verify no stray .tmp files remain
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("stray tmp file found: %s", entry.Name())
		}
	}
}

func TestGeoUpdaterPreservesExistingOnFailure(t *testing.T) {
	tempDir := t.TempDir()

	existingGeoIP := filepath.Join(tempDir, "geoip.dat")
	existingGeoSite := filepath.Join(tempDir, "geosite.dat")
	oldPayload := "ORIGINAL-STABLE-ASSET-CONTENT-OLD-VERSION-KEEP-THIS-DATA-ON-NETWORK-FAILURE"
	if err := os.WriteFile(existingGeoIP, []byte(oldPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingGeoSite, []byte(oldPayload), 0o644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	updater, err := NewGeoUpdater(GeoUpdaterConfig{
		Enabled:    true,
		AutoUpdate: true,
		GeoIPURL:   server.URL + "/geoip.dat",
		GeoSiteURL: server.URL + "/geosite.dat",
		TargetDir:  tempDir,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := updater.UpdateOnce(context.Background()); err == nil {
		t.Fatal("expected update error on 500 status")
	}

	// Existing assets must not have been deleted or corrupted
	geoipContent, err := os.ReadFile(existingGeoIP)
	if err != nil || string(geoipContent) != oldPayload {
		t.Fatalf("existing geoip was corrupted or lost: %v", err)
	}

	geositeContent, err := os.ReadFile(existingGeoSite)
	if err != nil || string(geositeContent) != oldPayload {
		t.Fatalf("existing geosite was corrupted or lost: %v", err)
	}
}

func TestGeoUpdaterDisabledOrNoAutoUpdateIsNoop(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("D", 200)))
	}))
	defer server.Close()

	// When Enabled is false
	u1, err := NewGeoUpdater(GeoUpdaterConfig{
		Enabled:    false,
		AutoUpdate: true,
		GeoIPURL:   server.URL + "/geoip.dat",
		GeoSiteURL: server.URL + "/geosite.dat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := u1.UpdateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// When AutoUpdate is false
	u2, err := NewGeoUpdater(GeoUpdaterConfig{
		Enabled:    true,
		AutoUpdate: false,
		GeoIPURL:   server.URL + "/geoip.dat",
		GeoSiteURL: server.URL + "/geosite.dat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := u2.UpdateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if requests.Load() != 0 {
		t.Fatalf("requests were made when disabled: %d", requests.Load())
	}
}

func TestGeoUpdaterStartAndClose(t *testing.T) {
	tempDir := t.TempDir()

	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("VALID-DATA-PAYLOAD-SAMPLE-", 10)))
	}))
	defer server.Close()

	updater, err := NewGeoUpdater(GeoUpdaterConfig{
		Enabled:        true,
		AutoUpdate:     true,
		GeoIPURL:       server.URL + "/geoip.dat",
		GeoSiteURL:     server.URL + "/geosite.dat",
		UpdateInterval: 50 * time.Millisecond,
		TargetDir:      tempDir,
		HTTPClient:     server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := updater.Start(ctx); err != nil {
		t.Fatal(err)
	}

	for range 50 {
		if downloads.Load() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := updater.Close(); err != nil {
		t.Fatal(err)
	}

	if downloads.Load() < 2 {
		t.Fatalf("expected at least 2 downloads, got %d", downloads.Load())
	}
}
