package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/config"
	"github.com/only-hydrat/hydrat/internal/freesubs"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

type recordingFreeSourceStore struct {
	items  []sources.PreviewItem
	result store.ImportResult
}

func (recorder *recordingFreeSourceStore) ImportSources(_ context.Context, items []sources.PreviewItem) (store.ImportResult, error) {
	recorder.items = items
	return recorder.result, nil
}

const freeSourceRealityLink = "vless://11111111-1111-1111-1111-111111111111@reality.example:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF&sid=ab12&sni=www.microsoft.com#reality"

// freeSourceLoopService builds a discovery pass with every feed source disabled,
// so the loop runs without touching the network.
func freeSourceLoopService() *freesubs.Service {
	return &freesubs.Service{Discovery: freesubs.New(freesubs.Options{
		Catalog:      []freesubs.Feed{},
		Repositories: []freesubs.Repository{},
		Feeds:        []freesubs.Feed{},
	})}
}

func TestRunFreeSourceLoopStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runFreeSourceLoop(ctx, config.FreeSourcesConfig{Interval: time.Hour}, freeSourceLoopService())
	}()

	// The loop syncs once immediately, so it must still return promptly when the
	// controller shuts down instead of sleeping until the next tick.
	time.AfterFunc(50*time.Millisecond, cancel)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("free source loop ignored context cancellation")
	}
}

func TestNewFreeSourceServiceImportsConfiguredFeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(freeSourceRealityLink + "\n"))
	}))
	defer server.Close()

	cfg := config.Defaults()
	cfg.FreeSources.Enabled = true
	// One feed slot keeps the built-in catalog out of this test: configured
	// feeds are checked first and the rest is truncated.
	cfg.FreeSources.MaxFeeds = 1
	cfg.FreeSources.MaxBodyBytes = 1 << 20
	cfg.FreeSources.Feeds = []config.FreeSourceFeedConfig{{Label: "custom", URL: server.URL}}
	cfg.FreeSources.Repositories = []config.FreeSourceRepoConfig{}

	recorder := &recordingFreeSourceStore{result: store.ImportResult{Imported: 1}}
	service := newFreeSourceService(cfg, recorder, nil)
	result, err := service.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if result.Report.Checked != 1 || result.Report.Usable != 1 || result.Report.Reality != 1 {
		t.Fatalf("report=%+v", result.Report)
	}
	if len(recorder.items) != 1 || recorder.items[0].Kind != sources.KindFreeVLESSSubscription {
		t.Fatalf("items=%+v", recorder.items)
	}
	if recorder.items[0].Display != "custom" {
		t.Fatalf("label=%q", recorder.items[0].Display)
	}
}
