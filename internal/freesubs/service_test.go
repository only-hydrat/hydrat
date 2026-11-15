package freesubs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

type fakeStore struct {
	items  []sources.PreviewItem
	result store.ImportResult
	err    error
}

func (fake *fakeStore) ImportSources(_ context.Context, items []sources.PreviewItem) (store.ImportResult, error) {
	fake.items = items
	return fake.result, fake.err
}

func TestServiceSyncImportsUsableFeedsAndSignalsChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(realityLink + "\n" + tlsLink + "\n"))
	}))
	defer server.Close()

	changed := make(chan struct{}, 1)
	fake := &fakeStore{result: store.ImportResult{Imported: 1}}
	service := &Service{
		Discovery: New(Options{
			Client:       &http.Client{Timeout: 5 * time.Second},
			Catalog:      []Feed{},
			Repositories: []Repository{},
			Feeds:        []Feed{{Label: "free", URL: server.URL}},
		}),
		Store:   fake,
		Changed: changed,
	}

	result, err := service.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Report.Usable != 1 || result.Report.Reality != 1 {
		t.Fatalf("result=%+v", result)
	}
	if len(fake.items) != 1 || fake.items[0].Kind != sources.KindFreeVLESSSubscription {
		t.Fatalf("imported items=%+v", fake.items)
	}
	if fake.items[0].Display != "free" {
		t.Fatalf("label=%q", fake.items[0].Display)
	}
	select {
	case <-changed:
	default:
		t.Fatal("source change was not signalled")
	}
}

func TestServiceSyncSkipsStoreWhenNoFeedIsUsable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	fake := &fakeStore{}
	service := &Service{
		Discovery: New(Options{
			Client:       &http.Client{Timeout: 5 * time.Second},
			Catalog:      []Feed{},
			Repositories: []Repository{},
			Feeds:        []Feed{{Label: "dead", URL: server.URL}},
		}),
		Store: fake,
	}
	result, err := service.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Usable != 0 || fake.items != nil {
		t.Fatalf("result=%+v items=%+v", result, fake.items)
	}
}

func TestServiceSyncReportsImportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(realityLink + "\n"))
	}))
	defer server.Close()

	service := &Service{
		Discovery: New(Options{
			Client:       &http.Client{Timeout: 5 * time.Second},
			Catalog:      []Feed{},
			Repositories: []Repository{},
			Feeds:        []Feed{{Label: "free", URL: server.URL}},
		}),
		Store: &fakeStore{err: errors.New("disk on fire")},
	}
	if _, err := service.Sync(context.Background()); err == nil {
		t.Fatal("import failure was swallowed")
	}
}
