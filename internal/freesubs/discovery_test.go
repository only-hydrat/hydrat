package freesubs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

func TestDiscoveryRunChecksFeedsAndBuildsItems(t *testing.T) {
	plain := realityLink + "\n" + tlsLink + "\n"
	wrapped := base64.StdEncoding.EncodeToString([]byte(realityLink + "\n"))
	var repositoryPath string

	mux := http.NewServeMux()
	mux.HandleFunc("/plain.txt", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(plain))
	})
	mux.HandleFunc("/wrapped.txt", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(wrapped))
	})
	mux.HandleFunc("/empty.txt", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("nothing useful here"))
	})
	mux.HandleFunc("/api/repos/owner/repo/contents/sub", func(writer http.ResponseWriter, request *http.Request) {
		repositoryPath = request.URL.Path
		host := "http://" + request.Host
		entries := []repositoryEntry{
			{Name: "README.md", Type: "file", Size: 100, DownloadURL: host + "/api/readme"},
			{Name: "vless", Type: "file", Size: 100, DownloadURL: host + "/plain.txt"},
			{Name: "source_status.json", Type: "file", Size: 10, DownloadURL: host + "/api/status"},
		}
		_ = json.NewEncoder(writer).Encode(entries)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	discovery := New(Options{
		Client:  &http.Client{Timeout: 5 * time.Second},
		APIBase: server.URL + "/api",
		Catalog: []Feed{},
		Feeds: []Feed{
			{Label: "plain", URL: server.URL + "/plain.txt"},
			{Label: "wrapped", URL: server.URL + "/wrapped.txt"},
			{Label: "empty", URL: server.URL + "/empty.txt"},
			{Label: "duplicate", URL: server.URL + "/plain.txt"},
			{Label: "broken", URL: server.URL + "/missing.txt"},
		},
		Repositories: []Repository{{Label: "collector", Owner: "owner", Name: "repo", Path: "sub"}},
	})

	report := discovery.Run(context.Background())
	if repositoryPath != "/api/repos/owner/repo/contents/sub" {
		t.Fatalf("repository listing path=%q", repositoryPath)
	}
	if report.Usable != 2 {
		t.Fatalf("usable=%d report=%+v", report.Usable, report)
	}
	if report.Candidates != 3 || report.Reality != 2 {
		t.Fatalf("candidates=%d reality=%d", report.Candidates, report.Reality)
	}
	if report.Failed == 0 {
		t.Fatal("dead feed was not reported as failed")
	}

	feeds := UsableFeeds(report)
	for _, feed := range feeds {
		if strings.Contains(feed.URL, "empty") || strings.Contains(feed.URL, "missing") || strings.Contains(feed.URL, "readme") {
			t.Fatalf("unusable feed marked usable: %+v", feed)
		}
	}

	items := Items(report)
	if len(items) != 2 {
		t.Fatalf("items=%+v", items)
	}
	for _, item := range items {
		if item.Kind != sources.KindFreeVLESSSubscription || item.Fingerprint == "" || item.Payload == "" {
			t.Fatalf("bad item=%+v", item)
		}
		if item.Display == "" || item.Display == item.Payload {
			t.Fatalf("item label not applied: %+v", item)
		}
	}
}

func TestDiscoveryRejectsOversizedAndFailedBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/big.txt":
			_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	discovery := New(Options{
		Client:  &http.Client{Timeout: 5 * time.Second},
		MaxBody: 1024,
		Catalog: []Feed{},
		Feeds: []Feed{
			{Label: "big", URL: server.URL + "/big.txt"},
			{Label: "missing", URL: server.URL + "/missing.txt"},
		},
		Repositories: []Repository{},
	})
	report := discovery.Run(context.Background())
	if report.Usable != 0 {
		t.Fatalf("usable=%d", report.Usable)
	}
	if Items(report) != nil {
		t.Fatal("failed report produced source items")
	}
}

func TestDiscoveryKeepsConfiguredFeedsWithinMaxFeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/mine.txt" {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = writer.Write([]byte(realityLink + "\n"))
	}))
	defer server.Close()

	discovery := New(Options{
		Client:   &http.Client{Timeout: 5 * time.Second},
		MaxFeeds: 1,
		Catalog: []Feed{
			{Label: "catalog-one", URL: server.URL + "/catalog-one.txt"},
			{Label: "catalog-two", URL: server.URL + "/catalog-two.txt"},
		},
		Feeds:        []Feed{{Label: "mine", URL: server.URL + "/mine.txt"}},
		Repositories: []Repository{},
	})
	report := discovery.Run(context.Background())
	if report.Checked != 1 {
		t.Fatalf("checked=%d report=%+v", report.Checked, report)
	}
	if report.Feeds[0].URL != server.URL+"/mine.txt" || report.Usable != 1 {
		t.Fatalf("configured feed was truncated away: %+v", report.Feeds)
	}
}
