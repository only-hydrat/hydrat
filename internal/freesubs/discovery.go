package freesubs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/only-hydrat/hydrat/internal/sources"
)

// Defaults bound the discovery pass so a background run cannot flood the
// inventory or the network.
const (
	DefaultMaxBody     = int64(8 * 1024 * 1024)
	DefaultMaxFeeds    = 40
	DefaultConcurrency = 4
	DefaultUserAgent   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	githubAPIBase      = "https://api.github.com"
	maxRepoFiles       = 8
)

// Options configures a discovery pass.
type Options struct {
	Client      *http.Client
	MaxBody     int64
	MaxFeeds    int
	Concurrency int
	UserAgent   string
	GitHubToken string
	APIBase     string
	// Catalog overrides the built-in feed list; an empty non-nil slice disables it.
	Catalog []Feed
	// Repositories overrides the built-in collector list; an empty non-nil slice disables it.
	Repositories []Repository
	Feeds        []Feed
}

// FeedResult reports what a single feed answered.
type FeedResult struct {
	Label      string `json:"label"`
	URL        string `json:"url"`
	Candidates int    `json:"candidates"`
	Reality    int    `json:"reality"`
	Format     string `json:"format"`
	Error      string `json:"error,omitempty"`
}

// Report is the outcome of one discovery pass.
type Report struct {
	Feeds      []FeedResult `json:"feeds"`
	Checked    int          `json:"checked"`
	Usable     int          `json:"usable"`
	Candidates int          `json:"candidates"`
	Reality    int          `json:"reality"`
	Failed     int          `json:"failed"`
}

// Discovery finds, checks and reports free-subscription feeds.
type Discovery struct {
	opts Options
}

// New builds a discovery pass with sane defaults.
func New(opts Options) *Discovery {
	if opts.Client == nil {
		opts.Client = &http.Client{}
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.MaxFeeds <= 0 {
		opts.MaxFeeds = DefaultMaxFeeds
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.APIBase == "" {
		opts.APIBase = githubAPIBase
	}
	return &Discovery{opts: opts}
}

// Run discovers feeds from the catalog, the configured repositories and any
// extra feeds, checks each one and returns a report sorted by usefulness.
func (discovery *Discovery) Run(ctx context.Context) Report {
	catalog := discovery.opts.Catalog
	if catalog == nil {
		catalog = Catalog()
	}
	feeds := make([]Feed, 0, len(catalog)+len(discovery.opts.Feeds)+8)
	// Configured feeds go first: a large catalog must never push an explicitly
	// requested feed past the MaxFeeds limit.
	feeds = append(feeds, discovery.opts.Feeds...)
	feeds = append(feeds, catalog...)
	repositories := discovery.opts.Repositories
	if repositories == nil {
		repositories = Repositories()
	}

	for _, repository := range repositories {
		listed, err := discovery.listRepository(ctx, repository)
		if err != nil {
			continue
		}
		feeds = append(feeds, listed...)
	}

	feeds = dedupeFeeds(feeds)
	if len(feeds) > discovery.opts.MaxFeeds {
		feeds = feeds[:discovery.opts.MaxFeeds]
	}

	results := make([]FeedResult, len(feeds))
	var wait sync.WaitGroup
	semaphore := make(chan struct{}, discovery.opts.Concurrency)
	for index, feed := range feeds {
		wait.Add(1)
		go func(index int, feed Feed) {
			defer wait.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[index] = discovery.check(ctx, feed)
		}(index, feed)
	}
	wait.Wait()

	report := Report{Feeds: results}
	for _, result := range results {
		report.Checked++
		if result.Error != "" || result.Candidates == 0 {
			report.Failed++
			continue
		}
		report.Usable++
		report.Candidates += result.Candidates
		report.Reality += result.Reality
	}
	sort.SliceStable(report.Feeds, func(i, j int) bool {
		if report.Feeds[i].Candidates != report.Feeds[j].Candidates {
			return report.Feeds[i].Candidates > report.Feeds[j].Candidates
		}
		return report.Feeds[i].Label < report.Feeds[j].Label
	})
	return report
}

func (discovery *Discovery) check(ctx context.Context, feed Feed) FeedResult {
	result := FeedResult{Label: feed.Label, URL: feed.URL}
	body, contentType, err := discovery.fetch(ctx, feed.URL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	text, encoded := decodeBody(body)
	switch {
	case encoded:
		result.Format = "base64"
	case strings.Contains(strings.ToLower(contentType), "html"):
		result.Format = "html"
	default:
		result.Format = "plain"
	}
	result.Candidates, result.Reality = CountVLESS(text)
	if result.Candidates == 0 {
		result.Error = "no VLESS links in feed"
		return result
	}
	return result
}

func (discovery *Discovery) fetch(ctx context.Context, link string) ([]byte, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("User-Agent", discovery.opts.UserAgent)
	request.Header.Set("Accept", "*/*")
	response, err := discovery.opts.Client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("fetch feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", fmt.Errorf("fetch feed: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, discovery.opts.MaxBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("read feed: %w", err)
	}
	if int64(len(body)) > discovery.opts.MaxBody {
		return nil, "", errors.New("feed exceeds size limit")
	}
	return body, response.Header.Get("Content-Type"), nil
}

type repositoryEntry struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
}

func (discovery *Discovery) listRepository(ctx context.Context, repository Repository) ([]Feed, error) {
	if repository.Owner == "" || repository.Name == "" {
		return nil, errors.New("repository owner and name are required")
	}
	endpoint := strings.TrimRight(discovery.opts.APIBase, "/") + "/repos/" +
		url.PathEscape(repository.Owner) + "/" + url.PathEscape(repository.Name) + "/contents"
	if path := strings.Trim(strings.TrimSpace(repository.Path), "/"); path != "" {
		endpoint += "/" + escapePath(path)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", discovery.opts.UserAgent)
	if token := strings.TrimSpace(discovery.opts.GitHubToken); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := discovery.opts.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("list repository: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list repository: HTTP %d", response.StatusCode)
	}
	var entries []repositoryEntry
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode repository listing: %w", err)
	}
	files := make([]repositoryEntry, 0, len(entries))
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Type != "file" || entry.DownloadURL == "" {
			continue
		}
		if entry.Size > 0 && entry.Size > discovery.opts.MaxBody {
			continue
		}
		files = append(files, entry)
		names[strings.ToLower(entry.Name)] = true
	}
	feeds := make([]Feed, 0, maxRepoFiles)
	hasVLESSOnly := false
	for _, entry := range files {
		if IsVLESSOnlyFile(entry.Name) {
			hasVLESSOnly = true
			break
		}
	}
	for _, entry := range files {
		if !IsFeedFile(entry.Name) {
			continue
		}
		// A pre-encoded twin carries the same links; the plain file wins.
		if strings.HasSuffix(strings.ToLower(entry.Name), "base64") &&
			names[strings.TrimSuffix(strings.ToLower(entry.Name), "base64")] {
			continue
		}
		// A vless-only file already contains every VLESS link of the mixed one.
		if hasVLESSOnly && !IsVLESSOnlyFile(entry.Name) {
			continue
		}
		label := repository.Label
		if label == "" {
			label = repository.Owner + "/" + repository.Name
		}
		feeds = append(feeds, Feed{Label: label + " " + entry.Name, URL: entry.DownloadURL})
		if len(feeds) >= maxRepoFiles {
			break
		}
	}
	return feeds, nil
}

func escapePath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func dedupeFeeds(feeds []Feed) []Feed {
	seen := make(map[string]struct{}, len(feeds))
	result := make([]Feed, 0, len(feeds))
	for _, feed := range feeds {
		parsed, err := url.Parse(strings.TrimSpace(feed.URL))
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		parsed.Fragment = ""
		key := strings.ToLower(parsed.Host) + parsed.EscapedPath() + "?" + parsed.RawQuery
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		feed.URL = parsed.String()
		if strings.TrimSpace(feed.Label) == "" {
			feed.Label = parsed.Host
		}
		result = append(result, feed)
	}
	return result
}

// UsableFeeds returns the feeds that answered with at least one VLESS link.
func UsableFeeds(report Report) []Feed {
	feeds := make([]Feed, 0, report.Usable)
	for _, feed := range report.Feeds {
		if feed.Error != "" || feed.Candidates == 0 {
			continue
		}
		feeds = append(feeds, Feed{Label: feed.Label, URL: feed.URL})
	}
	return feeds
}

// Items converts a report into source items ready for store.ImportSources.
// Only feeds that passed the check are converted, so a failed feed never
// enters the inventory as a dead source.
func Items(report Report) []sources.PreviewItem {
	feeds := UsableFeeds(report)
	if len(feeds) == 0 {
		return nil
	}
	lines := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		lines = append(lines, "free-source "+feed.URL)
	}
	preview := sources.PreviewInput(strings.Join(lines, "\n"))
	labels := make(map[string]string, len(feeds))
	for _, feed := range feeds {
		labels[feed.URL] = feed.Label
	}
	items := make([]sources.PreviewItem, 0, len(preview.Items))
	for _, item := range preview.Items {
		if item.Error != "" || item.Fingerprint == "" {
			continue
		}
		if label := labels[strings.TrimSpace(item.Payload)]; label != "" {
			item.Display = label
		}
		items = append(items, item)
	}
	return items
}
