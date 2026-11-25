package refresh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

var (
	errPublicInventoryLimit = errors.New("public candidate budget is full or all candidates are already imported")
	sharedAddressSpace      = netip.MustParsePrefix("100.64.0.0/10")
)

const (
	maxPublicCandidatesPerSource = 64
	maxPublicCandidates          = 200
)

func isPublicSource(kind sources.Kind) bool {
	return kind == sources.KindPublicSubscription
}

// CheckSuggestedPublicSources reports which catalogue feeds the ordinary
// refresh pipeline can use. Existing sources do not need to be rechecked.
func (refresher *Refresher) CheckSuggestedPublicSources(ctx context.Context) (sources.Preview, error) {
	listed, err := refresher.store.ListSources(ctx)
	if err != nil {
		return sources.Preview{}, err
	}
	existing := make(map[string]bool, len(listed))
	for _, source := range listed {
		if !source.PendingDelete {
			existing[source.Fingerprint] = true
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	items := sources.SuggestedPublicSubscriptions()
	slots := make(chan struct{}, 4)
	var checks sync.WaitGroup
	for index := range items {
		item := &items[index]
		if existing[item.Fingerprint] {
			item.Duplicate = true
			continue
		}
		checks.Go(func() {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				item.Error = safeRefreshError(ctx.Err()).Error()
				return
			}
			input, err := refresher.readPublicSubscription(ctx, item.Payload)
			if err == nil {
				_, err = parseSourceCandidates(item.Kind, input)
			}
			if err != nil {
				item.Error = safeRefreshError(err).Error()
			}
		})
	}
	checks.Wait()

	preview := sources.Preview{Items: items}
	for _, item := range items {
		switch {
		case item.Error != "":
			preview.ErrorCount++
		case item.Duplicate:
			preview.DuplicateCount++
		default:
			preview.ValidCount++
		}
	}
	return preview, nil
}

func (refresher *Refresher) publicSourceClient() *http.Client {
	// Public GitHub sources use fixed HTTPS hosts and never carry private
	// subscription headers, cookies or redirect targets.
	client := *refresher.client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func (refresher *Refresher) readPublicSubscription(ctx context.Context, link string) (string, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "raw.githubusercontent.com" || parsed.User != nil {
		return "", errors.New("invalid public subscription URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return "", err
	}
	response, err := refresher.publicSourceClient().Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch subscription: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch subscription: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, refresher.maxBody+1))
	if err != nil {
		return "", fmt.Errorf("read subscription: %w", err)
	}
	if int64(len(body)) > refresher.maxBody {
		return "", errors.New("subscription exceeds size limit")
	}
	return decodeSubscription(string(body)), nil
}

func publicRepositoryEndpoint(link string) bool {
	parsed, err := url.Parse(link)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
	}
	return strings.Contains(host, ".") && !strings.HasSuffix(host, ".localhost") &&
		!strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal")
}

func (refresher *Refresher) limitPublicCandidates(ctx context.Context, sourceID string, incoming []store.CandidateInput, existing []store.Candidate, otherFingerprints map[string]bool) ([]store.CandidateInput, error) {
	listed, err := refresher.store.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	publicSources := make(map[string]bool)
	for _, source := range listed {
		if isPublicSource(source.Kind) && source.Enabled {
			publicSources[source.ID] = true
		}
	}
	otherPublicCount := 0
	for _, candidate := range existing {
		if candidate.SourceID != sourceID && publicSources[candidate.SourceID] {
			otherPublicCount++
		}
	}
	budget := min(maxPublicCandidates, max(1, refresher.inventoryLimit/10))
	sourceCount := max(1, len(publicSources))
	perSource := min(maxPublicCandidatesPerSource, (budget+sourceCount-1)/sourceCount)
	limit := min(perSource, budget-otherPublicCount, refresher.inventoryLimit-len(otherFingerprints))
	if limit <= 0 {
		return nil, errPublicInventoryLimit
	}
	limited := make([]store.CandidateInput, 0, min(limit, len(incoming)))
	for _, candidate := range incoming {
		if !otherFingerprints[candidate.Fingerprint] {
			limited = append(limited, candidate)
			if len(limited) == limit {
				break
			}
		}
	}
	if len(limited) == 0 {
		return nil, errPublicInventoryLimit
	}
	return limited, nil
}
