package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/socks5"
)

// Liveness performs two independent, small HTTP checks. A candidate is only
// considered hard-down when both the primary and confirmation checks fail.
type Liveness struct {
	ClientFactory func(string) *http.Client
	// ResponseBudget leaves time in the caller deadline to serialize and return
	// an observation. Zero preserves the background-probe default.
	ResponseBudget  time.Duration
	PrimaryURL      string
	ConfirmationURL string
}

func (liveness Liveness) Observe(ctx context.Context, socksAddress string) health.Observation {
	client := liveness.client(ctx, socksAddress)
	defer client.CloseIdleConnections()
	type result struct {
		primary bool
		ok      bool
		failure string
		elapsed int64
	}
	primaryURL := liveness.PrimaryURL
	if primaryURL == "" {
		primaryURL = "https://www.google.com/generate_204"
	}
	confirmationURL := liveness.ConfirmationURL
	if confirmationURL == "" {
		confirmationURL = "https://cp.cloudflare.com/generate_204"
	}
	results := make(chan result, 2)
	go func() {
		ok, failure, elapsed := livenessRequest(ctx, client, primaryURL)
		results <- result{primary: true, ok: ok, failure: failure, elapsed: elapsed}
	}()
	go func() {
		ok, failure, elapsed := livenessRequest(ctx, client, confirmationURL)
		results <- result{ok: ok, failure: failure, elapsed: elapsed}
	}()
	var observation health.Observation
	for range 2 {
		item := <-results
		if item.primary {
			observation.PrimaryOK = item.ok
			observation.PrimaryFailure = item.failure
			observation.PrimaryElapsedMS = item.elapsed
		} else {
			observation.ConfirmationOK = item.ok
			observation.ConfirmationFailure = item.failure
			observation.ConfirmationElapsedMS = item.elapsed
		}
	}
	return observation
}

func livenessRequest(ctx context.Context, client *http.Client, endpoint string) (bool, string, int64) {
	started := time.Now()
	elapsed := func() int64 { return time.Since(started).Milliseconds() }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "request_error", elapsed()
	}
	response, err := client.Do(request)
	if err != nil {
		var networkError net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
			return false, "timeout", elapsed()
		}
		return false, "network_error", elapsed()
	}
	if _, err := discardBody(ctx, response.Body, 4096); err != nil {
		return false, "body_error", elapsed()
	}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return false, fmt.Sprintf("http_%d", response.StatusCode), elapsed()
	}
	return true, "", elapsed()
}

func (liveness Liveness) client(ctx context.Context, socksAddress string) *http.Client {
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		// Critical probes explicitly reserve response time and may use a
		// deadline longer than the background probe's three-second default.
		if remaining := time.Until(deadline); remaining > 0 &&
			(remaining < timeout || liveness.ResponseBudget > 0) {
			responseBudget := liveness.ResponseBudget
			if responseBudget <= 0 {
				responseBudget = 100 * time.Millisecond
			}
			timeout = remaining / 2
			if remaining > 2*responseBudget {
				timeout = remaining - responseBudget
			}
		}
	}
	if liveness.ClientFactory != nil {
		return withHTTPTimeout(liveness.ClientFactory(socksAddress), timeout)
	}
	dialer := socks5.Dialer{ProxyAddress: socksAddress}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: 8, MaxIdleConnsPerHost: 2,
		DisableKeepAlives: true, IdleConnTimeout: timeout,
		TLSHandshakeTimeout: timeout,
	}}
}
