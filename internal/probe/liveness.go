package probe

import (
	"context"
	"net/http"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/socks5"
)

// Liveness performs two independent, small HTTP checks. A candidate is only
// considered hard-down when both the primary and confirmation checks fail.
type Liveness struct {
	ClientFactory   func(string) *http.Client
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
	}
	primaryURL := liveness.PrimaryURL
	if primaryURL == "" {
		primaryURL = "https://www.google.com/generate_204"
	}
	confirmationURL := liveness.ConfirmationURL
	if confirmationURL == "" {
		confirmationURL = "https://www.gstatic.com/generate_204"
	}
	results := make(chan result, 2)
	go func() {
		results <- result{primary: true, ok: requestOK(ctx, client, primaryURL)}
	}()
	go func() {
		results <- result{ok: requestOK(ctx, client, confirmationURL)}
	}()
	var observation health.Observation
	for range 2 {
		item := <-results
		if item.primary {
			observation.PrimaryOK = item.ok
		} else {
			observation.ConfirmationOK = item.ok
		}
	}
	return observation
}

func (liveness Liveness) client(ctx context.Context, socksAddress string) *http.Client {
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
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
