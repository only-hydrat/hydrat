package probe

import (
	"context"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

// MeasureOnion shares the ordinary QoE transport and diagnostics. Requests use
// SOCKS domain names: no host DNS, direct HTTP control or throughput download.
// Public fixed targets cannot be supplied by clients or redirected off onion.
func (measurer *QoEMeasurer) MeasureOnion(ctx context.Context, candidateID, socksAddress string) qoe.Observation {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	client := measurer.routeClient(socksAddress)
	defer client.CloseIdleConnections()
	targets := []struct{ service, url string }{
		{"onion_search", "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"},
		{"onion_project", "http://xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion/"},
	}
	checks := make([]qoe.HTTPCheck, len(targets))
	var workers sync.WaitGroup
	for i, target := range targets {
		workers.Add(1)
		go func() {
			defer workers.Done()
			c := checkStatusDetailed(ctx, client, target.url, func(status int) bool { return status >= 200 && status < 400 })
			c.Service, c.Path = target.service, "route"
			checks[i] = c
		}()
	}
	workers.Wait()
	o := qoe.Observation{At: measurer.now(), Success: true, ApplicationChecks: checks, ComparisonPolicy: qoe.OnionComparisonPolicy}
	for _, c := range checks {
		o.Success = o.Success && c.OK
		o.TTFB = max(o.TTFB, time.Duration(c.ElapsedMS)*time.Millisecond)
	}
	if !o.Success {
		o.ErrorCode = qoe.ReasonApplicationGates
		o.Infrastructure = true
		o.UnconfirmedHTTP = true
	}
	return o
}
