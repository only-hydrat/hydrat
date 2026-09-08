package probe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestLivenessChecksPrimaryAndIndependentConfirmation(t *testing.T) {
	var requests atomic.Int32
	observer := Liveness{
		PrimaryURL: "https://cp.cloudflare.com/generate_204",
		ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			status := http.StatusNoContent
			if request.URL.Host == "cp.cloudflare.com" {
				status = http.StatusServiceUnavailable
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		})}
	}}

	result := observer.Observe(context.Background(), "127.0.0.1:11080")
	if result.PrimaryOK || !result.ConfirmationOK || requests.Load() != 2 {
		t.Fatalf("observation=%+v requests=%d", result, requests.Load())
	}
}

func TestLivenessUsesCallerDeadlineAndRunsChecksConcurrently(t *testing.T) {
	observer := Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			select {
			case <-time.After(900 * time.Millisecond):
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
		})}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	result := observer.Observe(ctx, "127.0.0.1:11080")
	if !result.PrimaryOK || !result.ConfirmationOK {
		t.Fatalf("observation=%+v", result)
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("checks were not concurrent: %s", elapsed)
	}
}

func TestLivenessReservesTimeToReportHardFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()

	client := (Liveness{}).client(ctx, "127.0.0.1:1")
	if client.Timeout < 680*time.Millisecond || client.Timeout > 720*time.Millisecond {
		t.Fatalf("default HTTP timeout %s does not preserve background reserve before %s", client.Timeout, deadline)
	}

	criticalClient := (Liveness{ResponseBudget: 25 * time.Millisecond}).client(
		ctx,
		"127.0.0.1:1",
	)
	if criticalClient.Timeout < 750*time.Millisecond || criticalClient.Timeout > 790*time.Millisecond {
		t.Fatalf("critical HTTP timeout %s does not reserve a stable response budget before %s", criticalClient.Timeout, deadline)
	}
}
