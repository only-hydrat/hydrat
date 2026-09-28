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
		PrimaryURL: "https://www.google.com/generate_204",
		ClientFactory: func(string) *http.Client {
			return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				status := http.StatusNoContent
				if request.URL.Host == "www.google.com" {
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

func TestLivenessReportsSafeFailureCodesAndDurations(t *testing.T) {
	observer := Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host == "www.google.com" {
				return nil, context.DeadlineExceeded
			}
			return &http.Response{StatusCode: http.StatusServiceUnavailable,
				Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		})}
	}}
	result := observer.Observe(context.Background(), "127.0.0.1:11080")
	if result.PrimaryOK || result.ConfirmationOK ||
		result.PrimaryFailure != "timeout" ||
		result.ConfirmationFailure != "http_503" ||
		result.PrimaryElapsedMS < 0 || result.ConfirmationElapsedMS < 0 {
		t.Fatalf("liveness diagnostics=%+v", result)
	}
}

func TestLivenessDefaultsUseIndependentProviders(t *testing.T) {
	hosts := make(chan string, 2)
	observer := Liveness{ClientFactory: func(string) *http.Client {
		return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			hosts <- request.URL.Host
			return &http.Response{StatusCode: http.StatusNoContent,
				Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		})}
	}}
	observer.Observe(context.Background(), "127.0.0.1:11080")
	first, second := <-hosts, <-hosts
	if first == second || (first != "cp.cloudflare.com" && second != "cp.cloudflare.com") {
		t.Fatalf("defaults do not include independent Cloudflare confirmation: %q %q", first, second)
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
