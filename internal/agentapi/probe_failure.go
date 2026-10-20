package agentapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

// ProbeDiagnostics contains only bounded operational metadata, never raw errors
// from Xray, requests, subscription payloads or response bodies.
type ProbeDiagnostics struct {
	Phase         string `json:"phase,omitempty"`
	QueueMS       int64  `json:"queue_ms,omitempty"`
	ElapsedMS     int64  `json:"elapsed_ms,omitempty"`
	RuntimeStatus string `json:"runtime_status,omitempty"`
	RuntimeEpoch  uint64 `json:"runtime_epoch,omitempty"`
}

type ProbeError struct {
	Code  string
	Phase string
	Cause error
}

func (err *ProbeError) Error() string { return safeInfrastructureCode(err.Code) }
func (err *ProbeError) Unwrap() error { return err.Cause }

func safeInfrastructureCode(code string) string {
	switch code {
	case "agent_unavailable", "agent_transport", "agent_deadline", "agent_canceled", "agent_response_invalid", "agent_http_error",
		"worker_timeout", "probe_runtime_unavailable", "probe_runtime_interrupted", "probe_setup_failed", "probe_cleanup_failed",
		"probe_infrastructure", "probe_timeout", "probe_canceled", "tor_profile_unavailable",
		"qoe_endpoint_unavailable", "qoe_endpoint_http", "qoe_endpoint_size", "qoe_endpoint_malformed",
		"qoe_dns_unavailable", "qoe_application_gates_unavailable", "qoe_measurement_canceled", "qoe_proxy_unavailable":
		return code
	default:
		return "probe_infrastructure"
	}
}

// IsProbeInfrastructureCode includes the historical fallback for old records.
func IsProbeInfrastructureCode(code string) bool {
	return code != "" && safeInfrastructureCode(code) == code
}

func safeProbePhase(phase string) string {
	switch phase {
	case "admission", "queue", "runtime", "configure", "measure", "cleanup", "transport", "response":
		return phase
	default:
		return "measure"
	}
}

func safeRuntimeStatus(status string) string {
	switch status {
	case "ready", "draining", "starting", "restarting", "closed", "not_started":
		return status
	default:
		return "unknown"
	}
}

func (diagnostics *ProbeDiagnostics) sanitize() {
	if diagnostics == nil {
		return
	}
	diagnostics.Phase = safeProbePhase(diagnostics.Phase)
	diagnostics.RuntimeStatus = safeRuntimeStatus(diagnostics.RuntimeStatus)
	diagnostics.QueueMS = min(600_000, max(0, diagnostics.QueueMS))
	diagnostics.ElapsedMS = min(600_000, max(0, diagnostics.ElapsedMS))
}

// ProbeFailureDetails projects failures for persistent state and logs. Unknown
// error text is deliberately discarded at this boundary.
func ProbeFailureDetails(response ProbeResponse, err error) (string, string) {
	code := safeInfrastructureCode(response.ErrorCode)
	phase := "measure"
	if err != nil {
		code = "agent_transport"
		phase = "transport"
		var probeErr *ProbeError
		switch {
		case errors.As(err, &probeErr):
			code, phase = safeInfrastructureCode(probeErr.Code), safeProbePhase(probeErr.Phase)
		case errors.Is(err, context.Canceled):
			code = "agent_canceled"
		case errors.Is(err, context.DeadlineExceeded):
			code = "agent_deadline"
		}
	}
	d := ProbeDiagnostics{Phase: phase}
	if response.Diagnostics != nil {
		d = *response.Diagnostics
	}
	d.sanitize()
	details := fmt.Sprintf("phase=%s queue_ms=%d elapsed_ms=%d runtime=%s epoch=%d",
		d.Phase, d.QueueMS, d.ElapsedMS, d.RuntimeStatus, d.RuntimeEpoch)
	if response.QoE != nil {
		details += qoe.HTTPFailureSummary(response.QoE.ApplicationChecks)
	}
	return code, details
}

func (response *ProbeResponse) sanitizeHTTPDiagnostics() {
	if response.QoE != nil {
		observation := *response.QoE
		observation.ApplicationChecks = qoe.SafeHTTPChecks(observation.ApplicationChecks)
		if observation.ComparisonPolicy != "" {
			decoded, err := hex.DecodeString(observation.ComparisonPolicy)
			if err != nil || len(decoded) != 32 {
				observation.ComparisonPolicy = ""
			}
		}
		if observation.UnconfirmedHTTP && observation.ComparisonPolicy == "" {
			observation.UnconfirmedHTTP = false
			observation.Infrastructure = true
			observation.Success = false
			observation.ErrorCode = "probe_infrastructure"
		}
		response.QoE = &observation
	}
}

func SharedProbeUnavailable(response ProbeResponse) bool {
	return response.FailureClass == FailureInfrastructure && response.ErrorCode == "probe_runtime_unavailable"
}

func (client *Client) pauseBackgroundProbes() {
	client.backgroundMu.Lock()
	defer client.backgroundMu.Unlock()
	if !client.backgroundPaused {
		client.backgroundPaused = true
		client.backgroundDelay = 5 * time.Second
		client.backgroundRetryAt = client.probeTime().Add(client.backgroundDelay)
	}
}

func (client *Client) probeTime() time.Time {
	if client.probeNow != nil {
		return client.probeNow()
	}
	return time.Now()
}

func (client *Client) backgroundProbesReady(ctx context.Context) bool {
	client.backgroundMu.Lock()
	defer client.backgroundMu.Unlock()
	if !client.backgroundPaused {
		return true
	}
	if client.probeTime().Before(client.backgroundRetryAt) {
		return false
	}
	healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	snapshot, err := client.ProbeRuntimeHealth(healthCtx)
	if err == nil && (snapshot.Status == "ready" || snapshot.Status == "") {
		client.backgroundPaused = false
		client.backgroundDelay = 0
		return true
	}
	client.backgroundDelay = min(30*time.Second, 2*client.backgroundDelay)
	client.backgroundRetryAt = client.probeTime().Add(client.backgroundDelay)
	return false
}
