package agentapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
)

type ProbeMode string

const (
	ProbeModeFast           ProbeMode = "fast"
	ProbeModeFull           ProbeMode = "full"
	ProbeModeActive         ProbeMode = "active"
	ProbeModeActiveCritical ProbeMode = "active-critical"
	ProbeModeQoE            ProbeMode = "qoe"
)

type FailureClass string

const (
	FailureNone           FailureClass = ""
	FailureCandidate      FailureClass = "candidate"
	FailureInfrastructure FailureClass = "infrastructure"
)

type ProbeRequest struct {
	CandidateID string       `json:"candidate_id"`
	Kind        sources.Kind `json:"kind"`
	Payload     string       `json:"payload"`
}

type ProbeResponse struct {
	CandidateID  string             `json:"candidate_id"`
	Success      bool               `json:"success"`
	FailureClass FailureClass       `json:"failure_class,omitempty"`
	ErrorCode    string             `json:"error_code,omitempty"`
	Metrics      health.Metrics     `json:"metrics"`
	Evaluation   health.Evaluation  `json:"evaluation"`
	Observation  health.Observation `json:"observation"`
	QoE          *qoe.Observation   `json:"qoe,omitempty"`
}

type ProbeRunner interface {
	Probe(context.Context, ProbeMode, ProbeRequest) (ProbeResponse, error)
}

type probeLimits struct {
	fast           chan struct{}
	full           chan struct{}
	active         chan struct{}
	activeCritical chan struct{}
	qoe            chan struct{}
}

type probeDeadlines struct {
	fast    time.Duration
	full    time.Duration
	active  time.Duration
	qoe     time.Duration
	torFast time.Duration
	torFull time.Duration
}

func newProbeLimits(fast, full, active int) probeLimits {
	if fast <= 0 {
		fast = 8
	}
	if full <= 0 {
		full = 4
	}
	if active <= 0 {
		active = 16
	}
	return probeLimits{
		fast: make(chan struct{}, fast), full: make(chan struct{}, full), active: make(chan struct{}, active),
		activeCritical: make(chan struct{}, 48), qoe: make(chan struct{}, 4),
	}
}

func (limits probeLimits) forMode(mode ProbeMode) chan struct{} {
	switch mode {
	case ProbeModeFast:
		return limits.fast
	case ProbeModeFull:
		return limits.full
	case ProbeModeQoE:
		return limits.qoe
	case ProbeModeActiveCritical:
		return limits.activeCritical
	default:
		return limits.active
	}
}

func defaultProbeDeadlines() probeDeadlines {
	return probeDeadlines{
		fast: 3 * time.Second, full: 20 * time.Second, active: 10 * time.Second, qoe: 10 * time.Second,
		torFast: 5 * time.Minute, torFull: 6 * time.Minute,
	}
}

func (deadlines probeDeadlines) forMode(mode ProbeMode) time.Duration {
	switch mode {
	case ProbeModeFast:
		return deadlines.fast
	case ProbeModeFull:
		return deadlines.full
	case ProbeModeQoE:
		return deadlines.qoe
	case ProbeModeActiveCritical:
		return deadlines.active
	default:
		return deadlines.active
	}
}

func (deadlines probeDeadlines) forRequest(mode ProbeMode, kind sources.Kind) time.Duration {
	if kind == sources.KindTorBridge {
		switch mode {
		case ProbeModeFast:
			return deadlines.torFast
		case ProbeModeFull:
			return deadlines.torFull
		}
	}
	return deadlines.forMode(mode)
}

func (server *Server) probe(response http.ResponseWriter, request *http.Request, mode ProbeMode) {
	runner := server.probeRunner
	if mode == ProbeModeActiveCritical {
		runner = server.criticalActiveProbeRunner
	}
	if runner == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "probe runner is unavailable"})
		return
	}
	var body ProbeRequest
	if !server.decodeJSON(response, request, &body) {
		return
	}
	if err := validateProbeRequest(body); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(
		request.Context(),
		server.probeDeadlines.forRequest(mode, body.Kind),
	)
	defer cancel()
	limit := server.probeLimits.forMode(mode)
	select {
	case limit <- struct{}{}:
		defer func() { <-limit }()
	case <-ctx.Done():
		writeJSON(response, http.StatusGatewayTimeout, ProbeResponse{
			CandidateID: body.CandidateID, FailureClass: FailureInfrastructure, ErrorCode: "worker_timeout",
		})
		return
	}
	result, err := runner.Probe(ctx, mode, body)
	if err != nil {
		code := "probe_infrastructure"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "probe_timeout"
		} else if errors.Is(err, context.Canceled) {
			code = "probe_canceled"
		}
		result = ProbeResponse{
			CandidateID: body.CandidateID, FailureClass: FailureInfrastructure, ErrorCode: code,
		}
	}
	if result.CandidateID == "" {
		result.CandidateID = body.CandidateID
	}
	writeJSON(response, http.StatusOK, result)
}

func validateProbeRequest(request ProbeRequest) error {
	if strings.TrimSpace(request.CandidateID) == "" || len(request.CandidateID) > 128 {
		return errors.New("candidate_id is invalid")
	}
	if request.Kind != sources.KindVLESS && request.Kind != sources.KindTorBridge {
		return errors.New("candidate kind is invalid")
	}
	if request.Payload == "" {
		return errors.New("candidate payload is required")
	}
	return nil
}
