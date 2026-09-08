package health

import "time"

type Protocol string

const (
	ProtocolVLESS Protocol = "vless"
	ProtocolTor   Protocol = "tor"
)

type Metrics struct {
	SuccessRatio    float64
	PacketDropRatio float64
	Latency         time.Duration
	ThroughputMbps  float64
	ActiveLoad      float64
	ChatGPTWeb      bool
	OpenAI401       bool
	TelegramWeb     bool
	TelegramMTProto bool
	YouTubeWeb      bool
	InstagramWeb    bool
	UDP             bool
	CustomGates     map[string]bool
}

type Evaluation struct {
	Score        float64 `json:"score"`
	TCPQualified bool    `json:"tcp_qualified"`
	UDPQualified bool    `json:"udp_qualified"`
}

func Evaluate(metrics Metrics, protocol Protocol) Evaluation {
	stability := clamp(metrics.SuccessRatio) * (1 - clamp(metrics.PacketDropRatio))
	latency := 1 - clamp(float64(metrics.Latency)/(float64(2)*float64(time.Second)))
	throughput := clamp(metrics.ThroughputMbps / 50)
	load := 1 - clamp(metrics.ActiveLoad)
	score := 100 * (0.50*stability + 0.25*latency + 0.15*throughput + 0.10*load)
	gates := metrics.ChatGPTWeb && metrics.OpenAI401 && metrics.TelegramWeb &&
		metrics.TelegramMTProto && metrics.YouTubeWeb && metrics.InstagramWeb
	tcp := gates && (protocol == ProtocolTor || score >= 80)
	udp := tcp && protocol == ProtocolVLESS && metrics.UDP
	return Evaluation{Score: score, TCPQualified: tcp, UDPQualified: udp}
}

func QualificationFailureCode(metrics Metrics, evaluation Evaluation) string {
	switch {
	case !metrics.ChatGPTWeb:
		return "chatgpt_web_failed"
	case !metrics.OpenAI401:
		return "openai_api_failed"
	case !metrics.TelegramWeb:
		return "telegram_web_failed"
	case !metrics.TelegramMTProto:
		return "telegram_mtproto_failed"
	case !metrics.YouTubeWeb:
		return "youtube_web_failed"
	case !metrics.InstagramWeb:
		return "instagram_web_failed"
	case !evaluation.TCPQualified:
		return "score_too_low"
	default:
		return ""
	}
}

func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

type Observation struct {
	PrimaryOK      bool
	ConfirmationOK bool
}

type State struct {
	Available         bool      `json:"available"`
	Degraded          bool      `json:"degraded"`
	QuarantinedUntil  time.Time `json:"quarantined_until,omitempty"`
	RecoverySuccesses int       `json:"recovery_successes"`
}

type Tracker struct {
	quarantine time.Duration
	recoveries int
	state      State
}

func NewTracker(quarantine time.Duration, recoveries int) *Tracker {
	if quarantine <= 0 {
		quarantine = 5 * time.Minute
	}
	if recoveries <= 0 {
		recoveries = 3
	}
	return &Tracker{quarantine: quarantine, recoveries: recoveries, state: State{Available: true}}
}

func (tracker *Tracker) Observe(now time.Time, observation Observation) {
	switch {
	case !observation.PrimaryOK && !observation.ConfirmationOK:
		tracker.state.Available = false
		tracker.state.Degraded = false
		tracker.state.QuarantinedUntil = now.Add(tracker.quarantine)
		tracker.state.RecoverySuccesses = 0
	case observation.PrimaryOK && observation.ConfirmationOK:
		tracker.state.Degraded = false
		if !tracker.state.QuarantinedUntil.IsZero() {
			tracker.state.RecoverySuccesses++
		}
	default:
		tracker.state.Degraded = true
		if !tracker.state.QuarantinedUntil.IsZero() {
			tracker.state.RecoverySuccesses = 0
		}
	}
	tracker.refreshAvailability(now)
}

func (tracker *Tracker) State(now time.Time) State {
	tracker.refreshAvailability(now)
	return tracker.state
}

func (tracker *Tracker) refreshAvailability(now time.Time) {
	if tracker.state.QuarantinedUntil.IsZero() {
		return
	}
	if !now.Before(tracker.state.QuarantinedUntil) && tracker.state.RecoverySuccesses >= tracker.recoveries {
		tracker.state.Available = true
		tracker.state.QuarantinedUntil = time.Time{}
		tracker.state.RecoverySuccesses = 0
	}
}
