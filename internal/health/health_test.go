package health

import (
	"testing"
	"time"
)

func TestScoreUsesApprovedWeightsAndQualificationGates(t *testing.T) {
	result := Evaluate(Metrics{
		SuccessRatio: 1, PacketDropRatio: 0, Latency: 100 * time.Millisecond,
		ThroughputMbps: 50, ActiveLoad: 0,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}, ProtocolVLESS)
	if result.Score < 97 || !result.TCPQualified || !result.UDPQualified {
		t.Fatalf("healthy result=%+v", result)
	}

	blocked := Evaluate(Metrics{
		SuccessRatio: 1, Latency: 50 * time.Millisecond, ThroughputMbps: 100,
		ChatGPTWeb: true, OpenAI401: false, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}, ProtocolVLESS)
	if blocked.TCPQualified || blocked.UDPQualified {
		t.Fatalf("OpenAI gate did not disqualify candidate: %+v", blocked)
	}

	tor := Evaluate(Metrics{
		SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 50,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
	}, ProtocolTor)
	if !tor.TCPQualified || tor.UDPQualified {
		t.Fatalf("Tor qualification=%+v", tor)
	}
}

func TestChatGPTIsMandatoryQualificationGate(t *testing.T) {
	result := Evaluate(Metrics{
		SuccessRatio: 1, Latency: 50 * time.Millisecond, ThroughputMbps: 100,
		ChatGPTWeb: false, OpenAI401: true, TelegramWeb: true,
		TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
	}, ProtocolVLESS)
	if result.TCPQualified || result.UDPQualified {
		t.Fatalf("ChatGPT gate did not disqualify candidate: %+v", result)
	}
}

func TestQualificationFailureCodeIdentifiesFirstFailedRequirement(t *testing.T) {
	tests := []struct {
		name    string
		metrics Metrics
		want    string
	}{
		{"chatgpt", Metrics{OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true}, "chatgpt_web_failed"},
		{"openai", Metrics{ChatGPTWeb: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true}, "openai_api_failed"},
		{"telegram web", Metrics{ChatGPTWeb: true, OpenAI401: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true}, "telegram_web_failed"},
		{"telegram mtproto", Metrics{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, YouTubeWeb: true, InstagramWeb: true}, "telegram_mtproto_failed"},
		{"youtube", Metrics{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, InstagramWeb: true}, "youtube_web_failed"},
		{"instagram", Metrics{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true}, "instagram_web_failed"},
		{"score", Metrics{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true}, "score_too_low"},
		{"healthy", Metrics{
			SuccessRatio: 1, Latency: 50 * time.Millisecond, ThroughputMbps: 100,
			ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
		}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluation := Evaluate(test.metrics, ProtocolVLESS)
			if got := QualificationFailureCode(test.metrics, evaluation); got != test.want {
				t.Fatalf("QualificationFailureCode()=%q want %q; evaluation=%+v", got, test.want, evaluation)
			}
		})
	}
}

func TestScoreRewardsHigherMeasuredThroughput(t *testing.T) {
	base := Metrics{
		SuccessRatio: 1, PacketDropRatio: 0, Latency: 100 * time.Millisecond,
		ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
	}
	slow := base
	slow.ThroughputMbps = 5
	fast := base
	fast.ThroughputMbps = 50
	slowScore := Evaluate(slow, ProtocolVLESS).Score
	fastScore := Evaluate(fast, ProtocolVLESS).Score
	if fastScore <= slowScore || fastScore-slowScore < 10 {
		t.Fatalf("throughput did not materially affect score: slow=%.2f fast=%.2f", slowScore, fastScore)
	}
}

func TestTorAccessGatesQualifySlowRouteWhileScoreStillRanksIt(t *testing.T) {
	metrics := Metrics{
		SuccessRatio: 1, PacketDropRatio: 0, Latency: 800 * time.Millisecond,
		ThroughputMbps: 5,
		ChatGPTWeb:     true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true,
	}

	tor := Evaluate(metrics, ProtocolTor)
	if tor.Score >= 80 {
		t.Fatalf("test route unexpectedly met performance threshold: %+v", tor)
	}
	if !tor.TCPQualified || tor.UDPQualified {
		t.Fatalf("accessible Tor route was rejected: %+v", tor)
	}

	vless := Evaluate(metrics, ProtocolVLESS)
	if vless.TCPQualified || vless.UDPQualified {
		t.Fatalf("VLESS performance threshold was bypassed: %+v", vless)
	}
}

func TestTrackerQuarantinesHardFailureAndRequiresThreeRecoveries(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	tracker := NewTracker(5*time.Minute, 3)
	tracker.Observe(start, Observation{PrimaryOK: false, ConfirmationOK: false})
	state := tracker.State(start)
	if state.Available || !state.QuarantinedUntil.Equal(start.Add(5*time.Minute)) {
		t.Fatalf("hard failure state=%+v", state)
	}

	for index := 0; index < 3; index++ {
		tracker.Observe(start.Add(time.Duration(index+1)*time.Minute), Observation{PrimaryOK: true, ConfirmationOK: true})
	}
	if tracker.State(start.Add(4 * time.Minute)).Available {
		t.Fatal("candidate recovered before quarantine elapsed")
	}
	if !tracker.State(start.Add(5 * time.Minute)).Available {
		t.Fatalf("candidate did not recover after three successes: %+v", tracker.State(start.Add(5*time.Minute)))
	}
}

func TestSingleEndpointFailureIsDegradedNotHardFailed(t *testing.T) {
	tracker := NewTracker(5*time.Minute, 3)
	now := time.Unix(1_800_000_000, 0)
	tracker.Observe(now, Observation{PrimaryOK: false, ConfirmationOK: true})
	state := tracker.State(now)
	if !state.Available || !state.Degraded {
		t.Fatalf("state=%+v", state)
	}
}
