package qoe

import (
	"testing"
	"time"
)

func TestApplyTracksOldestSampleInCurrentWindow(t *testing.T) {
	policy := DefaultPolicy()
	policy.WindowSize = 3
	startedAt := time.Unix(1_800_000_000, 0)
	decision := Apply(policy, State{}, []Sample{
		{At: startedAt.Add(-time.Minute), Valid: true, Success: true},
		{At: startedAt, Valid: true, Success: true},
		{At: startedAt.Add(time.Second), Valid: true, Success: true},
	}, nil, Observation{
		At: startedAt.Add(2 * time.Second), Success: true,
		TTFB: time.Millisecond, ThroughputMbps: 10, Bytes: 65536,
	})
	if !decision.State.WindowStartedAt.Equal(startedAt) {
		t.Fatalf("window started at %s want %s", decision.State.WindowStartedAt, startedAt)
	}
	if decision.State.WindowMaxGap != time.Second {
		t.Fatalf("window maximum gap=%s want=1s", decision.State.WindowMaxGap)
	}
}

func TestApplyDegradesOnThreeBadOfFiveAndFreezesBaseline(t *testing.T) {
	policy := DefaultPolicy()
	state := State{
		Status: StatusHealthy, BaselineTTFB: 200 * time.Millisecond,
		BaselineThroughputMbps: 20, BaselineSamples: 5,
	}
	recent := []Sample{
		{Valid: true, Bad: false},
		{Valid: true, Bad: true},
		{Valid: true, Bad: false},
		{Valid: true, Bad: true},
	}
	decision := Apply(policy, state, recent, nil, Observation{
		At: time.Unix(1_800_000_000, 0), Success: true,
		TTFB: 2 * time.Second, ThroughputMbps: 2, Bytes: 65536,
	})
	if decision.State.Status != StatusDegraded {
		t.Fatalf("status=%s", decision.State.Status)
	}
	if decision.State.BaselineTTFB != state.BaselineTTFB ||
		decision.State.BaselineThroughputMbps != state.BaselineThroughputMbps {
		t.Fatalf("degraded sample changed baseline: %+v", decision.State)
	}
	if decision.Transition.From != StatusHealthy || decision.Transition.To != StatusDegraded {
		t.Fatalf("transition=%+v", decision.Transition)
	}
}

func TestApplyRecoversOnFourGoodOfFive(t *testing.T) {
	policy := DefaultPolicy()
	state := State{
		Status: StatusDegraded, BaselineTTFB: 200 * time.Millisecond,
		BaselineThroughputMbps: 20, BaselineSamples: 5,
	}
	recent := []Sample{{Valid: true, Bad: true}, {Valid: true}, {Valid: true}, {Valid: true}}
	decision := Apply(policy, state, recent, nil, Observation{
		At: time.Unix(1_800_000_001, 0), Success: true,
		TTFB: 180 * time.Millisecond, ThroughputMbps: 22, Bytes: 65536,
	})
	if decision.State.Status != StatusHealthy || decision.Transition.To != StatusHealthy {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestApplyPreservesDegradationReasonUntilRecovery(t *testing.T) {
	policy := DefaultPolicy()
	policy.WindowSize = 3
	policy.BadSamples = 2
	policy.RecoveryGoodSamples = 3
	state := State{
		Status: StatusDegraded, LastReason: ReasonApplicationGates,
		BaselineTTFB: 200 * time.Millisecond, BaselineThroughputMbps: 20, BaselineSamples: 5,
	}
	decision := Apply(policy, state, []Sample{
		{Valid: true, Bad: true, Reason: ReasonApplicationGates},
		{Valid: true, Bad: true, Reason: ReasonApplicationGates},
	}, nil, Observation{
		At: time.Unix(1_800_000_001, 0), Success: true,
		TTFB: 180 * time.Millisecond, ThroughputMbps: 22, Bytes: 65536,
	})
	if decision.State.Status != StatusDegraded || decision.State.LastReason != ReasonApplicationGates {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestApplyIgnoresInfrastructureObservation(t *testing.T) {
	state := State{Status: StatusHealthy, BaselineSamples: 5}
	decision := Apply(DefaultPolicy(), state, []Sample{{Valid: true}}, nil, Observation{
		At:             time.Unix(1_800_000_002, 0),
		Infrastructure: true,
		ErrorCode:      "qoe_endpoint_unavailable",
	})
	if decision.Sample != nil || decision.State != state || decision.Transition.Changed() {
		t.Fatalf("infrastructure result mutated state: %+v", decision)
	}
}

func TestApplyLearnsMedianFromFiveSuccesses(t *testing.T) {
	learning := []Sample{
		{Valid: true, Success: true, TTFB: 500 * time.Millisecond, ThroughputMbps: 50},
		{Valid: true, Success: true, TTFB: 100 * time.Millisecond, ThroughputMbps: 10},
		{Valid: true, Success: true, TTFB: 400 * time.Millisecond, ThroughputMbps: 40},
		{Valid: true, Success: true, TTFB: 200 * time.Millisecond, ThroughputMbps: 20},
	}
	decision := Apply(DefaultPolicy(), State{Status: StatusLearning}, learning, learning, Observation{
		At:             time.Unix(1_800_000_003, 0),
		Success:        true,
		TTFB:           300 * time.Millisecond,
		Bytes:          65536,
		ThroughputMbps: 30,
	})
	if decision.State.Status != StatusHealthy {
		t.Fatalf("status=%s", decision.State.Status)
	}
	if decision.State.BaselineTTFB != 300*time.Millisecond ||
		decision.State.BaselineThroughputMbps != 30 || decision.State.BaselineSamples != 5 {
		t.Fatalf("state=%+v", decision.State)
	}
}

func TestApplyUsesInitialSevereThresholds(t *testing.T) {
	tests := []struct {
		name       string
		ttfb       time.Duration
		throughput float64
		wantBad    bool
	}{
		{name: "ttfb above limit", ttfb: 3*time.Second + time.Nanosecond, throughput: 1, wantBad: true},
		{name: "ttfb at limit", ttfb: 3 * time.Second, throughput: 1},
		{name: "throughput below limit", ttfb: time.Second, throughput: 0.255, wantBad: true},
		{name: "throughput at limit", ttfb: time.Second, throughput: 0.256},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Apply(DefaultPolicy(), State{Status: StatusLearning}, nil, nil, Observation{
				At:             time.Unix(1_800_000_004, 0),
				Success:        true,
				TTFB:           test.ttfb,
				Bytes:          65536,
				ThroughputMbps: test.throughput,
			})
			if decision.Sample == nil || decision.Sample.Bad != test.wantBad {
				t.Fatalf("sample=%+v want bad=%t", decision.Sample, test.wantBad)
			}
		})
	}
}

func TestApplyUsesRelativeThresholds(t *testing.T) {
	state := State{
		Status: StatusHealthy, BaselineTTFB: time.Second,
		BaselineThroughputMbps: 20, BaselineSamples: 5,
	}
	tests := []struct {
		name       string
		ttfb       time.Duration
		throughput float64
		wantBad    bool
	}{
		{name: "floor alone is insufficient", ttfb: 2 * time.Second, throughput: 20},
		{name: "ttfb exceeds floor and relative limit", ttfb: 2500*time.Millisecond + time.Nanosecond, throughput: 20, wantBad: true},
		{name: "throughput below ratio", ttfb: time.Second, throughput: 6.9, wantBad: true},
		{name: "throughput at ratio", ttfb: time.Second, throughput: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Apply(DefaultPolicy(), state, nil, nil, Observation{
				At:             time.Unix(1_800_000_005, 0),
				Success:        true,
				TTFB:           test.ttfb,
				Bytes:          65536,
				ThroughputMbps: test.throughput,
			})
			if decision.Sample == nil || decision.Sample.Bad != test.wantBad {
				t.Fatalf("sample=%+v want bad=%t", decision.Sample, test.wantBad)
			}
		})
	}
}

func TestApplyUpdatesHealthyBaselineWithPointOneEWMA(t *testing.T) {
	state := State{
		Status: StatusHealthy, BaselineTTFB: 200 * time.Millisecond,
		BaselineThroughputMbps: 20, BaselineSamples: 5,
	}
	decision := Apply(DefaultPolicy(), state, nil, nil, Observation{
		At:             time.Unix(1_800_000_006, 0),
		Success:        true,
		TTFB:           300 * time.Millisecond,
		Bytes:          65536,
		ThroughputMbps: 30,
	})
	if decision.State.BaselineTTFB != 210*time.Millisecond ||
		decision.State.BaselineThroughputMbps != 21 {
		t.Fatalf("state=%+v", decision.State)
	}
}

func TestEffectiveTimeUsesDeadlineForCandidateFailure(t *testing.T) {
	policy := DefaultPolicy()
	decision := Apply(policy, State{Status: StatusHealthy, BaselineSamples: 5}, nil, nil, Observation{
		At:        time.Unix(1_800_000_007, 0),
		ErrorCode: "qoe_candidate_timeout",
	})
	if decision.Sample == nil || decision.Sample.EffectiveTime != policy.Deadline {
		t.Fatalf("sample=%+v", decision.Sample)
	}

	const throughput = 8
	want := 100*time.Millisecond + 65536*8*time.Second/(throughput*1_000_000)
	if got := EffectiveTime(100*time.Millisecond, throughput, 65536); got != want {
		t.Fatalf("EffectiveTime()=%s want %s", got, want)
	}
}

func TestApplyBoundsErrorCodeToASCII(t *testing.T) {
	decision := Apply(DefaultPolicy(), State{Status: StatusLearning}, nil, nil, Observation{
		At:        time.Unix(1_800_000_008, 0),
		ErrorCode: "qoe candidate/timeout\nсекрет-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
	})
	if decision.Sample == nil {
		t.Fatal("missing candidate failure sample")
	}
	if len(decision.Sample.Reason) > 64 {
		t.Fatalf("reason length=%d reason=%q", len(decision.Sample.Reason), decision.Sample.Reason)
	}
	for _, character := range []byte(decision.Sample.Reason) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.') {
			t.Fatalf("unsafe reason byte %q in %q", character, decision.Sample.Reason)
		}
	}
}

func TestAvailabilityFailureSeparatesOutageFromQualityDegradation(t *testing.T) {
	for _, reason := range []string{
		ReasonApplicationGates,
		ReasonDNSRoute,
		ReasonRouteTimeout,
		ReasonRouteTLS,
		ReasonRouteTransport,
	} {
		if !AvailabilityFailure(reason) {
			t.Fatalf("reason %q was not classified as availability failure", reason)
		}
	}
	for _, reason := range []string{"", "qoe_ttfb", "qoe_throughput"} {
		if AvailabilityFailure(reason) {
			t.Fatalf("quality reason %q was classified as availability failure", reason)
		}
	}
}

func TestApplyDegradesOnSeparatedAvailabilityFailures(t *testing.T) {
	policy := DefaultPolicy()
	policy.WindowSize = 3
	policy.BadSamples = 2
	policy.RecoveryGoodSamples = 3
	policy.AvailabilityWindow = 6
	policy.AvailabilityFailures = 2
	state := State{
		Status: StatusHealthy, BaselineTTFB: 200 * time.Millisecond,
		BaselineThroughputMbps: 20, BaselineSamples: 3,
	}
	recent := []Sample{
		{Valid: true, Bad: true, Reason: ReasonRouteTimeout},
		{Valid: true, Success: true},
		{Valid: true, Success: true},
		{Valid: true, Success: true},
		{Valid: true, Bad: true, Reason: ReasonRouteTLS},
	}
	decision := Apply(policy, state, recent, nil, Observation{
		At: time.Unix(1_800_000_100, 0), Success: true,
		TTFB: 180 * time.Millisecond, ThroughputMbps: 22, Bytes: 65536,
	})
	if decision.State.Status != StatusDegraded ||
		decision.State.LastReason != ReasonRouteTLS {
		t.Fatalf("decision=%+v", decision)
	}
	if decision.State.WindowBad != 1 {
		t.Fatalf("short performance window was replaced: %+v", decision.State)
	}
}

func TestApplyRequiresTwoConfirmedDNSRouteFailures(t *testing.T) {
	policy := DefaultPolicy()
	state := State{
		Status: StatusHealthy, BaselineTTFB: 200 * time.Millisecond,
		BaselineThroughputMbps: 20, BaselineSamples: policy.WindowSize,
	}
	firstAt := time.Unix(1_800_000_100, 0)
	first := Apply(policy, state, nil, nil, Observation{
		At: firstAt, ErrorCode: ReasonDNSRoute,
	})
	if first.State.Status != StatusHealthy {
		t.Fatalf("one DNS failure degraded route: %+v", first)
	}
	decision := Apply(policy, first.State, []Sample{{
		At: firstAt, Valid: true, Bad: true, Reason: ReasonDNSRoute,
	}}, nil, Observation{
		At: firstAt.Add(time.Second), ErrorCode: ReasonDNSRoute,
	})
	if decision.State.Status != StatusDegraded ||
		decision.State.LastReason != ReasonDNSRoute {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestApplyKeepsAvailabilityIncidentDegradedUntilLongWindowClears(t *testing.T) {
	policy := DefaultPolicy()
	policy.WindowSize = 3
	policy.BadSamples = 2
	policy.RecoveryGoodSamples = 3
	policy.AvailabilityWindow = 6
	policy.AvailabilityFailures = 2
	state := State{
		Status: StatusDegraded, LastReason: ReasonRouteTimeout,
		BaselineTTFB: 200 * time.Millisecond, BaselineThroughputMbps: 20,
		BaselineSamples: 3,
	}
	good := Sample{Valid: true, Success: true}
	bad := Sample{Valid: true, Bad: true, Reason: ReasonRouteTimeout}
	blocked := Apply(policy, state, []Sample{bad, good, good, bad, good}, nil,
		Observation{At: time.Unix(1_800_000_101, 0), Success: true,
			TTFB: 180 * time.Millisecond, ThroughputMbps: 22, Bytes: 65536})
	if blocked.State.Status != StatusDegraded {
		t.Fatalf("availability incident recovered early: %+v", blocked)
	}
	recovered := Apply(policy, state, []Sample{bad, good, good, good, good}, nil,
		Observation{At: time.Unix(1_800_000_102, 0), Success: true,
			TTFB: 180 * time.Millisecond, ThroughputMbps: 22, Bytes: 65536})
	if recovered.State.Status != StatusHealthy {
		t.Fatalf("cleared availability incident did not recover: %+v", recovered)
	}
}
