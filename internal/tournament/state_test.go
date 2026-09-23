package tournament

import (
	"testing"
	"time"
)

func TestStateCandidateFailuresBanOnThirdAttempt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	state := State{Fingerprint: "candidate"}
	for attempt := 1; attempt <= 3; attempt++ {
		state = ApplyProbe(state, ProbeResult{
			Stage: ProbeFull, Outcome: ProbeCandidateFailure, ErrorCode: "timeout",
		}, now.Add(time.Duration(attempt-1)*time.Minute), 5*time.Hour)
		if state.FailureStreak != attempt {
			t.Fatalf("attempt %d state=%+v", attempt, state)
		}
	}
	if state.Status != StatusBanned || !state.BannedUntil.Equal(now.Add(5*time.Hour)) {
		t.Fatalf("state=%+v", state)
	}
}

func TestStateInfrastructureFailureDoesNotChangeStreak(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	before := State{
		Fingerprint: "candidate", FailureStreak: 2, FullSuccessStreak: 1,
		Status: StatusPreflight, WindowStartedAt: now,
	}
	after := ApplyProbe(before, ProbeResult{
		Stage: ProbeFull, Outcome: ProbeInfrastructureFailure, ErrorCode: "agent_unavailable",
	}, now.Add(time.Minute), 5*time.Hour)
	if after.FailureStreak != before.FailureStreak ||
		after.FullSuccessStreak != before.FullSuccessStreak ||
		after.Status != before.Status {
		t.Fatalf("before=%+v after=%+v", before, after)
	}
}

func TestStateRequiresTwoFullSuccessesAndUsesConservativeScore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	state := ApplyProbe(State{Fingerprint: "candidate", FailureStreak: 2}, ProbeResult{
		Stage: ProbeFast, Outcome: ProbeSuccess,
	}, now, 5*time.Hour)
	if state.FullSuccessStreak != 0 || state.Status != StatusPreflight || state.FailureStreak != 2 {
		t.Fatalf("fast success qualified candidate: %+v", state)
	}
	state = ApplyProbe(state, ProbeResult{Stage: ProbeFull, Outcome: ProbeSuccess, Score: 90}, now.Add(time.Minute), 5*time.Hour)
	if state.FullSuccessStreak != 1 || state.Status == StatusQualified || state.FailureStreak != 0 {
		t.Fatalf("first full success state=%+v", state)
	}
	state = ApplyProbe(state, ProbeResult{Stage: ProbeFull, Outcome: ProbeSuccess, Score: 80}, now.Add(2*time.Minute), 5*time.Hour)
	if state.FullSuccessStreak != 2 || state.Status != StatusQualified || state.ConservativeScore != 80 {
		t.Fatalf("second full success state=%+v", state)
	}
}

func TestStateFiveHourResetClearsBanAndStreaksButKeepsStaleScore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	state := State{
		Fingerprint: "candidate", Status: StatusBanned, FailureStreak: 3,
		FullSuccessStreak: 2, WindowStartedAt: now, BannedUntil: now.Add(5 * time.Hour),
		LastScore: 95, ConservativeScore: 91,
	}
	reset := ResetIfExpired(state, now.Add(5*time.Hour), 5*time.Hour)
	if reset.Status != StatusUnknown || reset.FailureStreak != 0 ||
		reset.FullSuccessStreak != 0 || !reset.BannedUntil.IsZero() ||
		reset.LastScore != 95 || reset.ConservativeScore != 91 || !reset.Stale {
		t.Fatalf("reset=%+v", reset)
	}
}

func TestQualifiedCandidateSurvivesExpiredWindowInfrastructureFailureAndSuccessfulRecheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	state := State{
		Fingerprint: "working", Status: StatusQualified, FullSuccessStreak: 2,
		WindowStartedAt: now, LastFullProbeAt: now, LastScore: 90,
		ConservativeScore: 80,
	}
	expired := now.Add(5 * time.Hour)
	state = ApplyProbe(state, ProbeResult{
		Stage: ProbeFast, Outcome: ProbeInfrastructureFailure,
		ErrorCode: "agent_unavailable",
	}, expired, 5*time.Hour)
	if state.Status != StatusQualified || state.FullSuccessStreak != 2 ||
		!state.WindowStartedAt.Equal(now) {
		t.Fatalf("infrastructure failure removed a verified route: %+v", state)
	}
	state = ApplyProbe(state, ProbeResult{
		Stage: ProbeFast, Outcome: ProbeSuccess,
	}, expired.Add(time.Minute), 5*time.Hour)
	if state.Status != StatusQualified || state.FullSuccessStreak < 2 ||
		!state.WindowStartedAt.Equal(expired.Add(time.Minute)) {
		t.Fatalf("successful fast recheck removed a verified route: %+v", state)
	}
	state = ApplyProbe(state, ProbeResult{
		Stage: ProbeFull, Outcome: ProbeSuccess, Score: 85,
	}, expired.Add(2*time.Minute), 5*time.Hour)
	if state.Status != StatusQualified || state.ConservativeScore != 85 {
		t.Fatalf("successful full recheck removed a verified route: %+v", state)
	}
	state = ApplyProbe(state, ProbeResult{
		Stage: ProbeFast, Outcome: ProbeCandidateFailure, ErrorCode: "liveness_failed",
	}, expired.Add(3*time.Minute), 5*time.Hour)
	if state.Status != StatusUnknown || state.FullSuccessStreak != 0 {
		t.Fatalf("real route failure remained qualified: %+v", state)
	}
}
