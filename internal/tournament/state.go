package tournament

import "time"

type Status string

const (
	StatusUnknown   Status = "unknown"
	StatusPreflight Status = "preflight"
	StatusProbing   Status = "probing"
	StatusQualified Status = "qualified"
	StatusBanned    Status = "banned"
	StatusDraining  Status = "draining"
)

type ProbeStage string

const (
	ProbeFast ProbeStage = "fast"
	ProbeFull ProbeStage = "full"
)

type ProbeOutcome string

const (
	ProbeSuccess               ProbeOutcome = "success"
	ProbeCandidateFailure      ProbeOutcome = "candidate_failure"
	ProbeInfrastructureFailure ProbeOutcome = "infrastructure_failure"
)

type ProbeResult struct {
	Stage        ProbeStage
	Outcome      ProbeOutcome
	Score        float64
	ErrorCode    string
	ErrorMessage string
}

type State struct {
	Fingerprint       string
	Status            Status
	FailureStreak     int
	FullSuccessStreak int
	WindowStartedAt   time.Time
	BannedUntil       time.Time
	LastFastProbeAt   time.Time
	LastFullProbeAt   time.Time
	LastSuccessAt     time.Time
	LastFailureAt     time.Time
	LastErrorCode     string
	LastErrorMessage  string
	LastScore         float64
	ConservativeScore float64
	Stale             bool
	UpdatedAt         time.Time
}

func ApplyProbe(state State, result ProbeResult, now time.Time, window time.Duration) State {
	state = ResetIfExpired(state, now, window)
	if result.Outcome == ProbeInfrastructureFailure {
		state.LastErrorCode = result.ErrorCode
		state.LastErrorMessage = result.ErrorMessage
		state.UpdatedAt = now
		return state
	}
	if state.WindowStartedAt.IsZero() {
		state.WindowStartedAt = now
	}

	if result.Outcome == ProbeCandidateFailure {
		if result.Stage == ProbeFast {
			state.LastFastProbeAt = now
		} else {
			state.LastFullProbeAt = now
		}
		state.FailureStreak++
		state.FullSuccessStreak = 0
		state.LastFailureAt = now
		state.LastErrorCode = result.ErrorCode
		state.LastErrorMessage = result.ErrorMessage
		state.Stale = true
		if state.FailureStreak >= 3 {
			state.Status = StatusBanned
			state.BannedUntil = state.WindowStartedAt.Add(window)
		} else {
			state.Status = StatusUnknown
		}
		state.UpdatedAt = now
		return state
	}

	state.LastSuccessAt = now
	state.LastErrorCode = ""
	state.LastErrorMessage = ""
	if result.Stage == ProbeFast {
		state.LastFastProbeAt = now
		state.Status = StatusPreflight
		state.UpdatedAt = now
		return state
	}

	previousScore := state.LastScore
	previousSuccesses := state.FullSuccessStreak
	state.FailureStreak = 0
	state.FullSuccessStreak++
	state.LastFullProbeAt = now
	state.LastScore = result.Score
	state.Stale = false
	if previousSuccesses > 0 {
		state.ConservativeScore = minimum(previousScore, result.Score)
	}
	if state.FullSuccessStreak >= 2 {
		state.Status = StatusQualified
	} else {
		state.Status = StatusPreflight
	}
	state.UpdatedAt = now
	return state
}

func ResetIfExpired(state State, now time.Time, window time.Duration) State {
	if window <= 0 || state.WindowStartedAt.IsZero() || now.Before(state.WindowStartedAt.Add(window)) {
		return state
	}
	state.Status = StatusUnknown
	state.FailureStreak = 0
	state.FullSuccessStreak = 0
	state.WindowStartedAt = now
	state.BannedUntil = time.Time{}
	state.Stale = true
	state.UpdatedAt = now
	return state
}

func minimum(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
