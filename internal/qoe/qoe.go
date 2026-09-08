package qoe

import (
	"sort"
	"time"
)

type Status string

const (
	MaxWindowSize                    = 100
	MaxProbeWorkers                  = 4
	MinimumAlternativeSpeedup        = 1.3
	ReasonApplicationGates           = "qoe_application_gates"
	ReasonDNSRoute                   = "qoe_dns_route"
	ReasonRouteTimeout               = "qoe_route_timeout"
	ReasonRouteTLS                   = "qoe_route_tls"
	ReasonRouteTransport             = "qoe_route_transport"
	StatusLearning            Status = "learning"
	StatusHealthy             Status = "healthy"
	StatusDegraded            Status = "degraded"
)

type Policy struct {
	WindowSize            int
	BadSamples            int
	RecoveryGoodSamples   int
	AvailabilityWindow    int
	AvailabilityFailures  int
	SampleBytes           int64
	Deadline              time.Duration
	InitialTTFBLimit      time.Duration
	TTFBFloor             time.Duration
	TTFBMultiplier        float64
	InitialThroughputMbps float64
	ThroughputRatio       float64
	EWMAWeight            float64
}

type Observation struct {
	At               time.Time
	Success          bool
	Infrastructure   bool
	ErrorCode        string
	TTFB             time.Duration
	TransferDuration time.Duration
	Bytes            int64
	ThroughputMbps   float64
	// UDPReachable is set only when a real QUIC handshake was attempted.
	// It is intentionally independent from TCP QoE so one broken transport
	// cannot evacuate the other.
	UDPReachable *bool
}

type Sample struct {
	At               time.Time
	Valid            bool
	Success          bool
	Bad              bool
	Reason           string
	TTFB             time.Duration
	TransferDuration time.Duration
	Bytes            int64
	ThroughputMbps   float64
	EffectiveTime    time.Duration
}

type State struct {
	CandidateID            string
	Status                 Status
	BaselineTTFB           time.Duration
	BaselineThroughputMbps float64
	BaselineSamples        int
	CurrentTTFB            time.Duration
	CurrentThroughputMbps  float64
	WindowValid            int
	WindowBad              int
	WindowStartedAt        time.Time
	WindowMaxGap           time.Duration
	MedianEffectiveTime    time.Duration
	LastValidAt            time.Time
	LastReason             string
	DegradedAt             time.Time
	RecoveredAt            time.Time
	UpdatedAt              time.Time
}

type Transition struct {
	From Status
	To   Status
}

// AvailabilityFailure reports reasons that prove the assigned route cannot
// currently serve required client traffic. They trigger evacuation after the
// QoE window confirms degradation; performance-only reasons retain hysteresis.
func AvailabilityFailure(reason string) bool {
	switch reason {
	case ReasonApplicationGates,
		ReasonDNSRoute,
		ReasonRouteTimeout,
		ReasonRouteTLS,
		ReasonRouteTransport:
		return true
	default:
		return false
	}
}

func (transition Transition) Changed() bool { return transition.From != transition.To }

type Decision struct {
	State      State
	Sample     *Sample
	Transition Transition
}

func DefaultPolicy() Policy {
	return Policy{
		WindowSize:            5,
		BadSamples:            3,
		RecoveryGoodSamples:   4,
		AvailabilityWindow:    20,
		AvailabilityFailures:  2,
		SampleBytes:           65536,
		Deadline:              10 * time.Second,
		InitialTTFBLimit:      3 * time.Second,
		TTFBFloor:             1500 * time.Millisecond,
		TTFBMultiplier:        2.5,
		InitialThroughputMbps: 0.256,
		ThroughputRatio:       0.35,
		EWMAWeight:            0.1,
	}
}

func EffectiveTime(ttfb time.Duration, throughputMbps float64, bytes int64) time.Duration {
	if throughputMbps <= 0 || bytes <= 0 {
		return ttfb
	}
	transfer := float64(bytes*8) / (throughputMbps * 1_000_000) * float64(time.Second)
	return ttfb + time.Duration(transfer)
}

func Apply(policy Policy, current State, recent, learningSuccesses []Sample, observation Observation) Decision {
	if observation.Infrastructure {
		return Decision{
			State:      current,
			Transition: Transition{From: current.Status, To: current.Status},
		}
	}

	previousStatus := current.Status
	if previousStatus == "" {
		previousStatus = StatusLearning
		current.Status = StatusLearning
	}

	sample := sampleFromObservation(policy, current, observation)
	window := latestWindow(policy.WindowSize, recent, sample)
	availabilityWindow := latestWindow(policy.AvailabilityWindow, recent, sample)
	availabilityFailures := countAvailabilityFailures(availabilityWindow)
	availabilityDegraded := policy.AvailabilityFailures > 0 &&
		availabilityFailures >= policy.AvailabilityFailures
	current.WindowValid, current.WindowBad = windowCounts(window)
	current.WindowStartedAt = time.Time{}
	if len(window) > 0 {
		current.WindowStartedAt = window[0].At
	}
	current.WindowMaxGap = maxSampleGap(window)
	current.MedianEffectiveTime = medianEffectiveTime(window)
	current.CurrentTTFB = sample.TTFB
	current.CurrentThroughputMbps = sample.ThroughputMbps
	current.LastValidAt = sample.At
	current.UpdatedAt = sample.At

	nextStatus := previousStatus
	if current.WindowBad >= policy.BadSamples || availabilityDegraded {
		nextStatus = StatusDegraded
	} else if previousStatus == StatusDegraded &&
		current.WindowValid-current.WindowBad >= policy.RecoveryGoodSamples {
		if current.BaselineSamples >= policy.WindowSize {
			nextStatus = StatusHealthy
		} else {
			nextStatus = StatusLearning
		}
	}

	if previousStatus != StatusDegraded && nextStatus != StatusDegraded {
		if current.BaselineSamples < policy.WindowSize {
			learnBaseline(policy, &current, learningSuccesses, sample)
			if current.BaselineSamples >= policy.WindowSize {
				nextStatus = StatusHealthy
			}
		} else if sample.Success && !sample.Bad {
			current.BaselineTTFB = ewmaDuration(current.BaselineTTFB, sample.TTFB, policy.EWMAWeight)
			current.BaselineThroughputMbps = ewmaFloat(
				current.BaselineThroughputMbps,
				sample.ThroughputMbps,
				policy.EWMAWeight,
			)
		}
	}

	current.Status = nextStatus
	if nextStatus == StatusDegraded {
		reason := latestBadReason(window)
		if availabilityDegraded {
			reason = latestAvailabilityFailureReason(availabilityWindow)
		}
		if reason != "" {
			current.LastReason = reason
		}
	} else {
		current.LastReason = sample.Reason
	}
	if previousStatus != StatusDegraded && nextStatus == StatusDegraded {
		current.DegradedAt = observation.At
	}
	if previousStatus == StatusDegraded && nextStatus != StatusDegraded {
		current.RecoveredAt = observation.At
	}

	return Decision{
		State:      current,
		Sample:     sample,
		Transition: Transition{From: previousStatus, To: nextStatus},
	}
}

func countAvailabilityFailures(window []Sample) int {
	count := 0
	for _, sample := range window {
		if sample.Bad && AvailabilityFailure(sample.Reason) {
			count++
		}
	}
	return count
}

func latestAvailabilityFailureReason(window []Sample) string {
	for index := len(window) - 1; index >= 0; index-- {
		if window[index].Bad && AvailabilityFailure(window[index].Reason) {
			return window[index].Reason
		}
	}
	return ""
}

func latestBadReason(window []Sample) string {
	for index := len(window) - 1; index >= 0; index-- {
		if window[index].Bad && window[index].Reason != "" {
			return window[index].Reason
		}
	}
	return ""
}

func sampleFromObservation(policy Policy, state State, observation Observation) *Sample {
	sample := &Sample{
		At:               observation.At,
		Valid:            true,
		Success:          observation.Success,
		TTFB:             observation.TTFB,
		TransferDuration: observation.TransferDuration,
		Bytes:            observation.Bytes,
		ThroughputMbps:   observation.ThroughputMbps,
	}
	if !observation.Success {
		sample.Bad = true
		sample.Reason = safeReason(observation.ErrorCode)
		sample.EffectiveTime = policy.Deadline
		return sample
	}

	sample.EffectiveTime = EffectiveTime(sample.TTFB, sample.ThroughputMbps, sample.Bytes)
	if state.BaselineSamples < policy.WindowSize {
		switch {
		case sample.TTFB > policy.InitialTTFBLimit:
			sample.Bad = true
			sample.Reason = "qoe_ttfb"
		case sample.ThroughputMbps < policy.InitialThroughputMbps:
			sample.Bad = true
			sample.Reason = "qoe_throughput"
		}
		return sample
	}

	slowTTFB := sample.TTFB > policy.TTFBFloor &&
		float64(sample.TTFB) > float64(state.BaselineTTFB)*policy.TTFBMultiplier
	slowThroughput := sample.ThroughputMbps < state.BaselineThroughputMbps*policy.ThroughputRatio
	switch {
	case slowTTFB:
		sample.Bad = true
		sample.Reason = "qoe_ttfb"
	case slowThroughput:
		sample.Bad = true
		sample.Reason = "qoe_throughput"
	}
	return sample
}

func latestWindow(size int, recent []Sample, sample *Sample) []Sample {
	window := make([]Sample, 0, len(recent)+1)
	for _, candidate := range recent {
		if candidate.Valid {
			window = append(window, candidate)
		}
	}
	if sample.Valid {
		window = append(window, *sample)
	}
	if size <= 0 {
		return nil
	}
	if len(window) > size {
		window = window[len(window)-size:]
	}
	return window
}

func windowCounts(window []Sample) (valid, bad int) {
	valid = len(window)
	for _, sample := range window {
		if sample.Bad {
			bad++
		}
	}
	return valid, bad
}

func maxSampleGap(window []Sample) time.Duration {
	var maximum time.Duration
	for index := 1; index < len(window); index++ {
		gap := window[index].At.Sub(window[index-1].At)
		if gap < 0 {
			return time.Duration(1<<63 - 1)
		}
		if gap > maximum {
			maximum = gap
		}
	}
	return maximum
}

func learnBaseline(policy Policy, state *State, learningSuccesses []Sample, sample *Sample) {
	successes := make([]Sample, 0, len(learningSuccesses)+1)
	for _, candidate := range learningSuccesses {
		if candidate.Valid && candidate.Success {
			successes = append(successes, candidate)
		}
	}
	if sample.Valid && sample.Success {
		successes = append(successes, *sample)
	}
	if len(successes) > policy.WindowSize {
		successes = successes[:policy.WindowSize]
	}
	state.BaselineSamples = len(successes)
	if len(successes) != policy.WindowSize || policy.WindowSize == 0 {
		return
	}

	ttfb := make([]time.Duration, 0, len(successes))
	throughput := make([]float64, 0, len(successes))
	for _, success := range successes {
		ttfb = append(ttfb, success.TTFB)
		throughput = append(throughput, success.ThroughputMbps)
	}
	state.BaselineTTFB = medianDuration(ttfb)
	state.BaselineThroughputMbps = medianFloat(throughput)
}

func medianEffectiveTime(window []Sample) time.Duration {
	values := make([]time.Duration, 0, len(window))
	for _, sample := range window {
		values = append(values, sample.EffectiveTime)
	}
	return medianDuration(values)
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return sorted[middle-1]/2 + sorted[middle]/2
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

func ewmaDuration(previous, current time.Duration, weight float64) time.Duration {
	return time.Duration((1-weight)*float64(previous) + weight*float64(current))
}

func ewmaFloat(previous, current, weight float64) float64 {
	return (1-weight)*previous + weight*current
}

func safeReason(reason string) string {
	bounded := make([]byte, 0, 64)
	for _, character := range reason {
		var safe byte
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '_', character == '-', character == '.':
			safe = byte(character)
		default:
			safe = '_'
		}
		if len(bounded) == cap(bounded) {
			break
		}
		bounded = append(bounded, safe)
	}
	return string(bounded)
}
