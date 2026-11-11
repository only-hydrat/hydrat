package qoe

import "time"

// OnionPolicy applies the existing latency/availability state machine without
// a throughput download. Ordinary route policy and evidence remain unchanged.
func OnionPolicy() Policy {
	p := DefaultPolicy()
	p.WindowSize = 3
	p.BadSamples = 3
	p.RecoveryGoodSamples = 2
	p.AvailabilityWindow = 3
	p.AvailabilityFailures = 2
	p.InitialTTFBLimit = 5 * time.Second
	p.TTFBFloor = 5 * time.Second
	p.InitialThroughputMbps = 0
	p.ThroughputRatio = 0
	p.Deadline = 9 * time.Second
	return p
}

// OnionRank returns healthy, unknown, or degraded in increasing priority order.
// Expired evidence is unknown, allowing recovered bridges back into discovery.
func OnionRank(s State, now time.Time) (int, time.Duration) {
	if s.LastValidAt.IsZero() || s.LastValidAt.After(now) || now.Sub(s.LastValidAt) > EvidenceMaxAge {
		return 1, 0
	}
	if s.Status == StatusDegraded {
		return 2, s.MedianTTFB
	}
	if s.Status == StatusHealthy && s.WindowValid >= OnionPolicy().WindowSize {
		return 0, s.MedianTTFB
	}
	return 1, 0
}
