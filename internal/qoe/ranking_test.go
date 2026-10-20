package qoe

import (
	"math"
	"testing"
	"time"
)

func TestBalancedQualityUsesWindowMediansNotLatestOutlier(t *testing.T) {
	policy := DefaultPolicy()
	var state State
	var samples []Sample
	for i, speed := range []float64{8, 8, 8, 8, 100} {
		decision := Apply(policy, state, samples, samples, Observation{At: time.Unix(1800000000+int64(i), 0), Success: true, TTFB: 200 * time.Millisecond, ThroughputMbps: speed, Bytes: 262144})
		state = decision.State
		samples = append(samples, *decision.Sample)
	}
	if state.MedianTTFB != 200*time.Millisecond || state.MedianThroughputMbps != 8 {
		t.Fatalf("latest outlier changed ranking window: %+v", state)
	}
	if math.Abs(state.Quality()-math.Sqrt(8/0.2)) > 1e-9 {
		t.Fatalf("quality=%v", state.Quality())
	}
	fast := state
	fast.MedianThroughputMbps *= 4
	fast.MedianTTFB *= 4
	if fast.Quality() != state.Quality() {
		t.Fatal("speed and delay do not have equal weights")
	}
}
