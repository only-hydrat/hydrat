package probetimeout

import "time"

const (
	maxDuration            = time.Duration(1<<63 - 1)
	ProbeResponseSlack     = 5 * time.Second
	MaxProbeServerDeadline = maxDuration - ProbeResponseSlack
)

func RequestTimeout(serverDeadline time.Duration) time.Duration {
	if serverDeadline <= 0 {
		return ProbeResponseSlack
	}
	if serverDeadline > MaxProbeServerDeadline {
		return maxDuration
	}
	return serverDeadline + ProbeResponseSlack
}
