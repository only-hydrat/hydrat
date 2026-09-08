package controller

import (
	"errors"
	"strings"
	"sync"
	"time"
)

type HardFailureEvent struct {
	CandidateID    string
	ProbeStartedAt time.Time
	DetectedAt     time.Time
	Deadline       time.Time
}

func NewHardFailureEvent(
	candidateID string,
	probeStartedAt time.Time,
	detectedAt time.Time,
	deadlineFromProbeStart time.Duration,
) (HardFailureEvent, error) {
	if strings.TrimSpace(candidateID) == "" {
		return HardFailureEvent{}, errors.New("hard failure candidate ID is required")
	}
	if probeStartedAt.IsZero() || detectedAt.IsZero() ||
		detectedAt.Before(probeStartedAt) {
		return HardFailureEvent{}, errors.New("hard failure probe timestamps are invalid")
	}
	if deadlineFromProbeStart <= 0 {
		return HardFailureEvent{}, errors.New("hard failure deadline budget is required")
	}
	deadline := probeStartedAt.Add(deadlineFromProbeStart)
	if !deadline.After(detectedAt) {
		return HardFailureEvent{}, errors.New("hard failure was detected after its deadline")
	}
	return HardFailureEvent{
		CandidateID: candidateID, ProbeStartedAt: probeStartedAt,
		DetectedAt: detectedAt, Deadline: deadline,
	}, nil
}

// HardFailureMailbox coalesces route failures because emergency placement
// scans every persisted hard-failed route. The earliest deadline is retained.
type HardFailureMailbox struct {
	mu      sync.Mutex
	pending *HardFailureEvent
	wake    chan struct{}
}

func NewHardFailureMailbox() *HardFailureMailbox {
	return &HardFailureMailbox{wake: make(chan struct{}, 1)}
}

func (mailbox *HardFailureMailbox) Publish(event HardFailureEvent) {
	if mailbox == nil || event.Deadline.IsZero() {
		return
	}
	mailbox.mu.Lock()
	if mailbox.pending == nil || event.Deadline.Before(mailbox.pending.Deadline) {
		copy := event
		mailbox.pending = &copy
	}
	mailbox.mu.Unlock()
	select {
	case mailbox.wake <- struct{}{}:
	default:
	}
}

func (mailbox *HardFailureMailbox) Wake() <-chan struct{} {
	if mailbox == nil {
		return nil
	}
	return mailbox.wake
}

func (mailbox *HardFailureMailbox) Pop() (HardFailureEvent, bool) {
	if mailbox == nil {
		return HardFailureEvent{}, false
	}
	mailbox.mu.Lock()
	defer mailbox.mu.Unlock()
	if mailbox.pending == nil {
		return HardFailureEvent{}, false
	}
	event := *mailbox.pending
	mailbox.pending = nil
	return event, true
}
