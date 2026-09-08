package controller

import (
	"testing"
	"time"
)

func TestHardFailureEventDeadlineIsDerivedFromProbeStart(t *testing.T) {
	started := time.Unix(1_900_000_000, 0)
	detected := started.Add(550 * time.Millisecond)
	event, err := NewHardFailureEvent(
		"candidate", started, detected, 1575*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := started.Add(1575 * time.Millisecond); !event.Deadline.Equal(want) {
		t.Fatalf("deadline=%s want=%s", event.Deadline, want)
	}
	if event.CandidateID != "candidate" || !event.ProbeStartedAt.Equal(started) ||
		!event.DetectedAt.Equal(detected) {
		t.Fatalf("event=%+v", event)
	}
}

func TestHardFailureMailboxPreservesEarliestDeadlineWhenCoalescing(t *testing.T) {
	mailbox := NewHardFailureMailbox()
	base := time.Unix(1_900_000_000, 0)
	for _, event := range []HardFailureEvent{
		{CandidateID: "late", Deadline: base.Add(3 * time.Second)},
		{CandidateID: "earliest", Deadline: base.Add(time.Second)},
		{CandidateID: "middle", Deadline: base.Add(2 * time.Second)},
	} {
		mailbox.Publish(event)
	}
	select {
	case <-mailbox.Wake():
	default:
		t.Fatal("coalesced hard failure did not wake consumer")
	}
	event, ok := mailbox.Pop()
	if !ok || event.CandidateID != "earliest" ||
		!event.Deadline.Equal(base.Add(time.Second)) {
		t.Fatalf("coalesced event=%+v ok=%v", event, ok)
	}
	if _, ok := mailbox.Pop(); ok {
		t.Fatal("mailbox retained duplicate coalesced events")
	}
}

func TestHardFailureMailboxKeepsOriginalDeadlineAcrossRetry(t *testing.T) {
	mailbox := NewHardFailureMailbox()
	deadline := time.Unix(1_900_000_000, 0).Add(time.Second)
	mailbox.Publish(HardFailureEvent{CandidateID: "candidate", Deadline: deadline})
	<-mailbox.Wake()
	event, ok := mailbox.Pop()
	if !ok {
		t.Fatal("hard failure event missing")
	}
	retry := event
	if !retry.Deadline.Equal(deadline) {
		t.Fatalf("retry deadline=%s want=%s", retry.Deadline, deadline)
	}
}
