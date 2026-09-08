package tournament

import (
	"reflect"
	"testing"
	"time"
)

func TestDiscoveryQueueIsFairAndDeterministic(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	jobs := BuildDiscoveryQueue([]Candidate{
		{Fingerprint: "top", InWorkingPool: true, LastFullProbeAt: now.Add(-time.Hour)},
		{Fingerprint: "other", LastFullProbeAt: now.Add(-time.Hour)},
		{Fingerprint: "one-success", FullSuccessStreak: 1, LastFullProbeAt: now.Add(-time.Hour)},
		{Fingerprint: "boundary", Stale: true, NearBoundary: true, LastFullProbeAt: now.Add(-time.Hour)},
		{Fingerprint: "expired", Status: StatusBanned, WindowStartedAt: now.Add(-6 * time.Hour), BannedUntil: now.Add(-time.Hour), LastFullProbeAt: now.Add(-6 * time.Hour)},
		{Fingerprint: "unseen-b"},
		{Fingerprint: "unseen-a"},
		{Fingerprint: "still-banned", Status: StatusBanned, BannedUntil: now.Add(time.Hour)},
	}, QueuePolicy{Now: now, ResetWindow: 5 * time.Hour})
	got := make([]string, 0, len(jobs))
	for _, job := range jobs {
		got = append(got, job.Fingerprint)
	}
	want := []string{"unseen-a", "unseen-b", "expired", "boundary", "one-success", "other", "top"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestDiscoveryQueueCoalescesFingerprintAndStage(t *testing.T) {
	queue := NewQueue()
	queue.Push(Job{Fingerprint: "candidate", Stage: ProbeFull, Priority: PriorityOther})
	queue.Push(Job{Fingerprint: "candidate", Stage: ProbeFull, Priority: PriorityUnseen})
	queue.Push(Job{Fingerprint: "candidate", Stage: ProbeFast, Priority: PriorityUnseen})
	if queue.Len() != 2 {
		t.Fatalf("len=%d", queue.Len())
	}
	first, ok := queue.Pop()
	if !ok || first.Stage != ProbeFast && first.Stage != ProbeFull || first.Priority != PriorityUnseen {
		t.Fatalf("first=%+v ok=%v", first, ok)
	}
}
