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
	}, QueuePolicy{Now: now, ResetWindow: 5 * time.Hour, PreferWorking: true})
	got := make([]string, 0, len(jobs))
	for _, job := range jobs {
		got = append(got, job.Fingerprint)
	}
	want := []string{"top", "one-success", "boundary", "unseen-a", "unseen-b", "expired", "other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestDiscoveryQueuePrioritizesAssignedAndOldestCheckedCandidates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	jobs := BuildDiscoveryQueue([]Candidate{
		{Fingerprint: "recent", LastFullProbeAt: now.Add(-time.Minute)},
		{Fingerprint: "old", LastFullProbeAt: now.Add(-time.Hour)},
		{Fingerprint: "assigned", Assigned: true, LastFullProbeAt: now.Add(-time.Minute)},
		{Fingerprint: "reserve", InWorkingPool: true, LastFullProbeAt: now.Add(-time.Minute)},
		{Fingerprint: "one-success", FullSuccessStreak: 1, LastFullProbeAt: now.Add(-time.Minute)},
	}, QueuePolicy{Now: now, ResetWindow: 5 * time.Hour, PreferWorking: true})
	got := make([]string, 0, len(jobs))
	for _, job := range jobs {
		got = append(got, job.Fingerprint)
	}
	want := []string{"assigned", "reserve", "one-success", "old", "recent"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("priority and fairness=%v want=%v", got, want)
	}
}

func TestDiscoveryQueueDefaultKeepsUnseenTorAheadOfWarmPool(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	jobs := BuildDiscoveryQueue([]Candidate{
		{Fingerprint: "warm", Status: StatusQualified, InWorkingPool: true,
			FullSuccessStreak: 2, LastFullProbeAt: now.Add(-time.Minute)},
		{Fingerprint: "new"},
	}, QueuePolicy{Now: now, ResetWindow: 5 * time.Hour})
	if len(jobs) != 2 || jobs[0].Fingerprint != "new" {
		t.Fatalf("Tor discovery starved: %+v", jobs)
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
