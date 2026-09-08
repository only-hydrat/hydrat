package tournament

import (
	"container/heap"
	"sort"
	"time"
)

type Priority int

const (
	PriorityUnseen Priority = iota
	PriorityResetExpired
	PriorityBoundaryStale
	PriorityOneSuccess
	PriorityOther
	PriorityWorkingPool
)

type Job struct {
	Fingerprint string
	CandidateID string
	Stage       ProbeStage
	Priority    Priority
	Generation  int64
}

type QueuePolicy struct {
	Now         time.Time
	ResetWindow time.Duration
}

func BuildDiscoveryQueue(candidates []Candidate, policy QueuePolicy) []Job {
	jobs := make([]Job, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Status == StatusBanned && policy.Now.Before(candidate.BannedUntil) {
			continue
		}
		job := Job{Fingerprint: candidate.Fingerprint, Stage: ProbeFull, Priority: PriorityOther}
		switch {
		case candidate.LastFastProbeAt.IsZero() && candidate.LastFullProbeAt.IsZero():
			job.Priority = PriorityUnseen
			job.Stage = ProbeFast
		case !candidate.WindowStartedAt.IsZero() &&
			!policy.Now.Before(candidate.WindowStartedAt.Add(policy.ResetWindow)):
			job.Priority = PriorityResetExpired
			job.Stage = ProbeFast
		case candidate.Status == StatusUnknown && candidate.LastFullProbeAt.IsZero():
			job.Priority = PriorityOther
			job.Stage = ProbeFast
		case candidate.Stale && candidate.NearBoundary:
			job.Priority = PriorityBoundaryStale
		case candidate.FullSuccessStreak == 1:
			job.Priority = PriorityOneSuccess
		case candidate.InWorkingPool:
			job.Priority = PriorityWorkingPool
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(left, right int) bool {
		if jobs[left].Priority == jobs[right].Priority {
			return jobs[left].Fingerprint < jobs[right].Fingerprint
		}
		return jobs[left].Priority < jobs[right].Priority
	})
	return jobs
}

type queuedJob struct {
	job   Job
	index int
}

type jobHeap []*queuedJob

func (items jobHeap) Len() int { return len(items) }
func (items jobHeap) Less(left, right int) bool {
	if items[left].job.Priority == items[right].job.Priority {
		if items[left].job.Fingerprint == items[right].job.Fingerprint {
			return items[left].job.Stage < items[right].job.Stage
		}
		return items[left].job.Fingerprint < items[right].job.Fingerprint
	}
	return items[left].job.Priority < items[right].job.Priority
}
func (items jobHeap) Swap(left, right int) {
	items[left], items[right] = items[right], items[left]
	items[left].index = left
	items[right].index = right
}
func (items *jobHeap) Push(value any) {
	entry := value.(*queuedJob)
	entry.index = len(*items)
	*items = append(*items, entry)
}
func (items *jobHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	old[len(old)-1] = nil
	last.index = -1
	*items = old[:len(old)-1]
	return last
}

type Queue struct {
	items jobHeap
	byKey map[string]*queuedJob
}

func NewQueue() *Queue {
	queue := &Queue{byKey: make(map[string]*queuedJob)}
	heap.Init(&queue.items)
	return queue
}

func (queue *Queue) Len() int { return queue.items.Len() }

func (queue *Queue) Push(job Job) {
	key := queueKey(job)
	if current, ok := queue.byKey[key]; ok {
		if job.Priority < current.job.Priority {
			current.job.Priority = job.Priority
		}
		if job.Generation > current.job.Generation {
			current.job.Generation = job.Generation
		}
		heap.Fix(&queue.items, current.index)
		return
	}
	entry := &queuedJob{job: job}
	queue.byKey[key] = entry
	heap.Push(&queue.items, entry)
}

func (queue *Queue) Pop() (Job, bool) {
	if queue.items.Len() == 0 {
		return Job{}, false
	}
	entry := heap.Pop(&queue.items).(*queuedJob)
	delete(queue.byKey, queueKey(entry.job))
	return entry.job, true
}

func queueKey(job Job) string {
	return job.Fingerprint + "\x00" + string(job.Stage)
}
