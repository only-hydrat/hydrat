package controller

import (
	"container/heap"
	"sync"
)

type PlacementReason string

const (
	PlacementHardFailure          PlacementReason = "hard_failure"
	PlacementQoEDegraded          PlacementReason = "qoe_degraded"
	PlacementManual               PlacementReason = "manual_reassign"
	PlacementClientLifecycle      PlacementReason = "client_lifecycle"
	PlacementPromotion            PlacementReason = "pool_promotion"
	PlacementStartupNormalization PlacementReason = "startup_normalization"
	PlacementPeriodic             PlacementReason = "periodic"
)

func placementPriority(reason PlacementReason) int {
	switch reason {
	case PlacementHardFailure:
		return 0
	case PlacementQoEDegraded:
		return 1
	case PlacementManual:
		return 2
	case PlacementClientLifecycle:
		return 3
	case PlacementPromotion:
		return 4
	default:
		return 5
	}
}

type placementHeap []PlacementReason

func (items placementHeap) Len() int { return len(items) }
func (items placementHeap) Less(left, right int) bool {
	leftPriority := placementPriority(items[left])
	rightPriority := placementPriority(items[right])
	if leftPriority == rightPriority {
		return items[left] < items[right]
	}
	return leftPriority < rightPriority
}
func (items placementHeap) Swap(left, right int) {
	items[left], items[right] = items[right], items[left]
}
func (items *placementHeap) Push(value any) { *items = append(*items, value.(PlacementReason)) }
func (items *placementHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	*items = old[:len(old)-1]
	return last
}

type PlacementQueue struct {
	mu      sync.Mutex
	items   placementHeap
	pending map[PlacementReason]bool
}

func NewPlacementQueue() *PlacementQueue {
	queue := &PlacementQueue{pending: make(map[PlacementReason]bool)}
	heap.Init(&queue.items)
	return queue
}

func (queue *PlacementQueue) Enqueue(reason PlacementReason) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.pending[reason] {
		return
	}
	queue.pending[reason] = true
	heap.Push(&queue.items, reason)
}

func (queue *PlacementQueue) Pop() (PlacementReason, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.items.Len() == 0 {
		return "", false
	}
	reason := heap.Pop(&queue.items).(PlacementReason)
	delete(queue.pending, reason)
	return reason, true
}

func (queue *PlacementQueue) Take(reason PlacementReason) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if !queue.pending[reason] {
		return false
	}
	for index, item := range queue.items {
		if item != reason {
			continue
		}
		heap.Remove(&queue.items, index)
		delete(queue.pending, reason)
		return true
	}
	return false
}

func (queue *PlacementQueue) Len() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.items.Len()
}
