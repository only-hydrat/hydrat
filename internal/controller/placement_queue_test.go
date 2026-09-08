package controller

import "testing"

func TestPlacementQueueOrdersAllReasons(t *testing.T) {
	queue := NewPlacementQueue()
	for _, reason := range []PlacementReason{
		PlacementPeriodic, PlacementPromotion, PlacementClientLifecycle,
		PlacementManual, PlacementQoEDegraded, PlacementHardFailure,
	} {
		queue.Enqueue(reason)
	}
	want := []PlacementReason{
		PlacementHardFailure, PlacementQoEDegraded, PlacementManual, PlacementClientLifecycle,
		PlacementPromotion, PlacementPeriodic,
	}
	for _, expected := range want {
		got, ok := queue.Pop()
		if !ok || got != expected {
			t.Fatalf("got=%s ok=%v want=%s", got, ok, expected)
		}
	}
}
