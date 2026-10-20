package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestHardFailoverUsesSpareComparableRoutesBeforeOverloadingMappedReserve(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	specs := []engineQoECandidateSpec{}
	for i, name := range []string{"a", "b", "c", "d"} {
		specs = append(specs, engineQoECandidateSpec{name: name, kind: sources.KindVLESS, score: 95 - float64(i), tcp: true, udp: true, failureDomain: name})
	}
	db, candidates := newEngineQoEFixture(t, now, specs)
	qualifyEngineReserveCandidates(t, db, now, candidates)
	for i := 0; i < 6; i++ {
		putEngineQoEClient(t, db, fmt.Sprint(i), fmt.Sprintf("10.44.0.%d/32", i+2), now, true, candidates["a"].ID, candidates["a"].ID)
	}
	engine := NewEngine(db, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute))
	if err := engine.CycleForReason(ctx, now, PlacementStartupNormalization); err != nil {
		t.Fatal(err)
	}
	reservation, err := db.ReserveCandidateObservation(ctx, candidates["a"], store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CommitCandidateActiveHardFailureObservation(ctx, candidates["a"], reservation, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := engine.CycleForReason(ctx, now.Add(time.Second), PlacementHardFailure); err != nil {
		t.Fatal(err)
	}
	assignments, _ := db.ListAssignments(ctx)
	counts := map[string]int{}
	for _, assignment := range assignments {
		counts[assignment.TCPOutbound]++
	}
	for id, count := range counts {
		if count > 2 || id == candidates["a"].ID {
			t.Fatalf("hard failover concentrated clients: %v", counts)
		}
	}
}
