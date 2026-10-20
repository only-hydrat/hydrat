package controller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
)

type qoeAdmissionClock struct {
	interval time.Duration
	ticker   *manualRuntimeTicker
	ready    chan struct{}
	once     sync.Once
}

func (*qoeAdmissionClock) Now() time.Time { return time.Now() }
func (clock *qoeAdmissionClock) NewTicker(interval time.Duration) runtimeTicker {
	if interval == clock.interval {
		clock.once.Do(func() { close(clock.ready) })
		return clock.ticker
	}
	return realRuntimeClock{}.NewTicker(interval)
}

// Model successive admission ticks without advancing the measurement cadence.
func drainDueQoEProbes(t *testing.T, monitor *QoEMonitor, agent *recordingQoEAgent, now time.Time) {
	t.Helper()
	for i := 0; i < 32; i++ {
		before := len(agent.callIDs())
		if err := monitor.Run(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if len(agent.callIDs()) == before {
			return
		}
	}
	t.Fatal("due QoE work never drained")
}

func TestQoESweepIsBoundedAndReservesBackgroundCapacity(t *testing.T) {
	specs := make([]qoeCandidateSpec, 0, 10)
	for i := 0; i < 10; i++ {
		specs = append(specs, qoeCandidateSpec{name: fmt.Sprint(i), tcp: true, udp: true, score: 100 - float64(i)})
	}
	database, candidates := qoeMonitorStore(t, specs)
	now := time.Unix(1_900_000_000, 0)
	assigned := make(map[string]bool)
	for i := 0; i < 8; i++ {
		id := candidates[fmt.Sprint(i)].ID
		assigned[id] = true
		assignQoECandidate(t, database, id, now, true)
	}
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Workers: 4, Now: func() time.Time { return now }}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	ids := agent.callIDs()
	if len(ids) != 4 {
		t.Fatalf("sweep launched %d probes, want bounded batch of 4", len(ids))
	}
	critical, background := 0, 0
	for _, id := range ids {
		if assigned[id] {
			critical++
		} else {
			background++
		}
	}
	if critical != 3 || background != 1 {
		t.Fatalf("critical=%d background=%d, want 3:1", critical, background)
	}
}

func TestQoEWakeUsesOneSecondAdmissionNotMeasurementCadence(t *testing.T) {
	if got := QoEWakeInterval(30*time.Second, 5*time.Minute, time.Minute); got != time.Second {
		t.Fatalf("admission wake=%s, want 1s", got)
	}
}

func TestQoEMonitorFutureTimestampDoesNotPostponeChecks(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, udp: true, score: 90}})
	now := time.Unix(1_900_000_000, 0)
	candidate := candidates["route"]
	assignQoECandidate(t, database, candidate.ID, now, true)
	seedHealthyBaseline(t, database, candidate, now.Add(time.Hour))
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Workers: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(agent.callIDs()) != 1 {
		t.Fatal("future QoE timestamp suppressed a due check")
	}
}

func TestQoEMonitorPrioritizesAppliedReserveOverHigherScoredStandby(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	database, candidates := newEngineQoEFixture(t, now, []engineQoECandidateSpec{
		{name: "primary", kind: sources.KindVLESS, score: 100, tcp: true, udp: true, failureDomain: "a"},
		{name: "reserve", kind: sources.KindVLESS, score: 90, tcp: true, udp: true, failureDomain: "b"},
		{name: "spare", kind: sources.KindVLESS, score: 80, tcp: true, udp: true, failureDomain: "c"},
	})
	qualifyEngineReserveCandidates(t, database, now, candidates)
	putEngineQoEClient(t, database, "alice", "10.44.0.2/32", now, false, candidates["primary"].ID, candidates["primary"].ID)
	engine := NewEngine(database, &engineAgent{}, nil, scheduler.New(scheduler.PolicyDefaults()), []byte("test-secret"), WithQoEEnabled(false), WithActiveProbeInterval(time.Minute))
	if err := engine.Cycle(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, mappings, err := database.ListAppliedReserveMappings(context.Background())
	if err != nil || len(mappings) != 1 || mappings[0].TCPReserveCandidateID == "" {
		t.Fatalf("reserve mappings=%+v err=%v", mappings, err)
	}
	reserved := map[string]bool{mappings[0].TCPReserveCandidateID: true, mappings[0].UDPReserveCandidateID: true}
	for name, candidate := range candidates {
		at := now.Add(-31 * time.Second)
		if name == "primary" {
			at = now
		}
		seedHealthyBaseline(t, database, candidate, at)
		if name != "primary" && !reserved[candidate.ID] {
			row := candidateHealthByID(t, database, candidate.ID)
			row.Score = 100
			if err := database.SaveCandidateHealth(context.Background(), row); err != nil {
				t.Fatal(err)
			}
		}
	}
	agent := &recordingQoEAgent{now: now}
	monitor := &QoEMonitor{Store: database, Agent: agent, Workers: 1, StandbyCandidates: 1}
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if ids := agent.callIDs(); len(ids) != 1 || !reserved[ids[0]] {
		t.Fatalf("applied reserve starved: %v", ids)
	}
}
