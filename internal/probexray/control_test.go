package probexray

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestControlReconfiguresFourSlotsThroughOneXrayAPI(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 4, runner)
	batch := []SlotCandidate{
		{Slot: 0, Config: json.RawMessage(`{"protocol":"vless","settings":{}}`)},
		{Slot: 1, Config: json.RawMessage(`{"protocol":"vless","settings":{}}`)},
	}
	if err := control.Configure(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	commandCount := len(runner.commands)
	if err := control.Configure(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != commandCount {
		t.Fatalf("unchanged slot configuration called Xray API again: before=%d after=%d", commandCount, len(runner.commands))
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "api ado --server=127.0.0.1:10086") || !strings.Contains(joined, "api adrules --server=127.0.0.1:10086") || strings.Contains(joined, "restart") {
		t.Fatalf("commands=%s", joined)
	}
	if !strings.Contains(strings.Join(runner.stdin, "\n"), `"inboundTag":["probe-slot-0"]`) || !strings.Contains(strings.Join(runner.stdin, "\n"), `"tag":"probe-outbound-1"`) {
		t.Fatalf("configs=%v", runner.stdin)
	}
}

func TestResetInvalidatesDigestAndRejectsStaleEpoch(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 20, runner)
	control.Reset(1)
	slot := NewRange(control, 0, 1)
	candidate := []SlotCandidate{{Slot: 0, Config: json.RawMessage(`{"protocol":"freedom"}`)}}
	if err := slot.ConfigureEpoch(context.Background(), 1, candidate); err != nil {
		t.Fatal(err)
	}
	before := len(runner.commands)
	control.Reset(2)
	if err := slot.ConfigureEpoch(context.Background(), 2, candidate); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) <= before {
		t.Fatal("fresh Xray epoch reused the previous digest")
	}
	freshCommands := strings.Join(runner.commands[before:], "\n")
	if !strings.Contains(freshCommands, "api ado --server=127.0.0.1:10086") ||
		!strings.Contains(freshCommands, "api adrules --server=127.0.0.1:10086") {
		t.Fatalf("fresh Xray epoch commands=%s", freshCommands)
	}
	before = len(runner.commands)
	if err := slot.ClearEpoch(context.Background(), 1); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale clear error=%v", err)
	}
	if len(runner.commands) != before {
		t.Fatal("stale epoch mutated the new Xray process")
	}
}

func TestClearEpochRemovesOnlyItsRangeAndAddsBlockingRoute(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 20, runner)
	control.Reset(1)
	first := NewRange(control, 0, 1)
	second := NewRange(control, 1, 1)
	candidate := []SlotCandidate{{Slot: 0, Config: json.RawMessage(`{"protocol":"freedom"}`)}}
	if err := first.ConfigureEpoch(context.Background(), 1, candidate); err != nil {
		t.Fatal(err)
	}
	if err := second.ConfigureEpoch(context.Background(), 1, candidate); err != nil {
		t.Fatal(err)
	}

	before := len(runner.commands)
	if err := first.ClearEpoch(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands[before:], "\n")
	stdin := strings.Join(runner.stdin[before:], "\n")
	if !strings.Contains(commands, "api rmo --server=127.0.0.1:10086 probe-outbound-0") {
		t.Fatalf("clear commands=%s", commands)
	}
	if strings.Contains(commands, "probe-outbound-1") {
		t.Fatalf("clear crossed range boundary: %s", commands)
	}
	if !strings.Contains(stdin, `"ruleTag":"probe-block-0"`) ||
		!strings.Contains(stdin, `"ruleTag":"probe-route-1"`) {
		t.Fatalf("clear routing=%s", stdin)
	}
}

func TestResetFencesConfigureWaitingForGate(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 20, runner)
	control.Reset(1)
	if err := control.gate.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	configureDone := make(chan error, 1)
	go func() {
		configureDone <- NewPriorityRange(control, 0, 1).ConfigureEpoch(
			context.Background(),
			1,
			[]SlotCandidate{{Slot: 0, Config: json.RawMessage(`{"protocol":"freedom"}`)}},
		)
	}()
	waitForGateWaiters(t, control.gate, true, 1)

	resetDone := make(chan struct{})
	go func() {
		control.Reset(2)
		close(resetDone)
	}()
	waitForGateWaiters(t, control.gate, true, 2)
	control.gate.release()

	select {
	case <-resetDone:
	case <-time.After(time.Second):
		t.Fatal("reset did not acquire the gate")
	}
	select {
	case err := <-configureDone:
		if !errors.Is(err, ErrStaleEpoch) {
			t.Fatalf("queued configure error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued configure did not return")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("stale queued configure mutated Xray: %v", runner.commands)
	}
}

func TestCanceledConfigureEpochDoesNotMutateXray(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 20, runner)
	control.Reset(1)
	if err := control.gate.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewRange(control, 0, 1).ConfigureEpoch(ctx, 1, []SlotCandidate{{
			Slot: 0, Config: json.RawMessage(`{"protocol":"freedom"}`),
		}})
	}()
	waitForGateWaiters(t, control.gate, false, 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("configure error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled configure did not return")
	}
	control.gate.release()
	if len(runner.commands) != 0 {
		t.Fatalf("canceled configure mutated Xray: %v", runner.commands)
	}
}

func TestControlAcceptsSixtyFourSlotsAndRejectsSixtyFive(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 64, runner)
	if err := control.Configure(context.Background(), []SlotCandidate{{
		Slot: 63, Config: json.RawMessage(`{"protocol":"vless","settings":{}}`),
	}}); err != nil {
		t.Fatalf("64-slot control rejected slot 63: %v", err)
	}
	joined := strings.Join(runner.stdin, "\n")
	if !strings.Contains(joined, `"inboundTag":["probe-slot-63"]`) ||
		!strings.Contains(joined, `"tag":"probe-outbound-63"`) {
		t.Fatalf("slot 63 was not configured: %s", joined)
	}

	tooLarge := New("xray", "127.0.0.1:10086", 65, &controlRunner{})
	if err := tooLarge.Configure(context.Background(), nil); err == nil {
		t.Fatal("65-slot control was accepted")
	}
}

func TestIndependentRangesKeepOtherModeOutboundsConfigured(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 4, runner)
	active := NewRange(control, 2, 2)
	full := NewRange(control, 0, 2)
	if err := active.Configure(context.Background(), []SlotCandidate{{
		Slot: 0, Config: json.RawMessage(`{"protocol":"vless","settings":{"mode":"active"}}`),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := full.Configure(context.Background(), []SlotCandidate{{
		Slot: 0, Config: json.RawMessage(`{"protocol":"vless","settings":{"mode":"full"}}`),
	}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.stdin, "\n")
	if !strings.Contains(joined, `"inboundTag":["probe-slot-2"]`) ||
		!strings.Contains(joined, `"inboundTag":["probe-slot-0"]`) {
		t.Fatalf("range routing was lost: %s", joined)
	}
}

func TestPriorityGateLetsActiveProbeRunBeforeQueuedQualification(t *testing.T) {
	gate := newPriorityGate()
	if err := gate.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	order := make(chan string, 2)
	go func() {
		if err := gate.acquire(context.Background(), false); err != nil {
			order <- "qualification error"
			return
		}
		order <- "qualification"
		gate.release()
	}()
	waitForGateWaiters(t, gate, false, 1)
	go func() {
		if err := gate.acquire(context.Background(), true); err != nil {
			order <- "active error"
			return
		}
		order <- "active"
		gate.release()
	}()
	waitForGateWaiters(t, gate, true, 1)

	gate.release()
	select {
	case got := <-order:
		if got != "active" {
			t.Fatalf("first waiter = %q, want active", got)
		}
	case <-time.After(time.Second):
		t.Fatal("priority gate did not release a waiter")
	}
}

func TestPriorityGateCanceledActiveWaiterDoesNotBlockQualification(t *testing.T) {
	gate := newPriorityGate()
	if err := gate.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	activeDone := make(chan error, 1)
	go func() { activeDone <- gate.acquire(ctx, true) }()
	waitForGateWaiters(t, gate, true, 1)
	cancel()
	select {
	case err := <-activeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active acquire error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled active waiter did not return")
	}
	waitForGateWaiters(t, gate, true, 0)

	qualification := make(chan error, 1)
	go func() { qualification <- gate.acquire(context.Background(), false) }()
	waitForGateWaiters(t, gate, false, 1)
	gate.release()
	select {
	case err := <-qualification:
		if err != nil {
			t.Fatal(err)
		}
		gate.release()
	case <-time.After(time.Second):
		t.Fatal("canceled active waiter blocked qualification")
	}
}

func TestCanceledPriorityRangeDoesNotMutateXray(t *testing.T) {
	runner := &controlRunner{}
	control := New("xray", "127.0.0.1:10086", 2, runner)
	if err := control.gate.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewPriorityRange(control, 1, 1).Configure(ctx, []SlotCandidate{{
			Slot: 0, Config: json.RawMessage(`{"protocol":"vless","settings":{}}`),
		}})
	}()
	waitForGateWaiters(t, control.gate, true, 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("configure error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled priority range did not return")
	}
	control.gate.release()

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.commands) != 0 {
		t.Fatalf("canceled range mutated Xray: %v", runner.commands)
	}
}

func waitForGateWaiters(t *testing.T, gate *priorityGate, priority bool, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gate.mu.Lock()
		got := gate.regularWaiters
		if priority {
			got = gate.priorityWaiters
		}
		gate.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiter count did not reach %d", want)
}

type controlRunner struct {
	mu       sync.Mutex
	commands []string
	stdin    []string
}

func (runner *controlRunner) Run(_ context.Context, stdin, name string, args ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.commands = append(runner.commands, strings.Join(append([]string{name}, args...), " "))
	runner.stdin = append(runner.stdin, stdin)
	return nil
}
