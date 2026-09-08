package proberuntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type originArrivalAck struct {
	id       string
	endpoint string
	arrived  <-chan string
}

type originArrivalRegistry struct {
	mu         sync.Mutex
	next       uint64
	pending    map[string]*originArrivalEntry
	unexpected uint64
}

type originArrivalEntry struct {
	arrived   chan string
	delivered bool
}

func newOriginArrivalRegistry() *originArrivalRegistry {
	return &originArrivalRegistry{
		pending: make(map[string]*originArrivalEntry),
	}
}

func (registry *originArrivalRegistry) register(endpoint string) *originArrivalAck {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.next++
	id := fmt.Sprintf("%s-%d", endpoint, registry.next)
	arrived := make(chan string, 1)
	registry.pending[id] = &originArrivalEntry{arrived: arrived}
	return &originArrivalAck{id: id, endpoint: endpoint, arrived: arrived}
}

func (registry *originArrivalRegistry) signal(id, endpoint string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, exists := registry.pending[id]
	if !exists || entry.delivered {
		registry.unexpected++
		return false
	}
	entry.delivered = true
	entry.arrived <- endpoint
	return true
}

func (registry *originArrivalRegistry) retire(arrival *originArrivalAck) {
	if arrival == nil {
		return
	}
	registry.mu.Lock()
	delete(registry.pending, arrival.id)
	registry.mu.Unlock()
}

func (registry *originArrivalRegistry) counts() (pending, unexpected uint64) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return uint64(len(registry.pending)), registry.unexpected
}

var explicitHeldCancelCause = errors.New("explicit held probe cancellation")

func validateExplicitHeldCancellation(
	requestErr error,
	requestCtx context.Context,
) error {
	if !errors.Is(requestErr, explicitHeldCancelCause) ||
		context.Cause(requestCtx) != explicitHeldCancelCause ||
		requestCtx.Err() != context.Canceled {
		return fmt.Errorf(
			"request error=%v context_error=%v cause=%v, want private explicit cancellation",
			requestErr,
			requestCtx.Err(),
			context.Cause(requestCtx),
		)
	}
	return nil
}

func validateHeldRequestPending[T any](
	requestCtx context.Context,
	done <-chan T,
) error {
	if err := requestCtx.Err(); err != nil {
		return fmt.Errorf(
			"held request context ended before explicit cancellation: %w",
			err,
		)
	}
	select {
	case <-done:
		return errors.New("held request completed before explicit cancellation")
	default:
		return nil
	}
}

func TestOriginArrivalRegistryCorrelatesAndRetiresRequests(t *testing.T) {
	registry := newOriginArrivalRegistry()
	cancel := registry.register("/cancel")
	abort := registry.register("/abort")
	if cancel.id == abort.id {
		t.Fatalf("duplicate origin arrival ID %q", cancel.id)
	}

	if !registry.signal(abort.id, "/abort") {
		t.Fatal("abort arrival was not delivered")
	}
	select {
	case path := <-abort.arrived:
		if path != "/abort" {
			t.Fatalf("abort arrival path=%q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("abort arrival timed out")
	}
	select {
	case path := <-cancel.arrived:
		t.Fatalf("abort arrival crossed into cancel request: %q", path)
	default:
	}

	registry.retire(cancel)
	registry.retire(abort)
	if registry.signal(cancel.id, "/cancel") {
		t.Fatal("retired request accepted an origin arrival")
	}
	if pending, unexpected := registry.counts(); pending != 0 || unexpected != 1 {
		t.Fatalf("origin arrivals pending=%d unexpected=%d, want 0/1", pending, unexpected)
	}
}

func TestOriginArrivalRegistryDuplicateSignalIsBounded(t *testing.T) {
	registry := newOriginArrivalRegistry()
	arrival := registry.register("/abort")
	defer registry.retire(arrival)

	if !registry.signal(arrival.id, "/abort") {
		t.Fatal("first origin arrival was not delivered")
	}
	if registry.signal(arrival.id, "/abort") {
		t.Fatal("duplicate origin arrival blocked or was accepted")
	}
	select {
	case path := <-arrival.arrived:
		if path != "/abort" {
			t.Fatalf("origin arrival path=%q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("origin arrival timed out")
	}
}

func TestOriginArrivalRegistryHeldCancelsDoNotCrossRecycles(t *testing.T) {
	registry := newOriginArrivalRegistry()
	first := registry.register("/cancel")
	second := registry.register("/cancel")

	if !registry.signal(first.id, "/cancel") {
		t.Fatal("first held cancel arrival was not delivered")
	}
	if path := <-first.arrived; path != "/cancel" {
		t.Fatalf("first held cancel path=%q", path)
	}
	if registry.signal(first.id, "/cancel") {
		t.Fatal("duplicate first-recycle arrival was accepted after acknowledgement")
	}
	registry.retire(first)
	if registry.signal(first.id, "/cancel") {
		t.Fatal("late first-recycle arrival was accepted")
	}
	select {
	case path := <-second.arrived:
		t.Fatalf("late first-recycle arrival crossed into second recycle: %q", path)
	default:
	}
	if !registry.signal(second.id, "/cancel") {
		t.Fatal("second held cancel arrival was not delivered")
	}
	if path := <-second.arrived; path != "/cancel" {
		t.Fatalf("second held cancel path=%q", path)
	}
	registry.retire(second)

	if pending, unexpected := registry.counts(); pending != 0 || unexpected != 2 {
		t.Fatalf("origin arrivals pending=%d unexpected=%d, want 0/2", pending, unexpected)
	}
}

func TestValidateExplicitHeldCancellationRequiresPrivateCause(t *testing.T) {
	requestCtx, cancel := context.WithCancelCause(context.Background())
	cancel(explicitHeldCancelCause)
	requestErr := fmt.Errorf("HTTP request: %w", explicitHeldCancelCause)
	if err := validateExplicitHeldCancellation(requestErr, requestCtx); err != nil {
		t.Fatalf("valid explicit held cancellation rejected: %v", err)
	}

	t.Run("ancestor cancellation cannot satisfy", func(t *testing.T) {
		parent, cancelParent := context.WithCancel(context.Background())
		requestCtx, explicitCancel := context.WithCancelCause(parent)
		cancelParent()
		explicitCancel(explicitHeldCancelCause)
		if err := validateExplicitHeldCancellation(context.Canceled, requestCtx); err == nil {
			t.Fatal("ancestor cancellation satisfied explicit held cancellation")
		}
	})
	t.Run("request error must carry private cause", func(t *testing.T) {
		requestCtx, cancel := context.WithCancelCause(context.Background())
		cancel(explicitHeldCancelCause)
		if err := validateExplicitHeldCancellation(context.Canceled, requestCtx); err == nil {
			t.Fatal("generic request cancellation satisfied private cause")
		}
	})
}

func TestValidateHeldRequestPendingBeforeExplicitCancel(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	if err := validateHeldRequestPending(requestCtx, done); err != nil {
		t.Fatalf("live held request rejected: %v", err)
	}

	cancel()
	if err := validateHeldRequestPending(requestCtx, make(chan int, 1)); err == nil {
		t.Fatal("canceled held request accepted as pending")
	}

	liveCtx := context.Background()
	completed := make(chan int, 1)
	completed <- 1
	if err := validateHeldRequestPending(liveCtx, completed); err == nil {
		t.Fatal("completed held request accepted as pending")
	}
}

func TestIntentionalOriginAbortIsClassifiedAsEOF(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		_ *http.Request,
	) {
		connection, _, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack origin connection: %v", err)
			return
		}
		_ = connection.Close()
	}))
	defer origin.Close()

	response, err := origin.Client().Get(origin.URL)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("intentional abort error=%v, want EOF", err)
	}
}
