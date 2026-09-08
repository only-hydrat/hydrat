package probexray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

var ErrStaleEpoch = errors.New("stale probe Xray epoch")

const maxProbeSlots = 64

type SlotCandidate struct {
	Slot   int
	Config json.RawMessage
}

type Control struct {
	binary     string
	server     string
	slots      int
	runner     xrayapi.Runner
	gate       *priorityGate
	lastDigest [sha256.Size]byte
	hasDigest  bool
	configured map[int]json.RawMessage
	epoch      uint64
}

func New(binary, server string, slots int, runner xrayapi.Runner) *Control {
	if runner == nil {
		runner = xrayapi.ExecRunner{}
	}
	return &Control{
		binary: binary, server: server, slots: slots, runner: runner,
		gate: newPriorityGate(), configured: make(map[int]json.RawMessage),
	}
}

func (control *Control) Configure(ctx context.Context, candidates []SlotCandidate) error {
	return control.configureCurrentRange(ctx, 0, control.slots, candidates, false)
}

func (control *Control) Reset(epoch uint64) {
	control.gate.reset(func() {
		control.epoch = epoch
		control.lastDigest = [sha256.Size]byte{}
		control.hasDigest = false
		control.configured = make(map[int]json.RawMessage)
	})
}

type Range struct {
	control  *Control
	offset   int
	slots    int
	priority bool
}

func NewRange(control *Control, offset, slots int) *Range {
	return &Range{control: control, offset: offset, slots: slots}
}

func NewPriorityRange(control *Control, offset, slots int) *Range {
	return &Range{control: control, offset: offset, slots: slots, priority: true}
}

func (probeRange *Range) Configure(ctx context.Context, candidates []SlotCandidate) error {
	if probeRange == nil || probeRange.control == nil {
		return errors.New("probe control is required")
	}
	return probeRange.control.configureCurrentRange(ctx, probeRange.offset, probeRange.slots, candidates, probeRange.priority)
}

func (probeRange *Range) ConfigureEpoch(
	ctx context.Context,
	epoch uint64,
	candidates []SlotCandidate,
) error {
	if probeRange == nil || probeRange.control == nil {
		return errors.New("probe control is required")
	}
	return probeRange.control.configureRange(
		ctx, epoch, probeRange.offset, probeRange.slots, candidates, probeRange.priority,
	)
}

func (probeRange *Range) ClearEpoch(ctx context.Context, epoch uint64) error {
	return probeRange.ConfigureEpoch(ctx, epoch, nil)
}

func (control *Control) configureCurrentRange(
	ctx context.Context,
	offset, slots int,
	candidates []SlotCandidate,
	priority bool,
) error {
	if err := control.gate.acquire(ctx, priority); err != nil {
		return err
	}
	defer control.gate.release()
	return control.configureRangeLocked(ctx, control.epoch, offset, slots, candidates)
}

func (control *Control) configureRange(
	ctx context.Context,
	epoch uint64,
	offset, slots int,
	candidates []SlotCandidate,
	priority bool,
) error {
	if err := control.gate.acquire(ctx, priority); err != nil {
		return err
	}
	defer control.gate.release()
	return control.configureRangeLocked(ctx, epoch, offset, slots, candidates)
}

func (control *Control) configureRangeLocked(
	ctx context.Context,
	epoch uint64,
	offset, slots int,
	candidates []SlotCandidate,
) error {
	if err := control.checkMutation(ctx, epoch); err != nil {
		return err
	}
	if control.slots <= 0 || control.slots > maxProbeSlots {
		return errors.New("invalid probe slot count")
	}
	if offset < 0 || slots <= 0 || offset+slots > control.slots {
		return errors.New("invalid probe slot range")
	}
	sorted := append([]SlotCandidate(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slot < sorted[j].Slot })
	next := make(map[int]json.RawMessage, len(control.configured)+len(sorted))
	for slot, config := range control.configured {
		if slot < offset || slot >= offset+slots {
			next[slot] = append(json.RawMessage(nil), config...)
		}
	}
	seen := make(map[int]bool)
	for _, candidate := range sorted {
		if candidate.Slot < 0 || candidate.Slot >= slots || seen[candidate.Slot] {
			return fmt.Errorf("invalid or duplicate probe slot %d", candidate.Slot)
		}
		seen[candidate.Slot] = true
		globalSlot := offset + candidate.Slot
		next[globalSlot] = append(json.RawMessage(nil), candidate.Config...)
	}
	encodedCandidates, err := json.Marshal(next)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encodedCandidates)
	if control.hasDigest && digest == control.lastDigest {
		return nil
	}
	outbounds := make([]map[string]any, 0, len(sorted))
	rules := make([]map[string]any, 0, control.slots+2)
	rules = append(rules, map[string]any{
		"type": "field", "ruleTag": "probe-api", "inboundTag": []string{"api"}, "outboundTag": "api",
	})
	for slot := offset; slot < offset+slots; slot++ {
		tag := fmt.Sprintf("probe-outbound-%d", slot)
		if err := control.checkMutation(ctx, epoch); err != nil {
			return err
		}
		_ = control.runner.Run(ctx, "", control.binary, "api", "rmo", "--server="+control.server, tag)
		config, exists := next[slot]
		if !exists {
			continue
		}
		var outbound map[string]any
		if err := json.Unmarshal(config, &outbound); err != nil {
			return err
		}
		outbound["tag"] = tag
		outbounds = append(outbounds, outbound)
	}
	for slot := 0; slot < control.slots; slot++ {
		if _, exists := next[slot]; !exists {
			rules = append(rules, map[string]any{
				"type": "field", "ruleTag": fmt.Sprintf("probe-block-%d", slot),
				"inboundTag": []string{fmt.Sprintf("probe-slot-%d", slot)}, "outboundTag": "block",
			})
			continue
		}
		rules = append(rules, map[string]any{
			"type": "field", "ruleTag": fmt.Sprintf("probe-route-%d", slot),
			"inboundTag":  []string{fmt.Sprintf("probe-slot-%d", slot)},
			"outboundTag": fmt.Sprintf("probe-outbound-%d", slot),
		})
	}
	if len(outbounds) > 0 {
		body, _ := json.Marshal(map[string]any{"outbounds": outbounds})
		if err := control.checkMutation(ctx, epoch); err != nil {
			return err
		}
		if err := control.runner.Run(ctx, string(body), control.binary, "api", "ado", "--server="+control.server); err != nil {
			return err
		}
	}
	routingBody, _ := json.Marshal(map[string]any{"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}})
	if err := control.checkMutation(ctx, epoch); err != nil {
		return err
	}
	if err := control.runner.Run(ctx, string(routingBody), control.binary, "api", "adrules", "--server="+control.server); err != nil {
		return err
	}
	control.lastDigest = digest
	control.hasDigest = true
	control.configured = next
	return nil
}

func (control *Control) checkMutation(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if epoch != control.epoch {
		return ErrStaleEpoch
	}
	return nil
}

type priorityGate struct {
	mu              sync.Mutex
	held            bool
	resetQueue      []*gateWaiter
	priorityQueue   []*gateWaiter
	regularQueue    []*gateWaiter
	priorityWaiters int
	regularWaiters  int
}

type gateWaiter struct {
	ready   chan struct{}
	granted bool
}

func newPriorityGate() *priorityGate { return &priorityGate{} }

func (gate *priorityGate) acquire(ctx context.Context, priority bool) error {
	gate.mu.Lock()
	if err := ctx.Err(); err != nil {
		gate.mu.Unlock()
		return err
	}
	if !gate.held && gate.priorityWaiters == 0 {
		gate.held = true
		gate.mu.Unlock()
		return nil
	}
	waiter := &gateWaiter{ready: make(chan struct{})}
	if priority {
		gate.priorityWaiters++
		gate.priorityQueue = append(gate.priorityQueue, waiter)
	} else {
		gate.regularWaiters++
		gate.regularQueue = append(gate.regularQueue, waiter)
	}
	gate.mu.Unlock()

	select {
	case <-waiter.ready:
		return nil
	case <-ctx.Done():
		gate.mu.Lock()
		if waiter.granted {
			gate.grantNextLocked()
		} else if priority {
			gate.priorityQueue = removeWaiter(gate.priorityQueue, waiter)
			gate.priorityWaiters--
		} else {
			gate.regularQueue = removeWaiter(gate.regularQueue, waiter)
			gate.regularWaiters--
		}
		gate.mu.Unlock()
		return ctx.Err()
	}
}

func (gate *priorityGate) release() {
	gate.mu.Lock()
	gate.grantNextLocked()
	gate.mu.Unlock()
}

func (gate *priorityGate) reset(callback func()) {
	gate.mu.Lock()
	if !gate.held {
		gate.held = true
		gate.mu.Unlock()
		callback()
		gate.release()
		return
	}
	waiter := &gateWaiter{ready: make(chan struct{})}
	gate.resetQueue = append(gate.resetQueue, waiter)
	gate.priorityWaiters++
	gate.mu.Unlock()

	<-waiter.ready
	callback()
	gate.release()
}

func (gate *priorityGate) grantNextLocked() {
	var waiter *gateWaiter
	switch {
	case len(gate.resetQueue) > 0:
		waiter = gate.resetQueue[0]
		gate.resetQueue = gate.resetQueue[1:]
		gate.priorityWaiters--
	case len(gate.priorityQueue) > 0:
		waiter = gate.priorityQueue[0]
		gate.priorityQueue = gate.priorityQueue[1:]
		gate.priorityWaiters--
	case len(gate.regularQueue) > 0:
		waiter = gate.regularQueue[0]
		gate.regularQueue = gate.regularQueue[1:]
		gate.regularWaiters--
	default:
		gate.held = false
		return
	}
	waiter.granted = true
	close(waiter.ready)
}

func removeWaiter(queue []*gateWaiter, target *gateWaiter) []*gateWaiter {
	for index, waiter := range queue {
		if waiter == target {
			copy(queue[index:], queue[index+1:])
			return queue[:len(queue)-1]
		}
	}
	return queue
}
