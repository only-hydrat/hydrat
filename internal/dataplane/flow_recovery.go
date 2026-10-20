package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

// FlowRecovery is emitted only for a confirmed failure with an applied TCP
// replacement. It is not a request to reset all connections of a client.
type FlowRecovery struct {
	ClientID            string `json:"client_id"`
	SourceCIDR          string `json:"source_cidr"`
	FailedOutbound      string `json:"failed_outbound"`
	ReplacementOutbound string `json:"replacement_outbound"`
}

type PendingFlowRecovery struct {
	Recovery FlowRecovery       `json:"recovery"`
	Snapshot *xrayflow.Snapshot `json:"snapshot,omitempty"`
}

type flowRecoveryAdapter interface {
	FlowSnapshot(context.Context) (xrayflow.Snapshot, error)
	ResetFlow(context.Context, xrayflow.ResetRequest) (int, error)
}

const flowRecoveryTimeout = 200 * time.Millisecond
const flowRecoveryBatch = 4
const maxPendingFlowRecoveries = 2048

func ValidateFlowRecoveries(plan DesiredPlan, recoveries []FlowRecovery) error {
	if len(recoveries) > len(plan.Clients) {
		return errors.New("too many flow recovery scopes")
	}
	seen := make(map[string]bool)
	for _, q := range recoveries {
		p, err := netip.ParsePrefix(q.SourceCIDR)
		if err != nil || !p.IsSingleIP() || !p.Addr().Is4() || p.String() != q.SourceCIDR {
			return errors.New("invalid flow recovery source")
		}
		if err := (xrayflow.ResetRequest{Outbound: q.FailedOutbound, Source: p.Addr().String(), Snapshot: xrayflow.Snapshot{Instance: "00000000000000000000000000000000"}}).Validate(); err != nil {
			return err
		}
		if seen[q.ClientID] || q.FailedOutbound == q.ReplacementOutbound {
			return errors.New("duplicate or unchanged flow recovery scope")
		}
		seen[q.ClientID] = true
		matched := false
		for _, route := range plan.Clients {
			if route.ClientID == q.ClientID && route.SourceCIDR == q.SourceCIDR && !route.BlockTCP && route.TCPOutbound != "" && route.TCPOutbound == q.ReplacementOutbound {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("flow recovery does not match replacement route")
		}
	}
	return nil
}

func validateFlowRecoveryTransition(previous DesiredPlan, recoveries []FlowRecovery) error {
	for _, q := range recoveries {
		matched := false
		for _, route := range previous.Clients {
			if route.ClientID == q.ClientID && route.SourceCIDR == q.SourceCIDR && !route.BlockTCP && route.TCPOutbound == q.FailedOutbound {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("flow recovery does not match previous serving route")
		}
	}
	return nil
}

func recoveryStillApplicable(plan DesiredPlan, q FlowRecovery) bool {
	for _, route := range plan.Clients {
		if route.ClientID == q.ClientID {
			return route.SourceCIDR == q.SourceCIDR && !route.BlockTCP && route.TCPOutbound != "" && route.TCPOutbound != q.FailedOutbound
		}
	}
	return false
}

func (r *Reconciler) prepareFlowRecoveriesLocked(ctx context.Context, plan DesiredPlan, recoveries []FlowRecovery, rehydrating bool) []PendingFlowRecovery {
	var pending []PendingFlowRecovery
	seen := make(map[string]bool)
	for _, job := range r.applied.PendingFlowRecoveries {
		if recoveryStillApplicable(plan, job.Recovery) {
			pending = append(pending, job)
			seen[job.Recovery.ClientID+"\x00"+job.Recovery.FailedOutbound] = true
		}
	}
	// Rehydration must not turn a persisted old intent into a fresh reset token.
	// Existing pending tokens either match the old core or safely return409.
	if rehydrating || plan.Generation <= r.applied.Generation {
		return pending
	}
	var snapshot *xrayflow.Snapshot
	if adapter, ok := r.adapter.(flowRecoveryAdapter); ok && len(recoveries) > 0 {
		probeCtx, cancel := context.WithTimeout(ctx, flowRecoveryTimeout)
		s, err := adapter.FlowSnapshot(probeCtx)
		cancel()
		if err == nil {
			snapshot = &s
		}
	}
	for _, q := range recoveries {
		key := q.ClientID + "\x00" + q.FailedOutbound
		if seen[key] {
			continue
		}
		if len(pending) >= maxPendingFlowRecoveries {
			log.Print("flow recovery not queued: bounded backlog full")
			continue
		}
		pending = append(pending, PendingFlowRecovery{Recovery: q, Snapshot: snapshot})
		seen[key] = true
	}
	return pending
}

// RetryFlowRecoveries never reasserts routing or weakens readiness. It is a
// bounded maintenance pass; a control outage must not undo a working failover.
func (r *Reconciler) RetryFlowRecoveries(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.runtimeReady || r.recoveryRequired.Load() {
		return ErrRuntimeRecovering
	}
	return r.retryFlowRecoveriesLocked(ctx)
}

func (r *Reconciler) retryFlowRecoveriesLocked(ctx context.Context) error {
	if len(r.applied.PendingFlowRecoveries) == 0 {
		return nil
	}
	adapter, ok := r.adapter.(flowRecoveryAdapter)
	if !ok {
		return errors.New("flow recovery control unavailable")
	}
	jobs := append([]PendingFlowRecovery(nil), r.applied.PendingFlowRecoveries...)
	var pending []PendingFlowRecovery
	for _, job := range jobs {
		if recoveryStillApplicable(r.applied.DesiredPlan, job.Recovery) {
			pending = append(pending, job)
		}
	}
	limit := min(flowRecoveryBatch, len(pending))
	var captured *xrayflow.Snapshot
	for i := 0; i < limit; i++ {
		if pending[i].Snapshot != nil {
			continue
		}
		if captured == nil {
			probeCtx, cancel := context.WithTimeout(ctx, flowRecoveryTimeout)
			s, err := adapter.FlowSnapshot(probeCtx)
			cancel()
			if err != nil {
				return errors.New("flow recovery snapshot unavailable")
			}
			captured = &s
		}
		pending[i].Snapshot = captured
	}
	// Persist the exact cut-off before the mutating RPC. Lost replies/restarts
	// may retry the token but must never recapture newer same-tag sessions.
	next := r.applied
	next.PendingFlowRecoveries = pending
	if err := writeAppliedPlan(r.statePath, next); err != nil {
		return err
	}
	r.applied = next
	var remaining []PendingFlowRecovery
	var failed []PendingFlowRecovery
	var firstError error
	for i, job := range pending {
		if i >= limit {
			remaining = append(remaining, job)
			continue
		}
		p, err := netip.ParsePrefix(job.Recovery.SourceCIDR)
		if err != nil || !p.IsSingleIP() || !p.Addr().Is4() {
			return errors.New("invalid persisted flow recovery source")
		}
		resetCtx, cancel := context.WithTimeout(ctx, flowRecoveryTimeout)
		closed, err := adapter.ResetFlow(resetCtx, xrayflow.ResetRequest{Snapshot: *job.Snapshot, Outbound: job.Recovery.FailedOutbound, Source: p.Addr().String()})
		cancel()
		if err != nil && !errors.Is(err, xrayflow.ErrStaleInstance) {
			failed = append(failed, job)
			if firstError == nil {
				firstError = errors.New("flow recovery reset pending")
			}
			continue
		}
		log.Printf("flow recovery client=%s closed=%d core_restarted=%t", job.Recovery.ClientID, closed, errors.Is(err, xrayflow.ErrStaleInstance))
	}
	remaining = append(remaining, failed...)
	next = r.applied
	next.PendingFlowRecoveries = remaining
	if err := writeAppliedPlan(r.statePath, next); err != nil {
		return fmt.Errorf("persist flow recovery completion: %w", err)
	}
	r.applied = next
	return firstError
}
