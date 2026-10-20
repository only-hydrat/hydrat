package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
)

func TestMissingReserveProofIsNotSearchBudgetExhaustion(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	selector := scheduler.New(scheduler.PolicyDefaults())
	candidates := []scheduler.Candidate{
		{ID: "p", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true, ActiveFresh: true},
		{ID: "r", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true, ActiveEligible: true},
	}
	clients := []scheduler.Client{{ID: "alice"}}
	result := scheduler.Result{Assignments: map[string]scheduler.Assignment{"alice": {TCP: "p", UDP: "p"}}}
	reserves := map[string]scheduler.ReserveSelection{"alice": {TCP: "r", UDP: "r"}}
	err := validateScheduledCriticalCapacity(ctx, selector, now, 16, clients, candidates, result, reserves)
	var coverage *ActiveCriticalCoveragePlanError
	if !errors.As(err, &coverage) {
		t.Fatalf("expected failed reserve validation, got %v", err)
	}
	if coverage.SearchExhausted || strings.Contains(err.Error(), "search exhausted") {
		t.Fatalf("proof wait mislabeled as exhausted search: %v", err)
	}
	if got := readinessReason(err); got != "reserve_not_ready" {
		t.Fatalf("readiness reason=%s", got)
	}
	if !retryActiveCriticalCoverage(err) {
		t.Fatal("proof wait stopped recovery retries")
	}
	if !strings.Contains(err.Error(), "alice:tcp:proof_not_fresh") {
		t.Fatalf("missing bounded proof-wait detail: %v", err)
	}
	candidates[1].ActiveFresh = true
	if err := validateScheduledCriticalCapacity(ctx, selector, now, 16, clients, candidates, result, reserves); err != nil {
		t.Fatalf("fresh proof did not restore ready: %v", err)
	}
	candidates[1].CircuitOpen = true
	err = validateScheduledCriticalCapacity(ctx, selector, now, 16, clients, candidates, result, reserves)
	if err == nil || !strings.Contains(err.Error(), "alice:tcp:not_admitted") || strings.Contains(err.Error(), "proof_not_fresh") {
		t.Fatalf("rejected reserve mislabeled as proof wait: %v", err)
	}
	delete(reserves, "alice")
	err = validateScheduledCriticalCapacity(ctx, selector, now, 16, clients, candidates, result, reserves)
	if err == nil || !strings.Contains(err.Error(), "alice:tcp:missing") {
		t.Fatalf("missing reserve mislabeled: %v", err)
	}
}

func TestActualCoverageBudgetStillRetriesAndReportsSearchBudget(t *testing.T) {
	err := newCriticalCoverageBudget(16).exhaustedError([]string{"alice:tcp:reserve"})
	if !retryActiveCriticalCoverage(err) {
		t.Fatal("actual search budget no longer retries")
	}
	if got := readinessReason(err); got != "search_budget" {
		t.Fatalf("readiness reason=%s", got)
	}
}

func TestReadinessReasonRejectsUnrecognizedCoverageCause(t *testing.T) {
	if got := readinessReason(&ActiveCriticalCoveragePlanError{Cause: "private-token"}); got != "active_critical_capacity" {
		t.Fatalf("unsafe reason=%q", got)
	}
}

func TestProspectiveValidationDoesNotRerankAnAdmissibleReserve(t *testing.T) {
	now := time.Unix(1900000000, 0)
	selector := scheduler.New(scheduler.PolicyDefaults())
	candidates := []scheduler.Candidate{
		{ID: "p", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true},
		{ID: "r", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true},
		{ID: "better", Protocol: scheduler.ProtocolVLESS, Score: 1000, TCPQualified: true, UDPQualified: true, ReserveEligible: true},
	}
	clients := []scheduler.Client{{ID: "alice"}, {ID: "bob"}}
	result := scheduler.Result{Assignments: map[string]scheduler.Assignment{
		"alice": {TCP: "p", UDP: "p"}, "bob": {TCP: "p", UDP: "p"},
	}}
	reserves := map[string]scheduler.ReserveSelection{
		"alice": {TCP: "r", UDP: "r"}, "bob": {TCP: "better", UDP: "better"},
	}
	if err := validateProspectiveScheduledCriticalCapacity(context.Background(), selector, now, 16, clients, candidates, result, reserves); err != nil {
		t.Fatalf("ranking revoked an admissible retained reserve: %v", err)
	}
}

func TestCanonicalProofWaitIsNotSearchExhaustionAndRetainsItsTargets(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1900000000, 0)
	selector := scheduler.New(scheduler.PolicyDefaults())
	engine := &Engine{activeCriticalRouteLimit: 2}
	defer resetCriticalCoverageSession(&engine.bootstrapCoverageMu, &engine.bootstrapCoverageSearch)
	candidates := []scheduler.Candidate{
		{ID: "p", RouteKey: "p", Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ActiveEligible: true, ActiveFresh: true, ReserveEligible: true},
		{ID: "r", RouteKey: "r", Score: 100, Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true},
		{ID: "s", RouteKey: "s", Score: 90, Protocol: scheduler.ProtocolVLESS, TCPQualified: true, UDPQualified: true, ReserveEligible: true},
	}
	clients := []scheduler.Client{{ID: "alice", PreserveTCP: true, PreserveUDP: true,
		Assignment:     scheduler.Assignment{TCP: "p", UDP: "p", TCPSince: now, UDPSince: now},
		AppliedReserve: scheduler.ReserveSelection{TCP: "r", UDP: "r"}}}
	for i := range 3 {
		_, err := engine.scheduleCandidatesForCycle(ctx, now.Add(time.Duration(i)*time.Second), selector, clients, candidates)
		var coverage *ActiveCriticalCoveragePlanError
		if !errors.As(err, &coverage) || coverage.SearchExhausted || coverage.Cause != coverageReserveNotReady || !retryActiveCriticalCoverage(err) {
			t.Fatalf("canonical proof wait mislabeled: %v", err)
		}
		targets, err := engine.cappedProspectiveScheduleCandidates(ctx, now, selector, clients, candidates)
		if err != nil || len(targets) != 2 || targets[0].ID != "p" || targets[1].ID != "r" {
			t.Fatalf("proof targets changed during ranking/proof churn: %+v %v", targets, err)
		}
		candidates[2].Score += 1000
		candidates[0].ActiveFresh = !candidates[0].ActiveFresh
	}
	candidates[1].ActiveEligible, candidates[1].ActiveFresh = true, true
	pool, err := engine.scheduleCandidatesForCycle(ctx, now.Add(3*time.Second), selector, clients, candidates)
	if err != nil {
		t.Fatalf("fresh reserve proof did not repair next cycle: %v", err)
	}
	result := selector.Schedule(now, clients, pool)
	reserve, err := selector.SelectReservesContext(ctx, now, "alice", result.Assignments["alice"], pool, clients[0].AppliedReserve)
	if err != nil || reserve.TCP != "r" || reserve.UDP != "r" || result.Assignments["alice"].TCP != "p" {
		t.Fatalf("repair changed primary or lost proved reserve: %+v %+v %v", result, reserve, err)
	}
	// A rejected target must not be kept merely because it was cached.
	candidates[1].CircuitOpen = true
	_, err = engine.scheduleCandidatesForCycle(ctx, now, selector, clients, candidates)
	if err == nil {
		t.Fatal("unproved replacement should not be ready")
	}
	cached, found, err := engine.cachedBootstrapCoverageCandidates(now, selector, clients, candidates)
	if err != nil || !found {
		t.Fatalf("replacement proof cover was not retained: %v", err)
	}
	for _, target := range cached {
		if target.ID == "r" {
			t.Fatal("placement kept waiting for a failed cached reserve")
		}
	}
	targets, err := engine.cappedProspectiveScheduleCandidates(ctx, now, selector, clients, candidates)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.ID == "r" {
			t.Fatal("failed reserve survived proof-target admission")
		}
	}
}
