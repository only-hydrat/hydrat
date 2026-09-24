package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

const (
	activeCandidateQoEFreshness  = 2 * time.Minute
	standbyCandidateQoEFreshness = 10 * time.Minute
)

type Agent interface {
	Apply(context.Context, dataplane.DesiredPlan) error
	Activity(context.Context) ([]wireguard.PeerActivity, error)
}

type ProfileProvider interface {
	Profiles() []torpool.Profile
}

type planProfileProvider interface {
	ProfileProvider
	PlanProfiles() ([]torpool.Profile, uint64, bool)
	AcquirePlanCommit(uint64) (func(), bool)
}

type staticProfileProvider []torpool.Profile

func (profiles staticProfileProvider) Profiles() []torpool.Profile {
	return append([]torpool.Profile(nil), profiles...)
}

type planProfileFence struct {
	provider planProfileProvider
	version  uint64
	stable   bool
}

type EngineOption func(*Engine)

func WithQoEEnabled(enabled bool) EngineOption {
	return func(engine *Engine) {
		engine.qoeEnabled = enabled
	}
}

func WithRouting(directSuffixes, directDomains []string) EngineOption {
	return func(engine *Engine) {
		if len(directSuffixes) > 0 {
			engine.directSuffixes = append([]string(nil), directSuffixes...)
		}
		if len(directDomains) > 0 {
			engine.directDomains = append([]string(nil), directDomains...)
		}
	}
}

func (engine *Engine) Routing() ([]string, []string) {
	return append([]string(nil), engine.directSuffixes...), append([]string(nil), engine.directDomains...)
}

func (engine *Engine) SetRouting(directSuffixes, directDomains []string) {
	if directSuffixes != nil {
		engine.directSuffixes = append([]string(nil), directSuffixes...)
	}
	if directDomains != nil {
		engine.directDomains = append([]string(nil), directDomains...)
	}
}

func (engine *Engine) DisallowRUEgress() bool {
	return engine.disallowRUEgress
}

func (engine *Engine) SetDisallowRUEgress(disallow bool) {
	engine.disallowRUEgress = disallow
}

func WithDisallowRUEgress(disallow bool) EngineOption {
	return func(engine *Engine) {
		engine.disallowRUEgress = disallow
	}
}

// WithQoEPromotionEvidence defines the minimum recent QoE evidence required
// before a healthy standby may receive an optional quality-driven move.
func WithQoEPromotionEvidence(
	window int,
	latestFreshness time.Duration,
	windowFreshness time.Duration,
	maximumSampleGap time.Duration,
) EngineOption {
	return func(engine *Engine) {
		if window > 0 {
			engine.qoePromotionWindow = window
		}
		if latestFreshness > 0 {
			engine.qoePromotionFreshness = latestFreshness
		}
		if windowFreshness > 0 {
			engine.qoePromotionWindowFreshness = windowFreshness
		}
		if maximumSampleGap > 0 {
			engine.qoePromotionMaximumSampleGap = maximumSampleGap
		}
	}
}

func WithDNSResolver(resolver string) EngineOption {
	return func(engine *Engine) {
		engine.dnsResolvers = []string{resolver}
	}
}

func WithDNSResolvers(resolvers []string) EngineOption {
	return func(engine *Engine) {
		engine.dnsResolvers = append([]string(nil), resolvers...)
	}
}

func WithActiveProbeInterval(interval time.Duration) EngineOption {
	return func(engine *Engine) {
		const maxDuration = time.Duration(1<<63 - 1)
		if interval <= 0 || interval > maxDuration/2 {
			engine.reserveActiveFreshness = 0
			engine.activeHardFailureFreshness = 0
			return
		}
		engine.reserveActiveFreshness = 2 * interval
		engine.activeHardFailureFreshness = 2 * interval
	}
}

// WithActiveProofFreshness keeps a successful reserve proof usable across the
// complete pipelined detection, observation, and placement window. A newly
// observed failure still revokes the proof immediately.
func WithActiveProofFreshness(freshness time.Duration) EngineOption {
	return func(engine *Engine) {
		if freshness > 0 {
			engine.reserveActiveFreshness = freshness
		}
	}
}

func WithActiveFailureFreshness(freshness time.Duration) EngineOption {
	return func(engine *Engine) {
		if freshness > 0 {
			engine.activeHardFailureFreshness = freshness
		}
	}
}

func WithActiveCriticalRouteLimit(limit int) EngineOption {
	return func(engine *Engine) {
		if limit > 0 {
			engine.activeCriticalRouteLimit = limit
		}
	}
}

type ActiveCriticalRouteLimitError struct {
	Planned int
	Limit   int
}

func (err *ActiveCriticalRouteLimitError) Error() string {
	return fmt.Sprintf(
		"active critical candidate coverage %d exceeds configured capacity %d",
		err.Planned, err.Limit,
	)
}

func (err *ActiveCriticalRouteLimitError) Unwrap() error {
	return ErrActiveCriticalCoverageExceeded
}

type Engine struct {
	// cycleGate makes one Engine the controller's single-writer boundary across
	// activity collection, desired-plan persistence, agent apply, assignments,
	// and the applied-generation mark while allowing deadline-bound emergency
	// work to abandon admission without waiting for the current writer.
	cycleGate                    chan struct{}
	store                        *store.Store
	agent                        Agent
	profiles                     ProfileProvider
	scheduler                    *scheduler.Scheduler
	torSecret                    []byte
	qoeEnabled                   bool
	qoePromotionWindow           int
	qoePromotionFreshness        time.Duration
	qoePromotionWindowFreshness  time.Duration
	qoePromotionMaximumSampleGap time.Duration
	dnsResolvers                 []string
	reserveActiveFreshness       time.Duration
	activeHardFailureFreshness   time.Duration
	activeCriticalRouteLimit     int
	directSuffixes               []string
	directDomains                []string
	disallowRUEgress             bool
	coverageMu                   sync.Mutex
	coverageSearch               *criticalCoverageSession
	bootstrapCoverageMu          sync.Mutex
	bootstrapCoverageSearch      *criticalCoverageSession
	bootstrapCoverageEvaluate    func(
		context.Context, time.Time, *scheduler.Scheduler,
		[]scheduler.Client, []scheduler.Candidate, []string,
	) (criticalCoverageEvaluation, error)
	coverageEvaluate func(
		context.Context, time.Time, *scheduler.Scheduler,
		[]scheduler.Client, []scheduler.Candidate, []string,
	) (criticalCoverageEvaluation, error)

	beforeDesiredPlanSave        func()
	afterSchedulerPreviewPrepare func()
	beforeSameSemanticCommit     func()
}

func (engine *Engine) reserveActiveObservationFresh(
	now, observedAt time.Time,
) bool {
	return activeObservationFresh(now, observedAt, engine.reserveActiveFreshness)
}

func (engine *Engine) activeHardFailureObservationFresh(
	now, observedAt time.Time,
) bool {
	return activeObservationFresh(
		now, observedAt, engine.activeHardFailureFreshness,
	)
}

func activeObservationFresh(now, observedAt time.Time, freshness time.Duration) bool {
	return freshness > 0 &&
		!observedAt.IsZero() && !observedAt.After(now) &&
		now.Sub(observedAt) <= freshness
}

func promotionQoEReady(
	now time.Time,
	state qoe.State,
	window int,
	latestFreshness time.Duration,
	windowFreshness time.Duration,
	maximumSampleGap time.Duration,
) bool {
	return window > 0 && state.Status == qoe.StatusHealthy &&
		state.WindowValid >= window && state.WindowBad == 0 &&
		activeObservationFresh(now, state.LastValidAt, latestFreshness) &&
		activeObservationFresh(now, state.WindowStartedAt, windowFreshness) &&
		maximumSampleGap > 0 && state.WindowMaxGap <= maximumSampleGap
}

func NewEngine(database *store.Store, agent Agent, profiles ProfileProvider, placement *scheduler.Scheduler, torSecret []byte, options ...EngineOption) *Engine {
	if placement == nil {
		placement = scheduler.New(scheduler.PolicyDefaults())
	}
	engine := &Engine{
		store: database, agent: agent, profiles: profiles, scheduler: placement,
		torSecret: append([]byte(nil), torSecret...), qoeEnabled: true,
		qoePromotionWindow:           qoe.DefaultPolicy().WindowSize,
		qoePromotionFreshness:        standbyCandidateQoEFreshness,
		qoePromotionWindowFreshness:  standbyCandidateQoEFreshness,
		qoePromotionMaximumSampleGap: standbyCandidateQoEFreshness,
		dnsResolvers:                 []string{"1.1.1.1"}, cycleGate: make(chan struct{}, 1),
		directSuffixes: []string{".ru"},
	}
	engine.cycleGate <- struct{}{}
	for _, option := range options {
		option(engine)
	}
	return engine
}

func (engine *Engine) Cycle(ctx context.Context, now time.Time) error {
	return engine.CycleForReason(ctx, now, PlacementPeriodic)
}

func (engine *Engine) CycleForReason(
	ctx context.Context,
	now time.Time,
	reason PlacementReason,
) error {
	release, err := engine.acquireCycle(ctx)
	if err != nil {
		return err
	}
	defer release()
	profiles, profileFence := engine.capturePlanProfiles()
	if reason == PlacementHardFailure {
		const maxInventoryAttempts = 3
		for attempt := 0; attempt < maxInventoryAttempts; attempt++ {
			err := engine.hardFailureCycle(ctx, now, profiles, profileFence)
			if !errors.Is(err, store.ErrCandidateInventoryChanged) &&
				!errors.Is(err, store.ErrCandidateEvidenceChanged) {
				return err
			}
		}
		return store.ErrCandidateInventoryChanged
	}

	const maxInventoryAttempts = 3
	for attempt := 0; attempt < maxInventoryAttempts; attempt++ {
		preview := engine.scheduler.BeginPreview()
		committed := false
		err := engine.cycleOnce(
			ctx,
			now,
			reason,
			profiles,
			profileFence,
			preview.Scheduler(),
			func(publish func() error) error {
				if err := preview.CommitAfter(publish); err != nil {
					return err
				}
				committed = true
				return nil
			},
		)
		if !committed {
			preview.Discard()
		}
		if !errors.Is(err, store.ErrCandidateInventoryChanged) &&
			!errors.Is(err, store.ErrCandidateEvidenceChanged) &&
			!errors.Is(err, scheduler.ErrPreviewChanged) {
			if err == nil && reason == PlacementStartupNormalization {
				if readyErr := engine.ActiveCardinalityReady(ctx, now); readyErr == nil {
					engine.clearBootstrapCoverageCache()
				}
			}
			return err
		}
		if attempt == maxInventoryAttempts-1 {
			return err
		}
	}
	return nil
}

func (engine *Engine) acquireCycle(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-engine.cycleGate:
	}
	if err := ctx.Err(); err != nil {
		engine.cycleGate <- struct{}{}
		return nil, err
	}
	return func() { engine.cycleGate <- struct{}{} }, nil
}

func (engine *Engine) cycleOnce(
	ctx context.Context,
	now time.Time,
	reason PlacementReason,
	profiles ProfileProvider,
	profileFence *planProfileFence,
	placementScheduler *scheduler.Scheduler,
	commitPreview func(func() error) error,
) error {
	if engine.store == nil || engine.agent == nil {
		return errors.New("controller engine requires store and agent")
	}
	if _, err := engine.store.RebaseUnsafeDesiredPlan(ctx); err != nil {
		return fmt.Errorf("rebase unsafe desired plan: %w", err)
	}
	if err := engine.updateActivity(ctx, now); err != nil {
		return fmt.Errorf("update WireGuard activity: %w", err)
	}
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return err
	}
	clientByID := make(map[string]store.ClientRecord, len(clients))
	for _, client := range clients {
		clientByID[client.ID] = client
	}
	assignments, err := engine.store.ListAssignments(ctx)
	if err != nil {
		return err
	}
	assignmentByClient := make(map[string]store.AssignmentRecord, len(assignments))
	for _, assignment := range assignments {
		assignmentByClient[assignment.ClientID] = assignment
	}
	activeCandidateIDs := make(map[string]bool)
	activeCutoff := now.Add(-activeCandidateQoEFreshness)
	for _, assignment := range assignments {
		client, exists := clientByID[assignment.ClientID]
		if !exists || client.Paused || client.LastTrafficAt == nil ||
			time.Unix(*client.LastTrafficAt, 0).Before(activeCutoff) {
			continue
		}
		for _, candidateID := range []string{assignment.TCPOutbound, assignment.UDPOutbound} {
			if candidateID != "" {
				activeCandidateIDs[candidateID] = true
			}
		}
	}
	referencedCandidateIDs := make(map[string]bool)
	for _, assignment := range assignments {
		for _, candidateID := range []string{
			assignment.TCPOutbound,
			assignment.UDPOutbound,
		} {
			if candidateID != "" {
				referencedCandidateIDs[candidateID] = true
			}
		}
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return err
	}
	_, appliedReserveMappings, err := engine.store.ListAppliedReserveMappings(ctx)
	if err != nil {
		return err
	}
	appliedReservesByClient := make(
		map[string]scheduler.ReserveSelection, len(appliedReserveMappings),
	)
	for _, mapping := range appliedReserveMappings {
		appliedReservesByClient[mapping.ClientID] = scheduler.ReserveSelection{
			TCP: mapping.TCPReserveCandidateID,
			UDP: mapping.UDPReserveCandidateID,
		}
	}
	appliedAssignments, err := appliedPrimaryAssignments(state)
	if err != nil {
		return err
	}
	for _, encodedPlan := range [][]byte{state.DesiredPlan, state.AppliedPlan} {
		for _, candidateID := range candidateReferencesFromPlan(encodedPlan) {
			referencedCandidateIDs[candidateID] = true
		}
	}
	referencedIDs := make([]string, 0, len(referencedCandidateIDs))
	for candidateID := range referencedCandidateIDs {
		referencedIDs = append(referencedIDs, candidateID)
	}
	candidateSnapshot, err := engine.loadRouteCandidateSnapshotWithProfiles(
		ctx, now, referencedIDs, activeCandidateIDs, profiles,
	)
	if err != nil {
		return err
	}
	inventoryEpoch := candidateSnapshot.inventoryEpoch
	rowByID := candidateSnapshot.rowsByID
	profileByCandidate := candidateSnapshot.profilesByCandidate
	scheduleCandidates := candidateSnapshot.placementCandidates
	scheduleClients := make([]scheduler.Client, 0, len(clients))
	for _, client := range clients {
		if client.Paused {
			continue
		}
		assignment := assignmentByClient[client.ID]
		var traffic time.Time
		if client.LastTrafficAt != nil {
			traffic = time.Unix(*client.LastTrafficAt, 0)
		}
		scheduleClients = append(scheduleClients, scheduler.Client{
			ID: client.ID, LastTraffic: traffic,
			Assignment: scheduler.Assignment{
				TCP: assignment.TCPOutbound, UDP: assignment.UDPOutbound,
				TCPSince: assignment.TCPSince, UDPSince: assignment.UDPSince,
			},
		})
	}
	allScheduleCandidates := scheduleCandidates
	degradedAvailabilityRecovery := canRecoverStaticallyBlockedAppliedTransport(
		state, scheduleClients, allScheduleCandidates,
		engine.activeCriticalRouteLimit,
	) || canRecoverDegradedAssignedTransport(scheduleClients, allScheduleCandidates) ||
		(reason == PlacementManual && canRecoverManualAssignedTransport(
			now, placementScheduler, scheduleClients, allScheduleCandidates,
		))
	scheduleCandidates, err = engine.scheduleCandidatesForCycle(
		ctx, now, placementScheduler, scheduleClients, scheduleCandidates,
	)
	if err != nil {
		if !degradedAvailabilityRecovery || !isActiveCriticalCoverageError(err) {
			return err
		}
		// Full primary/reserve coverage is a readiness requirement, not a
		// reason to black out a transport that still has a usable primary.
		// Keep the degraded plan within the same active-probe cardinality cap;
		// CapacityReady continues to expose the missing coverage.
		scheduleCandidates = boundedDegradedAvailabilityCandidates(
			scheduleClients, allScheduleCandidates,
			engine.activeCriticalRouteLimit,
		)
	}
	placement := placementScheduler.ScheduleWithOptions(
		now, scheduleClients, scheduleCandidates,
		scheduler.ScheduleOptions{
			SuppressQualityMoves: reason != PlacementPeriodic,
		},
	)
	preserveServingAssignmentsForCapacityEvents(
		reason, scheduleClients, placement.Assignments,
		engine.activeCriticalRouteLimit,
	)
	preserveLastKnownGoodWithoutReplacement(
		scheduleClients, placement.Assignments, appliedAssignments,
	)
	for clientID, assignment := range placement.Assignments {
		applied := appliedAssignments[clientID]
		_, tcpExists := rowByID[assignment.TCP]
		_, udpExists := rowByID[assignment.UDP]
		if (assignment.TCP != "" && !tcpExists && assignment.TCP == applied.TCP) ||
			(assignment.UDP != "" && !udpExists && assignment.UDP == applied.UDP) {
			// The dataplane still has this exact applied route, but its
			// source inventory row is no longer available to rebuild it.
			// Leave the applied generation untouched until a verified
			// replacement can be rendered.
			return nil
		}
	}
	reservesByClient := make(map[string]scheduler.ReserveSelection, len(placement.Assignments))
	for clientID, assignment := range placement.Assignments {
		selected, err := placementScheduler.SelectReservesContext(
			ctx, now, clientID, assignment, scheduleCandidates,
		)
		if err != nil {
			return err
		}
		applied, exists := appliedReservesByClient[clientID]
		if exists {
			validation, err := placementScheduler.ValidateReserveSelectionContext(
				ctx, now, clientID, assignment, applied, scheduleCandidates,
			)
			if err != nil {
				return err
			}
			if validation.TCP {
				selected.TCP = applied.TCP
			}
			if validation.UDP {
				selected.UDP = applied.UDP
			}
		}
		reservesByClient[clientID] = selected
	}
	if engine.activeCriticalRouteLimit > 0 {
		if err := validateScheduledCriticalCapacity(
			ctx, placementScheduler, now, engine.activeCriticalRouteLimit,
			scheduleClients, scheduleCandidates, placement, reservesByClient,
		); err != nil {
			if !degradedAvailabilityRecovery || !isActiveCriticalCoverageError(err) {
				return err
			}
		}
	}
	selectedExpectations := make(map[string]store.CandidatePlanExpectation)
	for clientID, assignment := range placement.Assignments {
		reserves := reservesByClient[clientID]
		for _, candidateID := range []string{
			assignment.TCP, assignment.UDP, reserves.TCP, reserves.UDP,
		} {
			if candidateID == "" {
				continue
			}
			candidate, exists := rowByID[candidateID]
			if !exists {
				return store.ErrCandidateInventoryChanged
			}
			selectedExpectations[candidateID] = store.CandidatePlanExpectation{
				Candidate:      candidate,
				AllowDraining:  referencedCandidateIDs[candidateID],
				EvidenceDigest: candidateSnapshot.evidenceByCandidate[candidateID],
			}
		}
	}
	expectations := make(
		[]store.CandidatePlanExpectation, 0, len(selectedExpectations),
	)
	for _, expectation := range selectedExpectations {
		expectations = append(expectations, expectation)
	}

	suffixes := engine.directSuffixes
	if len(suffixes) == 0 {
		suffixes = []string{".ru"}
	}
	plan := dataplane.DesiredPlan{
		Outbounds:      []dataplane.Outbound{},
		Clients:        []dataplane.ClientRoute{},
		DirectSuffixes: append([]string(nil), suffixes...),
		DirectDomains:  append([]string(nil), engine.directDomains...),
		FailClosed:     true,
	}
	outbounds := make(map[string]dataplane.Outbound)
	assignmentUpdates := make([]store.AssignmentRecord, 0, len(clients))
	reserveMappings := make([]store.RouteReserveMapping, 0, len(clients))
	for clientID, assignment := range placement.Assignments {
		client := clientByID[clientID]
		assignmentUpdates = append(assignmentUpdates, store.AssignmentRecord{
			ClientID: clientID, TCPOutbound: assignment.TCP, UDPOutbound: assignment.UDP,
			TCPSince: assignment.TCPSince, UDPSince: assignment.UDPSince,
			UpdatedAt: now,
		})
		route := dataplane.ClientRoute{
			ClientID: clientID, SourceCIDR: client.Address,
			BlockTCP: assignment.TCP == "", BlockUDP: assignment.UDP == "",
		}
		if assignment.TCP != "" {
			tcpID, err := engine.outbound(clientID, assignment.TCP, rowByID, candidateSnapshot.payloadByCandidate, profileByCandidate, outbounds)
			if err != nil {
				return err
			}
			route.TCPOutbound = tcpID
			resolver, err := engine.dnsResolverForCandidate(assignment.TCP)
			if err != nil {
				return err
			}
			dnsOutbound, err := dataplane.BuildDNSOutbound(
				clientID, outbounds[tcpID], resolver,
			)
			if err != nil {
				return err
			}
			outbounds[dnsOutbound.ID] = dnsOutbound
			route.DNSOutbound = dnsOutbound.ID
		}
		if assignment.UDP != "" {
			udpID, err := engine.outbound(clientID, assignment.UDP, rowByID, candidateSnapshot.payloadByCandidate, profileByCandidate, outbounds)
			if err != nil {
				return err
			}
			route.UDPOutbound = udpID
		}
		reserves := reservesByClient[clientID]
		if reserves.TCP != "" {
			reserveID, err := engine.outbound(
				clientID, reserves.TCP, rowByID, candidateSnapshot.payloadByCandidate,
				profileByCandidate, outbounds,
			)
			if err != nil {
				return err
			}
			route.TCPReserveOutbound = reserveID
			resolver, err := engine.dnsResolverForCandidate(reserves.TCP)
			if err != nil {
				return err
			}
			reserveDNS, err := dataplane.BuildDNSOutbound(
				clientID, outbounds[reserveID], resolver,
			)
			if err != nil {
				return err
			}
			outbounds[reserveDNS.ID] = reserveDNS
		}
		if reserves.UDP != "" {
			reserveID, err := engine.outbound(
				clientID, reserves.UDP, rowByID, candidateSnapshot.payloadByCandidate,
				profileByCandidate, outbounds,
			)
			if err != nil {
				return err
			}
			route.UDPReserveOutbound = reserveID
		}
		if reserves.TCP != "" || reserves.UDP != "" {
			mapping := store.RouteReserveMapping{ClientID: clientID}
			if reserves.TCP != "" {
				mapping.TCPPrimaryCandidateID = assignment.TCP
				mapping.TCPReserveCandidateID = reserves.TCP
			}
			if reserves.UDP != "" {
				mapping.UDPPrimaryCandidateID = assignment.UDP
				mapping.UDPReserveCandidateID = reserves.UDP
			}
			reserveMappings = append(reserveMappings, mapping)
		}
		plan.Clients = append(plan.Clients, route)
	}
	for _, client := range clients {
		if !client.Paused {
			continue
		}
		assignmentUpdates = append(assignmentUpdates, store.AssignmentRecord{
			ClientID: client.ID, TCPSince: now, UDPSince: now, UpdatedAt: now,
		})
	}
	for _, outbound := range outbounds {
		plan.Outbounds = append(plan.Outbounds, outbound)
	}
	candidateDigest, err := plan.SemanticDigest()
	if err != nil {
		return err
	}
	persisted, persistedDigest, hasDesired, err := validatePersistedPlanState(state)
	if err != nil {
		return err
	}
	sameSemantic := hasDesired && candidateDigest == persistedDigest
	if engine.beforeDesiredPlanSave != nil {
		engine.beforeDesiredPlanSave()
	}
	switch {
	case state.InvalidatedGeneration != 0:
		plan.Generation = state.InvalidatedGeneration + 1
		return engine.saveApplyAndMark(
			ctx,
			plan,
			reason,
			assignmentUpdates,
			inventoryEpoch,
			expectations,
			reserveMappings,
			commitPreview, profileFence,
		)
	case sameSemantic && state.DesiredGeneration == state.AppliedGeneration:
		if engine.beforeSameSemanticCommit != nil {
			engine.beforeSameSemanticCommit()
		}
		return commitPreview(func() error {
			return engine.store.ValidateCandidatePlanSnapshot(
				ctx, inventoryEpoch, expectations,
			)
		})
	case sameSemantic:
		if engine.beforeSameSemanticCommit != nil {
			engine.beforeSameSemanticCommit()
		}
		release, err := acquireTorPlanFence(persisted, profileFence)
		if err != nil {
			return err
		}
		defer release()
		if err := commitPreview(func() error {
			return engine.store.ValidateCandidatePlanSnapshot(
				ctx, inventoryEpoch, expectations,
			)
		}); err != nil {
			return err
		}
		return engine.applyPlan(ctx, persisted, state.DesiredPlan)
	default:
		plan.Generation = max(
			state.DesiredGeneration, state.InvalidatedGeneration,
		) + 1
		return engine.saveApplyAndMark(
			ctx,
			plan,
			reason,
			assignmentUpdates,
			inventoryEpoch,
			expectations,
			reserveMappings,
			commitPreview, profileFence,
		)
	}
}
