package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/failoverbudget"
	"github.com/only-hydrat/hydrat/internal/scheduler"
)

func (engine *Engine) NormalizeActiveCriticalRoutes(
	ctx context.Context,
	now time.Time,
) error {
	if engine.activeCriticalRouteLimit <= 0 {
		return nil
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return err
	}
	desired, _, hasDesired, err := validatePersistedPlanState(state)
	if err != nil {
		return err
	}
	needsNormalization := hasDesired &&
		activeCriticalPlanCandidateCount(desired) > engine.activeCriticalRouteLimit
	if state.AppliedGeneration > 0 {
		applied, _, err := decodePersistedPlan(
			"applied", state.AppliedGeneration, state.AppliedPlan,
		)
		if err != nil {
			return err
		}
		needsNormalization = needsNormalization ||
			activeCriticalPlanCandidateCount(applied) > engine.activeCriticalRouteLimit
	}
	if !needsNormalization {
		// Startup readiness also requires converging a missing or previously
		// incomplete ordinary plan once external capacity becomes available.
		return engine.CycleForReason(ctx, now, PlacementStartupNormalization)
	}
	return engine.CycleForReason(ctx, now, PlacementStartupNormalization)
}

// ActiveCardinalityReady is the safety gate for starting proof refresh and
// preemptible recovery work. It deliberately checks only persisted route
// cardinality; full primaries/reserves are enforced later by CapacityReady.
func (engine *Engine) ActiveCardinalityReady(ctx context.Context, _ time.Time) error {
	if engine.activeCriticalRouteLimit <= 0 {
		return nil
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return err
	}
	desired, _, hasDesired, err := validatePersistedPlanState(state)
	if err != nil {
		return err
	}
	planned := 0
	if hasDesired {
		planned = activeCriticalPlanCandidateCount(desired)
	}
	if state.AppliedGeneration > 0 {
		applied, _, decodeErr := decodePersistedPlan(
			"applied", state.AppliedGeneration, state.AppliedPlan,
		)
		if decodeErr != nil {
			return decodeErr
		}
		planned = max(planned, activeCriticalPlanCandidateCount(applied))
	}
	if planned <= engine.activeCriticalRouteLimit {
		return nil
	}
	return &ActiveCriticalRouteLimitError{
		Planned: planned, Limit: engine.activeCriticalRouteLimit,
	}
}


const (
	// A full greedy/search slice can evaluate the 200-candidate pool once for
	// each of the 16 active-critical slots (plus its baseline evaluation). Keep
	// enough deterministic headroom for that 3,201-evaluation worst case while
	// the wall-clock budget remains the authoritative startup bound.
	activeCriticalCoverageEvaluationLimit = 4096
	activeCriticalCoverageWallBudget      = failoverbudget.ActivePlanning
	// ActiveCriticalCoveragePlanningBudget bounds target selection, including
	// snapshot preparation and admission to the retained coverage planner,
	// separately from the fresh network-probe deadline.
	ActiveCriticalCoveragePlanningBudget = failoverbudget.ActiveTargetPlanning
)

type ActiveCriticalCoveragePlanError struct {
	Limit           int
	Unsatisfied     []string
	SearchExhausted bool
	Evaluations     int
}

func isActiveCriticalCoverageError(err error) bool {
	var coverageErr *ActiveCriticalCoveragePlanError
	return errors.As(err, &coverageErr)
}


func (err *ActiveCriticalCoveragePlanError) Error() string {
	detail := "no feasible cover"
	if err.SearchExhausted {
		detail = "bounded cover search exhausted"
	}
	return fmt.Sprintf(
		"active critical %s within limit %d after %d evaluations; unsatisfied: %s",
		detail, err.Limit, err.Evaluations, strings.Join(err.Unsatisfied, ", "),
	)
}

func (err *ActiveCriticalCoveragePlanError) Unwrap() error {
	return ErrActiveCriticalCoverageExceeded
}

func (err *ActiveCriticalCoveragePlanError) Temporary() bool {
	return err.SearchExhausted
}

type criticalCoverageBudget struct {
	limit       int
	started     time.Time
	evaluations int
}

func newCriticalCoverageBudget(limit int) *criticalCoverageBudget {
	return &criticalCoverageBudget{limit: limit, started: time.Now()}
}

func (budget *criticalCoverageBudget) evaluate(
	ctx context.Context,
	pool []scheduler.Candidate,
	evaluate func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error),
) (criticalCoverageEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return criticalCoverageEvaluation{}, err
	}
	if budget.evaluations >= activeCriticalCoverageEvaluationLimit ||
		time.Since(budget.started) >= activeCriticalCoverageWallBudget {
		return criticalCoverageEvaluation{}, budget.exhaustedError(nil)
	}
	budget.evaluations++
	result, err := evaluate(ctx, pool)
	if err != nil {
		return criticalCoverageEvaluation{}, err
	}
	if err := ctx.Err(); err != nil {
		return criticalCoverageEvaluation{}, err
	}
	return result, nil
}

func (budget *criticalCoverageBudget) exhaustedError(
	unsatisfied []string,
) error {
	return &ActiveCriticalCoveragePlanError{
		Limit: budget.limit, Unsatisfied: unsatisfied,
		SearchExhausted: true, Evaluations: budget.evaluations,
	}
}

type criticalCoverageEvaluation struct {
	satisfied  map[string]bool
	witnessIDs []string
}

type criticalCoverageBranch struct {
	index     int
	candidate scheduler.Candidate
	satisfied map[string]bool
}

type criticalCoverageSearchFrame struct {
	pool      []int
	next      int
	evaluated bool
}

type criticalCoverageSearchState struct {
	frames []criticalCoverageSearchFrame
}

type criticalCoverageSession struct {
	key      string
	ordered  []scheduler.Candidate
	required []string
	limit    int
	search   criticalCoverageSearchState
	cached   map[string]criticalCoverageEvaluation
	phase    criticalCoveragePhase
	fullPool []scheduler.Candidate
	// initialFull is the full-pool result already computed by the placement
	// cycle before it decides that the witness exceeds the active-route cap.
	// Reusing it prevents an identical retained evaluation from consuming the
	// first planning slice and then blocking every normalization retry.
	initialFull *criticalCoverageEvaluation

	selected       []scheduler.Candidate
	selectedIDs    map[string]bool
	current        criticalCoverageEvaluation
	greedyCursor   int
	greedyBest     criticalCoverageEvaluation
	greedyBestID   string
	greedyBestGain int

	ctx     context.Context
	cancel  context.CancelFunc
	pending *criticalCoverageEvaluationTask

	completed    bool
	completedIDs []string
}

type criticalCoveragePhase uint8

const (
	criticalCoveragePhaseFull criticalCoveragePhase = iota
	criticalCoveragePhaseWitness
	criticalCoveragePhaseGreedy
	criticalCoveragePhaseSearch
)

type criticalCoverageEvaluationResult struct {
	evaluation criticalCoverageEvaluation
	err        error
}

type criticalCoverageEvaluationTask struct {
	pool   []scheduler.Candidate
	result <-chan criticalCoverageEvaluationResult
	cancel context.CancelFunc
}

func (engine *Engine) cappedScheduleCandidates(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) ([]scheduler.Candidate, error) {
	return engine.cappedScheduleCandidatesWithFull(
		ctx, now, placement, clients, candidates, nil,
	)
}

func (engine *Engine) cappedScheduleCandidatesWithFull(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	full *criticalCoverageEvaluation,
) ([]scheduler.Candidate, error) {
	if engine.coverageEvaluate == nil && len(candidates) > engine.activeCriticalRouteLimit {
		if err := staticallyImpossibleCriticalCoverage(
			clients, candidates, engine.activeCriticalRouteLimit, false,
		); err != nil {
			resetCriticalCoverageSession(&engine.coverageMu, &engine.coverageSearch)
			return nil, err
		}
	}
	evaluate := engine.coverageEvaluate
	if evaluate == nil {
		evaluate = evaluateCriticalCoverage
	}
	if cached, found, err := engine.cachedBootstrapCoverageCandidates(
		now, placement, clients, candidates,
	); err != nil {
		return nil, err
	} else if found {
		required := criticalCoverageRequirements(clients)
		covered, evaluateErr := evaluate(
			ctx, now, placement, clients, cached, required,
		)
		if evaluateErr != nil {
			return nil, evaluateErr
		}
		if coverageComplete(covered, required) {
			return cached, nil
		}
	}
	return engine.cappedCriticalCandidates(
		ctx, now, placement, clients, candidates,
		&engine.coverageMu, &engine.coverageSearch, evaluate, false, true, full,
	)
}

// scheduleCandidatesForCycle avoids solving a non-monotonic subset problem
// when the deterministic full-pool schedule already materializes no more than
// the active-critical route limit. cycleOnce validates the actual schedule
// again before publishing it; larger schedules still use the bounded cover.
func (engine *Engine) scheduleCandidatesForCycle(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) ([]scheduler.Candidate, error) {
	limit := engine.activeCriticalRouteLimit
	if limit <= 0 || len(candidates) <= limit {
		return candidates, nil
	}
	if engine.coverageEvaluate == nil {
		if err := staticallyImpossibleCriticalCoverage(
			clients, candidates, limit, false,
		); err != nil {
			resetCriticalCoverageSession(&engine.coverageMu, &engine.coverageSearch)
			return nil, err
		}
	}
	evaluate := engine.coverageEvaluate
	if evaluate == nil {
		evaluate = evaluateCriticalCoverage
	}
	if resumed, found, resumeErr := engine.resumeScheduleCoverageSession(
		ctx, now, placement, clients, candidates, evaluate,
	); found {
		return resumed, resumeErr
	}
	required := criticalCoverageRequirements(clients)
	full, err := evaluate(ctx, now, placement, clients, candidates, required)
	if err != nil {
		return nil, err
	}
	if coverageComplete(full, required) &&
		(len(required) == 0 ||
			(len(full.witnessIDs) > 0 && len(full.witnessIDs) <= limit)) {
		return candidates, nil
	}
	if cached, found, cacheErr := engine.cachedBootstrapCoverageCandidates(
		now, placement, clients, candidates,
	); cacheErr != nil {
		return nil, cacheErr
	} else if found {
		covered, evaluateErr := evaluate(
			ctx, now, placement, clients, cached, required,
		)
		if evaluateErr != nil {
			return nil, evaluateErr
		}
		if coverageComplete(covered, required) {
			return cached, nil
		}
		// The retained prospective cover is the bounded set currently being
		// actively proved. Searching arbitrary subsets of the full inventory
		// cannot make those network observations arrive sooner, and can consume
		// the whole placement budget on every proof transition. Keep the cycle
		// safely unpublished until this canonical cover is ready.
		return nil, &ActiveCriticalCoveragePlanError{
			Limit: limit, Unsatisfied: missingCoverage(covered, required),
			SearchExhausted: true, Evaluations: 2,
		}
	}
	if !coverageComplete(full, required) {
		prospective, prospectiveErr := engine.cappedProspectiveScheduleCandidates(
			ctx, now, placement, clients, candidates,
		)
		if prospectiveErr != nil {
			return nil, prospectiveErr
		}
		covered, evaluateErr := evaluate(
			ctx, now, placement, clients, prospective, required,
		)
		if evaluateErr != nil {
			return nil, evaluateErr
		}
		if coverageComplete(covered, required) {
			return prospective, nil
		}
		// The proof-independent cover is now the canonical bounded set for
		// active monitoring. Retain it across cycles and wait for its network
		// observations instead of enumerating arbitrary proof-dependent subsets.
		return nil, &ActiveCriticalCoveragePlanError{
			Limit: limit, Unsatisfied: missingCoverage(covered, required),
			SearchExhausted: true, Evaluations: 2,
		}
	}
	return engine.cappedScheduleCandidatesWithFull(
		ctx, now, placement, clients, candidates, &full,
	)
}

// resumeScheduleCoverageSession gives an existing retained search its next
// slice before recomputing the full candidate pool. The retained session
// already owns the full-pool result that established its frontier; repeating
// that O(inventory) evaluation on every retry can consume the parent cycle
// deadline and leave the actual bounded search with zero evaluations.
func (engine *Engine) resumeScheduleCoverageSession(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	evaluate func(
		context.Context, time.Time, *scheduler.Scheduler,
		[]scheduler.Client, []scheduler.Candidate, []string,
	) (criticalCoverageEvaluation, error),
) ([]scheduler.Candidate, bool, error) {
	key, err := criticalCoveragePlanningKeyWithProofMode(
		now, placement, clients, candidates,
		engine.activeCriticalRouteLimit, true,
	)
	if err != nil {
		return nil, true, err
	}
	engine.coverageMu.Lock()
	matching := engine.coverageSearch != nil && engine.coverageSearch.key == key
	engine.coverageMu.Unlock()
	if !matching {
		return nil, false, nil
	}
	result, err := engine.cappedCriticalCandidates(
		ctx, now, placement, clients, candidates,
		&engine.coverageMu, &engine.coverageSearch,
		evaluate, false, true, nil,
	)
	return result, true, err
}

func (engine *Engine) cachedBootstrapCoverageCandidates(
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) ([]scheduler.Candidate, bool, error) {
	if engine.activeCriticalRouteLimit <= 0 ||
		len(candidates) <= engine.activeCriticalRouteLimit {
		return nil, false, nil
	}
	key, err := criticalCoveragePlanningKeyWithProofMode(
		now, placement, clients, candidates,
		engine.activeCriticalRouteLimit, false,
	)
	if err != nil {
		return nil, false, err
	}
	engine.bootstrapCoverageMu.Lock()
	defer engine.bootstrapCoverageMu.Unlock()
	session := engine.bootstrapCoverageSearch
	if session == nil || !session.completed || session.key != key {
		return nil, false, nil
	}
	byID := make(map[string]scheduler.Candidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	result := make([]scheduler.Candidate, 0, len(session.completedIDs))
	for _, candidateID := range session.completedIDs {
		candidate, exists := byID[candidateID]
		if !exists {
			return nil, false, nil
		}
		result = append(result, candidate)
	}
	return result, true, nil
}

func (engine *Engine) cappedProspectiveScheduleCandidates(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) ([]scheduler.Candidate, error) {
	if engine.bootstrapCoverageEvaluate == nil &&
		len(candidates) > engine.activeCriticalRouteLimit {
		if err := staticallyImpossibleCriticalCoverage(
			clients, candidates, engine.activeCriticalRouteLimit, false,
		); err != nil {
			resetCriticalCoverageSession(
				&engine.bootstrapCoverageMu, &engine.bootstrapCoverageSearch,
			)
			return nil, err
		}
	}
	evaluate := engine.bootstrapCoverageEvaluate
	if evaluate == nil {
		evaluate = evaluateProspectiveCriticalCoverage
	}
	return engine.cappedCriticalCandidates(
		ctx, now, placement, clients, candidates,
		&engine.bootstrapCoverageMu, &engine.bootstrapCoverageSearch,
		evaluate, true, false, nil,
	)
}

func resetCriticalCoverageSession(
	mu *sync.Mutex,
	search **criticalCoverageSession,
) {
	mu.Lock()
	defer mu.Unlock()
	if *search == nil {
		return
	}
	(*search).stop(true)
	*search = nil
}

func staticallyImpossibleCriticalCoverage(
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	limit int,
	requireActiveProof bool,
) error {
	if limit <= 0 || len(clients) == 0 {
		return nil
	}
	primaryTCP := make([]scheduler.Candidate, 0, len(candidates))
	primaryUDP := make([]scheduler.Candidate, 0, len(candidates))
	reserveTCP := make([]scheduler.Candidate, 0, len(candidates))
	reserveUDP := make([]scheduler.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.TCPQualified {
			primaryTCP = append(primaryTCP, candidate)
		}
		if candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified {
			primaryUDP = append(primaryUDP, candidate)
		}
		if !candidate.ReserveEligible ||
			(requireActiveProof && (!candidate.ActiveEligible || !candidate.ActiveFresh)) {
			continue
		}
		if candidate.TCPQualified &&
			(candidate.Protocol != scheduler.ProtocolTor || candidate.Warm) {
			reserveTCP = append(reserveTCP, candidate)
		}
		if candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified {
			reserveUDP = append(reserveUDP, candidate)
		}
	}
	tcpPrimaryPossible := len(primaryTCP) > 0
	udpPrimaryPossible := len(primaryUDP) > 0
	tcpReservePossible := distinctCoverageReservePossible(primaryTCP, reserveTCP)
	udpReservePossible := distinctCoverageReservePossible(primaryUDP, reserveUDP)
	if tcpPrimaryPossible && udpPrimaryPossible &&
		tcpReservePossible && udpReservePossible {
		return nil
	}
	clientIDs := make(map[string]bool, len(clients))
	for _, client := range clients {
		clientIDs[client.ID] = true
	}
	orderedClients := make([]string, 0, len(clientIDs))
	for clientID := range clientIDs {
		orderedClients = append(orderedClients, clientID)
	}
	sort.Strings(orderedClients)
	missing := make([]string, 0, 4*len(orderedClients))
	for _, clientID := range orderedClients {
		if !tcpPrimaryPossible {
			missing = append(missing, clientID+":tcp:primary")
		}
		if !udpPrimaryPossible {
			missing = append(missing, clientID+":udp:primary")
		}
		if !tcpReservePossible {
			missing = append(missing, clientID+":tcp:reserve")
		}
		if !udpReservePossible {
			missing = append(missing, clientID+":udp:reserve")
		}
	}
	return &ActiveCriticalCoveragePlanError{
		Limit: limit, Unsatisfied: missing,
	}
}

func distinctCoverageReservePossible(
	primaries []scheduler.Candidate,
	reserves []scheduler.Candidate,
) bool {
	for _, primary := range primaries {
		for _, reserve := range reserves {
			if distinctCoverageRoute(primary, reserve) {
				return true
			}
		}
	}
	return false
}

func distinctCoverageRoute(left, right scheduler.Candidate) bool {
	if left.ID == right.ID {
		return false
	}
	if left.RouteKey != "" && left.RouteKey == right.RouteKey {
		return false
	}
	return left.ProfileID == "" || left.ProfileID != right.ProfileID
}

func (engine *Engine) clearBootstrapCoverageCache() {
	engine.bootstrapCoverageMu.Lock()
	defer engine.bootstrapCoverageMu.Unlock()
	if engine.bootstrapCoverageSearch == nil {
		return
	}
	engine.bootstrapCoverageSearch.stop(true)
	engine.bootstrapCoverageSearch = nil
}

func (engine *Engine) cappedCriticalCandidates(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	coverageMu *sync.Mutex,
	coverageSearch **criticalCoverageSession,
	evaluate func(
		context.Context, time.Time, *scheduler.Scheduler,
		[]scheduler.Client, []scheduler.Candidate, []string,
	) (criticalCoverageEvaluation, error),
	retainCompleted bool,
	includeActiveProofInKey bool,
	initialFull *criticalCoverageEvaluation,
) ([]scheduler.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit := engine.activeCriticalRouteLimit
	if limit <= 0 || len(candidates) <= limit {
		coverageMu.Lock()
		if *coverageSearch != nil {
			(*coverageSearch).stop(true)
			*coverageSearch = nil
		}
		coverageMu.Unlock()
		return candidates, nil
	}
	key, err := criticalCoveragePlanningKeyWithProofMode(
		now, placement, clients, candidates, limit, includeActiveProofInKey,
	)
	if err != nil {
		return nil, err
	}
	coverageMu.Lock()
	defer coverageMu.Unlock()
	if *coverageSearch != nil && (*coverageSearch).key != key {
		(*coverageSearch).stop(true)
		*coverageSearch = nil
	}
	if *coverageSearch == nil {
		sessionCtx, cancel := context.WithCancel(context.Background())
		*coverageSearch = &criticalCoverageSession{
			key: key, limit: limit, phase: criticalCoveragePhaseFull,
			fullPool:    append([]scheduler.Candidate(nil), candidates...),
			ordered:     orderCriticalCoverageCandidates(clients, candidates),
			required:    criticalCoverageRequirements(clients),
			cached:      make(map[string]criticalCoverageEvaluation),
			initialFull: initialFull,
			ctx:         sessionCtx, cancel: cancel,
		}
	}
	session := *coverageSearch
	if session.completed {
		byID := make(map[string]scheduler.Candidate, len(candidates))
		for _, candidate := range candidates {
			byID[candidate.ID] = candidate
		}
		result := make([]scheduler.Candidate, 0, len(session.completedIDs))
		for _, candidateID := range session.completedIDs {
			candidate, exists := byID[candidateID]
			if !exists {
				session.stop(true)
				*coverageSearch = nil
				return nil, errors.New("cached critical coverage candidate is missing")
			}
			result = append(result, candidate)
		}
		return result, nil
	}
	sliceStarted := time.Now()
	sliceCtx, cancelSlice := context.WithTimeout(ctx, activeCriticalCoverageWallBudget)
	defer cancelSlice()
	budget := newCriticalCoverageBudget(limit)
	budget.started = sliceStarted
	found, complete, err := resumeCriticalCoveragePlanner(
		sliceCtx, session, budget,
		func(evalCtx context.Context, pool []scheduler.Candidate, required []string) (criticalCoverageEvaluation, error) {
			return evaluate(evalCtx, now, placement, clients, pool, required)
		},
	)
	if err != nil {
		if ctx.Err() != nil &&
			(!retainCompleted || errors.Is(ctx.Err(), context.Canceled)) {
			session.stop(true)
			session.ctx, session.cancel = context.WithCancel(context.Background())
		}
		return nil, coverageSliceError(ctx, budget, err, retainCompleted)
	}
	if complete {
		if found != nil {
			if retainCompleted {
				session.stop(true)
				session.completed = true
				session.completedIDs = make([]string, 0, len(found))
				for _, candidate := range found {
					session.completedIDs = append(session.completedIDs, candidate.ID)
				}
				session.ordered = nil
				session.fullPool = nil
				session.cached = nil
				session.search = criticalCoverageSearchState{}
				return found, nil
			}
			session.stop(true)
			*coverageSearch = nil
			return found, nil
		}
		session.stop(true)
		*coverageSearch = nil
		return nil, &ActiveCriticalCoveragePlanError{
			Limit: limit, Unsatisfied: missingCoverage(session.current, session.required),
			Evaluations: budget.evaluations,
		}
	}
	return nil, budget.exhaustedError(missingCoverage(session.current, session.required))
}

func resumeCriticalCoveragePlanner(
	sliceCtx context.Context,
	session *criticalCoverageSession,
	budget *criticalCoverageBudget,
	evaluate func(context.Context, []scheduler.Candidate, []string) (criticalCoverageEvaluation, error),
) ([]scheduler.Candidate, bool, error) {
	for {
		switch session.phase {
		case criticalCoveragePhaseFull:
			var full criticalCoverageEvaluation
			if session.initialFull != nil {
				full = *session.initialFull
				session.initialFull = nil
			} else {
				var err error
				full, err = session.evaluatePool(
					sliceCtx, budget, session.fullPool, nil, evaluate,
				)
				if err != nil {
					return nil, false, err
				}
			}
			if len(session.required) == 0 {
				session.required = make([]string, 0, len(full.satisfied))
				for requirement := range full.satisfied {
					session.required = append(session.required, requirement)
				}
				sort.Strings(session.required)
			}
			if len(session.required) == 0 {
				return nil, true, nil
			}
			if len(full.witnessIDs) > 0 && len(full.witnessIDs) <= session.limit {
				witnessSet := make(map[string]bool, len(full.witnessIDs))
				for _, candidateID := range full.witnessIDs {
					witnessSet[candidateID] = true
				}
				session.selected = make([]scheduler.Candidate, 0, len(witnessSet))
				for _, candidate := range session.fullPool {
					if witnessSet[candidate.ID] {
						session.selected = append(session.selected, candidate)
					}
				}
				if len(session.selected) == len(witnessSet) {
					session.phase = criticalCoveragePhaseWitness
					continue
				}
			}
			initializeCriticalCoverageGreedy(session)
		case criticalCoveragePhaseWitness:
			witness, err := session.evaluatePool(
				sliceCtx, budget, session.selected, session.required, evaluate,
			)
			if err != nil {
				return nil, false, err
			}
			if coverageComplete(witness, session.required) {
				return append([]scheduler.Candidate(nil), session.selected...), true, nil
			}
			initializeCriticalCoverageGreedyFromWitness(session, witness)
		case criticalCoveragePhaseGreedy:
			if coverageComplete(session.current, session.required) {
				return append([]scheduler.Candidate(nil), session.selected...), true, nil
			}
			if len(session.selected) == session.limit || session.greedyCursor == len(session.ordered) {
				if session.greedyBestID == "" {
					session.phase = criticalCoveragePhaseSearch
					session.search.frames = []criticalCoverageSearchFrame{{next: 0}}
					continue
				}
				for _, candidate := range session.ordered {
					if candidate.ID == session.greedyBestID {
						session.selected = append(session.selected, candidate)
						session.selectedIDs[candidate.ID] = true
						break
					}
				}
				session.current = session.greedyBest
				session.greedyCursor = 0
				session.greedyBestID = ""
				session.greedyBest = criticalCoverageEvaluation{}
				session.greedyBestGain = len(session.current.satisfied)
				continue
			}
			candidate := session.ordered[session.greedyCursor]
			session.greedyCursor++
			if session.selectedIDs[candidate.ID] {
				continue
			}
			trial := append(append([]scheduler.Candidate(nil), session.selected...), candidate)
			evaluation, err := session.evaluatePool(
				sliceCtx, budget, trial, session.required, evaluate,
			)
			if err != nil {
				// The candidate cursor advances only after its atomic evaluation
				// completes; retain it while an in-flight task spans slices.
				session.greedyCursor--
				return nil, false, err
			}
			session.cached[criticalCoveragePoolKey(trial)] = evaluation
			if coverageComplete(evaluation, session.required) {
				return trial, true, nil
			}
			if len(evaluation.satisfied) > session.greedyBestGain {
				session.greedyBestID = candidate.ID
				session.greedyBestGain = len(evaluation.satisfied)
				session.greedyBest = evaluation
			}
		case criticalCoveragePhaseSearch:
			found, complete, err := resumeCriticalCoverageWith(
				session,
				func(pool []scheduler.Candidate) (criticalCoverageEvaluation, error) {
					return session.evaluatePool(
						sliceCtx, budget, pool, session.required, evaluate,
					)
				},
			)
			return found, complete, err
		}
	}
}


// CapacityReady validates the applied failover surface without mutating the
// scheduler or publishing a new plan. Fresh evidence remains protected by the
// ordinary cycle's publish CAS; this check reports only effective readiness.
func (engine *Engine) CapacityReady(ctx context.Context, now time.Time) error {
	if engine.activeCriticalRouteLimit <= 0 {
		return nil
	}
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return err
	}
	state, err := engine.store.LoadPlanState(ctx)
	if err != nil {
		return err
	}
	applied, _, _, err := validatePersistedPlanState(state)
	if err != nil {
		return err
	}
	if state.DesiredGeneration != state.AppliedGeneration {
		return &ActiveCriticalCoveragePlanError{
			Limit:       engine.activeCriticalRouteLimit,
			Unsatisfied: []string{"plan:generation"}, SearchExhausted: true,
		}
	}
	routes := make(map[string]dataplane.ClientRoute, len(applied.Clients))
	referenced := make(map[string]bool)
	for _, route := range applied.Clients {
		routes[route.ClientID] = route
		for _, handlerID := range []string{
			route.TCPOutbound, route.UDPOutbound,
			route.TCPReserveOutbound, route.UDPReserveOutbound,
		} {
			if candidateID := candidateIDFromHandler(handlerID, route.ClientID); candidateID != "" {
				referenced[candidateID] = true
			}
		}
	}
	referencedIDs := make([]string, 0, len(referenced))
	for candidateID := range referenced {
		referencedIDs = append(referencedIDs, candidateID)
	}
	snapshot, err := engine.loadRouteCandidateSnapshot(
		ctx, now, referencedIDs, referenced,
	)
	if err != nil {
		return err
	}
	selector := engine.scheduler.ReadView()
	reserveCandidates := append(
		[]scheduler.Candidate(nil), snapshot.placementCandidates...,
	)
	present := make(map[string]bool, len(reserveCandidates))
	for _, candidate := range reserveCandidates {
		present[candidate.ID] = true
	}
	for candidateID := range referenced {
		if candidate, exists := snapshot.allByID[candidateID]; exists && !present[candidateID] {
			reserveCandidates = append(reserveCandidates, candidate)
			present[candidateID] = true
		}
	}
	sort.SliceStable(reserveCandidates, func(left, right int) bool {
		return reserveCandidates[left].ID < reserveCandidates[right].ID
	})
	scheduleClients := make([]scheduler.Client, 0, len(clients))
	result := scheduler.Result{Assignments: make(map[string]scheduler.Assignment, len(clients))}
	reserves := make(map[string]scheduler.ReserveSelection, len(clients))
	for _, client := range clients {
		if client.Paused {
			continue
		}
		route := routes[client.ID]
		scheduleClients = append(scheduleClients, scheduler.Client{ID: client.ID})
		result.Assignments[client.ID] = scheduler.Assignment{
			TCP: candidateIDFromHandler(route.TCPOutbound, client.ID),
			UDP: candidateIDFromHandler(route.UDPOutbound, client.ID),
		}
		reserves[client.ID] = scheduler.ReserveSelection{
			TCP: candidateIDFromHandler(route.TCPReserveOutbound, client.ID),
			UDP: candidateIDFromHandler(route.UDPReserveOutbound, client.ID),
		}
	}
	if err := validateScheduledCriticalCapacity(
		ctx, selector, now, engine.activeCriticalRouteLimit,
		scheduleClients, reserveCandidates, result, reserves,
	); err != nil {
		return err
	}
	missing := make([]string, 0)
	for _, client := range clients {
		if client.Paused {
			continue
		}
		route, exists := routes[client.ID]
		if !exists || route.BlockTCP || route.TCPOutbound == "" {
			missing = append(missing, client.ID+":tcp:primary")
		} else if candidate := snapshot.allByID[candidateIDFromHandler(route.TCPOutbound, client.ID)]; !candidate.TCPQualified || candidate.CircuitOpen {
			missing = append(missing, client.ID+":tcp:primary")
		}
		if !exists || route.BlockUDP || route.UDPOutbound == "" {
			missing = append(missing, client.ID+":udp:primary")
		} else if candidate := snapshot.allByID[candidateIDFromHandler(route.UDPOutbound, client.ID)]; candidate.Protocol != scheduler.ProtocolVLESS || !candidate.UDPQualified || candidate.CircuitOpen {
			missing = append(missing, client.ID+":udp:primary")
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return &ActiveCriticalCoveragePlanError{
		Limit:       engine.activeCriticalRouteLimit,
		Unsatisfied: missing, SearchExhausted: true,
	}
}
