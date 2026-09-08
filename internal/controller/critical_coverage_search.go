package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
)

func criticalCoverageRequirements(clients []scheduler.Client) []string {
	clientIDs := make(map[string]bool, len(clients))
	for _, client := range clients {
		clientIDs[client.ID] = true
	}
	ordered := make([]string, 0, len(clientIDs))
	for clientID := range clientIDs {
		ordered = append(ordered, clientID)
	}
	sort.Strings(ordered)
	required := make([]string, 0, 4*len(ordered))
	for _, clientID := range ordered {
		required = append(required,
			clientID+":tcp:primary",
			clientID+":udp:primary",
			clientID+":tcp:reserve",
			clientID+":udp:reserve",
		)
	}
	return required
}

func initializeCriticalCoverageGreedy(session *criticalCoverageSession) {
	session.selected = make([]scheduler.Candidate, 0, session.limit)
	session.selectedIDs = make(map[string]bool, session.limit)
	session.current = criticalCoverageEvaluation{satisfied: make(map[string]bool)}
	initializeCriticalCoverageGreedyState(session)
}

func initializeCriticalCoverageGreedyFromWitness(
	session *criticalCoverageSession,
	witness criticalCoverageEvaluation,
) {
	// The full-pool schedule is already a deterministic near-cover. Keep its
	// candidates so a changing active-proof snapshot only has to fill the
	// missing requirements instead of restarting from an empty pool.
	selected := append([]scheduler.Candidate(nil), session.selected...)
	session.selected = selected
	session.selectedIDs = make(map[string]bool, session.limit)
	for _, candidate := range selected {
		session.selectedIDs[candidate.ID] = true
	}
	session.current = witness
	initializeCriticalCoverageGreedyState(session)
}

func initializeCriticalCoverageGreedyState(session *criticalCoverageSession) {
	session.greedyCursor = 0
	session.greedyBest = criticalCoverageEvaluation{}
	session.greedyBestID = ""
	session.greedyBestGain = len(session.current.satisfied)
	session.phase = criticalCoveragePhaseGreedy
}

func searchCriticalCoverage(
	ctx context.Context,
	ordered []scheduler.Candidate,
	limit int,
	required []string,
	budget *criticalCoverageBudget,
	evaluate func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error),
) ([]scheduler.Candidate, error) {
	session := &criticalCoverageSession{
		ordered: ordered, required: required, limit: limit,
		search: criticalCoverageSearchState{frames: []criticalCoverageSearchFrame{{next: 0}}},
	}
	found, complete, err := resumeCriticalCoverage(ctx, session, budget, evaluate)
	if err != nil || !complete {
		return found, err
	}
	return found, nil
}

func (session *criticalCoverageSession) evaluatePool(
	sliceCtx context.Context,
	budget *criticalCoverageBudget,
	pool []scheduler.Candidate,
	required []string,
	evaluate func(context.Context, []scheduler.Candidate, []string) (criticalCoverageEvaluation, error),
) (criticalCoverageEvaluation, error) {
	poolKey := criticalCoveragePoolKey(pool)
	if session.pending == nil {
		if err := sliceCtx.Err(); err != nil {
			return criticalCoverageEvaluation{}, err
		}
		if budget.evaluations >= activeCriticalCoverageEvaluationLimit ||
			time.Since(budget.started) >= activeCriticalCoverageWallBudget {
			return criticalCoverageEvaluation{}, budget.exhaustedError(nil)
		}
		budget.evaluations++
		result := make(chan criticalCoverageEvaluationResult, 1)
		poolCopy := append([]scheduler.Candidate(nil), pool...)
		requiredCopy := append([]string(nil), required...)
		taskCtx, cancelTask := context.WithCancel(session.ctx)
		session.pending = &criticalCoverageEvaluationTask{
			pool: poolCopy, result: result, cancel: cancelTask,
		}
		go func() {
			evaluation, err := evaluate(taskCtx, poolCopy, requiredCopy)
			result <- criticalCoverageEvaluationResult{evaluation: evaluation, err: err}
		}()
	} else if criticalCoveragePoolKey(session.pending.pool) != poolKey {
		return criticalCoverageEvaluation{}, errors.New("coverage planner pending evaluation cursor mismatch")
	}
	select {
	case <-sliceCtx.Done():
		return criticalCoverageEvaluation{}, sliceCtx.Err()
	case result := <-session.pending.result:
		session.pending.cancel()
		session.pending = nil
		return result.evaluation, result.err
	}
}

func (session *criticalCoverageSession) stop(cancelSession bool) {
	if cancelSession {
		session.cancel()
	}
	if session.pending == nil {
		return
	}
	session.pending.cancel()
	<-session.pending.result
	session.pending = nil
}

func resumeCriticalCoverage(
	ctx context.Context,
	session *criticalCoverageSession,
	budget *criticalCoverageBudget,
	evaluate func(context.Context, []scheduler.Candidate) (criticalCoverageEvaluation, error),
) ([]scheduler.Candidate, bool, error) {
	return resumeCriticalCoverageWith(
		session,
		func(pool []scheduler.Candidate) (criticalCoverageEvaluation, error) {
			return budget.evaluate(ctx, pool, evaluate)
		},
	)
}

func resumeCriticalCoverageWith(
	session *criticalCoverageSession,
	evaluate func([]scheduler.Candidate) (criticalCoverageEvaluation, error),
) ([]scheduler.Candidate, bool, error) {
	for len(session.search.frames) > 0 {
		frame := &session.search.frames[len(session.search.frames)-1]
		if !frame.evaluated {
			pool := coveragePool(session.ordered, frame.pool)
			evaluation, cached := session.cached[criticalCoveragePoolKey(pool)]
			if cached {
				delete(session.cached, criticalCoveragePoolKey(pool))
			} else {
				var err error
				evaluation, err = evaluate(pool)
				if err != nil {
					return nil, false, err
				}
			}
			frame.evaluated = true
			if coverageComplete(evaluation, session.required) {
				return pool, true, nil
			}
		}
		if len(frame.pool) < session.limit && frame.next < len(session.ordered) {
			candidateIndex := frame.next
			frame.next++
			childPool := append(append([]int(nil), frame.pool...), candidateIndex)
			session.search.frames = append(session.search.frames, criticalCoverageSearchFrame{
				pool: childPool, next: candidateIndex + 1,
			})
			continue
		}
		session.search.frames = session.search.frames[:len(session.search.frames)-1]
	}
	return nil, true, nil
}

func coveragePool(ordered []scheduler.Candidate, indices []int) []scheduler.Candidate {
	pool := make([]scheduler.Candidate, len(indices))
	for index, candidateIndex := range indices {
		pool[index] = ordered[candidateIndex]
	}
	return pool
}

func criticalCoveragePoolKey(pool []scheduler.Candidate) string {
	var key strings.Builder
	for _, candidate := range pool {
		_, _ = fmt.Fprintf(&key, "%d:%s|", len(candidate.ID), candidate.ID)
	}
	return key.String()
}

func coverageSliceError(
	parent context.Context,
	budget *criticalCoverageBudget,
	err error,
	parentDeadlineIsSlice bool,
) error {
	if errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(parent.Err(), context.Canceled) &&
		(parent.Err() == nil || parentDeadlineIsSlice) {
		return budget.exhaustedError(nil)
	}
	return err
}

func criticalCoveragePlanningKey(
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	limit int,
) (string, error) {
	return criticalCoveragePlanningKeyWithProofMode(
		now, placement, clients, candidates, limit, true,
	)
}

func criticalCoveragePlanningKeyWithProofMode(
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	limit int,
	includeActiveProof bool,
) (string, error) {
	orderedClients := append([]scheduler.Client(nil), clients...)
	sort.Slice(orderedClients, func(left, right int) bool {
		return orderedClients[left].ID < orderedClients[right].ID
	})
	orderedCandidates := append([]scheduler.Candidate(nil), candidates...)
	sort.Slice(orderedCandidates, func(left, right int) bool {
		return orderedCandidates[left].ID < orderedCandidates[right].ID
	})
	normalizedCandidates := make([]criticalCoverageCandidateKey, 0, len(orderedCandidates))
	for _, candidate := range orderedCandidates {
		normalizedCandidates = append(
			normalizedCandidates, normalizeCriticalCoverageCandidateWithProofMode(
				candidate, includeActiveProof,
			),
		)
	}
	payload := struct {
		Limit      int
		Scheduler  string
		Candidates []criticalCoverageCandidateKey
	}{
		Limit: limit, Scheduler: placement.PlanningFingerprint(now, orderedClients),
		Candidates: normalizedCandidates,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded)), nil
}

type criticalCoverageCandidateKey struct {
	ID, RouteKey, ProfileID, Protocol, FailureDomain string
	Score                                            float64
	TCPQualified, UDPQualified                       bool
	ReserveEligible, ActiveEligible, ActiveFresh     bool
	Warm, Retiring, CircuitOpen                      bool
	QoEStatus                                        string
	QoEEffective                                     int64
	QoEFresh                                         bool
}

func normalizeCriticalCoverageCandidate(
	candidate scheduler.Candidate,
) criticalCoverageCandidateKey {
	return normalizeCriticalCoverageCandidateWithProofMode(candidate, true)
}

func normalizeCriticalCoverageCandidateWithProofMode(
	candidate scheduler.Candidate,
	includeActiveProof bool,
) criticalCoverageCandidateKey {
	key := criticalCoverageCandidateKey{
		ID: candidate.ID, RouteKey: candidate.RouteKey, ProfileID: candidate.ProfileID,
		Protocol: string(candidate.Protocol), FailureDomain: candidate.FailureDomain,
		Score: candidate.Score, TCPQualified: candidate.TCPQualified,
		UDPQualified:    candidate.Protocol == scheduler.ProtocolVLESS && candidate.UDPQualified,
		ReserveEligible: candidate.ReserveEligible,
		Warm:            candidate.Protocol == scheduler.ProtocolTor && candidate.Warm,
		Retiring:        candidate.Retiring, CircuitOpen: candidate.CircuitOpen,
		QoEStatus: string(candidate.QoEStatus),
	}
	if includeActiveProof && candidate.ReserveEligible {
		key.ActiveEligible = candidate.ActiveEligible
		key.ActiveFresh = candidate.ActiveFresh
	}
	if candidate.QoEStatus == "healthy" || candidate.QoEStatus == "degraded" {
		key.QoEEffective = int64(candidate.QoEEffective)
		key.QoEFresh = candidate.QoEFresh
	}
	return key
}

func disjointCoverageLowerBound(
	current map[string]bool,
	required []string,
	branches []criticalCoverageBranch,
) int {
	type optionSet map[int]bool
	sets := make([]optionSet, 0)
	for _, requirement := range required {
		if current[requirement] || !strings.HasSuffix(requirement, ":primary") {
			continue
		}
		options := make(optionSet)
		for _, branch := range branches {
			if branch.satisfied[requirement] {
				options[branch.index] = true
			}
		}
		if len(options) != 0 {
			sets = append(sets, options)
		}
	}
	sort.SliceStable(sets, func(left, right int) bool {
		return len(sets[left]) < len(sets[right])
	})
	used := make(map[int]bool)
	lowerBound := 0
	for _, options := range sets {
		disjoint := true
		for candidate := range options {
			if used[candidate] {
				disjoint = false
				break
			}
		}
		if !disjoint {
			continue
		}
		lowerBound++
		for candidate := range options {
			used[candidate] = true
		}
	}
	return lowerBound
}

func evaluateCriticalCoverage(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	required []string,
) (criticalCoverageEvaluation, error) {
	return evaluateCriticalCoverageWithProofMode(
		ctx, now, placement, clients, candidates, required, true,
	)
}

func evaluateProspectiveCriticalCoverage(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	required []string,
) (criticalCoverageEvaluation, error) {
	return evaluateCriticalCoverageWithProofMode(
		ctx, now, placement, clients, candidates, required, false,
	)
}

func evaluateCriticalCoverageWithProofMode(
	ctx context.Context,
	now time.Time,
	placement *scheduler.Scheduler,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	required []string,
	requireActiveProof bool,
) (criticalCoverageEvaluation, error) {
	view := placement.ReadView()
	result, err := view.ScheduleContext(ctx, now, clients, candidates)
	if err != nil {
		return criticalCoverageEvaluation{}, err
	}
	satisfied := make(map[string]bool)
	witnessSet := make(map[string]bool)
	requiredSet := make(map[string]bool, len(required))
	for _, key := range required {
		requiredSet[key] = true
	}
	add := func(key string, present bool) {
		if present && (required == nil || requiredSet[key]) {
			satisfied[key] = true
		}
	}
	clientIDs := make([]string, 0, len(result.Assignments))
	for clientID := range result.Assignments {
		clientIDs = append(clientIDs, clientID)
	}
	sort.Strings(clientIDs)
	for _, clientID := range clientIDs {
		assignment := result.Assignments[clientID]
		var reserves scheduler.ReserveSelection
		var err error
		if requireActiveProof {
			reserves, err = view.SelectReservesContext(
				ctx, now, clientID, assignment, candidates,
			)
		} else {
			reserves, err = view.SelectProspectiveReservesContext(
				ctx, now, clientID, assignment, candidates,
			)
		}
		if err != nil {
			return criticalCoverageEvaluation{}, err
		}
		add(clientID+":tcp:primary", assignment.TCP != "")
		add(clientID+":udp:primary", assignment.UDP != "")
		add(clientID+":tcp:reserve", reserves.TCP != "" && reserves.TCP != assignment.TCP)
		add(clientID+":udp:reserve", reserves.UDP != "" && reserves.UDP != assignment.UDP)
		for _, candidateID := range []string{
			assignment.TCP, assignment.UDP, reserves.TCP, reserves.UDP,
		} {
			if candidateID != "" {
				witnessSet[candidateID] = true
			}
		}
	}
	witnessIDs := make([]string, 0, len(witnessSet))
	for candidateID := range witnessSet {
		witnessIDs = append(witnessIDs, candidateID)
	}
	sort.Strings(witnessIDs)
	return criticalCoverageEvaluation{
		satisfied: satisfied, witnessIDs: witnessIDs,
	}, nil
}

func orderCriticalCoverageCandidates(
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
) []scheduler.Candidate {
	incumbentUse := make(map[string]int)
	for _, client := range clients {
		incumbentUse[client.Assignment.TCP]++
		incumbentUse[client.Assignment.UDP]++
	}
	ordered := append([]scheduler.Candidate(nil), candidates...)
	sort.SliceStable(ordered, func(left, right int) bool {
		leftUse, rightUse := incumbentUse[ordered[left].ID], incumbentUse[ordered[right].ID]
		if leftUse != rightUse {
			return leftUse > rightUse
		}
		leftBoth := ordered[left].TCPQualified && ordered[left].UDPQualified
		rightBoth := ordered[right].TCPQualified && ordered[right].UDPQualified
		if leftBoth != rightBoth {
			return leftBoth
		}
		if ordered[left].Score != ordered[right].Score {
			return ordered[left].Score > ordered[right].Score
		}
		return ordered[left].ID < ordered[right].ID
	})
	return ordered
}

func coverageComplete(
	evaluation criticalCoverageEvaluation,
	required []string,
) bool {
	return len(evaluation.satisfied) == len(required)
}

func missingCoverage(
	evaluation criticalCoverageEvaluation,
	required []string,
) []string {
	missing := make([]string, 0)
	for _, requirement := range required {
		if !evaluation.satisfied[requirement] {
			missing = append(missing, requirement)
		}
	}
	return missing
}

func validateScheduledCriticalCapacity(
	ctx context.Context,
	selector *scheduler.Scheduler,
	now time.Time,
	limit int,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	result scheduler.Result,
	reserves map[string]scheduler.ReserveSelection,
) error {
	return validateScheduledCriticalCapacityWithProofMode(
		ctx, selector, now, limit, clients, candidates, result, reserves, true,
	)
}

func validateProspectiveScheduledCriticalCapacity(
	ctx context.Context,
	selector *scheduler.Scheduler,
	now time.Time,
	limit int,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	result scheduler.Result,
	reserves map[string]scheduler.ReserveSelection,
) error {
	return validateScheduledCriticalCapacityWithProofMode(
		ctx, selector, now, limit, clients, candidates, result, reserves, false,
	)
}

func validateScheduledCriticalCapacityWithProofMode(
	ctx context.Context,
	selector *scheduler.Scheduler,
	now time.Time,
	limit int,
	clients []scheduler.Client,
	candidates []scheduler.Candidate,
	result scheduler.Result,
	reserves map[string]scheduler.ReserveSelection,
	requireActiveProof bool,
) error {
	if limit <= 0 {
		return nil
	}
	criticalIDs := make(map[string]bool)
	for _, client := range clients {
		assignment := result.Assignments[client.ID]
		reserve := reserves[client.ID]
		for _, candidateID := range []string{
			assignment.TCP, assignment.UDP, reserve.TCP, reserve.UDP,
		} {
			if candidateID != "" {
				criticalIDs[candidateID] = true
			}
		}
	}
	criticalCandidates := make([]scheduler.Candidate, 0, len(criticalIDs))
	for _, candidate := range candidates {
		if criticalIDs[candidate.ID] {
			criticalCandidates = append(criticalCandidates, candidate)
		}
	}
	missing := make([]string, 0)
	for _, client := range clients {
		if err := ctx.Err(); err != nil {
			return err
		}
		assignment := result.Assignments[client.ID]
		reserve := reserves[client.ID]
		if assignment.TCP == "" {
			missing = append(missing, client.ID+":tcp:primary")
		}
		if assignment.UDP == "" {
			missing = append(missing, client.ID+":udp:primary")
		}
		var validation scheduler.ReserveValidation
		var err error
		if requireActiveProof {
			validation, err = selector.ValidateReserveSelectionContext(
				ctx, now, client.ID, assignment, reserve, candidates,
			)
		} else {
			var selected scheduler.ReserveSelection
			selected, err = selector.SelectProspectiveReservesContext(
				ctx, now, client.ID, assignment, criticalCandidates,
			)
			validation = scheduler.ReserveValidation{
				TCP: reserve.TCP != "" && reserve.TCP == selected.TCP,
				UDP: reserve.UDP != "" && reserve.UDP == selected.UDP,
			}
		}
		if err != nil {
			return err
		}
		if !validation.TCP {
			missing = append(missing, client.ID+":tcp:reserve")
		}
		if !validation.UDP {
			missing = append(missing, client.ID+":udp:reserve")
		}
	}
	if len(missing) == 0 && len(criticalIDs) <= limit {
		return nil
	}
	if len(criticalIDs) > limit {
		missing = append(missing, "active-critical:limit")
	}
	sort.Strings(missing)
	return &ActiveCriticalCoveragePlanError{
		Limit: limit, Unsatisfied: missing, SearchExhausted: true,
	}
}
