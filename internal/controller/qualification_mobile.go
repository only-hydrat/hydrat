package controller

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

const (
	mobileSavedRouteMaxAge  = 30 * time.Minute
	mobileBackgroundWorkers = 4
	mobileBackgroundBudget  = 24
)

// Keep the working pool warm and retain separately proven candidates for recovery.
func (service QualificationService) runMobileVLESS(ctx context.Context, candidates, inventory []store.Candidate, now time.Time) error {
	if len(candidates) == 0 {
		return nil
	}
	started := time.Now()
	routeKeys := make(map[string]mobileRouteIdentity, len(inventory))
	for _, candidate := range inventory {
		key := candidate.RouteKey
		if key == "" {
			key = candidate.ID
		}
		routeKeys[candidate.ID] = mobileRouteIdentity{key: key, vless: candidate.Kind == sources.KindVLESS}
	}
	pool, err := service.mobilePoolAvailability(ctx, routeKeys)
	if err != nil {
		return err
	}
	installed := service.MobileRouteInstalled != nil && service.MobileRouteInstalled()
	background := installed && pool.serving
	fullJobs, err := service.discoveryJobs(ctx, candidates, now, tournament.ProbeFull)
	if err != nil {
		return err
	}
	if background && service.MobileBackgroundMode != nil {
		mode := service.MobileBackgroundMode(now)
		if mode != "background" {
			service.reportMobileSearch(mode, 0)
			// Refresh live routes when due, even while exploring is paused.
			for _, job := range mobileFullJobs(fullJobs, now, mobilePoolState{full: true}, routeKeys, false) {
				if err := service.confirmMobileRoute(ctx, job, snapshotDecisionTime(now, started)); err != nil {
					return err
				}
			}
			return nil
		}
	}
	due := mobileFullJobs(fullJobs, now, pool, routeKeys, background)
	if pool.full && !background {
		for _, job := range due {
			if err := service.confirmMobileRoute(ctx, job, snapshotDecisionTime(now, started)); err != nil {
				return err
			}
		}
		pool, err = service.mobilePoolAvailability(ctx, routeKeys)
		if err != nil || pool.full {
			return err
		}
		due = nil
	}

	fastJobs, err := service.discoveryJobs(ctx, candidates, now, tournament.ProbeFast)
	if err != nil {
		return err
	}
	budget, workers := 64, service.FastWorkers
	mode := "search"
	if background {
		mode = "background"
		budget = mobileBackgroundBudget
		workers = service.MobileBackgroundWorkers
		if workers <= 0 {
			workers = min(service.FastWorkers, mobileBackgroundWorkers)
		}
	}
	pending := fairProbeJobs(interleaveProbeJobsByFailureDomain(fastJobs), budget)
	if background && len(pending) > budget {
		pending = pending[:budget]
	}
	if len(pending) == 0 && len(due) == 0 {
		service.reportMobileSearch("waiting", 0)
		return nil
	}
	service.reportMobileSearch(mode, min(workers, len(pending)))
	defer service.reportMobileSearch("waiting", 0)
	return service.discoverMobileRoutes(ctx, snapshotDecisionTime(now, started), pending, due, routeKeys, workers, background)
}

func (service QualificationService) reportMobileSearch(mode string, workers int) {
	if service.MobileSearchProgress != nil {
		service.MobileSearchProgress(mode, workers)
	}
}

func mobileFullJobs(jobs []qualificationJob, now time.Time, pool mobilePoolState, routeKeys map[string]mobileRouteIdentity, background bool) []qualificationJob {
	due := make([]qualificationJob, 0, 2)
	recoveryID := ""
	if !pool.full {
		var recovery qualificationJob
		for _, job := range jobs {
			key := routeKeys[job.candidate.ID].key
			if pool.covered[key] || (!job.savedReserve && !job.oneSuccess) {
				continue
			}
			if recovery.candidate.ID == "" {
				recovery = job
			}
			if pool.needsUDP && pool.udpKnown[job.candidate.ID] {
				recovery = job
				break
			}
		}
		if recovery.candidate.ID != "" {
			recoveryID = recovery.candidate.ID
			due = append(due, recovery)
		}
	}
	for _, job := range jobs {
		if job.candidate.ID == recoveryID || job.nextProbeAt.After(now) {
			continue
		}
		working := job.priority == tournament.PriorityAssigned || job.priority == tournament.PriorityWorkingPool
		if pool.full && !working && !(background && (job.savedReserve || job.oneSuccess)) {
			continue
		}
		due = append(due, job)
		if len(due) == cap(due) {
			break
		}
	}
	return due
}

func (service QualificationService) hasSavedMobileReserve(state store.CandidateProbeState) bool {
	return service.MobileReserves > 0 && state.Status == store.CandidateQualified &&
		state.FullSuccessStreak >= 2 && !state.InWorkingPool && !state.Stale &&
		!state.Draining && state.LastErrorCode == "" && !state.LastFullProbeAt.IsZero()
}

func (service QualificationService) discoverMobileRoutes(ctx context.Context, now time.Time, pending, due []qualificationJob, routeKeys map[string]mobileRouteIdentity, workers int, background bool) error {
	searchCtx, stopSearch := context.WithCancel(ctx)
	defer stopSearch()
	started := time.Now()
	stopWhenInstalled := !background && service.MobileRouteInstalled != nil && !service.MobileRouteInstalled()
	ready := make(chan qualificationJob, 1)
	return runConcurrentQualificationLanes(searchCtx,
		func(laneCtx context.Context) error {
			defer close(ready)
			err := service.runProbeJobsObserved(laneCtx, now, pending, tournament.ProbeFast, workers,
				func(result qualificationResult, state store.CandidateProbeState, at time.Time) error {
					if stopWhenInstalled && service.MobileRouteInstalled() {
						stopSearch()
						return context.Canceled
					}
					if result.err != nil || !result.response.Success || state.LastErrorCode != "" ||
						state.CandidateID != result.job.candidate.ID ||
						state.LastFastProbeAt.Before(at.Truncate(time.Second)) ||
						(state.Status != store.CandidatePreflight && state.Status != store.CandidateQualified) {
						return nil
					}
					select {
					case ready <- result.job:
						return nil
					case <-laneCtx.Done():
						return laneCtx.Err()
					}
				})
			if errors.Is(err, context.Canceled) && ctx.Err() == nil {
				return nil
			}
			return err
		},
		func(laneCtx context.Context) error {
			for {
				var job qualificationJob
				if len(due) != 0 {
					job, due = due[0], due[1:]
				} else {
					select {
					case <-laneCtx.Done():
						return laneCtx.Err()
					case next, ok := <-ready:
						if !ok {
							return laneCtx.Err()
						}
						job = next
					}
				}
				if err := service.confirmMobileRoute(laneCtx, job, snapshotDecisionTime(now, started)); err != nil {
					return err
				}
				if background {
					continue
				}
				pool, err := service.mobilePoolAvailability(laneCtx, routeKeys)
				if err != nil {
					return err
				}
				if pool.full {
					stopSearch()
					return nil
				}
			}
		},
	)
}

func (service QualificationService) confirmMobileRoute(ctx context.Context, job qualificationJob, now time.Time) error {
	started := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		probedAt := snapshotDecisionTime(now, started)
		if err := service.runProbeJobs(ctx, probedAt, []qualificationJob{job}, tournament.ProbeFull, 1); err != nil {
			return err
		}
		state, err := service.Store.CandidateProbeState(ctx, job.candidate.Fingerprint)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if state.FullSuccessStreak != 1 || state.LastErrorCode != "" ||
			state.LastFullProbeAt.Before(probedAt.Truncate(time.Second)) {
			return nil
		}
	}
	return nil
}

// Revisit score-based bans when the stored score meets the current minimum.
func (service QualificationService) mobileScoreRetries(ctx context.Context, now time.Time, states []store.CandidateProbeState) (map[string]bool, error) {
	if service.MobileReserves <= 0 || service.MinVLESSScore <= 0 {
		return nil, nil
	}
	previous := make(map[string]time.Time)
	for _, state := range states {
		if state.Status == store.CandidateBanned && state.BannedUntil.After(now) &&
			state.LastErrorCode == "score_too_low" && !state.LastFullProbeAt.IsZero() {
			previous[state.CandidateID] = state.LastFullProbeAt
		}
	}
	if len(previous) == 0 {
		return nil, nil
	}
	rows, err := service.Store.ListCandidateHealth(ctx)
	if err != nil {
		return nil, err
	}
	retries := make(map[string]bool)
	for _, row := range rows {
		if last, exists := previous[row.CandidateID]; exists && row.UpdatedAt.Equal(last) &&
			row.Score >= service.MinVLESSScore {
			retries[row.CandidateID] = true
		}
	}
	return retries, nil
}

type mobileRouteIdentity struct {
	key   string
	vless bool
}

type mobilePoolState struct {
	full, serving bool
	needsUDP      bool
	covered       map[string]bool
	udpKnown      map[string]bool
}

func (service QualificationService) mobilePoolAvailability(ctx context.Context, routeKeys map[string]mobileRouteIdentity) (mobilePoolState, error) {
	assignments, err := service.Store.ListAssignments(ctx)
	if err != nil {
		return mobilePoolState{}, err
	}
	primaries := make(map[string]bool)
	for _, assignment := range assignments {
		for _, id := range []string{assignment.TCPOutbound, assignment.UDPOutbound} {
			if id != "" {
				primaries[id] = true
			}
		}
	}
	states, err := service.Store.ListCandidateProbeStates(ctx)
	if err != nil {
		return mobilePoolState{}, err
	}
	health, err := service.Store.ListCandidateHealth(ctx)
	if err != nil {
		return mobilePoolState{}, err
	}
	byID := make(map[string]store.CandidateHealth, len(health))
	for _, row := range health {
		byID[row.CandidateID] = row
	}
	pool := mobilePoolState{covered: make(map[string]bool), udpKnown: make(map[string]bool)}
	udpRoutes := make(map[string]bool)
	for _, state := range states {
		row := byID[state.CandidateID]
		identity, current := routeKeys[state.CandidateID]
		if !current || !row.Available || row.ActiveHardFailure || !row.TCPQualified ||
			(identity.vless && row.Score < service.MinVLESSScore) {
			continue
		}
		pool.serving = pool.serving || primaries[state.CandidateID]
		pool.udpKnown[state.CandidateID] = identity.vless && row.UDPQualified
		if state.InWorkingPool && state.Status == store.CandidateQualified && !state.Stale && !state.Draining {
			pool.covered[identity.key] = true
			if pool.udpKnown[state.CandidateID] {
				udpRoutes[identity.key] = true
			}
		}
	}
	pool.needsUDP = len(udpRoutes) < 2
	pool.full = !pool.needsUDP && len(pool.covered) >= max(1, len(primaries))+service.MobileReserves
	return pool, nil
}

func distinctMobilePoolRoutes(candidates []tournament.Candidate, rows map[string]store.Candidate) []tournament.Candidate {
	indexByRoute := make(map[string]int)
	distinct := candidates[:0]
	for _, candidate := range candidates {
		row := rows[candidate.Fingerprint]
		if candidate.Stale {
			candidate.Status = tournament.StatusUnknown
		}
		if row.RouteKey == "" || candidate.Status != tournament.StatusQualified {
			distinct = append(distinct, candidate)
			continue
		}
		index, exists := indexByRoute[row.RouteKey]
		if !exists {
			indexByRoute[row.RouteKey] = len(distinct)
			distinct = append(distinct, candidate)
			continue
		}
		current := distinct[index]
		switch {
		case candidate.Assigned != current.Assigned:
			if candidate.Assigned {
				distinct[index] = candidate
			}
		case candidate.InWorkingPool != current.InWorkingPool:
			if candidate.InWorkingPool {
				distinct[index] = candidate
			}
		case candidate.ConservativeScore > current.ConservativeScore:
			distinct[index] = candidate
		}
	}
	return distinct
}

// Keep a second UDP-capable path in the mobile pool even when the
// TCP-only alternatives score higher. Placement still requires active proof.
func keepMobileUDPCoverage(selection *tournament.Selection, candidates []tournament.Candidate, rows map[string]store.Candidate, health []store.CandidateHealth, minimum float64, now time.Time) {
	byID := make(map[string]store.CandidateHealth, len(health))
	for _, row := range health {
		byID[row.CandidateID] = row
	}
	byFingerprint := make(map[string]tournament.Candidate, len(candidates))
	var alternatives []tournament.Candidate
	for _, candidate := range candidates {
		byFingerprint[candidate.Fingerprint] = candidate
		row := rows[candidate.Fingerprint]
		h := byID[row.ID]
		if row.Kind == sources.KindVLESS && h.TCPQualified && h.UDPQualified && h.Available &&
			!h.ActiveHardFailure && h.Score >= minimum && candidate.Status == tournament.StatusQualified &&
			candidate.FullSuccessStreak >= 2 && !candidate.Stale && !candidate.Draining && !candidate.BannedUntil.After(now) {
			alternatives = append(alternatives, candidate)
		}
	}
	sort.SliceStable(alternatives, func(i, j int) bool {
		if alternatives[i].ConservativeScore == alternatives[j].ConservativeScore {
			return alternatives[i].Fingerprint < alternatives[j].Fingerprint
		}
		return alternatives[i].ConservativeScore > alternatives[j].ConservativeScore
	})
	udp := make(map[string]bool)
	for _, candidate := range alternatives {
		udp[candidate.Fingerprint] = true
	}
	count := 0
	for _, fingerprint := range selection.Active {
		if udp[fingerprint] {
			count++
		}
	}
	for _, candidate := range alternatives {
		if count >= 2 {
			break
		}
		if slices.Contains(selection.Active, candidate.Fingerprint) {
			continue
		}
		worst := -1
		for index, fingerprint := range selection.Active {
			current := byFingerprint[fingerprint]
			if !udp[fingerprint] && !current.Assigned &&
				(worst < 0 || current.ConservativeScore < byFingerprint[selection.Active[worst]].ConservativeScore) {
				worst = index
			}
		}
		if worst < 0 {
			break
		}
		selection.Active[worst] = candidate.Fingerprint
		selection.Draining = slices.DeleteFunc(selection.Draining, func(id string) bool { return id == candidate.Fingerprint })
		count++
	}
	sort.Strings(selection.Active)
}
