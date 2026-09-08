package controller

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/tournament"
)


func (service QualificationService) signalPromotion() {
	if service.Promotions == nil {
		return
	}
	select {
	case service.Promotions <- struct{}{}:
	default:
	}
}

func (service QualificationService) nextTorJob(
	ctx context.Context,
	candidate store.Candidate,
	now time.Time,
) (qualificationJob, tournament.ProbeStage, bool, error) {
	for _, stage := range []tournament.ProbeStage{tournament.ProbeFast, tournament.ProbeFull} {
		jobs, err := service.discoveryJobs(ctx, []store.Candidate{candidate}, now, stage)
		if err != nil {
			return qualificationJob{}, "", false, err
		}
		if len(jobs) > 0 {
			return jobs[0], stage, true, nil
		}
	}
	return qualificationJob{}, "", false, nil
}

func (service QualificationService) runTorCandidates(
	ctx context.Context,
	torCandidates []store.Candidate,
	_ []store.Candidate,
	now time.Time,
) error {
	torContext := ctx
	if service.TorQualificationBudget > 0 {
		var cancel context.CancelFunc
		torContext, cancel = context.WithTimeout(ctx, service.TorQualificationBudget)
		defer cancel()
	}
	budgetExpired := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
	orderedCandidates, err := service.prioritizeTorCandidates(ctx, torCandidates, now)
	if err != nil {
		return err
	}
	if service.TorCandidatesPerCycle > 0 &&
		len(orderedCandidates) > service.TorCandidatesPerCycle {
		orderedCandidates = orderedCandidates[:service.TorCandidatesPerCycle]
	}
candidateLoop:
	for _, candidate := range orderedCandidates {
		for attempt := 0; attempt < 3; attempt++ {
			if torContext.Err() != nil {
				return budgetExpired()
			}
			job, stage, ok, err := service.nextTorJob(torContext, candidate, now)
			if errors.Is(err, sql.ErrNoRows) {
				continue candidateLoop
			}
			if err != nil && torContext.Err() != nil {
				return budgetExpired()
			}
			if err != nil || !ok {
				return err
			}
			result := service.executeProbe(torContext, job, stage)
			state, err := service.recordProbeResult(ctx, now, result, stage)
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				continue candidateLoop
			}
			if err != nil {
				return err
			}
			if torContext.Err() != nil {
				return budgetExpired()
			}
			if result.err != nil || !result.response.Success {
				break
			}
			if state.Status == store.CandidateQualified {
				currentCandidates, err := service.Store.ListCandidates(ctx, "")
				if err != nil {
					return err
				}
				profiles, err := service.updateWorkingPool(ctx, currentCandidates, now)
				if err != nil {
					return err
				}
				if state.FullSuccessStreak == 2 && hasWarmProfile(profiles, candidate.ID) {
					service.signalPromotion()
				}
				break
			}
		}
	}
	return ctx.Err()
}

func (service QualificationService) prioritizeTorCandidates(
	ctx context.Context,
	candidates []store.Candidate,
	now time.Time,
) ([]store.Candidate, error) {
	states, err := service.Store.ListCandidateProbeStates(ctx)
	if err != nil {
		return nil, err
	}
	stateByFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		stateByFingerprint[state.Fingerprint] = state
	}
	queueCandidates := make([]tournament.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		queueCandidates = append(
			queueCandidates,
			discoveryCandidate(candidate, stateByFingerprint[candidate.Fingerprint]),
		)
	}
	queue := tournament.BuildDiscoveryQueue(queueCandidates, tournament.QueuePolicy{
		Now: now, ResetWindow: service.ResetWindow,
	})
	priorityByFingerprint := make(map[string]tournament.Priority, len(queue))
	for _, job := range queue {
		priorityByFingerprint[job.Fingerprint] = job.Priority
	}
	ordered := make([]store.Candidate, 0, len(queue))
	for _, candidate := range candidates {
		if _, eligible := priorityByFingerprint[candidate.Fingerprint]; eligible {
			ordered = append(ordered, candidate)
		}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		leftPriority := priorityByFingerprint[ordered[left].Fingerprint]
		rightPriority := priorityByFingerprint[ordered[right].Fingerprint]
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		leftState := stateByFingerprint[ordered[left].Fingerprint]
		rightState := stateByFingerprint[ordered[right].Fingerprint]
		leftProbeAt := latestProbeAt(leftState)
		rightProbeAt := latestProbeAt(rightState)
		if leftProbeAt.Equal(rightProbeAt) {
			return false
		}
		return leftProbeAt.Before(rightProbeAt)
	})
	return ordered, nil
}

func latestProbeAt(state store.CandidateProbeState) time.Time {
	if state.LastFastProbeAt.After(state.LastFullProbeAt) {
		return state.LastFastProbeAt
	}
	return state.LastFullProbeAt
}

func hasWarmProfile(profiles []torpool.Profile, candidateID string) bool {
	for _, profile := range profiles {
		if profile.CandidateID == candidateID && profile.Role == "warm" {
			return true
		}
	}
	return false
}

// RepairRuntimeProfiles restores the persisted Tor working set after an agent
// restart without rerunning candidate probes or rewriting working-pool state.
// A matching runtime remains a read-only authoritative check.
