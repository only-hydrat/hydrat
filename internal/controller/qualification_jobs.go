package controller

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

type qualificationJob struct {
	candidate           store.Candidate
	payload             string
	reservation         store.ObservationReservation
	priority            tournament.Priority
	retryInfrastructure bool
}

type qualificationResult struct {
	job         qualificationJob
	reservation store.ObservationReservation
	response    agentapi.ProbeResponse
	reserveErr  error
	err         error
}

func (service QualificationService) discoveryJobs(
	ctx context.Context,
	candidates []store.Candidate,
	now time.Time,
	stage tournament.ProbeStage,
) ([]qualificationJob, error) {
	states, err := service.Store.ListCandidateProbeStates(ctx)
	if err != nil {
		return nil, err
	}
	stateByFingerprint := make(map[string]store.CandidateProbeState, len(states))
	for _, state := range states {
		stateByFingerprint[state.Fingerprint] = state
	}
	failureDomainStates, err := service.Store.ListFailureDomainStates(ctx)
	if err != nil {
		return nil, err
	}
	openDomains := make(map[string]store.FailureDomainState)
	for _, state := range failureDomainStates {
		if state.Domain != "" && state.OpenUntil.After(now) {
			openDomains[state.Domain] = state
		}
	}
	currentVLESSByDomain := make(map[string][]store.Candidate)
	currentVLESSByID := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		if candidate.Kind == sources.KindVLESS && candidate.FailureDomain != "" {
			currentVLESSByID[candidate.ID] = candidate
			currentVLESSByDomain[candidate.FailureDomain] = append(
				currentVLESSByDomain[candidate.FailureDomain],
				candidate,
			)
		}
	}
	canaries := make([]store.Candidate, 0, len(openDomains))
	for domain, state := range openDomains {
		current := currentVLESSByDomain[domain]
		if len(current) == 0 {
			continue
		}
		selected, exists := currentVLESSByID[state.CanaryCandidate]
		if !exists || selected.FailureDomain != domain {
			candidateIDs := make([]string, 0, len(current))
			for _, candidate := range current {
				candidateIDs = append(candidateIDs, candidate.ID)
			}
			elected, err := service.Store.ElectFailureDomainCanary(
				ctx, domain, candidateIDs, now,
			)
			if errors.Is(err, store.ErrFailureDomainNotOpen) {
				continue
			}
			if err != nil {
				return nil, err
			}
			selected, exists = currentVLESSByID[elected.CanaryCandidate]
			if !exists {
				continue
			}
		}
		canaries = append(canaries, selected)
	}
	sort.Slice(canaries, func(i, j int) bool {
		return canaries[i].ID < canaries[j].ID
	})
	queueCandidates := make([]tournament.Candidate, 0, len(candidates))
	candidateByFingerprint := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		if _, open := openDomains[candidate.FailureDomain]; candidate.FailureDomain != "" && open {
			continue
		}
		state := stateByFingerprint[candidate.Fingerprint]
		queueCandidates = append(queueCandidates, discoveryCandidate(candidate, state))
		candidateByFingerprint[candidate.Fingerprint] = candidate
	}
	queued := tournament.BuildDiscoveryQueue(queueCandidates, tournament.QueuePolicy{
		Now: now, ResetWindow: service.ResetWindow,
	})
	jobs := make([]qualificationJob, 0, len(queued))
	for _, queuedJob := range queued {
		if queuedJob.Stage != stage {
			continue
		}
		candidate := candidateByFingerprint[queuedJob.Fingerprint]
		payload, err := service.Store.CandidatePayload(ctx, candidate.ID)
		if err != nil {
			return nil, err
		}
		if service.DisallowRUEgress && sources.IsRussianEgress(candidate.Label, payload) {
			continue
		}
		jobs = append(jobs, qualificationJob{
			candidate: candidate, payload: payload, priority: queuedJob.Priority,
		})
	}
	if stage == tournament.ProbeFull {
		jobs = interleaveFullProbeJobsByFailureDomain(jobs)
		for _, candidate := range canaries {
			payload, err := service.Store.CandidatePayload(ctx, candidate.ID)
			if err != nil {
				return nil, err
			}
			if service.DisallowRUEgress && sources.IsRussianEgress(candidate.Label, payload) {
				continue
			}
			jobs = append(jobs, qualificationJob{candidate: candidate, payload: payload})
		}
	}
	return jobs, nil
}

func interleaveFullProbeJobsByFailureDomain(
	jobs []qualificationJob,
) []qualificationJob {
	if len(jobs) < 2 {
		return jobs
	}
	ordered := make([]qualificationJob, 0, len(jobs))
	for start := 0; start < len(jobs); {
		end := start + 1
		for end < len(jobs) && jobs[end].priority == jobs[start].priority {
			end++
		}
		ordered = append(ordered, interleaveFullProbePriorityGroup(jobs[start:end])...)
		start = end
	}
	return ordered
}

func interleaveFullProbePriorityGroup(jobs []qualificationJob) []qualificationJob {
	type domainBucket struct {
		jobs []qualificationJob
		next int
	}
	buckets := make([]domainBucket, 0, len(jobs))
	bucketByKey := make(map[string]int, len(jobs))
	for _, job := range jobs {
		key := "domain\x00" + job.candidate.FailureDomain
		if job.candidate.FailureDomain == "" {
			key = "candidate\x00" + job.candidate.ID
		}
		index, exists := bucketByKey[key]
		if !exists {
			index = len(buckets)
			bucketByKey[key] = index
			buckets = append(buckets, domainBucket{})
		}
		buckets[index].jobs = append(buckets[index].jobs, job)
	}
	ordered := make([]qualificationJob, 0, len(jobs))
	active := make([]int, len(buckets))
	for index := range buckets {
		active[index] = index
	}
	for len(active) > 0 {
		nextRound := make([]int, 0, len(active))
		for _, index := range active {
			bucket := &buckets[index]
			ordered = append(ordered, bucket.jobs[bucket.next])
			bucket.next++
			if bucket.next < len(bucket.jobs) {
				nextRound = append(nextRound, index)
			}
		}
		active = nextRound
	}
	return ordered
}

func discoveryCandidate(
	candidate store.Candidate,
	state store.CandidateProbeState,
) tournament.Candidate {
	return tournament.Candidate{
		Fingerprint: candidate.Fingerprint, Status: tournament.Status(state.Status),
		FullSuccessStreak: state.FullSuccessStreak,
		ConservativeScore: state.ConservativeScore,
		InWorkingPool:     state.InWorkingPool, Draining: state.Draining,
		Stale: state.Stale, BannedUntil: state.BannedUntil,
		WindowStartedAt: state.WindowStartedAt,
		LastFastProbeAt: state.LastFastProbeAt, LastFullProbeAt: state.LastFullProbeAt,
	}
}

func (service QualificationService) runProbeJobs(
	ctx context.Context,
	now time.Time,
	pending []qualificationJob,
	stage tournament.ProbeStage,
	workerCount int,
) error {
	observationStage := store.ObservationFull
	if stage == tournament.ProbeFast {
		observationStage = store.ObservationFast
	}
	requests := make([]store.ObservationRequest, 0, len(pending))
	for _, job := range pending {
		requests = append(requests, store.ObservationRequest{
			Candidate: job.candidate,
			Stage:     observationStage,
		})
	}
	reservations, err := service.Store.ReserveCandidateObservations(ctx, requests)
	if err != nil {
		return err
	}
	for index := range pending {
		pending[index].reservation = reservations[index]
	}
	jobs := make(chan qualificationJob)
	results := make(chan qualificationResult, len(pending))
	var workers sync.WaitGroup
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				result := service.executeProbe(ctx, job, stage)
				if job.retryInfrastructure &&
					(result.err != nil || result.response.FailureClass == agentapi.FailureInfrastructure) {
					timer := time.NewTimer(time.Second)
					select {
					case <-timer.C:
						result = service.executeProbe(ctx, job, stage)
					case <-ctx.Done():
						timer.Stop()
					}
				}
				results <- result
			}
		}()
	}
	go func() {
		for _, job := range pending {
			select {
			case jobs <- job:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	for result := range results {
		state, err := service.recordProbeResult(ctx, now, result, stage)
		if err != nil {
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				continue
			}
			return err
		}
		if stage == tournament.ProbeFull &&
			result.job.candidate.Kind == sources.KindVLESS &&
			state.Status == store.CandidateQualified &&
			state.FullSuccessStreak == 2 && !state.InWorkingPool {
			if err := service.promoteQualifiedVLESS(
				ctx, result.job.candidate, now,
			); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (service QualificationService) promoteQualifiedVLESS(
	ctx context.Context,
	candidate store.Candidate,
	now time.Time,
) error {
	if _, err := service.updateWorkingPool(ctx, nil, now); err != nil {
		return err
	}
	state, err := service.Store.CandidateProbeState(ctx, candidate.Fingerprint)
	if err != nil {
		return err
	}
	if state.CandidateID != candidate.ID || state.SourceID != candidate.SourceID {
		return store.ErrCandidateNoLongerCurrent
	}
	if state.Status == store.CandidateQualified &&
		state.InWorkingPool && !state.Draining {
		service.signalPromotion()
	}
	return nil
}

func (service QualificationService) executeProbe(
	ctx context.Context,
	job qualificationJob,
	stage tournament.ProbeStage,
) qualificationResult {
	if job.reservation.Sequence == 0 {
		observationStage := store.ObservationFull
		if stage == tournament.ProbeFast {
			observationStage = store.ObservationFast
		}
		reservation, err := service.Store.ReserveCandidateObservation(
			ctx, job.candidate, observationStage,
		)
		if err != nil {
			return qualificationResult{job: job, reserveErr: err}
		}
		job.reservation = reservation
	}
	request := agentapi.ProbeRequest{
		CandidateID: job.candidate.ID,
		Kind:        job.candidate.Kind,
		Payload:     job.payload,
	}
	var response agentapi.ProbeResponse
	var err error
	if stage == tournament.ProbeFast {
		response, err = service.Agent.ProbeFast(ctx, request)
	} else {
		response, err = service.Agent.ProbeFull(ctx, request)
	}
	return qualificationResult{
		job: job, reservation: job.reservation, response: response, err: err,
	}
}

func (service QualificationService) recordProbeResult(
	ctx context.Context,
	now time.Time,
	result qualificationResult,
	stage tournament.ProbeStage,
) (store.CandidateProbeState, error) {
	if result.reserveErr != nil {
		return store.CandidateProbeState{}, result.reserveErr
	}
	if result.reservation.Sequence == 0 {
		observationStage := store.ObservationFull
		if stage == tournament.ProbeFast {
			observationStage = store.ObservationFast
		}
		reservation, err := service.Store.ReserveCandidateObservation(
			ctx, result.job.candidate, observationStage,
		)
		if err != nil {
			return store.CandidateProbeState{}, err
		}
		result.reservation = reservation
	}
	transition := store.ProbeTransition{
		Fingerprint: result.job.candidate.Fingerprint,
		CandidateID: result.job.candidate.ID,
		SourceID:    result.job.candidate.SourceID,
		Full:        stage == tournament.ProbeFull,
		At:          now,
		ResetWindow: service.ResetWindow,
	}
	if result.err != nil || result.response.FailureClass == agentapi.FailureInfrastructure {
		transition.InfrastructureFailure = true
		transition.ErrorCode = "agent_unavailable"
		state, _, err := service.Store.CommitCandidateProbeObservation(
			ctx, result.job.candidate, result.reservation, transition, nil, nil,
		)
		return state, err
	}
	transition.Success = result.response.Success
	transition.ErrorCode = result.response.ErrorCode
	if stage == tournament.ProbeFast {
		if service.DisallowRUEgress && sources.IsRussianEgress(result.job.candidate.Label, result.job.payload) {
			transition.Success = false
			transition.ErrorCode = "ru_egress_forbidden"
		}
		state, _, err := service.Store.CommitCandidateProbeObservation(
			ctx, result.job.candidate, result.reservation, transition, nil, nil,
		)
		return state, err
	}
	available := result.response.Success && result.response.Evaluation.TCPQualified
	score := result.response.Evaluation.Score
	tcpQualified := result.response.Evaluation.TCPQualified
	udpQualified := result.response.Evaluation.UDPQualified
	errorCode := result.response.ErrorCode
	if service.DisallowRUEgress && sources.IsRussianEgress(result.job.candidate.Label, result.job.payload) {
		available = false
		tcpQualified = false
		udpQualified = false
		score = 0
		errorCode = "ru_egress_forbidden"
	}
	candidateHealth := store.CandidateHealth{
		CandidateID:    result.job.candidate.ID,
		Score:          score,
		TCPQualified:   tcpQualified,
		UDPQualified:   udpQualified,
		Available:      available,
		LatencyMS:      float64(result.response.Metrics.Latency) / float64(time.Millisecond),
		ThroughputMbps: result.response.Metrics.ThroughputMbps,
		UpdatedAt:      now,
	}
	transition.Success = available
	transition.Score = score
	transition.ErrorCode = errorCode
	sample := store.ProbeSample{
		CandidateID:     result.job.candidate.ID,
		Success:         available,
		LatencyMS:       float64(result.response.Metrics.Latency) / float64(time.Millisecond),
		ThroughputMbps:  result.response.Metrics.ThroughputMbps,
		PacketDropRatio: result.response.Metrics.PacketDropRatio,
		CreatedAt:       now,
	}
	state, commit, err := service.Store.CommitCandidateProbeObservation(
		ctx, result.job.candidate, result.reservation, transition,
		&candidateHealth, &sample,
	)
	if err != nil {
		return state, err
	}
	if !commit.Accepted {
		return state, nil
	}
	if result.job.candidate.Kind == sources.KindVLESS &&
		result.job.candidate.FailureDomain != "" &&
		available {
		if err := service.Store.RecordFailureDomainSuccess(
			ctx, result.job.candidate.FailureDomain, now,
		); err != nil {
			return state, err
		}
	} else if result.job.candidate.Kind == sources.KindVLESS &&
		result.job.candidate.FailureDomain != "" &&
		result.response.FailureClass == agentapi.FailureCandidate &&
		result.response.ErrorCode == "full_probe_failed" {
		domainStates, err := service.Store.ListFailureDomainStates(ctx)
		if err != nil {
			return state, err
		}
		for _, domainState := range domainStates {
			if domainState.Domain != result.job.candidate.FailureDomain ||
				domainState.CanaryCandidate != result.job.candidate.ID ||
				!domainState.OpenUntil.After(now) {
				continue
			}
			if _, err := service.Store.RecordFailureDomainFailure(
				ctx,
				result.job.candidate.FailureDomain,
				result.job.candidate.ID,
				now,
			); err != nil {
				return state, err
			}
			break
		}
	}
	return state, nil
}
