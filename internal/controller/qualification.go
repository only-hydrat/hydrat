package controller

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qualifier"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

type VLESSQualifier interface {
	Qualify(context.Context, []qualifier.Input) []qualifier.Result
}

type TorProfileAgent interface {
	ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error)
	ExploreNext(context.Context) ([]torpool.Profile, error)
}

type torRuntimeProfileRepairer interface {
	RepairProfiles(context.Context, []torpool.Candidate) (bool, error)
}

type CandidateMeasurer interface {
	Measure(context.Context, string, health.Protocol) (health.Metrics, error)
}

type CandidateProbeAgent interface {
	ProbeFast(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)
	ProbeFull(context.Context, agentapi.ProbeRequest) (agentapi.ProbeResponse, error)
}

type QualificationService struct {
	Store          *store.Store
	Agent          CandidateProbeAgent
	VLESS          VLESSQualifier
	Tor            TorProfileAgent
	Measurer       CandidateMeasurer
	PoolSize       int
	PromotionRatio float64
	ResetWindow    time.Duration
	FastWorkers    int
	FullWorkers    int
	// TorCandidatesPerCycle bounds background Tor qualification so a large Tor
	// pool cannot starve the next VLESS qualification cycle. Zero is unlimited.
	TorCandidatesPerCycle int
	// TorQualificationBudget caps the Tor portion of one mixed qualification
	// cycle. Zero is unlimited.
	TorQualificationBudget time.Duration
	// TorMutationTimeout bounds each working-pool/profile reconciliation. Zero
	// is unlimited.
	TorMutationTimeout       time.Duration
	Promotions               chan<- struct{}
	DisallowRUEgress         bool
	beforeWorkingPoolList    func(attempt int)
	beforeWorkingPoolReplace func(attempt int)
	beforeWorkingPoolPayload func(attempt, index int, candidate store.Candidate)
}

func (service QualificationService) Run(ctx context.Context, now time.Time) error {
	if service.Agent != nil {
		return service.runAgent(ctx, now)
	}
	candidates, err := service.Store.ListCandidates(ctx, "")
	if err != nil {
		return err
	}
	previousHealth, err := service.Store.ListCandidateHealth(ctx)
	if err != nil {
		return err
	}
	previousByID := make(map[string]store.CandidateHealth, len(previousHealth))
	for _, row := range previousHealth {
		previousByID[row.CandidateID] = row
	}
	vlessInputs := make([]qualifier.Input, 0)
	torCandidates := make([]torpool.Candidate, 0)
	payloadByID := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		payload, err := service.Store.CandidatePayload(ctx, candidate.ID)
		if err != nil {
			return err
		}
		payloadByID[candidate.ID] = payload
		switch candidate.Kind {
		case sources.KindVLESS:
			vlessInputs = append(vlessInputs, qualifier.Input{ID: candidate.ID, Payload: payload})
		case sources.KindTorBridge:
			score := 50.0
			if previous, exists := previousByID[candidate.ID]; exists {
				score = previous.Score
			}
			torCandidates = append(torCandidates, torpool.Candidate{
				ID: candidate.ID, Bridge: payload, Score: score, Qualified: true,
			})
		}
	}
	if service.VLESS != nil && len(vlessInputs) > 0 {
		requests := make([]store.ObservationRequest, 0, len(vlessInputs))
		for _, input := range vlessInputs {
			candidate, exists := candidateByID(candidates, input.ID)
			if !exists {
				continue
			}
			requests = append(requests, store.ObservationRequest{
				Candidate: candidate, Stage: store.ObservationFull,
			})
		}
		reservations, err := service.Store.ReserveCandidateObservations(
			ctx, requests,
		)
		if err != nil {
			return err
		}
		reservationByID := make(map[string]store.ObservationReservation, len(reservations))
		for _, reservation := range reservations {
			reservationByID[reservation.CandidateID] = reservation
		}
		for _, result := range service.VLESS.Qualify(ctx, vlessInputs) {
			candidate, exists := candidateByID(candidates, result.CandidateID)
			if !exists {
				continue
			}
			reservation, exists := reservationByID[result.CandidateID]
			if !exists {
				continue
			}
			transition := store.ProbeTransition{
				Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
				SourceID: candidate.SourceID, Full: true, At: now,
			}
			if result.InfrastructureFailure {
				sample := store.ProbeSample{
					CandidateID: result.CandidateID, Success: false, CreatedAt: now,
				}
				transition.InfrastructureFailure = true
				transition.ErrorCode = "agent_unavailable"
				_, _, err := service.Store.CommitCandidateProbeObservation(
					ctx, candidate, reservation, transition, nil, &sample,
				)
				if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
					continue
				}
				if err != nil {
					return err
				}
				continue
			}
			available := result.Err == nil && result.Evaluation.TCPQualified
			score := result.Evaluation.Score
			tcpQualified := result.Evaluation.TCPQualified
			udpQualified := result.Evaluation.UDPQualified
			errorCode := health.QualificationFailureCode(result.Metrics, result.Evaluation)
			if service.DisallowRUEgress && sources.IsRussianEgress(candidate.Label, payloadByID[candidate.ID]) {
				available = false
				tcpQualified = false
				udpQualified = false
				score = 0
				errorCode = "ru_egress_forbidden"
			}
			candidateHealth := store.CandidateHealth{
				CandidateID: result.CandidateID, Score: score,
				TCPQualified: tcpQualified, UDPQualified: udpQualified,
				Available: available, LatencyMS: float64(result.Metrics.Latency) / float64(time.Millisecond),
				ThroughputMbps: result.Metrics.ThroughputMbps, UpdatedAt: now,
			}
			sample := store.ProbeSample{
				CandidateID: result.CandidateID, Success: available,
				LatencyMS:      float64(result.Metrics.Latency) / float64(time.Millisecond),
				ThroughputMbps: result.Metrics.ThroughputMbps, PacketDropRatio: result.Metrics.PacketDropRatio, CreatedAt: now,
			}
			transition.Success = available
			transition.ErrorCode = errorCode
			transition.Score = score
			_, _, err := service.Store.CommitCandidateProbeObservation(
				ctx, candidate, reservation, transition, &candidateHealth, &sample,
			)
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				continue
			}
			if err != nil {
				return err
			}
		}
	}
	if service.Tor != nil && service.Measurer != nil && len(torCandidates) > 0 {
		requests := make([]store.ObservationRequest, 0, len(torCandidates))
		for _, candidate := range candidates {
			if candidate.Kind == sources.KindTorBridge {
				requests = append(requests, store.ObservationRequest{
					Candidate: candidate, Stage: store.ObservationFull,
				})
			}
		}
		reservations, err := service.Store.ReserveCandidateObservations(
			ctx, requests,
		)
		if err != nil {
			return err
		}
		reservationByID := make(map[string]store.ObservationReservation, len(reservations))
		for _, reservation := range reservations {
			reservationByID[reservation.CandidateID] = reservation
		}
		profiles, stableTorCandidates, err := service.reconcileAllActiveTor(
			ctx, previousByID,
		)
		if err != nil {
			return err
		}
		for _, profile := range profiles {
			candidate, exists := candidateByID(candidates, profile.CandidateID)
			if !exists {
				continue
			}
			reservation, exists := reservationByID[profile.CandidateID]
			if !exists {
				continue
			}
			metrics, measureErr := service.Measurer.Measure(ctx, profile.SocksAddr, health.ProtocolTor)
			evaluation := health.Evaluate(metrics, health.ProtocolTor)
			available := measureErr == nil && evaluation.TCPQualified
			score := evaluation.Score
			tcpQualified := evaluation.TCPQualified
			errorCode := health.QualificationFailureCode(metrics, evaluation)
			if service.DisallowRUEgress && sources.IsRussianEgress(candidate.Label, payloadByID[candidate.ID]) {
				available = false
				tcpQualified = false
				score = 0
				errorCode = "ru_egress_forbidden"
			}
			candidateHealth := store.CandidateHealth{
				CandidateID: profile.CandidateID, Score: score,
				TCPQualified: tcpQualified, UDPQualified: false, Available: available,
				LatencyMS:      float64(metrics.Latency) / float64(time.Millisecond),
				ThroughputMbps: metrics.ThroughputMbps, UpdatedAt: now,
			}
			sample := store.ProbeSample{
				CandidateID: profile.CandidateID, Success: available,
				LatencyMS:      float64(metrics.Latency) / float64(time.Millisecond),
				ThroughputMbps: metrics.ThroughputMbps, PacketDropRatio: metrics.PacketDropRatio, CreatedAt: now,
			}
			_, _, err := service.Store.CommitCandidateProbeObservation(
				ctx,
				candidate,
				reservation,
				store.ProbeTransition{
					Fingerprint: candidate.Fingerprint, CandidateID: candidate.ID,
					SourceID: candidate.SourceID, Full: true, Success: available,
					ErrorCode: errorCode,
					Score:     score, At: now,
				},
				&candidateHealth,
				&sample,
			)
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				continue
			}
			if err != nil {
				return err
			}
		}
		if len(stableTorCandidates) > len(profiles) {
			if _, err := service.Tor.ExploreNext(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func (service QualificationService) reconcileAllActiveTor(
	ctx context.Context,
	previousByID map[string]store.CandidateHealth,
) ([]torpool.Profile, []store.Candidate, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		current, err := service.Store.ListCandidates(ctx, "")
		if err != nil {
			return nil, nil, err
		}
		torRows := make([]store.Candidate, 0, len(current))
		for _, candidate := range current {
			if candidate.Kind == sources.KindTorBridge {
				torRows = append(torRows, candidate)
			}
		}
		payloads, epoch, err := service.Store.ActiveCandidatePayloadsSnapshot(
			ctx, torRows,
		)
		if err != nil {
			return nil, nil, err
		}
		if len(payloads) != len(torRows) {
			continue
		}
		candidates := make([]torpool.Candidate, 0, len(payloads))
		for _, snapshot := range payloads {
			score := 50.0
			if previous, exists := previousByID[snapshot.Candidate.ID]; exists {
				score = previous.Score
			}
			candidates = append(candidates, torpool.Candidate{
				ID: snapshot.Candidate.ID, Bridge: snapshot.Payload,
				Score: score, Qualified: true,
			})
		}
		profiles, err := service.Tor.ReconcileProfiles(ctx, candidates)
		if err != nil {
			return nil, nil, err
		}
		currentEpoch, err := service.Store.InventoryEpoch(ctx)
		if err != nil {
			return nil, nil, err
		}
		if currentEpoch == epoch {
			return profiles, torRows, nil
		}
		// A changed epoch retries immediately; the next RPC compensates the
		// runtime using a fresh active-only payload snapshot.
	}
	if _, err := service.Tor.ReconcileProfiles(ctx, nil); err != nil {
		return nil, nil, err
	}
	return nil, nil, store.ErrCandidateInventoryChanged
}

func candidateByID(candidates []store.Candidate, candidateID string) (store.Candidate, bool) {
	for _, candidate := range candidates {
		if candidate.ID == candidateID {
			return candidate, true
		}
	}
	return store.Candidate{}, false
}

func (service QualificationService) runAgent(ctx context.Context, now time.Time) error {
	candidates, err := service.Store.ListCandidates(ctx, "")
	if err != nil {
		return err
	}
	if service.PoolSize <= 0 {
		service.PoolSize = 200
	}
	if service.PromotionRatio <= 0 {
		service.PromotionRatio = 0.15
	}
	if service.ResetWindow <= 0 {
		service.ResetWindow = 5 * time.Hour
	}
	if service.FastWorkers <= 0 {
		service.FastWorkers = 8
	}
	if service.FullWorkers <= 0 {
		service.FullWorkers = 4
	}
	vlessCandidates := make([]store.Candidate, 0, len(candidates))
	torCandidates := make([]store.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		switch candidate.Kind {
		case sources.KindVLESS:
			vlessCandidates = append(vlessCandidates, candidate)
		case sources.KindTorBridge:
			torCandidates = append(torCandidates, candidate)
		}
	}
	return runConcurrentQualificationLanes(
		ctx,
		func(laneCtx context.Context) error {
			fullJobs, err := service.discoveryJobs(
				laneCtx, vlessCandidates, now, tournament.ProbeFull,
			)
			if err != nil {
				return err
			}
			healthRows, err := service.Store.ListCandidateHealth(laneCtx)
			if err != nil {
				return err
			}
			udpQualified := make(map[string]bool, len(healthRows))
			healthByID := make(map[string]store.CandidateHealth, len(healthRows))
			cachedTCP := make(map[string]bool, len(healthRows))
			for _, row := range healthRows {
				udpQualified[row.CandidateID] = row.UDPQualified
				healthByID[row.CandidateID] = row
			}
			probeStates, err := service.Store.ListCandidateProbeStates(laneCtx)
			if err != nil {
				return err
			}
			for _, state := range probeStates {
				if state.Status == store.CandidateUnknown || state.Status == store.CandidatePreflight {
					row := healthByID[state.CandidateID]
					cachedTCP[state.CandidateID] = row.Available && row.TCPQualified
				}
			}
			promotionJobs := make([]qualificationJob, 0, len(fullJobs))
			attemptedPromotions := make(map[string]struct{})
			for _, job := range fullJobs {
				if job.priority == tournament.PriorityOneSuccess ||
					udpQualified[job.candidate.ID] || cachedTCP[job.candidate.ID] {
					job.retryInfrastructure = udpQualified[job.candidate.ID] || cachedTCP[job.candidate.ID]
					promotionJobs = append(promotionJobs, job)
					attemptedPromotions[job.candidate.Fingerprint] = struct{}{}
				}
			}
			sort.SliceStable(promotionJobs, func(i, j int) bool {
				return udpQualified[promotionJobs[i].candidate.ID] &&
					!udpQualified[promotionJobs[j].candidate.ID]
			})
			if err := service.runProbeJobs(
				laneCtx, now, promotionJobs, tournament.ProbeFull, service.FullWorkers,
			); err != nil {
				return err
			}
			confirmationJobs, err := service.discoveryJobs(
				laneCtx, vlessCandidates, now, tournament.ProbeFull,
			)
			if err != nil {
				return err
			}
			confirmations := confirmationJobs[:0]
			for _, job := range confirmationJobs {
				_, attempted := attemptedPromotions[job.candidate.Fingerprint]
				if attempted && job.priority == tournament.PriorityOneSuccess {
					confirmations = append(confirmations, job)
				}
			}
			if err := service.runProbeJobs(
				laneCtx, now, confirmations, tournament.ProbeFull, service.FullWorkers,
			); err != nil {
				return err
			}
			fastJobs, err := service.discoveryJobs(
				laneCtx, vlessCandidates, now, tournament.ProbeFast,
			)
			if err != nil {
				return err
			}
			udpRecoveryFast := make([]qualificationJob, 0)
			remainingFast := make([]qualificationJob, 0, len(fastJobs))
			udpRecovery := make(map[string]struct{})
			for _, job := range fastJobs {
				if udpQualified[job.candidate.ID] {
					job.retryInfrastructure = true
					udpRecoveryFast = append(udpRecoveryFast, job)
					udpRecovery[job.candidate.Fingerprint] = struct{}{}
					attemptedPromotions[job.candidate.Fingerprint] = struct{}{}
				} else {
					remainingFast = append(remainingFast, job)
				}
			}
			if err := service.runProbeJobs(
				laneCtx, now, udpRecoveryFast, tournament.ProbeFast, service.FastWorkers,
			); err != nil {
				return err
			}
			for confirmation := 0; confirmation < 2; confirmation++ {
				recoveryJobs, err := service.discoveryJobs(
					laneCtx, vlessCandidates, now, tournament.ProbeFull,
				)
				if err != nil {
					return err
				}
				recovery := recoveryJobs[:0]
				for _, job := range recoveryJobs {
					_, attempted := udpRecovery[job.candidate.Fingerprint]
					if attempted && (confirmation == 0 || job.priority == tournament.PriorityOneSuccess) {
						recovery = append(recovery, job)
					}
				}
				if err := service.runProbeJobs(
					laneCtx, now, recovery, tournament.ProbeFull, service.FullWorkers,
				); err != nil {
					return err
				}
			}
			if err := service.runProbeJobs(
				laneCtx, now, remainingFast, tournament.ProbeFast, service.FastWorkers,
			); err != nil {
				return err
			}
			fullJobs, err = service.discoveryJobs(
				laneCtx, vlessCandidates, now, tournament.ProbeFull,
			)
			if err != nil {
				return err
			}
			remaining := fullJobs[:0]
			for _, job := range fullJobs {
				if _, attempted := attemptedPromotions[job.candidate.Fingerprint]; !attempted {
					remaining = append(remaining, job)
				}
			}
			if err := service.runProbeJobs(
				laneCtx, now, remaining, tournament.ProbeFull, service.FullWorkers,
			); err != nil {
				return err
			}
			currentCandidates, err := service.Store.ListCandidates(laneCtx, "")
			if err != nil {
				return err
			}
			_, err = service.updateWorkingPool(laneCtx, currentCandidates, now)
			return err
		},
		func(laneCtx context.Context) error {
			return service.runTorCandidates(
				laneCtx, torCandidates, candidates, now,
			)
		},
	)
}

func runConcurrentQualificationLanes(
	ctx context.Context,
	vless func(context.Context) error,
	tor func(context.Context) error,
) error {
	laneCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	for _, lane := range []func(context.Context) error{vless, tor} {
		lane := lane
		go func() { results <- lane(laneCtx) }()
	}
	var found []error
	for range 2 {
		if err := <-results; err != nil {
			found = append(found, err)
			cancel()
		}
	}
	return errors.Join(found...)
}
