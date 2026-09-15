package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/qualifier"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func (monitor *ActiveMonitor) applyObservations(
	ctx context.Context,
	now time.Time,
	observations map[string]health.Observation,
	healthByID map[string]store.CandidateHealth,
	candidateByID map[string]store.Candidate,
) error {
	reserved := make(map[string]activeObservation, len(observations))
	for candidateID, observation := range observations {
		candidate, found := candidateByID[candidateID]
		if !found {
			continue
		}
		reservation, err := monitor.Store.ReserveCandidateObservation(
			ctx, candidate, store.ObservationActive,
		)
		if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
			monitor.trackerMu.Lock()
			monitor.clearCandidateActiveStateLocked(candidateID)
			monitor.trackerMu.Unlock()
			continue
		}
		if err != nil {
			return err
		}
		reserved[candidateID] = activeObservation{
			observation: observation, reservation: reservation, completedAt: now,
		}
	}
	return monitor.applyReservedObservations(
		ctx, now, reserved, healthByID, candidateByID,
	)
}

func (monitor *ActiveMonitor) applyReservedObservations(
	ctx context.Context,
	now time.Time,
	observations map[string]activeObservation,
	healthByID map[string]store.CandidateHealth,
	candidateByID map[string]store.Candidate,
) error {
	capacityChanged := false
	defer func() {
		if capacityChanged && monitor.CapacityChanges != nil {
			select {
			case monitor.CapacityChanges <- struct{}{}:
			default:
			}
		}
	}()
	monitor.trackerMu.Lock()
	defer monitor.trackerMu.Unlock()
	rows, err := monitor.Store.ListCandidateHealth(ctx)
	if err != nil {
		return err
	}
	healthByID = make(map[string]store.CandidateHealth, len(rows))
	for _, row := range rows {
		healthByID[row.CandidateID] = row
	}
	if monitor.trackers == nil {
		monitor.trackers = make(map[string]*health.Tracker)
	}
	if monitor.hardFailureSuspects == nil {
		monitor.hardFailureSuspects = make(map[string]time.Time)
	}
	if monitor.availabilityFailures == nil {
		monitor.availabilityFailures = make(map[string]availabilityFailureState)
	}
	for candidateID, reserved := range observations {
		completedAt := reserved.completedAt
		if completedAt.IsZero() {
			completedAt = now
		}
		row, exists := healthByID[candidateID]
		if !exists {
			monitor.clearCandidateActiveStateLocked(candidateID)
			continue
		}
		candidate, found := candidateByID[candidateID]
		if !found {
			monitor.clearCandidateActiveStateLocked(candidateID)
			continue
		}
		proofFreshAfter := reserved.proofFreshAfter
		if monitor.ProofFreshness > 0 {
			proofFreshAfter = completedAt.Add(-monitor.ProofFreshness)
		}
		tracker := monitor.trackers[candidateID]
		if tracker == nil && !row.Available {
			// Only full qualification can restore a candidate that failed
			// YouTube/ChatGPT/Telegram gates. Liveness recovers quarantines that it
			// created itself, and cannot bypass those service gates.
			delete(monitor.hardFailureSuspects, candidateID)
			delete(monitor.availabilityFailures, candidateID)
			continue
		}
		wasAvailable := row.Available
		wasProofEligible := row.ActiveSuccess && row.ActiveCurrent &&
			(proofFreshAfter.IsZero() ||
				!row.ActiveObservedAt.Before(proofFreshAfter))
		dnsHardFailure := monitor.observeAvailabilityLocked(candidateID, reserved)
		completeFailure := !reserved.observation.PrimaryOK &&
			!reserved.observation.ConfirmationOK
		if completeFailure && !monitor.ConfirmCompleteFailureInCycle &&
			!reserved.probeStartedAt.IsZero() {
			suspectCompletedAt, suspected :=
				monitor.hardFailureSuspects[candidateID]
			if suspected && monitor.ProofFreshness > 0 &&
				reserved.probeStartedAt.After(
					suspectCompletedAt.Add(monitor.ProofFreshness),
				) {
				delete(monitor.hardFailureSuspects, candidateID)
				suspected = false
			}
			confirmed := suspected &&
				!reserved.probeStartedAt.Before(suspectCompletedAt)
			if !confirmed {
				commit, err := monitor.Store.CommitCandidateActiveOutcome(
					ctx, candidate, reserved.reservation,
					store.ActiveObservationOutcome{
						Available:           row.Available,
						ProofSuccess:        false,
						RetainPreviousProof: wasProofEligible,
						ProofFreshAfter:     proofFreshAfter,
					},
					completedAt,
				)
				if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
					monitor.clearCandidateActiveStateLocked(candidateID)
					continue
				}
				if err != nil {
					return err
				}
				if commit.Accepted && !suspected {
					monitor.hardFailureSuspects[candidateID] = completedAt
				}
				continue
			}
		}
		if tracker == nil {
			tracker = health.NewTracker(5*time.Minute, 3)
		}
		preview := *tracker
		preview.Observe(completedAt, reserved.observation)
		state := preview.State(completedAt)
		row.Available = state.Available
		row.UpdatedAt = completedAt
		retainPreviousProof := state.Degraded && state.Available && wasProofEligible
		recordedHealth := false
		accepted := false
		if wasAvailable && !state.Available {
			var err error
			var commit store.ObservationCommitResult
			if candidate.Kind == sources.KindVLESS && candidate.FailureDomain != "" {
				_, commit, err = monitor.Store.CommitActiveVLESSHardFailureObservation(
					ctx, candidate, reserved.reservation, completedAt,
				)
			} else {
				_, commit, err =
					monitor.Store.CommitCandidateActiveHardFailureObservation(
						ctx, candidate, reserved.reservation, completedAt,
					)
			}
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				monitor.clearCandidateActiveStateLocked(candidateID)
				continue
			}
			if err != nil {
				return err
			}
			if !commit.Accepted {
				continue
			}
			monitor.trackers[candidateID] = &preview
			delete(monitor.hardFailureSuspects, candidateID)
			accepted = true
			recordedHealth = true
			if accepted {
				message := "primary and confirmation liveness checks failed"
				if dnsHardFailure {
					message = fmt.Sprintf(
						"routed DNS failed in %d consecutive active cycles",
						monitor.availabilityFailureThreshold(),
					)
					delete(monitor.availabilityFailures, candidateID)
				}
				_ = monitor.Store.AppendEvent(ctx, store.Event{
					Kind: "candidate_hard_failure", CandidateID: candidateID,
					Message:   message,
					CreatedAt: completedAt,
				})
				if monitor.HardFailures != nil {
					probeStartedAt := reserved.probeStartedAt
					if probeStartedAt.IsZero() {
						probeStartedAt = completedAt
					}
					event, err := NewHardFailureEvent(
						candidateID,
						probeStartedAt,
						completedAt,
						monitor.HardFailureDeadline,
					)
					if err != nil {
						return fmt.Errorf("publish hard failure event: %w", err)
					}
					monitor.HardFailures.Publish(event)
				}
				if monitor.Trigger != nil {
					select {
					case monitor.Trigger <- struct{}{}:
					default:
					}
				}
			}
		}
		if !recordedHealth {
			commit, err := monitor.Store.CommitCandidateActiveOutcome(
				ctx, candidate, reserved.reservation,
				store.ActiveObservationOutcome{
					Available:           row.Available,
					ProofSuccess:        proofSuccess(reserved.observation),
					RetainPreviousProof: retainPreviousProof,
					ProofFreshAfter:     proofFreshAfter,
				},
				completedAt,
			)
			if errors.Is(err, store.ErrCandidateNoLongerCurrent) {
				monitor.clearCandidateActiveStateLocked(candidateID)
				continue
			}
			if err != nil {
				return err
			}
			if !commit.Accepted {
				continue
			}
			monitor.trackers[candidateID] = &preview
			if !completeFailure {
				delete(monitor.hardFailureSuspects, candidateID)
			}
			isProofEligible := retainPreviousProof ||
				(proofSuccess(reserved.observation) &&
					(proofFreshAfter.IsZero() ||
						!completedAt.Before(proofFreshAfter)))
			domainRecovered := false
			if row.Available && proofSuccess(reserved.observation) &&
				isProofEligible &&
				candidate.Kind == sources.KindVLESS && candidate.FailureDomain != "" {
				domainRecovered, err = monitor.Store.ResetFailureDomainOnSuccess(
					ctx, candidate.FailureDomain, completedAt,
				)
				if err != nil {
					return err
				}
			}
			if wasAvailable != row.Available || wasProofEligible != isProofEligible ||
				domainRecovered {
				capacityChanged = true
			}
			if reserved.promoteOnSuccess && commit.BecameProofEligible &&
				monitor.Promotions != nil {
				select {
				case monitor.Promotions <- struct{}{}:
				default:
				}
			}
		}
	}
	return nil
}

// clearCandidateActiveStateLocked removes all in-memory observation state for
// one candidate. The caller must hold trackerMu.
func (monitor *ActiveMonitor) clearCandidateActiveStateLocked(candidateID string) {
	delete(monitor.trackers, candidateID)
	delete(monitor.hardFailureSuspects, candidateID)
	delete(monitor.availabilityFailures, candidateID)
}

func (monitor *ActiveMonitor) observeAvailabilityLocked(
	candidateID string,
	reserved activeObservation,
) bool {
	state := monitor.availabilityFailures[candidateID]
	sequence := reserved.reservation.Sequence
	if sequence <= 0 || sequence <= state.lastSequence {
		return false
	}
	completedAt := reserved.completedAt
	consecutive := state.count > 0 && sequence == state.lastSequence+1 &&
		!state.lastCompletedAt.IsZero() &&
		!completedAt.Before(state.lastCompletedAt)
	state.lastSequence = sequence
	if monitor.AvailabilityFailureFreshness > 0 && consecutive {
		consecutive = completedAt.Sub(state.lastCompletedAt) <=
			monitor.AvailabilityFailureFreshness
	}
	if reserved.availability != nil && !reserved.availability.Infrastructure &&
		reserved.availability.ErrorCode == qoe.ReasonDNSRoute {
		if consecutive {
			state.count++
		} else {
			state.count = 1
		}
		state.lastCompletedAt = completedAt
	} else {
		state.count = 0
		state.lastCompletedAt = completedAt
	}
	monitor.availabilityFailures[candidateID] = state
	return state.count >= monitor.availabilityFailureThreshold()
}

func (monitor *ActiveMonitor) availabilityFailureThreshold() int {
	if monitor.AvailabilityFailureThreshold > 0 {
		return monitor.AvailabilityFailureThreshold
	}
	return 2
}

func proofSuccess(observation health.Observation) bool {
	return observation.PrimaryOK && observation.ConfirmationOK
}

func (monitor *ActiveMonitor) rotateVLESS(inputs []qualifier.Input) []qualifier.Input {
	monitor.cursorMu.Lock()
	defer monitor.cursorMu.Unlock()
	slots := monitor.Slots
	if slots <= 0 {
		slots = 4
	}
	if len(inputs) <= slots {
		monitor.vlessNext = 0
		return inputs
	}
	selected := make([]qualifier.Input, 0, slots)
	for len(selected) < slots {
		selected = append(selected, inputs[monitor.vlessNext%len(inputs)])
		monitor.vlessNext++
	}
	monitor.vlessNext %= len(inputs)
	return selected
}
