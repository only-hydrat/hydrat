package controller

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/tournament"
)

func (service QualificationService) RepairRuntimeProfiles(
	ctx context.Context,
	_ time.Time,
) (bool, error) {
	if service.Store == nil {
		return false, errors.New("qualification store is required")
	}
	repairer, ok := service.Tor.(torRuntimeProfileRepairer)
	if !ok {
		return false, nil
	}
	if service.TorMutationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.TorMutationTimeout)
		defer cancel()
	}
	snapshot, err := service.Store.LoadTorProfileSetSnapshot(
		ctx,
		store.TorProfileSetRequest{UsePersistedWorkingPool: true},
	)
	if err != nil {
		return false, err
	}
	return repairer.RepairProfiles(
		ctx,
		torCandidatesFromStore(snapshot.Candidates),
	)
}

func (service QualificationService) updateWorkingPool(
	ctx context.Context,
	_ []store.Candidate,
	now time.Time,
) ([]torpool.Profile, error) {
	if service.Tor != nil && service.TorMutationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.TorMutationTimeout)
		defer cancel()
	}
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if service.beforeWorkingPoolList != nil {
			service.beforeWorkingPoolList(attempt)
		}
		candidates, err := service.Store.ListCandidates(ctx, "")
		if err != nil {
			return nil, err
		}
		states, err := service.Store.ListCandidateProbeStates(ctx)
		if err != nil {
			return nil, err
		}
		assignments, err := service.Store.ListAssignments(ctx)
		if err != nil {
			return nil, err
		}
		assignedIDs := make(map[string]bool)
		for _, assignment := range assignments {
			assignedIDs[assignment.TCPOutbound] = true
			assignedIDs[assignment.UDPOutbound] = true
		}
		currentByFingerprint := make(map[string]store.Candidate, len(candidates))
		for _, candidate := range candidates {
			currentByFingerprint[candidate.Fingerprint] = candidate
		}
		selectionCandidates := make([]tournament.Candidate, 0, len(candidates))
		stateByFingerprint := make(map[string]store.CandidateProbeState, len(states))
		for _, state := range states {
			current, exists := currentByFingerprint[state.Fingerprint]
			if !exists || current.ID != state.CandidateID || current.SourceID != state.SourceID {
				continue
			}
			if service.DisallowRUEgress {
				if sources.IsRussianEgress(current.Label, "") {
					continue
				}
				if payload, err := service.Store.CandidatePayload(ctx, current.ID); err == nil {
					if sources.IsRussianEgress(current.Label, payload) {
						continue
					}
				}
			}
			stateByFingerprint[state.Fingerprint] = state
			selectionCandidates = append(selectionCandidates, tournament.Candidate{
				Fingerprint: state.Fingerprint, Status: tournament.Status(state.Status),
				FullSuccessStreak: state.FullSuccessStreak,
				ConservativeScore: state.ConservativeScore,
				InWorkingPool:     state.InWorkingPool, Draining: state.Draining,
				Assigned: assignedIDs[state.CandidateID], BannedUntil: state.BannedUntil,
			})
		}
		selection := tournament.SelectWorkingPool(
			selectionCandidates,
			tournament.SelectionPolicy{
				PoolSize: service.PoolSize, PromotionRatio: service.PromotionRatio, Now: now,
			},
		)
		requestedActive := poolCandidates(selection.Active, currentByFingerprint)
		requestedDraining := poolCandidates(selection.Draining, currentByFingerprint)
		if service.Tor == nil {
			epoch, err := service.Store.InventoryEpoch(ctx)
			if err != nil {
				return nil, err
			}
			if service.beforeWorkingPoolReplace != nil {
				service.beforeWorkingPoolReplace(attempt)
			}
			applied, err := service.Store.ReplaceWorkingPoolCurrentAtEpoch(
				ctx, requestedActive, requestedDraining, now, epoch,
			)
			if errors.Is(err, store.ErrCandidateInventoryChanged) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if len(applied.Active) != len(requestedActive) ||
				len(applied.Draining) != len(requestedDraining) {
				continue
			}
			return nil, nil
		}
		snapshotCandidates := make(
			[]store.Candidate, 0, len(requestedActive)+len(requestedDraining),
		)
		for _, candidate := range requestedActive {
			snapshotCandidates = append(snapshotCandidates, candidate)
		}
		for _, candidate := range requestedDraining {
			snapshotCandidates = append(snapshotCandidates, candidate)
		}
		for index, candidate := range snapshotCandidates {
			if service.beforeWorkingPoolPayload != nil {
				service.beforeWorkingPoolPayload(
					attempt, index, candidate,
				)
			}
		}
		torSnapshot, err := service.Store.LoadTorProfileSetSnapshot(
			ctx,
			store.TorProfileSetRequest{
				Active:   requestedActive,
				Draining: requestedDraining,
			},
		)
		if err != nil {
			return nil, err
		}
		profiles, err := service.Tor.ReconcileProfiles(
			ctx, torCandidatesFromStore(torSnapshot.Candidates),
		)
		if err != nil {
			return nil, err
		}
		currentSnapshot, err := service.Store.LoadTorProfileSetSnapshot(
			ctx,
			store.TorProfileSetRequest{
				Active:   requestedActive,
				Draining: requestedDraining,
			},
		)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(torSnapshot, currentSnapshot) {
			// The next bounded attempt immediately compensates the runtime
			// with a profile set rebuilt from the new active inventory.
			continue
		}
		if service.beforeWorkingPoolReplace != nil {
			service.beforeWorkingPoolReplace(attempt)
		}
		applied, err := service.Store.ReplaceWorkingPoolCurrentAtEpoch(
			ctx,
			requestedActive,
			requestedDraining,
			now,
			torSnapshot.InventoryEpoch,
		)
		if errors.Is(err, store.ErrCandidateInventoryChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(applied.Active) != len(requestedActive) ||
			len(applied.Draining) != len(requestedDraining) {
			continue
		}
		finalSnapshot, err := service.Store.LoadTorProfileSetSnapshot(
			ctx,
			store.TorProfileSetRequest{
				UsePersistedWorkingPool: true,
			},
		)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(
			torSnapshot.Candidates,
			finalSnapshot.Candidates,
		) {
			profiles, err = service.Tor.ReconcileProfiles(
				ctx, torCandidatesFromStore(finalSnapshot.Candidates),
			)
			if err != nil {
				return nil, err
			}
			currentFinal, err := service.Store.LoadTorProfileSetSnapshot(
				ctx,
				store.TorProfileSetRequest{
					UsePersistedWorkingPool: true,
				},
			)
			if err != nil {
				return nil, err
			}
			if !reflect.DeepEqual(finalSnapshot, currentFinal) {
				continue
			}
		}
		return profiles, nil
	}
	if err := service.Store.ClearWorkingPoolByKind(
		ctx, sources.KindTorBridge,
	); err != nil {
		return nil, err
	}
	if service.Tor != nil {
		fallback, err := service.Store.LoadTorProfileSetSnapshot(
			ctx,
			store.TorProfileSetRequest{
				UsePersistedWorkingPool: true,
			},
		)
		if err != nil {
			return nil, err
		}
		if _, err := service.Tor.ReconcileProfiles(
			ctx, torCandidatesFromStore(fallback.Candidates),
		); err != nil {
			return nil, err
		}
	}
	return nil, store.ErrCandidateInventoryChanged
}

func poolCandidates(
	fingerprints []string,
	currentByFingerprint map[string]store.Candidate,
) []store.Candidate {
	candidates := make([]store.Candidate, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if candidate, exists := currentByFingerprint[fingerprint]; exists {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func findProbeState(
	states []store.CandidateProbeState,
	fingerprint string,
) store.CandidateProbeState {
	for _, state := range states {
		if state.Fingerprint == fingerprint {
			return state
		}
	}
	return store.CandidateProbeState{}
}
