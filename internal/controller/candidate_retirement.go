package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

type CandidateRetirementTor interface {
	ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error)
	Profiles() []torpool.Profile
}

type CandidateRetirement struct {
	Store            *store.Store
	Tor              CandidateRetirementTor
	RetiredRetention time.Duration

	beforeSnapshot func(store.Candidate)
	beforeFinalize func(store.Candidate)
	advance        func(
		context.Context,
		string,
		int64,
		int64,
		string,
		time.Time,
		time.Duration,
	) (store.CandidateRetirementResult, error)
	cursor string
}

const candidateRetirementBatchSize = 32

func (collector *CandidateRetirement) Run(
	ctx context.Context,
	now time.Time,
) error {
	if collector.Store == nil {
		return errors.New("candidate retirement store is required")
	}
	if collector.RetiredRetention <= 0 {
		return errors.New("candidate retired retention must be positive")
	}
	if now.IsZero() {
		return errors.New("candidate retirement time is required")
	}
	due, err := collector.Store.ListCandidatesDueRetirementPage(
		ctx,
		now,
		collector.RetiredRetention,
		collector.cursor,
		candidateRetirementBatchSize,
	)
	if err != nil {
		return fmt.Errorf("list candidates due retirement: %w", err)
	}
	if len(due) == 0 && collector.cursor != "" {
		collector.cursor = ""
		due, err = collector.Store.ListCandidatesDueRetirementPage(
			ctx,
			now,
			collector.RetiredRetention,
			"",
			candidateRetirementBatchSize,
		)
		if err != nil {
			return fmt.Errorf("list candidates due retirement: %w", err)
		}
	}
	if len(due) == 0 {
		return nil
	}
	collector.cursor = due[len(due)-1].ID
	candidateIDs := make([]string, 0, len(due))
	listedByID := make(map[string]store.Candidate, len(due))
	for _, candidate := range due {
		candidateIDs = append(candidateIDs, candidate.ID)
		listedByID[candidate.ID] = candidate
		if collector.beforeSnapshot != nil {
			collector.beforeSnapshot(candidate)
		}
	}
	snapshot, err := collector.Store.LoadCandidateRetirementBatchSnapshot(
		ctx,
		candidateIDs,
		now,
		collector.RetiredRetention,
	)
	if err != nil {
		return fmt.Errorf("load candidate retirement snapshot: %w", err)
	}
	if snapshot.DesiredGeneration != snapshot.AppliedGeneration {
		return nil
	}
	eligible := make([]store.Candidate, 0, len(snapshot.Candidates))
	torTargetIDs := make([]string, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !candidateRetirementSnapshotDue(
			listedByID[candidate.ID],
			candidate,
			now,
			collector.RetiredRetention,
		) {
			continue
		}
		eligible = append(eligible, candidate)
		if candidate.Kind == sources.KindTorBridge {
			torTargetIDs = append(torTargetIDs, candidate.ID)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	expectedTorIDs := retirementTorCandidateIDs(snapshot.TorCandidates)
	if len(torTargetIDs) > 0 {
		if collector.Tor == nil {
			return errors.New("candidate retirement Tor reconciler is required")
		}
		requested := torCandidatesFromStore(snapshot.TorCandidates)
		profiles, err := collector.Tor.ReconcileProfiles(ctx, requested)
		if err != nil {
			return errors.Join(
				fmt.Errorf(
					"reconcile Tor before candidate retirement: %w",
					err,
				),
				collector.compensateTorRemovals(ctx, torTargetIDs),
			)
		}
		if err := validateRetirementTorBatchAcknowledgement(
			torTargetIDs, expectedTorIDs, profiles,
		); err != nil {
			return errors.Join(
				err,
				collector.compensateTorRemovals(ctx, torTargetIDs),
			)
		}
	}
	for _, candidate := range eligible {
		if collector.beforeFinalize != nil {
			collector.beforeFinalize(candidate)
		}
	}
	if len(torTargetIDs) > 0 {
		if err := validateRetirementTorBatchAcknowledgement(
			torTargetIDs,
			expectedTorIDs,
			collector.Tor.Profiles(),
		); err != nil {
			return errors.Join(
				err,
				collector.compensateTorRemovals(ctx, torTargetIDs),
			)
		}
	}
	var (
		changed    int
		advanceErr error
	)
	if collector.advance != nil {
		for _, candidate := range eligible {
			result, err := collector.advance(
				ctx,
				candidate.ID,
				snapshot.DesiredGeneration,
				snapshot.InventoryEpoch,
				snapshot.TorSemanticDigest,
				now,
				collector.RetiredRetention,
			)
			if err != nil {
				advanceErr = err
				break
			}
			if result.Changed {
				changed++
			}
		}
	} else {
		result, err := collector.Store.AdvanceCandidateRetirementBatch(
			ctx,
			eligible,
			snapshot.DesiredGeneration,
			snapshot.InventoryEpoch,
			snapshot.TorSemanticDigest,
			now,
			collector.RetiredRetention,
		)
		advanceErr = err
		changed = result.Changed
	}
	if advanceErr != nil || changed != len(eligible) {
		var compensationErr error
		if len(torTargetIDs) > 0 {
			compensationErr = collector.compensateTorRemovals(
				ctx, torTargetIDs,
			)
		}
		if advanceErr != nil {
			return errors.Join(
				fmt.Errorf(
					"advance candidate retirement: %w",
					advanceErr,
				),
				compensationErr,
			)
		}
		if compensationErr != nil {
			return fmt.Errorf(
				"compensate candidate retirement no-op: %w",
				compensationErr,
			)
		}
	}
	return nil
}

func retirementTorCandidateIDs(
	candidates []store.TorProfileCandidate,
) []string {
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, candidate.Candidate.ID)
	}
	sort.Strings(result)
	return result
}

func torCandidatesFromStore(
	candidates []store.TorProfileCandidate,
) []torpool.Candidate {
	result := make([]torpool.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, torpool.Candidate{
			ID:        candidate.Candidate.ID,
			Bridge:    candidate.Payload,
			Score:     candidate.ConservativeScore,
			Qualified: true,
			Draining:  candidate.Draining,
			Assigned:  candidate.Assigned || candidate.Mandatory,
		})
	}
	return result
}

func candidateRetirementSnapshotDue(
	listed, current store.Candidate,
	now time.Time,
	retiredRetention time.Duration,
) bool {
	if listed.ID == "" ||
		listed.ID != current.ID ||
		listed.SourceID != current.SourceID ||
		listed.Fingerprint != current.Fingerprint ||
		listed.Lifecycle != current.Lifecycle {
		return false
	}
	switch current.Lifecycle {
	case store.CandidateLifecycleDraining:
		return current.DrainAfter != nil &&
			*current.DrainAfter <= now.Unix()
	case store.CandidateLifecycleRetired:
		return current.RetiredAt != nil &&
			*current.RetiredAt <= now.Add(-retiredRetention).Unix()
	default:
		return false
	}
}

func (collector *CandidateRetirement) compensateTorRemovals(
	ctx context.Context,
	candidateIDs []string,
) error {
	if collector.Tor == nil {
		return errors.New("candidate retirement Tor reconciler is required")
	}
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		snapshot, err := collector.Store.LoadTorCompensationSnapshot(
			ctx, candidateIDs,
		)
		if err != nil {
			return fmt.Errorf("load Tor compensation snapshot: %w", err)
		}
		expectedIDs := retirementTorCandidateIDs(snapshot.Candidates)
		profiles, err := collector.Tor.ReconcileProfiles(
			ctx, torCandidatesFromStore(snapshot.Candidates),
		)
		if err != nil {
			return fmt.Errorf("reconcile Tor compensation: %w", err)
		}
		if err := validateTorProfileAcknowledgement(
			"",
			expectedIDs,
			snapshot.MandatoryCandidateIDs,
			profiles,
		); err != nil {
			return fmt.Errorf("validate Tor compensation: %w", err)
		}
		current, err := collector.Store.LoadTorCompensationSnapshot(
			ctx, candidateIDs,
		)
		if err != nil {
			return fmt.Errorf("reload Tor compensation snapshot: %w", err)
		}
		if reflect.DeepEqual(snapshot, current) {
			return nil
		}
	}
	return store.ErrCandidateInventoryChanged
}

func validateRetirementTorBatchAcknowledgement(
	excludedIDs []string,
	expectedCandidateIDs []string,
	profiles []torpool.Profile,
) error {
	return validateTorProfileBatchAcknowledgement(
		excludedIDs, expectedCandidateIDs, nil, profiles,
	)
}

func validateTorProfileAcknowledgement(
	excludedID string,
	expectedCandidateIDs []string,
	mandatoryCandidateIDs []string,
	profiles []torpool.Profile,
) error {
	var excludedIDs []string
	if excludedID != "" {
		excludedIDs = []string{excludedID}
	}
	return validateTorProfileBatchAcknowledgement(
		excludedIDs,
		expectedCandidateIDs,
		mandatoryCandidateIDs,
		profiles,
	)
}

func validateTorProfileBatchAcknowledgement(
	excludedIDs []string,
	expectedCandidateIDs []string,
	mandatoryCandidateIDs []string,
	profiles []torpool.Profile,
) error {
	expected := make(map[string]bool, len(expectedCandidateIDs))
	for _, candidateID := range expectedCandidateIDs {
		expected[candidateID] = true
	}
	excluded := make(map[string]bool, len(excludedIDs))
	for _, candidateID := range excludedIDs {
		if candidateID != "" {
			excluded[candidateID] = true
		}
	}
	materialized := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if profile.CandidateID == "" {
			return errors.New(
				"Tor reconciliation acknowledged an empty candidate identity",
			)
		}
		if excluded[profile.CandidateID] {
			return fmt.Errorf(
				"Tor reconciliation retained candidate %s",
				profile.CandidateID,
			)
		}
		if profile.CandidateID != "" && !expected[profile.CandidateID] {
			return fmt.Errorf(
				"Tor reconciliation acknowledged unexpected candidate %s",
				profile.CandidateID,
			)
		}
		materialized[profile.CandidateID] = true
	}
	for _, candidateID := range mandatoryCandidateIDs {
		if candidateID == "" || !materialized[candidateID] {
			return fmt.Errorf(
				"Tor reconciliation did not materialize mandatory candidate %s",
				candidateID,
			)
		}
	}
	return nil
}
