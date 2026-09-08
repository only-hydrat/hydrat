package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/only-hydrat/hydrat/internal/torpool"
)

type TorProfileRemote interface {
	FetchProfiles(context.Context) ([]torpool.Profile, error)
	ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error)
	ExploreNext(context.Context) ([]torpool.Profile, error)
}

type torProfileSnapshot struct {
	profiles []torpool.Profile
	version  uint64
}

type TorCoordinator struct {
	remote TorProfileRemote

	// mutation serializes server-side Tor mutations. commit is held only while
	// marking a remote mutation in-flight or while publishing a snapshot; the
	// remote call itself never holds it, so route failover cannot queue behind a
	// slow Tor process operation.
	mutation chan struct{}
	commit   sync.Mutex
	mutating atomic.Bool
	snapshot atomic.Pointer[torProfileSnapshot]
}

func NewTorCoordinator(remote TorProfileRemote) *TorCoordinator {
	coordinator := &TorCoordinator{
		remote: remote, mutation: make(chan struct{}, 1),
	}
	coordinator.mutation <- struct{}{}
	coordinator.snapshot.Store(&torProfileSnapshot{version: 1})
	return coordinator
}

func (coordinator *TorCoordinator) Sync(ctx context.Context) error {
	if coordinator == nil || coordinator.remote == nil {
		return errors.New("Tor profile remote is required")
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return err
	}
	defer coordinator.endMutation()
	profiles, err := coordinator.remote.FetchProfiles(ctx)
	if err != nil {
		coordinator.publishLocked(nil)
		return err
	}
	coordinator.publishLocked(profiles)
	return nil
}

func (coordinator *TorCoordinator) Profiles() []torpool.Profile {
	profiles, _, _ := coordinator.PlanProfiles()
	return profiles
}

// PlanProfiles returns an immutable snapshot and its version. stable=false
// means a server-side mutation is in flight, so plans containing Tor identity
// must fail temporary instead of trusting or waiting for this snapshot.
func (coordinator *TorCoordinator) PlanProfiles() ([]torpool.Profile, uint64, bool) {
	if coordinator == nil {
		return nil, 0, true
	}
	snapshot := coordinator.snapshot.Load()
	if snapshot == nil {
		return nil, 0, !coordinator.mutating.Load()
	}
	return append([]torpool.Profile(nil), snapshot.profiles...),
		snapshot.version, !coordinator.mutating.Load()
}

// AcquirePlanCommit is deliberately non-blocking. It fences a captured Tor
// snapshot across durable desired-plan publication and dataplane Apply, while
// refusing to wait behind any concurrent snapshot publication.
func (coordinator *TorCoordinator) AcquirePlanCommit(version uint64) (func(), bool) {
	if coordinator == nil {
		return func() {}, true
	}
	if !coordinator.commit.TryLock() {
		return nil, false
	}
	snapshot := coordinator.snapshot.Load()
	if coordinator.mutating.Load() || snapshot == nil || snapshot.version != version {
		coordinator.commit.Unlock()
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(coordinator.commit.Unlock) }, true
}

func (coordinator *TorCoordinator) ReconcileProfiles(
	ctx context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	if coordinator == nil || coordinator.remote == nil {
		return nil, errors.New("Tor profile remote is required")
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return nil, err
	}
	defer coordinator.endMutation()
	profiles, err := coordinator.remote.ReconcileProfiles(ctx, candidates)
	if err != nil {
		return coordinator.resyncMutation(ctx, err)
	}
	coordinator.publishLocked(profiles)
	return append([]torpool.Profile(nil), profiles...), nil
}

// RepairProfiles verifies the agent's authoritative runtime before mutating
// it. The common steady-state path is a read-only GET; after a gateway restart
// the whole fetch/reconcile sequence remains fenced as one Tor mutation so a
// placement cannot trust the stale pre-restart snapshot in between.
func (coordinator *TorCoordinator) RepairProfiles(
	ctx context.Context,
	candidates []torpool.Candidate,
) (bool, error) {
	if coordinator == nil || coordinator.remote == nil {
		return false, errors.New("Tor profile remote is required")
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return false, err
	}
	defer coordinator.endMutation()
	authoritative, err := coordinator.remote.FetchProfiles(ctx)
	if err != nil {
		coordinator.publishLocked(nil)
		return false, err
	}
	authoritativeWarm := warmTorProfiles(authoritative)
	current := coordinator.snapshot.Load()
	if len(candidates) == 0 && len(authoritativeWarm) == 0 {
		// Qualification owns the explorer slot. A transient explorer is not
		// persisted working-pool drift and must not be killed by the periodic
		// runtime repair while its bridge is being probed.
		coordinator.publishLocked(authoritative)
		return false, nil
	}
	if current != nil &&
		reflect.DeepEqual(warmTorProfiles(current.profiles), authoritativeWarm) &&
		warmProfilesBelongToCandidates(authoritativeWarm, candidates) {
		coordinator.publishLocked(authoritative)
		return false, nil
	}
	profiles, err := coordinator.remote.ReconcileProfiles(ctx, candidates)
	if err != nil {
		_, resyncErr := coordinator.resyncMutation(ctx, err)
		return false, resyncErr
	}
	coordinator.publishLocked(profiles)
	return true, nil
}

func warmTorProfiles(profiles []torpool.Profile) []torpool.Profile {
	warm := make([]torpool.Profile, 0, len(profiles))
	for _, profile := range profiles {
		if profile.Role == "warm" {
			warm = append(warm, profile)
		}
	}
	return warm
}

func warmProfilesBelongToCandidates(
	profiles []torpool.Profile,
	candidates []torpool.Candidate,
) bool {
	if len(profiles) == 0 || len(candidates) == 0 {
		return false
	}
	desired := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		if candidate.Qualified && candidate.ID != "" {
			desired[candidate.ID] = true
		}
	}
	for _, profile := range profiles {
		if !desired[profile.CandidateID] {
			return false
		}
	}
	return true
}

func (coordinator *TorCoordinator) ExploreNext(ctx context.Context) ([]torpool.Profile, error) {
	if coordinator == nil || coordinator.remote == nil {
		return nil, errors.New("Tor profile remote is required")
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return nil, err
	}
	defer coordinator.endMutation()
	profiles, err := coordinator.remote.ExploreNext(ctx)
	if err != nil {
		return coordinator.resyncMutation(ctx, err)
	}
	coordinator.publishLocked(profiles)
	return append([]torpool.Profile(nil), profiles...), nil
}

type definitelyUnsentTorMutation interface {
	error
	MutationDefinitelyNotSent() bool
}

func mutationDefinitelyNotSent(err error) bool {
	var unsent definitelyUnsentTorMutation
	return errors.As(err, &unsent) && unsent.MutationDefinitelyNotSent()
}

func (coordinator *TorCoordinator) resyncMutation(
	ctx context.Context,
	mutationErr error,
) ([]torpool.Profile, error) {
	if mutationDefinitelyNotSent(mutationErr) {
		return nil, mutationErr
	}
	profiles, err := coordinator.remote.FetchProfiles(ctx)
	if err != nil {
		coordinator.publishLocked(nil)
		return nil, errors.Join(
			mutationErr,
			fmt.Errorf("resync Tor profiles after failed mutation: %w", err),
		)
	}
	coordinator.publishLocked(profiles)
	// A successful GET establishes identity but does not establish whether a
	// failed mutation reached its requested postcondition. Preserve the
	// original operation error; Explore in particular must never claim success.
	return append([]torpool.Profile(nil), profiles...), mutationErr
}

func (coordinator *TorCoordinator) beginMutation(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-coordinator.mutation:
	}
	coordinator.commit.Lock()
	coordinator.mutating.Store(true)
	coordinator.commit.Unlock()
	return nil
}

func (coordinator *TorCoordinator) endMutation() {
	coordinator.commit.Lock()
	coordinator.mutating.Store(false)
	coordinator.commit.Unlock()
	coordinator.mutation <- struct{}{}
}

// publishLocked acquires only the short snapshot commit lock. Callers may hold
// mutation, but never commit, while invoking it.
func (coordinator *TorCoordinator) publishLocked(profiles []torpool.Profile) {
	coordinator.commit.Lock()
	defer coordinator.commit.Unlock()
	current := coordinator.snapshot.Load()
	version := uint64(1)
	if current != nil {
		version = current.version + 1
	}
	coordinator.snapshot.Store(&torProfileSnapshot{
		profiles: append([]torpool.Profile(nil), profiles...),
		version:  version,
	})
}
