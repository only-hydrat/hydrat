package controller

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestTorCoordinatorPublishesAtomicNonBlockingSnapshotAfterMutation(t *testing.T) {
	remote := &blockingTorProfileRemote{
		profiles: []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "old"}},
		entered:  make(chan struct{}, 1), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := coordinator.Profiles(); len(got) != 1 || got[0].CandidateID != "old" {
		t.Fatalf("initial snapshot=%+v", got)
	}
	done := make(chan error, 1)
	go func() {
		_, err := coordinator.ReconcileProfiles(context.Background(), []torpool.Candidate{{ID: "new"}})
		done <- err
	}()
	<-remote.entered
	read := make(chan []torpool.Profile, 1)
	go func() { read <- coordinator.Profiles() }()
	select {
	case got := <-read:
		if len(got) != 1 || got[0].CandidateID != "old" {
			t.Fatalf("in-flight snapshot=%+v", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Profiles blocked behind Tor mutation")
	}
	remote.mu.Lock()
	remote.next = []torpool.Profile{{Slot: 1, Role: "warm", CandidateID: "new"}}
	remote.mu.Unlock()
	close(remote.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := []torpool.Profile{{Slot: 1, Role: "warm", CandidateID: "new"}}
	if got := coordinator.Profiles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("published snapshot=%+v want=%+v", got, want)
	}
	got := coordinator.Profiles()
	got[0].CandidateID = "caller-mutated"
	if got := coordinator.Profiles(); got[0].CandidateID != "new" {
		t.Fatalf("snapshot aliases caller: %+v", got)
	}
}

func TestTorCoordinatorPlanFenceRejectsImmediatelyWhileRemoteMutationIsBlocked(t *testing.T) {
	remote := &blockingTorProfileRemote{
		profiles: []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "stable"}},
		entered:  make(chan struct{}, 1), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, version, stable := coordinator.PlanProfiles()
	if !stable {
		t.Fatal("initial authoritative snapshot was unstable")
	}
	done := make(chan error, 1)
	go func() { _, err := coordinator.ExploreNext(context.Background()); done <- err }()
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("Tor mutation did not reach remote")
	}
	read := make(chan []torpool.Profile, 1)
	go func() { read <- coordinator.Profiles() }()
	select {
	case got := <-read:
		if len(got) != 1 || got[0].CandidateID != "stable" {
			t.Fatalf("leased snapshot=%+v", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("snapshot reader blocked behind plan lease")
	}
	fenced := make(chan bool, 1)
	go func() {
		release, ok := coordinator.AcquirePlanCommit(version)
		if ok {
			release()
		}
		fenced <- ok
	}()
	select {
	case ok := <-fenced:
		if ok {
			t.Fatal("plan fence trusted snapshot during in-flight mutation")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("plan fence blocked behind remote mutation")
	}
	close(remote.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTorCoordinatorSerializesReconcileAndExploreMutations(t *testing.T) {
	remote := &blockingTorProfileRemote{
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { _, err := coordinator.ReconcileProfiles(context.Background(), nil); done <- err }()
	<-remote.entered
	go func() { _, err := coordinator.ExploreNext(context.Background()); done <- err }()
	select {
	case <-remote.entered:
		t.Fatal("concurrent Tor mutations reached remote")
	case <-time.After(50 * time.Millisecond):
	}
	close(remote.release)
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("second mutation did not run serially")
	}
	for index := 0; index < 2; index++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTorCoordinatorMutationAdmissionHonorsContext(t *testing.T) {
	remote := &blockingTorProfileRemote{
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := coordinator.ReconcileProfiles(context.Background(), nil)
		firstDone <- err
	}()
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("first Tor mutation did not reach remote")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	secondDone := make(chan error, 1)
	go func() {
		_, err := coordinator.ExploreNext(ctx)
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			close(remote.release)
			<-firstDone
			t.Fatalf("queued mutation error=%v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		close(remote.release)
		<-firstDone
		<-secondDone
		t.Fatal("queued Tor mutation ignored context deadline")
	}
	select {
	case <-remote.entered:
		close(remote.release)
		<-firstDone
		t.Fatal("expired queued mutation reached remote")
	default:
	}
	close(remote.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestTorCoordinatorRestartSyncLoadsAuthoritativeWarmProfiles(t *testing.T) {
	remote := &resyncTorProfileRemote{
		local: []torpool.Profile{{Slot: 9, Role: "warm", CandidateID: "stale-local"}},
		authoritative: []torpool.Profile{{
			Slot: 1, Role: "warm", CandidateID: "mapped-reserve",
			SocksAddr: "127.0.0.1:19051",
		}},
	}
	coordinator := NewTorCoordinator(remote)
	if got := coordinator.Profiles(); len(got) != 0 {
		t.Fatalf("constructor trusted process-local cache after restart: %+v", got)
	}
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 1 || profiles[0].CandidateID != "mapped-reserve" ||
		profiles[0].Slot != 1 || profiles[0].SocksAddr != "127.0.0.1:19051" {
		t.Fatalf("authoritative restart snapshot=%+v", profiles)
	}
}

func TestTorCoordinatorRepairsOnlyAuthoritativeProfileDrift(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative: []torpool.Profile{{
			Slot: 0, Role: "warm", CandidateID: "stable",
		}},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	desired := []torpool.Candidate{{ID: "stable", Qualified: true}}
	repaired, err := coordinator.RepairProfiles(context.Background(), desired)
	if err != nil || repaired || remote.mutationCalls != 0 {
		t.Fatalf("matching runtime repaired=%t mutations=%d err=%v",
			repaired, remote.mutationCalls, err)
	}

	remote.authoritative = nil
	remote.mutationProfiles = []torpool.Profile{{
		Slot: 1, Role: "warm", CandidateID: "stable",
	}}
	repaired, err = coordinator.RepairProfiles(context.Background(), desired)
	if err != nil || !repaired || remote.mutationCalls != 1 {
		t.Fatalf("drifted runtime repaired=%t mutations=%d err=%v",
			repaired, remote.mutationCalls, err)
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 1 || profiles[0].Slot != 1 ||
		profiles[0].CandidateID != "stable" {
		t.Fatalf("repaired snapshot=%+v", profiles)
	}
}

func TestTorCoordinatorRepairDoesNotKillTransientExplorerWithEmptyDesiredPool(t *testing.T) {
	remote := &resyncTorProfileRemote{}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote.authoritative = []torpool.Profile{{
		Slot: 3, Role: "explorer", CandidateID: "candidate-under-probe",
	}}

	repaired, err := coordinator.RepairProfiles(context.Background(), nil)
	if err != nil || repaired || remote.mutationCalls != 0 {
		t.Fatalf(
			"transient explorer repaired=%t mutations=%d err=%v",
			repaired, remote.mutationCalls, err,
		)
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 1 || profiles[0].Role != "explorer" ||
		profiles[0].CandidateID != "candidate-under-probe" {
		t.Fatalf("authoritative explorer snapshot=%+v", profiles)
	}
}

func TestTorCoordinatorRepairIgnoresExplorerReplacementWhenWarmPoolIsStable(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative: []torpool.Profile{
			{Slot: 0, Role: "warm", CandidateID: "stable-warm"},
			{Slot: 3, Role: "explorer", CandidateID: "old-probe"},
		},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote.authoritative[1].CandidateID = "new-probe"

	repaired, err := coordinator.RepairProfiles(context.Background(), []torpool.Candidate{{
		ID: "stable-warm", Qualified: true,
	}})
	if err != nil || repaired || remote.mutationCalls != 0 {
		t.Fatalf(
			"explorer replacement repaired=%t mutations=%d err=%v",
			repaired, remote.mutationCalls, err,
		)
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 2 || profiles[1].CandidateID != "new-probe" {
		t.Fatalf("authoritative replacement snapshot=%+v", profiles)
	}
}

func TestTorCoordinatorRepairRestoresDesiredWarmPoolAfterEmptyRestartSync(t *testing.T) {
	remote := &resyncTorProfileRemote{
		mutationProfiles: []torpool.Profile{{
			Slot: 0, Role: "warm", CandidateID: "persisted-warm",
		}},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	repaired, err := coordinator.RepairProfiles(context.Background(), []torpool.Candidate{{
		ID: "persisted-warm", Qualified: true,
	}})
	if err != nil || !repaired || remote.mutationCalls != 1 {
		t.Fatalf(
			"empty restart repair=%t mutations=%d err=%v",
			repaired, remote.mutationCalls, err,
		)
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 1 || profiles[0].Role != "warm" ||
		profiles[0].CandidateID != "persisted-warm" {
		t.Fatalf("restored warm snapshot=%+v", profiles)
	}
}

func TestTorCoordinatorResyncsAfterLostSuccessfulMutationResponse(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative:    []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "old"}},
		mutationProfiles: []torpool.Profile{{Slot: 1, Role: "warm", CandidateID: "new"}},
		mutationErr:      ambiguousTorMutationError{cause: errors.New("response connection reset")},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	profiles, err := coordinator.ReconcileProfiles(context.Background(), nil)
	if !errors.Is(err, remote.mutationErr) {
		t.Fatalf("authoritatively resynced mutation lost original error: %v", err)
	}
	if len(profiles) != 1 || profiles[0].CandidateID != "new" ||
		remote.fetchCalls != 2 {
		t.Fatalf("resynced profiles=%+v fetch_calls=%d", profiles, remote.fetchCalls)
	}
}

func TestTorCoordinatorInvalidatesSnapshotWhenLostMutationCannotResync(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative:    []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "old"}},
		mutationProfiles: []torpool.Profile{{Slot: 1, Role: "warm", CandidateID: "new"}},
		mutationErr:      ambiguousTorMutationError{cause: errors.New("response connection reset")},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote.fetchErr = errors.New("agent unavailable")
	if _, err := coordinator.ExploreNext(context.Background()); err == nil {
		t.Fatal("lost mutation plus failed resync returned success")
	}
	if profiles := coordinator.Profiles(); len(profiles) != 0 {
		t.Fatalf("failed resync retained stale Tor identity: %+v", profiles)
	}
}

func TestTorCoordinatorKeepsSnapshotAfterAuthoritativeMutationRejection(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative:    []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "old"}},
		mutationProfiles: []torpool.Profile{{Slot: 1, Role: "warm", CandidateID: "partial"}},
		mutationErr:      errors.New("HTTP 409 after partial mutation"),
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ReconcileProfiles(context.Background(), nil); err == nil {
		t.Fatal("authoritative rejection returned success")
	}
	profiles := coordinator.Profiles()
	if len(profiles) != 1 || profiles[0].CandidateID != "partial" || remote.fetchCalls != 2 {
		t.Fatalf("partial rejection resync snapshot=%+v fetch_calls=%d", profiles, remote.fetchCalls)
	}
}

type definitelyUnsentMutationError struct{ cause error }

func (err definitelyUnsentMutationError) Error() string               { return err.cause.Error() }
func (err definitelyUnsentMutationError) Unwrap() error               { return err.cause }
func (definitelyUnsentMutationError) MutationDefinitelyNotSent() bool { return true }

func TestTorCoordinatorDoesNotResyncDefinitelyUnsentCanceledMutation(t *testing.T) {
	remote := &resyncTorProfileRemote{
		authoritative: []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "old"}},
		mutationErr:   definitelyUnsentMutationError{cause: context.Canceled},
	}
	coordinator := NewTorCoordinator(remote)
	if err := coordinator.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ExploreNext(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("definitely unsent cancellation=%v", err)
	}
	if remote.fetchCalls != 1 {
		t.Fatalf("definitely unsent mutation fetched %d times", remote.fetchCalls)
	}
}

type blockingTorProfileRemote struct {
	mu       sync.Mutex
	profiles []torpool.Profile
	next     []torpool.Profile
	entered  chan struct{}
	release  chan struct{}
}

func (remote *blockingTorProfileRemote) Profiles() []torpool.Profile {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	return append([]torpool.Profile(nil), remote.profiles...)
}

func (remote *blockingTorProfileRemote) FetchProfiles(context.Context) ([]torpool.Profile, error) {
	return remote.Profiles(), nil
}

func (remote *blockingTorProfileRemote) ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error) {
	return remote.mutate()
}

type ambiguousTorMutationError struct{ cause error }

func (err ambiguousTorMutationError) Error() string       { return err.cause.Error() }
func (err ambiguousTorMutationError) Unwrap() error       { return err.cause }
func (ambiguousTorMutationError) AmbiguousMutation() bool { return true }

type resyncTorProfileRemote struct {
	local            []torpool.Profile
	authoritative    []torpool.Profile
	mutationProfiles []torpool.Profile
	mutationErr      error
	fetchErr         error
	fetchCalls       int
	mutationCalls    int
}

func (remote *resyncTorProfileRemote) Profiles() []torpool.Profile {
	return append([]torpool.Profile(nil), remote.local...)
}

func (remote *resyncTorProfileRemote) FetchProfiles(context.Context) ([]torpool.Profile, error) {
	remote.fetchCalls++
	if remote.fetchErr != nil {
		return nil, remote.fetchErr
	}
	return append([]torpool.Profile(nil), remote.authoritative...), nil
}

func (remote *resyncTorProfileRemote) ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error) {
	return remote.mutate()
}

func (remote *resyncTorProfileRemote) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return remote.mutate()
}

func (remote *resyncTorProfileRemote) mutate() ([]torpool.Profile, error) {
	remote.mutationCalls++
	if remote.mutationProfiles != nil {
		remote.authoritative = append(remote.authoritative[:0], remote.mutationProfiles...)
	}
	if remote.mutationErr != nil {
		return nil, remote.mutationErr
	}
	return append([]torpool.Profile(nil), remote.authoritative...), nil
}

func (remote *blockingTorProfileRemote) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return remote.mutate()
}

func (remote *blockingTorProfileRemote) mutate() ([]torpool.Profile, error) {
	remote.entered <- struct{}{}
	<-remote.release
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.next != nil {
		remote.profiles = append(remote.profiles[:0], remote.next...)
	}
	return append([]torpool.Profile(nil), remote.profiles...), nil
}
