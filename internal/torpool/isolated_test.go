package torpool

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestIsolatedProfileManagerKeepsProbeRuntimeOutOfServingProfiles(t *testing.T) {
	servingProfiles := []Profile{{CandidateID: "route", SocksAddr: "127.0.0.1:19050", Role: "warm"}}
	probeProfiles := []Profile{{CandidateID: "route", SocksAddr: "127.0.0.1:19150", Role: "warm"}}
	serving := &recordingProfileRuntime{profiles: servingProfiles}
	probing := &recordingProfileRuntime{profiles: probeProfiles}
	manager, err := NewIsolatedProfileManager(serving, probing)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	candidates := []Candidate{{ID: "route", Bridge: "obfs4 192.0.2.1:443 cert=x", Qualified: true}}
	got, err := manager.Reconcile(context.Background(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, servingProfiles) || !reflect.DeepEqual(manager.Profiles(), servingProfiles) {
		t.Fatalf("controller observed probe-only profiles: reconcile=%+v profiles=%+v", got, manager.Profiles())
	}
	probing.waitReconciles(t, 1)
	if serving.reconcileCount() != 1 {
		t.Fatalf("serving reconciles=%d", serving.reconcileCount())
	}
	got, err = manager.ExploreNext(context.Background())
	if err != nil || !reflect.DeepEqual(got, servingProfiles) ||
		serving.exploreCount() != 1 || probing.exploreCount() != 0 {
		t.Fatalf("explore profiles=%+v err=%v calls=%d/%d", got, err,
			serving.exploreCount(), probing.exploreCount())
	}
}

func TestIsolatedProfileManagerProbeFailureDoesNotBlockServingReconcile(t *testing.T) {
	probeErr := errors.New("probe runtime failed")
	servingProfiles := []Profile{{CandidateID: "route", Role: "warm"}}
	serving := &recordingProfileRuntime{profiles: servingProfiles}
	probing := &recordingProfileRuntime{err: probeErr}
	manager, err := NewIsolatedProfileManager(serving, probing)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	got, err := manager.Reconcile(context.Background(), []Candidate{{
		ID: "route", Bridge: "obfs4 192.0.2.1:443 cert=x", Qualified: true,
	}})
	if err != nil || !reflect.DeepEqual(got, servingProfiles) || serving.reconcileCount() != 1 {
		t.Fatalf("profiles=%+v err=%v serving reconciles=%d", got, err, serving.reconcileCount())
	}
	probing.waitReconciles(t, 1)
}

func TestIsolatedProfileManagerSlowProbeDoesNotConsumeServingDeadline(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	serving := &recordingProfileRuntime{profiles: []Profile{{CandidateID: "route", Role: "warm"}}}
	probing := &recordingProfileRuntime{started: started, release: release}
	manager, err := NewIsolatedProfileManager(serving, probing)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	startedAt := time.Now()
	if _, err := manager.Reconcile(context.Background(), []Candidate{{
		ID: "route", Bridge: "obfs4 192.0.2.1:443 cert=x", Qualified: true,
	}}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed > 100*time.Millisecond {
		t.Fatalf("serving reconcile waited for probe runtime: %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe mirror did not start")
	}
	close(release)
}

func TestIsolatedProfileManagerPersistentFailurePublishesHealth(t *testing.T) {
	probeErr := errors.New("probe data directory is not writable")
	reported := make(chan error, 1)
	serving := &recordingProfileRuntime{}
	probing := &recordingProfileRuntime{err: probeErr}
	manager, err := NewIsolatedProfileManager(
		serving, probing,
		WithProbeMirrorErrorReporter(func(err error) {
			select {
			case reported <- err:
			default:
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Reconcile(context.Background(), []Candidate{{ID: "route"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-reported:
		if !errors.Is(got, probeErr) {
			t.Fatalf("reported error=%v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("probe mirror failure was not reported")
	}
	if err := manager.ProbeMirrorHealth(); !errors.Is(err, probeErr) {
		t.Fatalf("probe mirror health=%v want %v", err, probeErr)
	}
}

func TestIsolatedProfileManagerRetryCoalescesLatestCandidateSet(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	serving := &recordingProfileRuntime{}
	probing := &recordingProfileRuntime{started: started, release: release}
	manager, err := NewIsolatedProfileManager(serving, probing)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Reconcile(context.Background(), []Candidate{{ID: "old"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first probe reconcile did not start")
	}
	if _, err := manager.Reconcile(context.Background(), []Candidate{{ID: "latest"}}); err != nil {
		t.Fatal(err)
	}
	close(release)
	probing.waitReconciles(t, 2)
	calls := probing.candidateCalls()
	if len(calls) < 2 || len(calls[len(calls)-1]) != 1 || calls[len(calls)-1][0].ID != "latest" {
		t.Fatalf("probe mirror calls=%+v", calls)
	}
}

func TestIsolatedProfileManagerCloseCancelsBlockedRetryAndJoins(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	manager, err := NewIsolatedProfileManager(
		&recordingProfileRuntime{},
		&recordingProfileRuntime{started: started, release: release},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), []Candidate{{ID: "route"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked retry did not start")
	}
	done := make(chan struct{})
	go func() {
		manager.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and join blocked probe reconcile")
	}
}

type recordingProfileRuntime struct {
	mu         sync.Mutex
	profiles   []Profile
	err        error
	reconciles int
	explores   int
	candidates [][]Candidate
	started    chan struct{}
	release    <-chan struct{}
}

func (runtime *recordingProfileRuntime) Reconcile(ctx context.Context, candidates []Candidate) ([]Profile, error) {
	runtime.mu.Lock()
	runtime.reconciles++
	runtime.candidates = append(runtime.candidates, append([]Candidate(nil), candidates...))
	profiles := append([]Profile(nil), runtime.profiles...)
	err := runtime.err
	started := runtime.started
	release := runtime.release
	runtime.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return profiles, err
}

func (runtime *recordingProfileRuntime) candidateCalls() [][]Candidate {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([][]Candidate, len(runtime.candidates))
	for index := range runtime.candidates {
		result[index] = append([]Candidate(nil), runtime.candidates[index]...)
	}
	return result
}

func (runtime *recordingProfileRuntime) Profiles() []Profile {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]Profile(nil), runtime.profiles...)
}

func (runtime *recordingProfileRuntime) ExploreNext(context.Context) ([]Profile, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.explores++
	return append([]Profile(nil), runtime.profiles...), runtime.err
}

func (runtime *recordingProfileRuntime) reconcileCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.reconciles
}

func (runtime *recordingProfileRuntime) exploreCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.explores
}

func (runtime *recordingProfileRuntime) waitReconciles(t *testing.T, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for runtime.reconcileCount() < count && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runtime.reconcileCount(); got < count {
		t.Fatalf("reconciles=%d want at least %d", got, count)
	}
}
