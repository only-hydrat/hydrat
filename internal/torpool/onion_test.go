package torpool

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnionPreparationCannotPublishReadinessAfterRoleChangedTwice(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	m, err := NewManager(Config{DataDir: t.TempDir(), WarmProfiles: 1, ExplorerProfiles: 1, PrepareOnion: func(ctx context.Context, _ Profile) error {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}}, &torRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c := Candidate{ID: "bridge", Bridge: "192.0.2.1:443", Qualified: true}
	m.mu.Lock()
	err = m.replaceProfile(t.Context(), 0, "warm", false, c)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("preparation not started")
	}
	m.mu.Lock()
	err = m.replaceProfile(t.Context(), 0, "explorer", false, c)
	if err == nil {
		err = m.replaceProfile(t.Context(), 0, "warm", false, c)
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	// Give the stale callback time to return. The current preparation cannot
	// succeed and must remain pending, even though the process is unchanged.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if m.Profiles()[0].OnionReady {
			t.Fatal("stale preparation marked promoted profile ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOnionPreparationDoesNotBlockOrdinaryProfile(t *testing.T) {
	release := make(chan struct{})
	runner := &torRunner{}
	manager, err := NewManager(Config{Binary: "tor", DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 1, PrepareOnion: func(ctx context.Context, _ Profile) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	profiles, err := manager.Reconcile(context.Background(), []Candidate{{ID: "bridge", Bridge: "192.0.2.1:443", Qualified: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].OnionReady {
		t.Fatal("premature readiness")
	}
	args := strings.Join(runner.invocations[0], " ")
	if !strings.Contains(args, "--CookieAuthentication 1") || !strings.Contains(args, "--ControlSocket") {
		t.Fatal("missing private control")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.Profiles()[0].OnionReady {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("profile not made ready")
}
