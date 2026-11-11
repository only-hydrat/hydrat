package controller

import (
	"context"
	"sort"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func (m *QoEMonitor) onionInstanceCurrent(id, instance string) bool {
	if instance == "" || m.Profiles == nil {
		return false
	}
	for _, p := range m.Profiles.Profiles() {
		if p.CandidateID == id && p.Instance == instance && p.OnionReady {
			return true
		}
	}
	return false
}

func (m *QoEMonitor) selectOnionJob(ctx context.Context, now time.Time, clients []store.ClientRecord, candidates map[string]store.Candidate, states map[string]store.CandidateProbeState, health map[string]store.CandidateHealth) (*qoeProbeJob, error) {
	enabled := false
	for _, c := range clients {
		enabled = enabled || c.OnionEnabled && !c.Paused
	}
	if !enabled || m.Profiles == nil {
		return nil, nil
	}
	profiles := m.Profiles.Profiles()
	sort.Slice(profiles, func(i, j int) bool {
		a, b := m.lastAttemptAt(profiles[i].CandidateID+"\x00onion", time.Time{}, now), m.lastAttemptAt(profiles[j].CandidateID+"\x00onion", time.Time{}, now)
		if a.Equal(b) {
			return profiles[i].CandidateID < profiles[j].CandidateID
		}
		return a.Before(b)
	})
	for _, p := range profiles {
		c, exists := candidates[p.CandidateID]
		h, s := health[p.CandidateID], states[p.CandidateID]
		if !exists || c.Kind != sources.KindTorBridge || (!p.OnionReady && (p.Role != "explorer" || now.Sub(p.StartedAt) < 3*time.Minute)) || p.Instance == "" || !h.TCPQualified || !h.Available || h.ActiveHardFailure || s.Status != store.CandidateQualified || s.Draining || c.Lifecycle != store.CandidateLifecycleActive {
			continue
		}
		// Bootstrap is not an onion route failure. Let new Tor processes establish
		// their circuits before measuring, without delaying ordinary worker jobs.
		if p.StartedAt.After(now) || now.Sub(p.StartedAt) < time.Minute {
			continue
		}
		job := qoeProbeJob{candidate: c, onionInstance: p.Instance}
		if m.reserve(job.key(), now, 20*time.Second, time.Time{}) {
			return &job, nil
		}
	}
	return nil, nil
}

// Reuse the same fenced Tor coordinator and profile pool. No extra processes,
// timer or mutation path: exploration advances after the existing QoE batch.
func (m *QoEMonitor) advanceOnionExploration(ctx context.Context, now time.Time, job qoeProbeJob) error {
	coordinator, ok := m.Profiles.(interface {
		ReconcileProfiles(context.Context, []torpool.Candidate) ([]torpool.Profile, error)
		ExploreNext(context.Context) ([]torpool.Profile, error)
	})
	if !ok {
		return nil
	}
	states, err := m.Store.ListOnionQoEStates(ctx)
	if err != nil {
		return err
	}
	var state store.OnionQoEState
	for _, s := range states {
		if s.State.CandidateID == job.candidate.ID {
			state = s
			break
		}
	}
	// Samples remain neutral during a shared service outage, but unknown
	// explorers must still progress after a bounded residence time.
	var profile torpool.Profile
	for _, p := range m.Profiles.Profiles() {
		if p.CandidateID == job.candidate.ID && p.Instance == job.onionInstance {
			profile = p
		}
	}
	if profile.Instance == "" {
		return nil
	}
	complete := state.Instance == profile.Instance && state.State.WindowValid >= qoe.OnionPolicy().WindowSize
	if !complete && (profile.Role != "explorer" || now.Sub(profile.StartedAt) < 3*time.Minute) {
		return nil
	}
	if !m.lastOnionReconcile.IsZero() && now.Sub(m.lastOnionReconcile) < time.Minute {
		return nil
	}
	m.lastOnionReconcile = now
	snapshot, err := m.Store.LoadTorProfileSetSnapshot(ctx, store.TorProfileSetRequest{UsePersistedWorkingPool: true})
	if err != nil {
		return err
	}
	mutationCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ps, err := coordinator.ReconcileProfiles(mutationCtx, torCandidatesFromStore(snapshot.Candidates))
	if err != nil {
		return err
	}
	for _, p := range ps {
		if p.Role == "explorer" && p.Instance == profile.Instance && now.Sub(p.StartedAt) >= 2*time.Minute {
			_, err = coordinator.ExploreNext(mutationCtx)
			break
		}
	}
	if err == nil {
		m.signalPlanning()
	}
	return err
}

// A complete fresh window ranks above unknown; stale evidence never blacklists
// a recovered bridge. A slow or unavailable route remains last until recovery.
func onionQualityRank(s store.OnionQoEState, instance string, now time.Time) (int, time.Duration) {
	if s.Instance != instance {
		return 1, 0
	}
	return qoe.OnionRank(s.State, now)
}
