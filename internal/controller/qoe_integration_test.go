package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestQoEIntegration(t *testing.T) {
	protocols := []struct {
		name string
		kind sources.Kind
		udp  bool
	}{
		{name: "vless", kind: sources.KindVLESS, udp: true},
		{name: "tor", kind: sources.KindTorBridge},
	}

	for _, protocol := range protocols {
		t.Run(protocol.name+"/moves_and_recovers", func(t *testing.T) {
			fixture := newQoEIntegrationFixture(t, protocol.kind, protocol.udp)
			monitor, prober := fixture.monitor()

			for index := 0; index < 5; index++ {
				prober.set(fixture.current.ID, integrationQoEObservation(200*time.Millisecond, 20))
				prober.set(fixture.alternative.ID, integrationQoEObservation(100*time.Millisecond, 40))
				fixture.runMonitor(t, monitor, prober, fixture.now.Add(time.Duration(index)*time.Second))
				wantStatus := qoe.StatusLearning
				if index == 4 {
					wantStatus = qoe.StatusHealthy
				}
				requireIntegrationQoEBoundary(
					t, fixture.database, fixture.current.ID,
					wantStatus, index+1, 0, index+1,
				)
			}
			requireIntegrationQoEStatus(t, fixture.database, fixture.current.ID, qoe.StatusHealthy)
			requireIntegrationQoEStatus(t, fixture.database, fixture.alternative.ID, qoe.StatusHealthy)

			for index := 0; index < 5; index++ {
				current := integrationQoEObservation(200*time.Millisecond, 20)
				if index%2 == 0 {
					current = integrationQoEObservation(2*time.Second, 20)
				}
				prober.set(fixture.current.ID, current)
				prober.set(fixture.alternative.ID, integrationQoEObservation(100*time.Millisecond, 40))
				fixture.runMonitor(t, monitor, prober, fixture.now.Add(time.Duration(index+5)*time.Second))
				bad := (index + 2) / 2
				wantStatus := qoe.StatusHealthy
				if bad == 3 {
					wantStatus = qoe.StatusDegraded
				}
				requireIntegrationQoEBoundary(
					t, fixture.database, fixture.current.ID,
					wantStatus, 5, bad, 5,
				)
			}
			requireIntegrationQoEStatus(t, fixture.database, fixture.current.ID, qoe.StatusDegraded)

			dataplaneAgent := &integrationDataplaneAgent{}
			engine := NewEngine(
				fixture.database,
				dataplaneAgent,
				fixture.profiles,
				scheduler.New(scheduler.PolicyDefaults()),
				[]byte("integration-tor-secret"),
			)
			cycleAt := fixture.now.Add(10 * time.Second)
			for snapshot := 0; snapshot < 3; snapshot++ {
				if err := engine.Cycle(
					context.Background(), cycleAt.Add(time.Duration(snapshot)*time.Second),
				); err != nil {
					t.Fatal(err)
				}
				assignment := integrationAssignment(t, fixture.database, fixture.clientID)
				wantTCP := fixture.current.ID
				if snapshot == 2 {
					wantTCP = fixture.alternative.ID
				}
				if assignment.TCPOutbound != wantTCP {
					t.Fatalf(
						"snapshot %d TCP assignment=%s want=%s",
						snapshot+1, assignment.TCPOutbound, wantTCP,
					)
				}
			}
			assignment := integrationAssignment(t, fixture.database, fixture.clientID)
			if assignment.TCPOutbound != fixture.alternative.ID {
				t.Fatalf("TCP assignment=%s want=%s", assignment.TCPOutbound, fixture.alternative.ID)
			}
			if protocol.udp && assignment.UDPOutbound != fixture.alternative.ID {
				t.Fatalf("UDP assignment=%s want=%s", assignment.UDPOutbound, fixture.alternative.ID)
			}
			if !protocol.udp && assignment.UDPOutbound != "" {
				t.Fatalf("Tor received UDP assignment %s", assignment.UDPOutbound)
			}
			if len(dataplaneAgent.plans) != 2 {
				t.Fatalf("applied plans=%d want=2", len(dataplaneAgent.plans))
			}

			for index := 0; index < 4; index++ {
				prober.set(fixture.current.ID, integrationQoEObservation(200*time.Millisecond, 20))
				prober.set(fixture.alternative.ID, integrationQoEObservation(100*time.Millisecond, 40))
				fixture.runMonitor(t, monitor, prober, cycleAt.Add(time.Duration(index+1)*time.Second))
				wantStatus := qoe.StatusDegraded
				wantBad := 2
				if index >= 2 {
					wantStatus = qoe.StatusHealthy
					wantBad = 1
				}
				requireIntegrationQoEBoundary(
					t, fixture.database, fixture.current.ID,
					wantStatus, 5, wantBad, 5,
				)
			}
			requireIntegrationQoEStatus(t, fixture.database, fixture.current.ID, qoe.StatusHealthy)
		})

		t.Run(protocol.name+"/preserves_without_significantly_better_alternative", func(t *testing.T) {
			fixture := newQoEIntegrationFixture(t, protocol.kind, protocol.udp)
			monitor, prober := fixture.monitor()
			for index := 0; index < 5; index++ {
				prober.set(fixture.current.ID, integrationQoEObservation(200*time.Millisecond, 20))
				prober.set(fixture.alternative.ID, integrationQoEObservation(1100*time.Millisecond, 20))
				fixture.runMonitor(t, monitor, prober, fixture.now.Add(time.Duration(index)*time.Second))
			}
			for index := 0; index < 5; index++ {
				current := integrationQoEObservation(200*time.Millisecond, 20)
				if index%2 == 0 {
					current = integrationQoEObservation(1600*time.Millisecond, 20)
				}
				prober.set(fixture.current.ID, current)
				prober.set(fixture.alternative.ID, integrationQoEObservation(1100*time.Millisecond, 20))
				fixture.runMonitor(t, monitor, prober, fixture.now.Add(time.Duration(index+5)*time.Second))
			}
			requireIntegrationQoEStatus(t, fixture.database, fixture.current.ID, qoe.StatusDegraded)

			engine := NewEngine(
				fixture.database,
				&integrationDataplaneAgent{},
				fixture.profiles,
				scheduler.New(scheduler.PolicyDefaults()),
				[]byte("integration-tor-secret"),
			)
			if err := engine.Cycle(context.Background(), fixture.now.Add(10*time.Second)); err != nil {
				t.Fatal(err)
			}
			assignment := integrationAssignment(t, fixture.database, fixture.clientID)
			if assignment.TCPOutbound != fixture.current.ID {
				t.Fatalf("TCP assignment=%s want retained %s", assignment.TCPOutbound, fixture.current.ID)
			}
			if protocol.udp && assignment.UDPOutbound != fixture.current.ID {
				t.Fatalf("UDP assignment=%s want retained %s", assignment.UDPOutbound, fixture.current.ID)
			}
		})
	}
}

type qoeIntegrationFixture struct {
	database    *store.Store
	current     store.Candidate
	alternative store.Candidate
	clientID    string
	now         time.Time
	profiles    ProfileProvider
}

func newQoEIntegrationFixture(t *testing.T, kind sources.Kind, udp bool) qoeIntegrationFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "qoe-integration.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	preview := sources.PreviewInput("https://example.net/qoe-subscription")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(ctx)
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	payloads := []string{
		"vless://11111111-1111-4111-8111-111111111111@198.51.100.10:443?security=tls&type=tcp#current",
		"vless://22222222-2222-4222-8222-222222222222@198.51.100.20:443?security=tls&type=tcp#alternative",
	}
	if kind == sources.KindTorBridge {
		payloads = []string{
			"Bridge 192.0.2.10:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"Bridge 192.0.2.20:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		}
	}
	inputs := []store.CandidateInput{
		{Kind: kind, Label: "current", Fingerprint: "qoe-current", Payload: payloads[0]},
		{Kind: kind, Label: "alternative", Fingerprint: "qoe-alternative", Payload: payloads[1]},
	}
	if err := database.ReplaceCandidates(ctx, sourceRows[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(ctx, "")
	if err != nil || len(candidates) != 2 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	byLabel := make(map[string]store.Candidate, len(candidates))
	for _, candidate := range candidates {
		byLabel[candidate.Label] = candidate
		// CandidateHealth is written only after the mandatory ChatGPT Web,
		// exact OpenAI 401, Telegram Web and MTProto qualification has passed.
		if err := database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID:  candidate.ID,
			Score:        map[string]float64{"current": 100, "alternative": 90}[candidate.Label],
			TCPQualified: true,
			UDPQualified: udp,
			Available:    true,
			UpdatedAt:    now.Add(-time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := database.RecordCandidateProbe(ctx, store.ProbeTransition{
				Fingerprint: candidate.Fingerprint,
				CandidateID: candidate.ID,
				SourceID:    candidate.SourceID,
				Full:        true,
				Success:     true,
				Score:       map[string]float64{"current": 100, "alternative": 90}[candidate.Label],
				At:          now.Add(-time.Minute + time.Duration(attempt)*time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := database.ReplaceWorkingPool(ctx, []string{
		byLabel["current"].Fingerprint,
		byLabel["alternative"].Fingerprint,
	}, nil); err != nil {
		t.Fatal(err)
	}

	clientID := "qoe-integration-client"
	if err := database.PutClient(ctx, store.ClientRecord{
		ID: clientID, Name: "QoE integration", Address: "10.88.0.2/32", PublicKey: "qoe-integration-peer",
	}, "private integration config"); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordActivity(ctx, clientID, now, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordActivity(ctx, clientID, now, 1, 1); err != nil {
		t.Fatal(err)
	}
	udpCandidate := ""
	if udp {
		udpCandidate = byLabel["current"].ID
	}
	if err := database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: clientID, TCPOutbound: byLabel["current"].ID, UDPOutbound: udpCandidate,
		TCPSince: now.Add(-time.Hour), UDPSince: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	var profiles ProfileProvider
	if kind == sources.KindTorBridge {
		profiles = profileProviderFunc(func() []torpool.Profile {
			return []torpool.Profile{
				{Slot: 0, Role: "warm", CandidateID: byLabel["current"].ID, SocksAddr: "127.0.0.1:19050"},
				{Slot: 1, Role: "warm", CandidateID: byLabel["alternative"].ID, SocksAddr: "127.0.0.1:19051"},
			}
		})
	}
	return qoeIntegrationFixture{
		database: database, current: byLabel["current"], alternative: byLabel["alternative"],
		clientID: clientID, now: now, profiles: profiles,
	}
}

func (fixture qoeIntegrationFixture) monitor() (*QoEMonitor, *integrationQoEProber) {
	prober := &integrationQoEProber{responses: make(map[string]qoe.Observation)}
	return &QoEMonitor{
		Store: fixture.database, Agent: prober, Profiles: fixture.profiles,
		Policy: qoe.DefaultPolicy(), Workers: 1, StandbyCandidates: 3,
		ActiveInterval: time.Nanosecond, IdleInterval: time.Nanosecond,
		DegradedInterval: time.Nanosecond,
	}, prober
}

func (fixture qoeIntegrationFixture) runMonitor(
	t *testing.T,
	monitor *QoEMonitor,
	prober *integrationQoEProber,
	now time.Time,
) {
	t.Helper()
	if err := monitor.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if unexpected := prober.takeUnexpected(); len(unexpected) != 0 {
		t.Fatalf("unexpected QoE probe candidates: %v", unexpected)
	}
}

func integrationQoEObservation(ttfb time.Duration, throughput float64) qoe.Observation {
	return qoe.Observation{
		Success: true, TTFB: ttfb, TransferDuration: 30 * time.Millisecond,
		Bytes: 65536, ThroughputMbps: throughput,
	}
}

type integrationQoEProber struct {
	mu         sync.Mutex
	responses  map[string]qoe.Observation
	unexpected []string
}

func (prober *integrationQoEProber) set(candidateID string, observation qoe.Observation) {
	prober.mu.Lock()
	defer prober.mu.Unlock()
	prober.responses[candidateID] = observation
}

func (prober *integrationQoEProber) ProbeQoE(
	_ context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	prober.mu.Lock()
	defer prober.mu.Unlock()
	observation, ok := prober.responses[request.CandidateID]
	if !ok {
		prober.unexpected = append(prober.unexpected, request.CandidateID)
		return agentapi.ProbeResponse{
			CandidateID: request.CandidateID, FailureClass: agentapi.FailureInfrastructure,
			ErrorCode: "integration_response_missing",
		}, nil
	}
	copy := observation
	return agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: copy.Success, QoE: &copy,
	}, nil
}

func (prober *integrationQoEProber) takeUnexpected() []string {
	prober.mu.Lock()
	defer prober.mu.Unlock()
	result := append([]string(nil), prober.unexpected...)
	prober.unexpected = nil
	return result
}

type integrationDataplaneAgent struct {
	plans []dataplane.DesiredPlan
}

func (agent *integrationDataplaneAgent) Apply(_ context.Context, plan dataplane.DesiredPlan) error {
	agent.plans = append(agent.plans, plan)
	return nil
}

func (*integrationDataplaneAgent) Activity(context.Context) ([]wireguard.PeerActivity, error) {
	return nil, nil
}

func requireIntegrationQoEStatus(t *testing.T, database *store.Store, candidateID string, want qoe.Status) qoe.State {
	t.Helper()
	states, err := database.ListCandidateQoEStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.CandidateID == candidateID {
			if state.Status != want {
				t.Fatalf("candidate %s QoE status=%s want=%s state=%+v", candidateID, state.Status, want, state)
			}
			return state
		}
	}
	t.Fatalf("QoE state for candidate %s not found: %s", candidateID, fmt.Sprint(states))
	return qoe.State{}
}

func requireIntegrationQoEBoundary(
	t *testing.T,
	database *store.Store,
	candidateID string,
	wantStatus qoe.Status,
	wantValid, wantBad, wantBaselineSamples int,
) {
	t.Helper()
	state := requireIntegrationQoEStatus(t, database, candidateID, wantStatus)
	if state.WindowValid != wantValid || state.WindowBad != wantBad ||
		state.BaselineSamples != wantBaselineSamples {
		t.Fatalf(
			"candidate %s boundary=(status=%s valid=%d bad=%d baseline=%d), want=(%s %d %d %d)",
			candidateID, state.Status, state.WindowValid, state.WindowBad, state.BaselineSamples,
			wantStatus, wantValid, wantBad, wantBaselineSamples,
		)
	}
}

func integrationAssignment(t *testing.T, database *store.Store, clientID string) store.AssignmentRecord {
	t.Helper()
	assignments, err := database.ListAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range assignments {
		if assignment.ClientID == clientID {
			return assignment
		}
	}
	t.Fatalf("assignment for %s not found: %+v", clientID, assignments)
	return store.AssignmentRecord{}
}
