package device

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/only-hydrat/hydrat/internal/controller"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

var directSuffixes = []string{".ru", ".su", ".xn--p1ai"}
var directDomains = []string{"thecode.media", "habr.com"}

// DNSResolversForPreset returns an isolated resolver pool for a local session.
func DNSResolversForPreset(preset int) []string {
	switch preset {
	case 1:
		return []string{"1.1.1.1", "1.0.0.1"}
	case 2:
		return []string{"9.9.9.9", "149.112.112.112"}
	case 3:
		return []string{"8.8.8.8", "8.8.4.4"}
	default:
		return []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}
	}
}

// TunnelBackend owns an already established TUN and the isolated probe and
// serving runtimes. Its transport is private to the local app.
type TunnelBackend interface {
	controller.CandidateProbeAgent
	controller.ActiveProbeAgent
	controller.CriticalActiveProbeAgent
	controller.QoEProbeAgent
	controller.TorProfileRemote
	ApplyWithRecovery(context.Context, dataplane.DesiredPlan, []dataplane.FlowRecovery) error
	LastTraffic() time.Time
}

type sessionAgent struct {
	TunnelBackend
	app *App
}

func (agent sessionAgent) Apply(ctx context.Context, plan dataplane.DesiredPlan) error {
	return agent.ApplyWithRecovery(ctx, plan, nil)
}

func (agent sessionAgent) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, actions []dataplane.FlowRecovery) error {
	if err := agent.TunnelBackend.ApplyWithRecovery(ctx, plan, actions); err != nil {
		return err
	}
	for _, route := range plan.Clients {
		if route.ClientID == profileID {
			agent.app.route.Store(&route)
			return nil
		}
	}
	agent.app.route.Store(nil)
	return nil
}

// Activity adapts the local packet timestamp to the controller's existing
// activity contract. The local database contains one profile and no peers.
func (agent sessionAgent) Activity(ctx context.Context) ([]wireguard.PeerActivity, error) {
	return []wireguard.PeerActivity{{LastUserTraffic: agent.LastTraffic()}}, ctx.Err()
}

type session struct {
	engine   *controller.Engine
	profiles *controller.TorCoordinator
	runtime  controller.Runtime
}

const mobileReserveCount = 3
const MobileCriticalSlots = 2 + mobileReserveCount
const MobileFastProbeWorkers = 8
const MobileMinVLESSScore = 75

type mobileSession struct {
	settings  MobileSettings
	started   time.Time
	preferred []string
}

func (app *App) session(backend TunnelBackend, dnsResolvers ...string) session {
	return app.newSession(backend, nil, dnsResolvers...)
}

func (app *App) newSession(backend TunnelBackend, mobile *mobileSession, dnsResolvers ...string) session {
	if len(dnsResolvers) == 0 {
		dnsResolvers = DNSResolversForPreset(0)
	}
	agent := sessionAgent{TunnelBackend: backend, app: app}
	profiles := controller.NewTorCoordinator(backend)
	const activeInterval = 4 * time.Second
	const activeDeadline = 4 * time.Second
	activeLimit, activeSlots := defaultCriticalSlots, 2
	if mobile != nil {
		activeLimit, activeSlots = MobileCriticalSlots, mobileReserveCount
	}
	engineOptions := []controller.EngineOption{
		controller.WithLocalDevice(),
		controller.WithRouting(directSuffixes, directDomains),
		controller.WithDisallowRUEgress(true),
		controller.WithDNSResolvers(dnsResolvers),
		controller.WithActiveProbeInterval(activeInterval),
		controller.WithActiveCriticalRouteLimit(activeLimit),
	}
	if mobile != nil {
		engineOptions = append(engineOptions,
			controller.WithMobileRoutes(mobile.started, mobileReserveCount, mobile.preferred),
			controller.WithMobileMinimumVLESSScore(float64(mobile.settings.MinVLESSScore)),
		)
	}
	engine := controller.NewEngine(app.database, agent, profiles, nil, app.key, engineOptions...)
	promotions := make(chan struct{}, 1)
	qualityChanges := make(chan struct{}, 1)
	capacityChanges := make(chan struct{}, 1)
	failures := controller.NewHardFailureMailbox()
	active := &controller.ActiveMonitor{
		Store: app.database, Agent: backend, Profiles: profiles, Targets: engine,
		Slots: activeSlots, CriticalLimit: activeLimit, ProbeDeadline: activeDeadline,
		ProofFreshness: 2 * activeInterval,
		HardFailures:   failures, HardFailureDeadline: 10 * time.Second,
		ConfirmCompleteFailureInCycle: true, Promotions: promotions,
		CapacityChanges: capacityChanges, SynchronousTargets: mobile != nil,
	}
	quality := &controller.QoEMonitor{
		Store: app.database, Agent: backend, Profiles: profiles,
		SyncActivity: engine.SyncActivity, Workers: 1, Trigger: qualityChanges,
	}
	qualification := controller.QualificationService{
		Store: app.database, Agent: backend, Tor: profiles, QoEEnabled: true,
		PoolSize: 32, FastWorkers: defaultFastProbeWorkers, FullWorkers: 1, DisallowRUEgress: true,
		TorCandidatesPerCycle: 2, TorQualificationBudget: 2 * time.Minute,
		TorMutationTimeout: time.Minute, Promotions: promotions,
	}
	if mobile != nil {
		qualification.MobileReserves = mobileReserveCount
		qualification.MobileRouteInstalled = app.mobileRouteInstalled
		qualification.MinVLESSScore = float64(mobile.settings.MinVLESSScore)
		qualification.FastWorkers = mobile.settings.FastWorkers
		qualification.MobileBackgroundWorkers = mobile.settings.BackgroundWorkers
		qualification.MobileBackgroundMode = app.mobileBackgroundMode(mobile.settings)
		qualification.MobileSearchProgress = func(mode string, workers int) {
			app.search.Store(&SearchStatus{Mode: mode, Workers: workers})
		}
	}
	runtime := controller.Runtime{
		Refresh: app.refreshSources, Qualify: qualification.Run,
		ProfileRepair: qualification.RepairRuntimeProfiles,
		Active:        active.Run, QoE: quality.Run, Place: engine.CycleForReason,
		StartupHardFailure: engine.HasStartupHardFailure,
		StartupNormalize:   engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:      engine.ActiveCardinalityReady,
		CapacityReady: func(ctx context.Context, now time.Time) error {
			if err := active.WarmTargets(ctx, now); err != nil {
				return err
			}
			return engine.CapacityReady(ctx, now)
		},
		SourceChanges: app.sourcesChanged, ClientChanges: app.sourceRemoved, HardFailureEvents: failures,
		Promotions: promotions, QoEDegradations: qualityChanges,
		CapacityChanges:       capacityChanges,
		SourceRefreshInterval: time.Hour, QualificationInterval: 5 * time.Minute,
		PlacementInterval: 30 * time.Second, ActiveInterval: activeInterval,
		ActiveDeadline: activeDeadline + time.Second, ActiveOverlap: 1,
		ActivePlanningDeadline: controller.ActiveCriticalCoveragePlanningBudget,
		QoEInterval:            time.Second, ProfileRepairInterval: 5 * time.Second,
	}
	if mobile != nil {
		if mobile.settings.PauseOnScreenOff {
			runtime.Active, runtime.QoE = app.mobileIdleProbes(backend.LastTraffic, runtime.Active, runtime.QoE)
			runtime.QoEInterval = 5 * time.Second
		}
		var inFlight atomic.Pointer[context.CancelFunc]
		var expedited atomic.Bool
		var lastQualification time.Time
		runtime.Qualify = func(ctx context.Context, at time.Time) error {
			probeCtx, cancel := context.WithCancel(ctx)
			inFlight.Store(&cancel)
			defer inFlight.Store(nil)
			defer cancel()
			if mobile.settings.PauseOnScreenOff {
				if app.deferMobileQualification(at, lastQualification, expedited.Swap(false)) {
					app.search.Store(&SearchStatus{Mode: "paused"})
					return nil
				}
				lastQualification = at
			}
			return qualification.Run(probeCtx, at)
		}
		runtime.InterruptQualification = func() {
			expedited.Store(true)
			if cancel := inFlight.Load(); cancel != nil {
				(*cancel)()
			}
		}
		runtime.StartupHardFailure = nil
		runtime.StartupNormalize = nil
		runtime.CapacityReady = nil
		runtime.QualificationInterval = 15 * time.Second
		runtime.SourceRefreshInterval = time.Duration(mobile.settings.SourceRefreshMinutes) * time.Minute
		runtime.QualifyCachedInventoryOnStart = true
		retirement := &controller.CandidateRetirement{Store: app.database, Tor: profiles, RetiredRetention: 24 * time.Hour}
		runtime.Maintenance = retirement.Run
	}
	return session{engine: engine, profiles: profiles, runtime: runtime}
}

// Run owns the decision loop for one connection. The caller cancels ctx to
// stop and closes the TUN only after the workers have returned.
func (app *App) Run(ctx context.Context, backend TunnelBackend, dnsResolvers ...string) error {
	return app.run(ctx, backend, nil, dnsResolvers...)
}

func (app *App) RunMobile(ctx context.Context, backend TunnelBackend, dnsResolvers ...string) error {
	return app.RunMobileWithSettings(ctx, backend, MobileSettings{}, dnsResolvers...)
}

func (app *App) RunMobileWithSettings(ctx context.Context, backend TunnelBackend, settings MobileSettings, dnsResolvers ...string) error {
	settings = settings.Normalized()
	return app.run(ctx, backend, &settings, dnsResolvers...)
}

func (app *App) run(ctx context.Context, backend TunnelBackend, mobile *MobileSettings, dnsResolvers ...string) error {
	if backend == nil {
		return errors.New("the local TUN and probe backend are required")
	}
	if !app.running.CompareAndSwap(false, true) {
		return errors.New("the app is already running")
	}
	defer app.running.Store(false)
	defer app.route.Store(nil)
	var mobileConfig *mobileSession
	if mobile != nil {
		mobileConfig = &mobileSession{started: time.Now(), settings: *mobile}
		defer app.search.Store(nil)
		app.mobileStartedAt.Store(mobileConfig.started.Unix())
		defer app.mobileStartedAt.Store(0)
		assignments, err := app.database.ListAssignments(ctx)
		if err != nil {
			return err
		}
		for _, assignment := range assignments {
			mobileConfig.preferred = append(mobileConfig.preferred, assignment.TCPOutbound, assignment.UDPOutbound)
		}
		_, mappings, err := app.database.ListAppliedReserveMappings(ctx)
		if err != nil {
			return err
		}
		for _, mapping := range mappings {
			mobileConfig.preferred = append(mobileConfig.preferred, mapping.TCPReserveCandidateID, mapping.UDPReserveCandidateID)
		}
	}
	session := app.newSession(backend, mobileConfig, dnsResolvers...)
	if err := session.profiles.Sync(ctx); err != nil {
		return err
	}
	return session.runtime.Start(ctx)
}
