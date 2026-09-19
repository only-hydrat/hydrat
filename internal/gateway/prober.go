package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

const (
	fullSlotStart              = 0
	fullSlotCount              = 4
	fastSlotStart              = 4
	fastSlotCount              = 8
	activeSlotStart            = 12
	activeSlotCount            = 4
	qoeSlotStart               = 16
	qoeSlotCount               = 4
	TotalProbeSlots            = 20
	BackgroundActiveProbeSlots = activeSlotCount
)

type qoeMeasurer interface {
	Measure(context.Context, string, string) qoe.Observation
}

type vlessQoEMeasurer interface {
	MeasureVLESS(context.Context, string, string, string) qoe.Observation
}

type availabilityMeasurer interface {
	MeasureAvailability(context.Context, string, string) qoe.Observation
}

const activeAvailabilityResponseReserve = 100 * time.Millisecond

type availabilityCheck struct {
	result <-chan qoe.Observation
	cancel context.CancelFunc
}

type TorProbeManager interface {
	ProbeCandidate(context.Context, torpool.Candidate) (torpool.Profile, error)
	Profiles() []torpool.Profile
	ProfileStatus(string) (torpool.ProfileStatus, bool)
}

type ProbeRuntime interface {
	Acquire(context.Context) (*proberuntime.Lease, error)
	Release(*proberuntime.Lease, error)
	Snapshot() proberuntime.Snapshot
}

type Prober struct {
	control          *probexray.Control
	runtime          ProbeRuntime
	cleanupTimeout   time.Duration
	measurer         probe.Measurer
	liveness         probe.Liveness
	qoe              qoeMeasurer
	tor              TorProbeManager
	portBase         int
	fullSlots        chan int
	fastSlots        chan int
	activeSlots      chan int
	activeOnly       bool
	activeRoutes     *criticalActiveRouteCache
	qoeSlots         chan int
	torProbeLease    chan struct{}
	torRetryInterval time.Duration
}

func NewProber(
	control *probexray.Control,
	runtime ProbeRuntime,
	cleanupTimeout time.Duration,
	measurer probe.Measurer,
	liveness probe.Liveness,
	qoeMeasurer *probe.QoEMeasurer,
	tor TorProbeManager,
	portBase int,
) (*Prober, error) {
	if control == nil {
		return nil, errors.New("probe Xray control is required")
	}
	if runtime == nil {
		return nil, errors.New("probe runtime is required")
	}
	if cleanupTimeout <= 0 {
		return nil, errors.New("probe cleanup timeout is required")
	}
	if portBase <= 0 {
		return nil, errors.New("probe SOCKS port base is required")
	}
	torProbeLease := make(chan struct{}, 1)
	torProbeLease <- struct{}{}
	return &Prober{
		control: control, runtime: runtime, cleanupTimeout: cleanupTimeout,
		measurer: measurer, liveness: liveness, qoe: qoeMeasurer, tor: tor, portBase: portBase,
		fullSlots:        slotPool(fullSlotStart, fullSlotCount),
		fastSlots:        slotPool(fastSlotStart, fastSlotCount),
		activeSlots:      slotPool(activeSlotStart, activeSlotCount),
		qoeSlots:         slotPool(qoeSlotStart, qoeSlotCount),
		torProbeLease:    torProbeLease,
		torRetryInterval: 250 * time.Millisecond,
	}, nil
}

func NewCriticalActiveProber(
	control *probexray.Control,
	runtime ProbeRuntime,
	cleanupTimeout time.Duration,
	liveness probe.Liveness,
	tor TorProbeManager,
	portBase int,
	workers int,
	availability ...*probe.QoEMeasurer,
) (*Prober, error) {
	if control == nil {
		return nil, errors.New("active Xray control is required")
	}
	if runtime == nil {
		return nil, errors.New("active probe runtime is required")
	}
	if cleanupTimeout <= 0 {
		return nil, errors.New("active probe cleanup timeout is required")
	}
	if portBase <= 0 || workers <= 0 {
		return nil, errors.New("active probe SOCKS base and workers are required")
	}
	var availabilityQoE qoeMeasurer
	if len(availability) > 0 {
		availabilityQoE = availability[0]
	}
	return &Prober{
		control: control, runtime: runtime, cleanupTimeout: cleanupTimeout,
		liveness: liveness, qoe: availabilityQoE, tor: tor, portBase: portBase,
		activeSlots: slotPool(0, workers), activeOnly: true,
		activeRoutes:     newCriticalActiveRouteCache(workers),
		torRetryInterval: 250 * time.Millisecond,
	}, nil
}

func (prober *Prober) Probe(ctx context.Context, mode agentapi.ProbeMode, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	if prober.activeOnly && mode != agentapi.ProbeModeActiveCritical {
		return agentapi.ProbeResponse{}, errors.New("critical active prober rejects background mode")
	}
	if request.Kind == sources.KindTorBridge {
		return prober.probeTor(ctx, mode, request)
	}
	if prober.activeOnly {
		return prober.probeCriticalActiveVLESS(ctx, request)
	}
	slots := prober.slots(mode)
	var slot int
	select {
	case slot = <-slots:
		defer func() { slots <- slot }()
	case <-ctx.Done():
		return agentapi.ProbeResponse{}, ctx.Err()
	}
	return prober.probeVLESS(ctx, slot, mode, request)
}

func (prober *Prober) probeCriticalActiveVLESS(
	ctx context.Context,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	outbound, err := xrayconfig.VLESSOutbound(request.Payload, "probe-outbound-0")
	if err != nil {
		return candidateProbeFailure(request.CandidateID, "invalid_candidate"), nil
	}
	encoded, err := json.Marshal(outbound)
	if err != nil {
		return candidateProbeFailure(request.CandidateID, "invalid_candidate"), nil
	}
	lease, err := prober.runtime.Acquire(ctx)
	if err != nil {
		return agentapi.ProbeResponse{}, err
	}
	var cleanupErr error
	defer func() { prober.runtime.Release(lease, cleanupErr) }()
	key := sha256.Sum256(encoded)
	slot, release, setupCleanupErr, err := prober.activeRoutes.acquire(
		lease.Context, lease.Epoch, request.CandidateID, key,
		func(setupCtx context.Context, slot int) (error, error) {
			probeRange := probexray.NewPriorityRange(prober.control, slot, 1)
			configureErr := probeRange.ConfigureEpoch(
				setupCtx, lease.Epoch,
				[]probexray.SlotCandidate{{Slot: 0, Config: encoded}},
			)
			if configureErr == nil {
				return nil, nil
			}
			cleanupCtx, cancel := context.WithTimeout(
				context.WithoutCancel(setupCtx), prober.cleanupTimeout,
			)
			defer cancel()
			return probeRange.ClearEpoch(cleanupCtx, lease.Epoch), configureErr
		},
	)
	cleanupErr = setupCleanupErr
	if setupCleanupErr != nil {
		return agentapi.ProbeResponse{}, setupCleanupErr
	}
	if err != nil {
		return agentapi.ProbeResponse{}, err
	}
	defer release()
	address := fmt.Sprintf("127.0.0.1:%d", prober.portBase+slot)
	availability := prober.startAvailabilityCheck(
		lease.Context, request.CandidateID, address,
	)
	observation := prober.liveness.Observe(lease.Context, address)
	availabilityObservation := awaitAvailabilityCheck(availability)
	if err := lease.Context.Err(); err != nil {
		return agentapi.ProbeResponse{}, err
	}
	response := agentapi.ProbeResponse{
		CandidateID: request.CandidateID,
		Success:     observation.PrimaryOK || observation.ConfirmationOK,
		Observation: observation,
		QoE:         availabilityObservation,
	}
	if !response.Success {
		response.FailureClass = agentapi.FailureCandidate
		response.ErrorCode = "liveness_failed"
	}
	return response, nil
}

func (prober *Prober) probeVLESS(
	ctx context.Context,
	slot int,
	mode agentapi.ProbeMode,
	request agentapi.ProbeRequest,
) (response agentapi.ProbeResponse, probeErr error) {
	control := probexray.NewRange(prober.control, slot, 1)
	if mode == agentapi.ProbeModeActive || mode == agentapi.ProbeModeActiveCritical ||
		mode == agentapi.ProbeModeQoE {
		control = probexray.NewPriorityRange(prober.control, slot, 1)
	}
	lease, err := prober.runtime.Acquire(ctx)
	if err != nil {
		return agentapi.ProbeResponse{}, err
	}
	defer func() {
		panicValue := recover()
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			prober.cleanupTimeout,
		)
		defer cancel()
		clearErr := control.ClearEpoch(cleanupCtx, lease.Epoch)
		prober.runtime.Release(lease, clearErr)
		if panicValue != nil {
			panic(panicValue)
		}
		if clearErr != nil {
			response = agentapi.ProbeResponse{}
			probeErr = fmt.Errorf("clear probe slot: %w", clearErr)
		}
	}()
	return prober.measureVLESS(lease.Context, lease.Epoch, control, slot, mode, request)
}

func (prober *Prober) measureVLESS(
	ctx context.Context,
	epoch uint64,
	control *probexray.Range,
	slot int,
	mode agentapi.ProbeMode,
	request agentapi.ProbeRequest,
) (agentapi.ProbeResponse, error) {
	outbound, err := xrayconfig.VLESSOutbound(request.Payload, fmt.Sprintf("probe-outbound-%d", slot))
	if err != nil {
		return candidateProbeFailure(request.CandidateID, "invalid_candidate"), nil
	}
	encoded, err := json.Marshal(outbound)
	if err != nil {
		return candidateProbeFailure(request.CandidateID, "invalid_candidate"), nil
	}
	if err := control.ConfigureEpoch(
		ctx,
		epoch,
		[]probexray.SlotCandidate{{Slot: 0, Config: encoded}},
	); err != nil {
		return agentapi.ProbeResponse{}, err
	}
	address := fmt.Sprintf("127.0.0.1:%d", prober.portBase+slot)
	if mode == agentapi.ProbeModeQoE {
		if prober.qoe == nil {
			return agentapi.ProbeResponse{}, errors.New("QoE measurer is unavailable")
		}
		var observation qoe.Observation
		if measurer, ok := prober.qoe.(vlessQoEMeasurer); ok {
			observation = measurer.MeasureVLESS(
				ctx, request.CandidateID, address, vlessFlow(request.Payload),
			)
		} else {
			observation = prober.qoe.Measure(ctx, request.CandidateID, address)
		}
		return qoeProbeResponse(request.CandidateID, observation), nil
	}
	if mode == agentapi.ProbeModeFull {
		metrics, err := prober.measurer.MeasureVLESS(ctx, address, vlessFlow(request.Payload))
		if contextErr := ctx.Err(); contextErr != nil {
			return agentapi.ProbeResponse{}, contextErr
		}
		if err != nil {
			return candidateProbeFailure(request.CandidateID, "full_probe_failed"), nil
		}
		return fullProbeResponse(request.CandidateID, metrics, health.ProtocolVLESS), nil
	}
	availability := prober.startAvailabilityCheck(ctx, request.CandidateID, address)
	observation := prober.liveness.Observe(ctx, address)
	availabilityObservation := awaitAvailabilityCheck(availability)
	if err := ctx.Err(); err != nil {
		return agentapi.ProbeResponse{}, err
	}
	response := agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: observation.PrimaryOK || observation.ConfirmationOK,
		Observation: observation, QoE: availabilityObservation,
	}
	if !response.Success {
		response.FailureClass = agentapi.FailureCandidate
		response.ErrorCode = "liveness_failed"
	}
	return response, nil
}

func vlessFlow(payload string) string {
	link, err := url.Parse(strings.TrimSpace(payload))
	if err != nil {
		return ""
	}
	return link.Query().Get("flow")
}

func (prober *Prober) probeTor(ctx context.Context, mode agentapi.ProbeMode, request agentapi.ProbeRequest) (agentapi.ProbeResponse, error) {
	if prober.tor == nil {
		return agentapi.ProbeResponse{}, errors.New("Tor probe manager is unavailable")
	}
	probeCtx := ctx
	var profile torpool.Profile
	var observation health.Observation
	if mode == agentapi.ProbeModeActive || mode == agentapi.ProbeModeActiveCritical ||
		mode == agentapi.ProbeModeQoE {
		status, exists := prober.tor.ProfileStatus(request.CandidateID)
		if !exists {
			// The logical working pool is larger than the bounded Tor runtime.
			// A missing local profile therefore says nothing about the bridge
			// itself and must never contribute candidate hard-failure evidence.
			return infrastructureProbeFailure(
				request.CandidateID, "tor_profile_unavailable",
			), nil
		}
		if status.Exited {
			return candidateProbeFailure(request.CandidateID, "tor_process_exited"), nil
		}
		if mode == agentapi.ProbeModeQoE && status.Profile.Role != "warm" {
			return candidateProbeFailure(request.CandidateID, "tor_profile_unavailable"), nil
		}
		profile = status.Profile
	} else {
		release, err := prober.acquireTorProbe(ctx)
		if err != nil {
			return agentapi.ProbeResponse{}, err
		}
		defer release()
		probeCtx, cancel := responseBudgetContext(ctx)
		defer cancel()
		if err := probeCtx.Err(); err != nil {
			return agentapi.ProbeResponse{}, err
		}
		profile, err = prober.tor.ProbeCandidate(probeCtx, torpool.Candidate{
			ID: request.CandidateID, Bridge: request.Payload, Score: 50, Qualified: true,
		})
		if err != nil {
			return agentapi.ProbeResponse{}, err
		}
		var profileAvailable bool
		observation, profileAvailable = prober.waitTorReady(probeCtx, profile)
		if !profileAvailable {
			return candidateProbeFailure(request.CandidateID, "tor_process_exited"), nil
		}
		if !observation.PrimaryOK && !observation.ConfirmationOK {
			return candidateProbeFailure(request.CandidateID, "tor_bootstrap_timeout"), nil
		}
	}
	if mode == agentapi.ProbeModeQoE {
		if prober.qoe == nil {
			return agentapi.ProbeResponse{}, errors.New("QoE measurer is unavailable")
		}
		observation := prober.qoe.Measure(ctx, request.CandidateID, profile.SocksAddr)
		if !prober.warmProfileAvailable(profile) {
			return candidateProbeFailure(request.CandidateID, "tor_process_exited"), nil
		}
		return qoeProbeResponse(request.CandidateID, observation), nil
	}
	if mode == agentapi.ProbeModeFull {
		metrics, err := prober.measurer.Measure(probeCtx, profile.SocksAddr, health.ProtocolTor)
		if !prober.profileAvailable(profile) {
			return candidateProbeFailure(request.CandidateID, "tor_process_exited"), nil
		}
		if err != nil {
			return candidateProbeFailure(request.CandidateID, "full_probe_failed"), nil
		}
		return fullProbeResponse(request.CandidateID, metrics, health.ProtocolTor), nil
	}
	if mode == agentapi.ProbeModeActive || mode == agentapi.ProbeModeActiveCritical {
		availability := prober.startAvailabilityCheck(
			ctx, request.CandidateID, profile.SocksAddr,
		)
		// Active checks observe the serving circuit exactly once. Retrying until
		// the deadline would turn a real two-endpoint traffic outage into an
		// infrastructure timeout and prevent evacuation.
		observation = prober.liveness.Observe(ctx, profile.SocksAddr)
		availabilityObservation := awaitAvailabilityCheck(availability)
		if err := ctx.Err(); err != nil {
			return agentapi.ProbeResponse{}, err
		}
		if !prober.profileAvailable(profile) {
			return candidateProbeFailure(request.CandidateID, "tor_process_exited"), nil
		}
		response := agentapi.ProbeResponse{
			CandidateID: request.CandidateID,
			Success:     observation.PrimaryOK || observation.ConfirmationOK,
			Observation: observation, QoE: availabilityObservation,
		}
		if !response.Success {
			response.FailureClass = agentapi.FailureCandidate
			response.ErrorCode = "liveness_failed"
		}
		return response, nil
	}
	response := agentapi.ProbeResponse{
		CandidateID: request.CandidateID, Success: observation.PrimaryOK || observation.ConfirmationOK,
		Observation: observation,
	}
	if !response.Success {
		response.FailureClass = agentapi.FailureCandidate
		response.ErrorCode = "liveness_failed"
	}
	return response, nil
}

func (prober *Prober) startAvailabilityCheck(
	ctx context.Context,
	candidateID string,
	socksAddress string,
) *availabilityCheck {
	measurer, ok := prober.qoe.(availabilityMeasurer)
	if !ok {
		return nil
	}
	availabilityCtx := ctx
	var cancel context.CancelFunc = func() {}
	if deadline, ok := ctx.Deadline(); ok {
		availabilityDeadline := deadline.Add(-activeAvailabilityResponseReserve)
		if availabilityDeadline.After(time.Now()) {
			availabilityCtx, cancel = context.WithDeadline(ctx, availabilityDeadline)
		} else {
			availabilityCtx, cancel = context.WithCancel(ctx)
			cancel()
		}
	} else {
		availabilityCtx, cancel = context.WithCancel(ctx)
	}
	result := make(chan qoe.Observation, 1)
	go func() {
		result <- measurer.MeasureAvailability(availabilityCtx, candidateID, socksAddress)
	}()
	return &availabilityCheck{result: result, cancel: cancel}
}

func awaitAvailabilityCheck(check *availabilityCheck) *qoe.Observation {
	if check == nil {
		return nil
	}
	defer check.cancel()
	observation := <-check.result
	return &observation
}

func (prober *Prober) acquireTorProbe(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-prober.torProbeLease:
		if err := ctx.Err(); err != nil {
			prober.torProbeLease <- struct{}{}
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() { prober.torProbeLease <- struct{}{} })
		}, nil
	}
}

func (prober *Prober) waitTorReady(ctx context.Context, profile torpool.Profile) (health.Observation, bool) {
	interval := prober.torRetryInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	var observation health.Observation
	for ctx.Err() == nil {
		if !prober.profileAvailable(profile) {
			return observation, false
		}
		observation = prober.liveness.Observe(ctx, profile.SocksAddr)
		if observation.PrimaryOK || observation.ConfirmationOK {
			return observation, true
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return observation, true
		case <-timer.C:
		}
	}
	return observation, true
}

func (prober *Prober) profileAvailable(wanted torpool.Profile) bool {
	status, exists := prober.tor.ProfileStatus(wanted.CandidateID)
	return exists && !status.Exited && status.Profile.Slot == wanted.Slot
}

func (prober *Prober) warmProfileAvailable(wanted torpool.Profile) bool {
	status, exists := prober.tor.ProfileStatus(wanted.CandidateID)
	return exists && !status.Exited && status.Profile.Role == "warm" &&
		status.Profile.CandidateID == wanted.CandidateID &&
		status.Profile.Slot == wanted.Slot && status.Profile.SocksAddr == wanted.SocksAddr
}

func responseBudgetContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	const reserve = 100 * time.Millisecond
	remaining := time.Until(deadline)
	if remaining <= reserve {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline.Add(-reserve))
}

func (prober *Prober) slots(mode agentapi.ProbeMode) chan int {
	switch mode {
	case agentapi.ProbeModeFast:
		return prober.fastSlots
	case agentapi.ProbeModeActive:
		return prober.activeSlots
	case agentapi.ProbeModeActiveCritical:
		return prober.activeSlots
	case agentapi.ProbeModeQoE:
		return prober.qoeSlots
	default:
		return prober.fullSlots
	}
}

func qoeProbeResponse(candidateID string, observation qoe.Observation) agentapi.ProbeResponse {
	response := agentapi.ProbeResponse{
		CandidateID: candidateID,
		Success:     observation.Success,
		QoE:         &observation,
	}
	if observation.Infrastructure {
		response.FailureClass = agentapi.FailureInfrastructure
		response.ErrorCode = observation.ErrorCode
	} else if !observation.Success {
		response.FailureClass = agentapi.FailureCandidate
		response.ErrorCode = observation.ErrorCode
	}
	return response
}

func slotPool(start, count int) chan int {
	slots := make(chan int, count)
	for slot := start; slot < start+count; slot++ {
		slots <- slot
	}
	return slots
}

type criticalActiveRouteCache struct {
	mu      sync.Mutex
	entries map[string]*criticalActiveRoute
	free    []int
	changed chan struct{}
	clock   uint64
}

type criticalActiveRoute struct {
	candidateID string
	slot        int
	epoch       uint64
	key         [sha256.Size]byte
	configured  bool
	settingUp   bool
	users       int
	lastUsed    uint64
}

type criticalActiveRouteSetup func(context.Context, int) (cleanupErr, err error)

func newCriticalActiveRouteCache(capacity int) *criticalActiveRouteCache {
	free := make([]int, capacity)
	for slot := range capacity {
		free[slot] = slot
	}
	return &criticalActiveRouteCache{
		entries: make(map[string]*criticalActiveRoute, capacity),
		free:    free,
		changed: make(chan struct{}),
	}
}

func (cache *criticalActiveRouteCache) acquire(
	ctx context.Context,
	epoch uint64,
	candidateID string,
	key [sha256.Size]byte,
	setup criticalActiveRouteSetup,
) (int, func(), error, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, nil, nil, err
		}
		cache.mu.Lock()
		entry := cache.entries[candidateID]
		if entry != nil {
			matches := entry.configured && entry.epoch == epoch && entry.key == key
			switch {
			case entry.settingUp || !matches && entry.users > 0:
				changed := cache.changed
				cache.mu.Unlock()
				if err := waitForCriticalActiveRouteChange(ctx, changed); err != nil {
					return 0, nil, nil, err
				}
				continue
			case matches:
				entry.users++
				cache.touchLocked(entry)
				cache.mu.Unlock()
				return entry.slot, cache.releaseFunc(entry), nil, nil
			default:
				entry.epoch = epoch
				entry.key = key
				entry.configured = false
				entry.settingUp = true
				entry.users = 1
				cache.touchLocked(entry)
				cache.mu.Unlock()
				return cache.finishSetup(ctx, entry, setup)
			}
		}

		slot, ok := cache.takeSlotLocked()
		if !ok {
			changed := cache.changed
			cache.mu.Unlock()
			if err := waitForCriticalActiveRouteChange(ctx, changed); err != nil {
				return 0, nil, nil, err
			}
			continue
		}
		entry = &criticalActiveRoute{
			candidateID: candidateID,
			slot:        slot,
			epoch:       epoch,
			key:         key,
			settingUp:   true,
			users:       1,
		}
		cache.touchLocked(entry)
		cache.entries[candidateID] = entry
		cache.mu.Unlock()
		return cache.finishSetup(ctx, entry, setup)
	}
}

func (cache *criticalActiveRouteCache) finishSetup(
	ctx context.Context,
	entry *criticalActiveRoute,
	setup criticalActiveRouteSetup,
) (int, func(), error, error) {
	cleanupErr, setupErr := setup(ctx, entry.slot)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry.settingUp = false
	if setupErr != nil || cleanupErr != nil {
		entry.users = 0
		delete(cache.entries, entry.candidateID)
		cache.free = append(cache.free, entry.slot)
		cache.notifyLocked()
		return 0, nil, cleanupErr, setupErr
	}
	entry.configured = true
	cache.touchLocked(entry)
	cache.notifyLocked()
	return entry.slot, cache.releaseFunc(entry), nil, nil
}

func (cache *criticalActiveRouteCache) takeSlotLocked() (int, bool) {
	if len(cache.free) > 0 {
		slot := cache.free[0]
		cache.free = cache.free[1:]
		return slot, true
	}
	var victim *criticalActiveRoute
	for _, entry := range cache.entries {
		if entry.settingUp || entry.users != 0 {
			continue
		}
		if victim == nil || entry.lastUsed < victim.lastUsed {
			victim = entry
		}
	}
	if victim == nil {
		return 0, false
	}
	delete(cache.entries, victim.candidateID)
	return victim.slot, true
}

func (cache *criticalActiveRouteCache) releaseFunc(entry *criticalActiveRoute) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			cache.mu.Lock()
			if entry.users > 0 {
				entry.users--
				cache.touchLocked(entry)
				cache.notifyLocked()
			}
			cache.mu.Unlock()
		})
	}
}

func (cache *criticalActiveRouteCache) touchLocked(entry *criticalActiveRoute) {
	cache.clock++
	entry.lastUsed = cache.clock
}

func (cache *criticalActiveRouteCache) notifyLocked() {
	close(cache.changed)
	cache.changed = make(chan struct{})
}

func waitForCriticalActiveRouteChange(ctx context.Context, changed <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
		return nil
	}
}

func candidateProbeFailure(candidateID, code string) agentapi.ProbeResponse {
	return agentapi.ProbeResponse{
		CandidateID: candidateID, FailureClass: agentapi.FailureCandidate, ErrorCode: code,
	}
}

func infrastructureProbeFailure(candidateID, code string) agentapi.ProbeResponse {
	return agentapi.ProbeResponse{
		CandidateID: candidateID, FailureClass: agentapi.FailureInfrastructure, ErrorCode: code,
	}
}

func fullProbeResponse(candidateID string, metrics health.Metrics, protocol health.Protocol) agentapi.ProbeResponse {
	evaluation := health.Evaluate(metrics, protocol)
	response := agentapi.ProbeResponse{
		CandidateID: candidateID,
		Success:     evaluation.TCPQualified,
		Metrics:     metrics,
		Evaluation:  evaluation,
	}
	if !response.Success {
		response.FailureClass = agentapi.FailureCandidate
		response.ErrorCode = health.QualificationFailureCode(metrics, evaluation)
	}
	return response
}
