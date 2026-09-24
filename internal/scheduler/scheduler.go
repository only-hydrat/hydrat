package scheduler

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

type Protocol string

const (
	ProtocolVLESS Protocol = "vless"
	ProtocolTor   Protocol = "tor"
)

type Candidate struct {
	ID              string
	Protocol        Protocol
	RouteKey        string
	ProfileID       string
	Score           float64
	TCPQualified    bool
	UDPQualified    bool
	ReserveEligible bool
	ActiveEligible  bool
	ActiveFresh     bool
	Warm            bool
	Retiring        bool
	FailureDomain   string
	CircuitOpen     bool
	QoEStatus       qoe.Status
	QoEEffective    time.Duration
	QoEFresh        bool
	QoEReason       string
	QoETracked      bool
	// QoEPromotionReady requires a recent, complete and clean QoE window.
	// It is intentionally used only for optional quality moves; emergency
	// failover can still use any currently qualified alternative.
	QoEPromotionReady bool
}

type Assignment struct {
	TCP      string    `json:"tcp"`
	UDP      string    `json:"udp"`
	TCPSince time.Time `json:"tcp_since"`
	UDPSince time.Time `json:"udp_since"`
}

type ReserveSelection struct {
	TCP string `json:"tcp"`
	UDP string `json:"udp"`
}

type ReserveValidation struct {
	TCP bool
	UDP bool
}

type Client struct {
	ID          string
	LastTraffic time.Time
	Assignment  Assignment
}

type Policy struct {
	InactiveAfter         time.Duration
	MinimumDwell          time.Duration
	MinimumImprovement    float64
	RequiredSnapshots     int
	MaxPlannedMoves       int
	QualityTier           float64
	QoEAlternativeSpeedup float64
}

func PolicyDefaults() Policy {
	return Policy{
		InactiveAfter: 2 * time.Minute, MinimumDwell: 30 * time.Minute,
		MinimumImprovement: 0.30, RequiredSnapshots: 3,
		MaxPlannedMoves: 1, QualityTier: 0.80, QoEAlternativeSpeedup: qoe.MinimumAlternativeSpeedup,
	}
}

type Result struct {
	Assignments  map[string]Assignment `json:"assignments"`
	Load         map[string]int        `json:"active_load"`
	PlannedMoves int                   `json:"planned_moves"`
	HardMoves    int                   `json:"hard_moves"`
	QoEMoves     int                   `json:"qoe_moves"`
}

// ScheduleOptions controls optional placement behavior without weakening
// repairs for unusable, retiring, or QoE-degraded routes.
type ScheduleOptions struct {
	SuppressQualityMoves bool
}

type exclusion struct {
	CandidateID string
	Until       time.Time
}

type Scheduler struct {
	mu         sync.Mutex
	policy     Policy
	streaks    map[string]int
	exclusions map[string][]exclusion
	version    uint64
	loopHook   func()
}

type Preview struct {
	owner       *Scheduler
	scheduler   *Scheduler
	baseVersion uint64
	done        bool
}

type previewChangedError struct{}

func (previewChangedError) Error() string   { return "scheduler preview changed" }
func (previewChangedError) Temporary() bool { return true }

var ErrPreviewChanged error = previewChangedError{}

func New(policy Policy) *Scheduler {
	defaults := PolicyDefaults()
	if policy.InactiveAfter <= 0 {
		policy.InactiveAfter = defaults.InactiveAfter
	}
	if policy.MinimumDwell <= 0 {
		policy.MinimumDwell = defaults.MinimumDwell
	}
	if policy.MinimumImprovement <= 0 {
		policy.MinimumImprovement = defaults.MinimumImprovement
	}
	if policy.RequiredSnapshots <= 0 {
		policy.RequiredSnapshots = defaults.RequiredSnapshots
	}
	if policy.MaxPlannedMoves <= 0 {
		policy.MaxPlannedMoves = defaults.MaxPlannedMoves
	}
	if policy.QualityTier <= 0 || policy.QualityTier > 1 {
		policy.QualityTier = defaults.QualityTier
	}
	if math.IsNaN(policy.QoEAlternativeSpeedup) || math.IsInf(policy.QoEAlternativeSpeedup, 0) ||
		policy.QoEAlternativeSpeedup < qoe.MinimumAlternativeSpeedup {
		policy.QoEAlternativeSpeedup = defaults.QoEAlternativeSpeedup
	}
	return &Scheduler{policy: policy, streaks: make(map[string]int), exclusions: make(map[string][]exclusion)}
}

func (scheduler *Scheduler) Exclude(clientID, candidateID string, until time.Time) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.exclusions[clientID] = compactExclusions(
		append(scheduler.exclusions[clientID], exclusion{
			CandidateID: candidateID, Until: until,
		}),
		time.Time{},
	)
	scheduler.version++
}

func compactExclusions(items []exclusion, now time.Time) []exclusion {
	untilByCandidate := make(map[string]time.Time, len(items))
	for _, item := range items {
		if item.CandidateID == "" || (!now.IsZero() && !item.Until.After(now)) {
			continue
		}
		if current, exists := untilByCandidate[item.CandidateID]; !exists || item.Until.After(current) {
			untilByCandidate[item.CandidateID] = item.Until
		}
	}
	ids := make([]string, 0, len(untilByCandidate))
	for candidateID := range untilByCandidate {
		ids = append(ids, candidateID)
	}
	sort.Strings(ids)
	compacted := make([]exclusion, 0, len(ids))
	for _, candidateID := range ids {
		compacted = append(compacted, exclusion{
			CandidateID: candidateID, Until: untilByCandidate[candidateID],
		})
	}
	return compacted
}

func (scheduler *Scheduler) compactExclusionsLocked(now time.Time) {
	for clientID, items := range scheduler.exclusions {
		compacted := compactExclusions(items, now)
		if len(compacted) == 0 {
			delete(scheduler.exclusions, clientID)
			continue
		}
		scheduler.exclusions[clientID] = compacted
	}
}

func (scheduler *Scheduler) Schedule(now time.Time, clients []Client, candidates []Candidate) Result {
	result, _ := scheduler.ScheduleContext(context.Background(), now, clients, candidates)
	return result
}

func (scheduler *Scheduler) ScheduleWithOptions(
	now time.Time,
	clients []Client,
	candidates []Candidate,
	options ScheduleOptions,
) Result {
	result, _ := scheduler.ScheduleContextWithOptions(
		context.Background(), now, clients, candidates, options,
	)
	return result
}

func (scheduler *Scheduler) ScheduleContext(
	ctx context.Context,
	now time.Time,
	clients []Client,
	candidates []Candidate,
) (Result, error) {
	return scheduler.ScheduleContextWithOptions(
		ctx, now, clients, candidates, ScheduleOptions{},
	)
}

func (scheduler *Scheduler) ScheduleContextWithOptions(
	ctx context.Context,
	now time.Time,
	clients []Client,
	candidates []Candidate,
	options ScheduleOptions,
) (Result, error) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.compactExclusionsLocked(now)
	previousStreaks := cloneStreaks(scheduler.streaks)
	result, err := scheduler.scheduleContext(ctx, now, clients, candidates, options)
	if err != nil {
		scheduler.streaks = previousStreaks
		return Result{}, err
	}
	scheduler.version++
	return result, nil
}

// SelectReserves is intentionally separate from ordinary placement. It does
// not mutate active assignments and deterministically chooses only prequalified
// routes that have a fresh active observation.
func (scheduler *Scheduler) scheduleContext(
	ctx context.Context,
	now time.Time,
	clients []Client,
	candidates []Candidate,
	options ScheduleOptions,
) (Result, error) {
	result := Result{Assignments: make(map[string]Assignment, len(clients)), Load: make(map[string]int)}
	if err := scheduler.checkContext(ctx); err != nil {
		return Result{}, err
	}
	candidates = normalizeOpenDomains(candidates)
	byID := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		if err := scheduler.checkContext(ctx); err != nil {
			return Result{}, err
		}
		byID[candidate.ID] = candidate
	}
	orderedClients := append([]Client(nil), clients...)
	sort.SliceStable(orderedClients, func(i, j int) bool {
		leftOpen := assignmentUsesOpenDomain(orderedClients[i].Assignment, byID)
		rightOpen := assignmentUsesOpenDomain(orderedClients[j].Assignment, byID)
		if leftOpen != rightOpen {
			return leftOpen
		}
		return orderedClients[i].ID < orderedClients[j].ID
	})
	initialLoad := activeLoad(now, orderedClients, scheduler.policy.InactiveAfter)
	for candidateID, count := range initialLoad {
		result.Load[candidateID] = count
	}
	domainLoad := activeDomainLoad(
		now, orderedClients, byID, scheduler.policy.InactiveAfter,
	)

	for _, client := range orderedClients {
		if err := scheduler.checkContext(ctx); err != nil {
			return Result{}, err
		}
		active := !client.LastTraffic.IsZero() && now.Sub(client.LastTraffic) <= scheduler.policy.InactiveAfter
		if active {
			adjustAssignmentLoad(result.Load, domainLoad, client.Assignment, byID, -1)
		}
		assignment := client.Assignment
		plannedMovesBefore := result.PlannedMoves
		hardMovesBefore := result.HardMoves
		assignment.TCP = scheduler.choose(
			now, client, "tcp", assignment.TCP, assignment.TCPSince,
			active, candidates, byID, result.Load, domainLoad, &result, false,
			options.SuppressQualityMoves,
		)
		if assignment.TCP != client.Assignment.TCP {
			assignment.TCPSince = now
		}
		shareQualityMoveBudget := assignment.TCP != client.Assignment.TCP &&
			result.PlannedMoves > plannedMovesBefore &&
			result.HardMoves == hardMovesBefore
		tcpCandidate, tcpExists := byID[assignment.TCP]
		tcpCanUDP := tcpExists &&
			tcpCandidate.Protocol == ProtocolVLESS &&
			tcpCandidate.UDPQualified &&
			scheduler.candidateUsable(now, client.ID, "udp", tcpCandidate) &&
			!tcpCandidate.Retiring &&
			!tcpCandidate.CircuitOpen &&
			tcpCandidate.QoEStatus != qoe.StatusDegraded

		currentUDP, currentUDPExists := byID[client.Assignment.UDP]
		if tcpCanUDP {
			if assignment.UDP != assignment.TCP {
				assignment.UDP = assignment.TCP
				assignment.UDPSince = now
				if currentUDPExists && currentUDP.QoEStatus == qoe.StatusDegraded {
					result.QoEMoves++
				}
			}
		} else {
			assignment.UDP = scheduler.choose(
				now, client, "udp", assignment.UDP, assignment.UDPSince,
				active, candidates, byID, result.Load, domainLoad, &result,
				shareQualityMoveBudget,
				options.SuppressQualityMoves,
			)
			if assignment.UDP != client.Assignment.UDP {
				assignment.UDPSince = now
			}
			if udpCandidate, udpExists := byID[assignment.UDP]; udpExists &&
				udpCandidate.Protocol == ProtocolVLESS &&
				udpCandidate.TCPQualified &&
				udpCandidate.UDPQualified &&
				scheduler.candidateUsable(now, client.ID, "tcp", udpCandidate) &&
				!udpCandidate.Retiring &&
				!udpCandidate.CircuitOpen &&
				udpCandidate.QoEStatus != qoe.StatusDegraded {
				assignment.TCP = assignment.UDP
				assignment.TCPSince = now
			}
		}
		result.Assignments[client.ID] = assignment
		if active {
			adjustAssignmentLoad(result.Load, domainLoad, assignment, byID, 1)
		}
	}
	result.Load = loadFromAssignments(now, orderedClients, result.Assignments, scheduler.policy.InactiveAfter)
	return result, nil
}

func (scheduler *Scheduler) BeginPreview() *Preview {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return &Preview{
		owner: scheduler, scheduler: scheduler.cloneLocked(),
		baseVersion: scheduler.version,
	}
}

func (scheduler *Scheduler) ReadView() *Scheduler {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.cloneLocked()
}

// PlanningFingerprint identifies every scheduler state component that can
// affect a schedule for the supplied clients at now. Exact wall time is not
// included; instead the time-dependent active/dwell/exclusion classifications
// are encoded so retry slices remain resumable until a planning boundary
// actually changes.
func (scheduler *Scheduler) PlanningFingerprint(now time.Time, clients []Client) string {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%+v|", scheduler.policy)
	ordered := append([]Client(nil), clients...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ID < ordered[right].ID })
	for _, client := range ordered {
		active := !client.LastTraffic.IsZero() && now.Sub(client.LastTraffic) <= scheduler.policy.InactiveAfter
		tcpDwell := !client.Assignment.TCPSince.IsZero() && now.Sub(client.Assignment.TCPSince) >= scheduler.policy.MinimumDwell
		udpDwell := !client.Assignment.UDPSince.IsZero() && now.Sub(client.Assignment.UDPSince) >= scheduler.policy.MinimumDwell
		_, _ = fmt.Fprintf(
			hash, "%s:%s:%s:%t:%t:%t|", client.ID,
			client.Assignment.TCP, client.Assignment.UDP,
			active, tcpDwell, udpDwell,
		)
	}
	streakKeys := make([]string, 0, len(scheduler.streaks))
	for key := range scheduler.streaks {
		streakKeys = append(streakKeys, key)
	}
	sort.Strings(streakKeys)
	for _, key := range streakKeys {
		_, _ = fmt.Fprintf(hash, "streak:%s:%d|", key, scheduler.streaks[key])
	}
	clientIDs := make([]string, 0, len(scheduler.exclusions))
	scheduler.compactExclusionsLocked(now)
	for clientID := range scheduler.exclusions {
		clientIDs = append(clientIDs, clientID)
	}
	sort.Strings(clientIDs)
	for _, clientID := range clientIDs {
		activeSet := make(map[string]bool)
		for _, item := range scheduler.exclusions[clientID] {
			activeSet[item.CandidateID] = true
		}
		active := make([]string, 0, len(activeSet))
		for candidateID := range activeSet {
			active = append(active, candidateID)
		}
		sort.Strings(active)
		for _, candidateID := range active {
			_, _ = fmt.Fprintf(hash, "%s:%s|", clientID, candidateID)
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (scheduler *Scheduler) cloneLocked() *Scheduler {
	return &Scheduler{
		policy: scheduler.policy, streaks: cloneStreaks(scheduler.streaks),
		exclusions: cloneExclusions(scheduler.exclusions),
		version:    scheduler.version, loopHook: scheduler.loopHook,
	}
}

func (preview *Preview) Scheduler() *Scheduler {
	return preview.scheduler
}

func (preview *Preview) ScheduleContext(
	ctx context.Context,
	now time.Time,
	clients []Client,
	candidates []Candidate,
) (Result, error) {
	if preview == nil || preview.done {
		return Result{}, errors.New("scheduler preview is already closed")
	}
	return preview.scheduler.ScheduleContext(ctx, now, clients, candidates)
}

func (scheduler *Scheduler) checkContext(ctx context.Context) error {
	if scheduler.loopHook != nil {
		scheduler.loopHook()
	}
	return ctx.Err()
}

func (preview *Preview) Commit() error {
	return preview.CommitAfter(nil)
}

// CommitAfter linearizes a bounded durable publication with the scheduler
// preview. The callback must perform only the local desired-state transaction;
// network/dataplane work belongs after this method returns.
func (preview *Preview) CommitAfter(publish func() error) error {
	if preview == nil || preview.done {
		return errors.New("scheduler preview is already closed")
	}
	preview.owner.mu.Lock()
	defer preview.owner.mu.Unlock()
	preview.done = true
	if preview.owner.version != preview.baseVersion {
		return ErrPreviewChanged
	}
	if publish != nil {
		if err := publish(); err != nil {
			return err
		}
	}
	preview.scheduler.mu.Lock()
	preview.owner.streaks = cloneStreaks(preview.scheduler.streaks)
	preview.owner.exclusions = cloneExclusions(preview.scheduler.exclusions)
	preview.scheduler.mu.Unlock()
	preview.owner.version++
	return nil
}

func (preview *Preview) Discard() {
	if preview == nil || preview.done {
		return
	}
	preview.done = true
}

func cloneStreaks(source map[string]int) map[string]int {
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneExclusions(
	source map[string][]exclusion,
) map[string][]exclusion {
	result := make(map[string][]exclusion, len(source))
	for clientID, exclusions := range source {
		result[clientID] = append([]exclusion(nil), exclusions...)
	}
	return result
}

func (scheduler *Scheduler) choose(
	now time.Time,
	client Client,
	network, currentID string,
	since time.Time,
	active bool,
	candidates []Candidate,
	byID map[string]Candidate,
	load map[string]int,
	domainLoad map[string]int,
	result *Result,
	shareQualityMoveBudget bool,
	suppressQualityMoves bool,
) string {
	eligible := scheduler.eligible(now, client.ID, network, candidates)
	preferred := rendezvous(client.ID+":"+network, eligible, load, domainLoad)
	openFallback := scheduler.openFallback(now, client.ID, network, candidates)
	preferredOpen := rendezvous(
		client.ID+":"+network, openFallback, load, domainLoad,
	)
	current, currentExists := byID[currentID]
	currentUsable := currentExists && scheduler.candidateUsable(now, client.ID, network, current)
	if current.Protocol == ProtocolTor {
		for _, c := range eligible {
			if c.Protocol == ProtocolVLESS {
				currentUsable = false
				break
			}
		}
	}
	if currentID == "" {
		if preferred != "" {
			return preferred
		}
		return preferredOpen
	}
	if currentExists && current.CircuitOpen {
		if preferred == "" && scheduler.openCurrentUsable(
			now, client.ID, network, current,
		) {
			scheduler.resetStreak(client.ID, network)
			return currentID
		}
		if preferred == "" {
			preferred = preferredOpen
		}
		if preferred == currentID {
			scheduler.resetStreak(client.ID, network)
			return currentID
		}
		if result.PlannedMoves >= scheduler.policy.MaxPlannedMoves {
			return currentID
		}
		if preferred == "" {
			result.HardMoves++
			result.PlannedMoves++
			return ""
		}
		result.HardMoves++
		result.PlannedMoves++
		scheduler.resetStreak(client.ID, network)
		return preferred
	}
	if !currentUsable {
		openDomainMove := false
		if preferred == "" && preferredOpen != "" {
			preferred = preferredOpen
			openDomainMove = true
		}
		if preferred == "" {
			return ""
		}
		if openDomainMove &&
			result.PlannedMoves >= scheduler.policy.MaxPlannedMoves {
			return currentID
		}
		if currentID != "" {
			result.HardMoves++
		}
		if openDomainMove {
			result.PlannedMoves++
		}
		scheduler.resetStreak(client.ID, network)
		return preferred
	}
	if current.Retiring {
		if preferred == "" {
			scheduler.resetStreak(client.ID, network)
			return currentID
		}
		result.HardMoves++
		scheduler.resetStreak(client.ID, network)
		return preferred
	}
	if current.QoEStatus == qoe.StatusDegraded {
		requiresEvacuation := qoe.RequiresEvacuation(current.QoEReason)
		alternative := scheduler.qoeAlternative(
			now, client.ID, network, current, candidates, domainLoad,
			!requiresEvacuation,
		)
		if alternative == "" {
			scheduler.resetStreak(client.ID, network)
			return currentID
		}
		if requiresEvacuation {
			if !shareQualityMoveBudget {
				result.PlannedMoves++
			}
			result.QoEMoves++
			scheduler.resetStreak(client.ID, network)
			return alternative
		}
		if now.Sub(since) < scheduler.policy.MinimumDwell {
			scheduler.resetStreak(client.ID, network)
			return currentID
		}
		key := client.ID + ":" + network + ":" + alternative
		scheduler.streaks[key]++
		if scheduler.streaks[key] < scheduler.policy.RequiredSnapshots ||
			(result.PlannedMoves >= scheduler.policy.MaxPlannedMoves &&
				!shareQualityMoveBudget) {
			return currentID
		}
		if !shareQualityMoveBudget {
			result.PlannedMoves++
		}
		result.QoEMoves++
		scheduler.resetStreak(client.ID, network)
		return alternative
	}
	if suppressQualityMoves {
		return currentID
	}
	qualityEligible := make([]Candidate, 0, len(eligible))
	for _, candidate := range eligible {
		if candidate.QoETracked &&
			(candidate.QoEStatus != qoe.StatusHealthy || !candidate.QoEFresh ||
				!candidate.QoEPromotionReady) {
			continue
		}
		qualityEligible = append(qualityEligible, candidate)
	}
	preferred = rendezvous(client.ID+":"+network, qualityEligible, load, domainLoad)
	if preferred == "" {
		scheduler.resetStreak(client.ID, network)
		return currentID
	}
	if currentID == preferred || !active {
		scheduler.resetStreak(client.ID, network)
		return currentID
	}
	target := byID[preferred]
	if current.Score <= 0 || target.Score < current.Score*(1+scheduler.policy.MinimumImprovement) || now.Sub(since) < scheduler.policy.MinimumDwell {
		scheduler.resetStreak(client.ID, network)
		return currentID
	}
	key := client.ID + ":" + network + ":" + preferred
	scheduler.streaks[key]++
	if scheduler.streaks[key] < scheduler.policy.RequiredSnapshots ||
		(result.PlannedMoves >= scheduler.policy.MaxPlannedMoves &&
			!shareQualityMoveBudget) {
		return currentID
	}
	if !shareQualityMoveBudget {
		result.PlannedMoves++
	}
	scheduler.resetStreak(client.ID, network)
	return preferred
}

func (scheduler *Scheduler) candidateUsable(now time.Time, clientID, network string, candidate Candidate) bool {
	if candidate.CircuitOpen || scheduler.excluded(now, clientID, candidate.ID) {
		return false
	}
	if network == "udp" {
		return candidate.Protocol == ProtocolVLESS && candidate.UDPQualified
	}
	return candidate.TCPQualified
}

func (scheduler *Scheduler) openCurrentUsable(
	now time.Time,
	clientID, network string,
	candidate Candidate,
) bool {
	if candidate.Retiring || candidate.QoEStatus == qoe.StatusDegraded ||
		scheduler.excluded(now, clientID, candidate.ID) {
		return false
	}
	if network == "udp" {
		return candidate.Protocol == ProtocolVLESS && candidate.UDPQualified
	}
	return candidate.TCPQualified
}

func (scheduler *Scheduler) eligible(now time.Time, clientID, network string, candidates []Candidate) []Candidate {
	return scheduler.eligibleCircuitState(
		now, clientID, network, candidates, false,
	)
}

func (scheduler *Scheduler) openFallback(
	now time.Time,
	clientID, network string,
	candidates []Candidate,
) []Candidate {
	return scheduler.eligibleCircuitState(
		now, clientID, network, candidates, true,
	)
}

func (scheduler *Scheduler) eligibleCircuitState(
	now time.Time,
	clientID, network string,
	candidates []Candidate,
	circuitOpen bool,
) []Candidate {
	filtered := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Retiring || candidate.CircuitOpen != circuitOpen ||
			candidate.QoEStatus == qoe.StatusDegraded {
			continue
		}
		qualified := candidate.TCPQualified
		if network == "udp" {
			qualified = candidate.Protocol == ProtocolVLESS && candidate.UDPQualified
		}
		if qualified && !scheduler.excluded(now, clientID, candidate.ID) {
			filtered = append(filtered, candidate)
		}
	}
	filtered = preferProtocolVLESS(filtered)
	proved := make([]Candidate, 0, len(filtered))
	for _, candidate := range filtered {
		if candidate.ActiveEligible && candidate.ActiveFresh {
			proved = append(proved, candidate)
		}
	}
	if len(proved) > 0 {
		filtered = proved
	}
	filtered = preferStableQoE(filtered)
	best := 0.0
	for _, candidate := range filtered {
		if candidate.Score > best {
			best = candidate.Score
		}
	}
	threshold := best * scheduler.policy.QualityTier
	result := filtered[:0]
	for _, candidate := range filtered {
		if candidate.Score >= threshold {
			result = append(result, candidate)
		}
	}
	return result
}

func (scheduler *Scheduler) excluded(now time.Time, clientID, candidateID string) bool {
	items := scheduler.exclusions[clientID]
	kept := items[:0]
	excluded := false
	for _, item := range items {
		if now.Before(item.Until) {
			kept = append(kept, item)
			if item.CandidateID == candidateID {
				excluded = true
			}
		}
	}
	if len(kept) == 0 {
		delete(scheduler.exclusions, clientID)
	} else {
		scheduler.exclusions[clientID] = kept
	}
	return excluded
}

func (scheduler *Scheduler) IsExcluded(now time.Time, clientID, candidateID string) bool {
	return scheduler.excluded(now, clientID, candidateID)
}

func (scheduler *Scheduler) resetStreak(clientID, network string) {
	prefix := clientID + ":" + network + ":"
	for key := range scheduler.streaks {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(scheduler.streaks, key)
		}
	}
}
