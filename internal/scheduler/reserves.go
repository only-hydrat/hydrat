package scheduler

import (
	"context"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func (scheduler *Scheduler) SelectReserves(
	now time.Time,
	clientID string,
	assignment Assignment,
	candidates []Candidate,
) ReserveSelection {
	result, _ := scheduler.SelectReservesContext(
		context.Background(), now, clientID, assignment, candidates,
	)
	return result
}

func (scheduler *Scheduler) SelectReservesContext(
	ctx context.Context,
	now time.Time,
	clientID string,
	assignment Assignment,
	candidates []Candidate,
) (ReserveSelection, error) {
	return scheduler.selectReservesContext(
		ctx, now, clientID, assignment, candidates, true,
	)
}

func (scheduler *Scheduler) ValidateReserveSelectionContext(
	ctx context.Context,
	now time.Time,
	clientID string,
	assignment Assignment,
	applied ReserveSelection,
	candidates []Candidate,
) (ReserveValidation, error) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	byID := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		if err := scheduler.checkContext(ctx); err != nil {
			return ReserveValidation{}, err
		}
		byID[candidate.ID] = candidate
	}
	tcpEligible, err := scheduler.eligibleReserveCandidatesContext(
		ctx,
		now, clientID, "tcp", assignment.TCP, candidates, byID,
		true, false,
	)
	if err != nil {
		return ReserveValidation{}, err
	}
	udpEligible, err := scheduler.eligibleReserveCandidatesContext(
		ctx,
		now, clientID, "udp", assignment.UDP, candidates, byID,
		true, false,
	)
	if err != nil {
		return ReserveValidation{}, err
	}
	result := ReserveValidation{}
	for _, candidate := range tcpEligible {
		if err := scheduler.checkContext(ctx); err != nil {
			return ReserveValidation{}, err
		}
		if applied.TCP != "" && applied.TCP == candidate.ID {
			result.TCP = true
		}
	}
	for _, candidate := range udpEligible {
		if err := scheduler.checkContext(ctx); err != nil {
			return ReserveValidation{}, err
		}
		if applied.UDP != "" && applied.UDP == candidate.ID {
			result.UDP = true
		}
	}
	return result, nil
}

func (scheduler *Scheduler) SelectProspectiveReserves(
	now time.Time,
	clientID string,
	assignment Assignment,
	candidates []Candidate,
) ReserveSelection {
	result, _ := scheduler.SelectProspectiveReservesContext(
		context.Background(), now, clientID, assignment, candidates,
	)
	return result
}

func (scheduler *Scheduler) SelectProspectiveReservesContext(
	ctx context.Context,
	now time.Time,
	clientID string,
	assignment Assignment,
	candidates []Candidate,
) (ReserveSelection, error) {
	return scheduler.selectReservesContext(
		ctx, now, clientID, assignment, candidates, false,
	)
}

func (scheduler *Scheduler) SelectEmergency(
	now time.Time,
	clientID, network, failedID string,
	candidates []Candidate,
	load, domainLoad map[string]int,
) string {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	byID := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	failed := byID[failedID]
	eligible := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID == failedID || sameRouteIdentity(failed, candidate) ||
			candidate.Retiring || candidate.CircuitOpen ||
			candidate.QoEStatus == qoe.StatusDegraded ||
			scheduler.excluded(now, clientID, candidate.ID) {
			continue
		}
		qualified := candidate.TCPQualified
		if network == "udp" {
			qualified = candidate.Protocol == ProtocolVLESS && candidate.UDPQualified
		}
		if qualified {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return ""
	}
	proved := eligible[:0]
	for _, candidate := range eligible {
		if candidate.ActiveEligible && candidate.ActiveFresh {
			proved = append(proved, candidate)
		}
	}
	if len(proved) > 0 {
		eligible = proved
	}
	if failed.FailureDomain != "" {
		distinct := eligible[:0]
		for _, candidate := range eligible {
			if candidateDomain(candidate) != candidateDomain(failed) {
				distinct = append(distinct, candidate)
			}
		}
		if len(distinct) > 0 {
			eligible = distinct
		}
	}
	eligible = preferStableQoE(eligible)
	selected := ""
	selectedDomainLoad := 0
	selectedLoad := 0
	selectedScore := 0.0
	for _, candidate := range eligible {
		candidateDomainLoad := domainLoad[candidateDomain(candidate)]
		candidateLoad := load[candidate.ID]
		if selected == "" || candidateDomainLoad < selectedDomainLoad ||
			(candidateDomainLoad == selectedDomainLoad && candidateLoad < selectedLoad) ||
			(candidateDomainLoad == selectedDomainLoad && candidateLoad == selectedLoad &&
				(candidate.Score > selectedScore ||
					(candidate.Score == selectedScore && candidate.ID < selected))) {
			selected = candidate.ID
			selectedDomainLoad = candidateDomainLoad
			selectedLoad = candidateLoad
			selectedScore = candidate.Score
		}
	}
	return selected
}

func (scheduler *Scheduler) selectReservesContext(
	ctx context.Context,
	now time.Time,
	clientID string,
	assignment Assignment,
	candidates []Candidate,
	requireActiveProof bool,
) (ReserveSelection, error) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	byID := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		if err := scheduler.checkContext(ctx); err != nil {
			return ReserveSelection{}, err
		}
		byID[candidate.ID] = candidate
	}
	tcp, err := scheduler.selectReserveContext(
		ctx,
		now, clientID, "tcp", assignment.TCP, candidates, byID,
		requireActiveProof,
	)
	if err != nil {
		return ReserveSelection{}, err
	}
	udp, err := scheduler.selectReserveContext(
		ctx,
		now, clientID, "udp", assignment.UDP, candidates, byID,
		requireActiveProof,
	)
	if err != nil {
		return ReserveSelection{}, err
	}
	result := ReserveSelection{TCP: tcp, UDP: udp}
	scheduler.version++
	return result, nil
}

func (scheduler *Scheduler) selectReserveContext(
	ctx context.Context,
	now time.Time,
	clientID, network, primaryID string,
	candidates []Candidate,
	byID map[string]Candidate,
	requireActiveProof bool,
) (string, error) {
	eligible, err := scheduler.eligibleReserveCandidatesContext(
		ctx, now, clientID, network, primaryID, candidates, byID,
		requireActiveProof, true,
	)
	if err != nil {
		return "", err
	}
	return rendezvous(
		clientID+":"+network+":reserve",
		eligible,
		map[string]int{},
		map[string]int{},
	), nil
}

func (scheduler *Scheduler) eligibleReserveCandidatesContext(
	ctx context.Context,
	now time.Time,
	clientID, network, primaryID string,
	candidates []Candidate,
	byID map[string]Candidate,
	requireActiveProof bool,
	preferQuality bool,
) ([]Candidate, error) {
	primary, exists := byID[primaryID]
	if primaryID == "" || !exists {
		return nil, nil
	}
	eligible := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if err := scheduler.checkContext(ctx); err != nil {
			return nil, err
		}
		if sameRouteIdentity(primary, candidate) ||
			!candidate.ReserveEligible ||
			(requireActiveProof && (!candidate.ActiveEligible || !candidate.ActiveFresh)) ||
			candidate.Retiring || candidate.CircuitOpen ||
			candidate.QoEStatus == qoe.StatusDegraded ||
			scheduler.excluded(now, clientID, candidate.ID) {
			continue
		}
		qualified := candidate.TCPQualified
		if candidate.Protocol == ProtocolTor {
			qualified = qualified && candidate.Warm
		}
		if network == "udp" {
			qualified = candidate.Protocol == ProtocolVLESS && candidate.UDPQualified
		}
		if !qualified {
			continue
		}
		eligible = append(eligible, candidate)
	}
	primaryDomain := candidateDomain(primary)
	preferDifferentVLESS := network == "tcp" && primary.Protocol == ProtocolVLESS
	hasDifferentDomain := false
	hasDifferentVLESS := false
	for _, candidate := range eligible {
		if err := scheduler.checkContext(ctx); err != nil {
			return nil, err
		}
		if candidateDomain(candidate) == primaryDomain {
			continue
		}
		hasDifferentDomain = true
		if candidate.Protocol == ProtocolVLESS {
			hasDifferentVLESS = true
		}
	}
	if hasDifferentDomain {
		preferred := eligible[:0]
		for _, candidate := range eligible {
			if err := scheduler.checkContext(ctx); err != nil {
				return nil, err
			}
			if candidateDomain(candidate) == primaryDomain {
				continue
			}
			if preferDifferentVLESS && hasDifferentVLESS &&
				candidate.Protocol != ProtocolVLESS {
				continue
			}
			preferred = append(preferred, candidate)
		}
		eligible = preferred
	}
	if !preferQuality {
		return eligible, nil
	}
	eligible = preferStableQoE(eligible)
	best := 0.0
	for _, candidate := range eligible {
		if err := scheduler.checkContext(ctx); err != nil {
			return nil, err
		}
		if candidate.Score > best {
			best = candidate.Score
		}
	}
	threshold := best * scheduler.policy.QualityTier
	qualityEligible := eligible[:0]
	for _, candidate := range eligible {
		if err := scheduler.checkContext(ctx); err != nil {
			return nil, err
		}
		if candidate.Score >= threshold {
			qualityEligible = append(qualityEligible, candidate)
		}
	}
	return qualityEligible, nil
}

func sameRouteIdentity(primary, candidate Candidate) bool {
	if primary.ID == candidate.ID {
		return true
	}
	if primary.RouteKey != "" && primary.RouteKey == candidate.RouteKey {
		return true
	}
	return primary.ProfileID != "" && primary.ProfileID == candidate.ProfileID
}

func (scheduler *Scheduler) qoeAlternative(
	now time.Time,
	clientID, network string,
	current Candidate,
	candidates []Candidate,
	domainLoad map[string]int,
	requireSpeedup bool,
) string {
	qualified := make([]Candidate, 0, len(candidates))
	currentDomain := candidateDomain(current)
	for _, candidate := range candidates {
		if candidate.Retiring || candidate.QoEStatus != qoe.StatusHealthy ||
			!candidate.QoEFresh || candidate.QoEEffective <= 0 ||
			!scheduler.candidateUsable(now, clientID, network, candidate) ||
			(requireSpeedup && float64(candidate.QoEEffective)*scheduler.policy.QoEAlternativeSpeedup > float64(current.QoEEffective)) {
			continue
		}
		qualified = append(qualified, candidate)
	}
	proved := qualified[:0]
	for _, candidate := range qualified {
		if candidate.ActiveEligible && candidate.ActiveFresh {
			proved = append(proved, candidate)
		}
	}
	if len(proved) > 0 {
		qualified = proved
	}
	hasDistinctDomain := false
	for _, candidate := range qualified {
		hasDistinctDomain = hasDistinctDomain ||
			candidateDomain(candidate) != currentDomain
	}
	selected := ""
	var selectedEffective time.Duration
	selectedDomainLoad := 0
	for _, candidate := range qualified {
		if hasDistinctDomain && candidateDomain(candidate) == currentDomain {
			continue
		}
		candidateDomainLoad := domainLoad[candidateDomain(candidate)]
		if selected == "" || candidate.QoEEffective < selectedEffective ||
			(candidate.QoEEffective == selectedEffective &&
				(candidateDomainLoad < selectedDomainLoad ||
					(candidateDomainLoad == selectedDomainLoad && candidate.ID < selected))) {
			selected = candidate.ID
			selectedEffective = candidate.QoEEffective
			selectedDomainLoad = candidateDomainLoad
		}
	}
	return selected
}

func preferStableQoE(candidates []Candidate) []Candidate {
	stable := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.QoETracked ||
			(candidate.QoEStatus == qoe.StatusHealthy && candidate.QoEFresh &&
				candidate.QoEEffective > 0) {
			stable = append(stable, candidate)
		}
	}
	if len(stable) > 0 {
		return stable
	}
	return candidates
}

func preferProtocolVLESS(candidates []Candidate) []Candidate {
	hasVLESS := false
	for _, candidate := range candidates {
		if candidate.Protocol == ProtocolVLESS {
			hasVLESS = true
			break
		}
	}
	if !hasVLESS {
		return candidates
	}
	vless := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Protocol == ProtocolVLESS {
			vless = append(vless, candidate)
		}
	}
	return vless
}
