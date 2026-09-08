package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

func (engine *Engine) dnsResolverForCandidate(candidateID string) (string, error) {
	resolver, err := dataplane.SelectDNSResolver(candidateID, engine.dnsResolvers)
	if err != nil {
		return "", fmt.Errorf("select DNS resolver for %s: %w", candidateID, err)
	}
	return resolver, nil
}

// Capacity and client-lifecycle passes may fill empty assignments and refresh
// reserves, but they must not move an already serving transport merely because
// pool membership changed. Confirmed failures are handled by hardFailureCycle;
// quality moves are handled by periodic/QoE placement with their dwell and
// improvement thresholds. The only exception is legacy normalization where
// the existing primaries alone exceed the runtime's hard route limit.
func preserveServingAssignmentsForCapacityEvents(
	reason PlacementReason,
	clients []scheduler.Client,
	assignments map[string]scheduler.Assignment,
	activeRouteLimit int,
) {
	if reason != PlacementStartupNormalization && reason != PlacementClientLifecycle {
		return
	}
	if activeRouteLimit > 0 {
		serving := make(map[string]bool)
		for _, client := range clients {
			if client.Assignment.TCP != "" {
				serving[client.Assignment.TCP] = true
			}
			if client.Assignment.UDP != "" {
				serving[client.Assignment.UDP] = true
			}
		}
		if len(serving) > activeRouteLimit {
			return
		}
	}
	for _, client := range clients {
		planned, exists := assignments[client.ID]
		if !exists {
			continue
		}
		if client.Assignment.TCP != "" {
			planned.TCP = client.Assignment.TCP
			planned.TCPSince = client.Assignment.TCPSince
		}
		if client.Assignment.UDP != "" {
			planned.UDP = client.Assignment.UDP
			planned.UDPSince = client.Assignment.UDPSince
		}
		assignments[client.ID] = planned
	}
}

// preserveLastKnownGoodWithoutReplacement prevents ordinary planning from
// turning a still-applied transport into an explicit block while qualification
// is rebuilding. Confirmed failures use hardFailureCycle, which performs its
// own verified reserve/emergency replacement and otherwise keeps the applied
// route unchanged.
func preserveLastKnownGoodWithoutReplacement(
	clients []scheduler.Client,
	assignments map[string]scheduler.Assignment,
	applied map[string]scheduler.Assignment,
) {
	for _, client := range clients {
		planned, exists := assignments[client.ID]
		if !exists {
			continue
		}
		lastApplied := applied[client.ID]
		if planned.TCP == "" && client.Assignment.TCP != "" &&
			client.Assignment.TCP == lastApplied.TCP {
			planned.TCP = client.Assignment.TCP
			planned.TCPSince = client.Assignment.TCPSince
		}
		if planned.UDP == "" && client.Assignment.UDP != "" &&
			client.Assignment.UDP == lastApplied.UDP {
			planned.UDP = client.Assignment.UDP
			planned.UDPSince = client.Assignment.UDPSince
		}
		assignments[client.ID] = planned
	}
}

func appliedPrimaryAssignments(state store.PlanState) (map[string]scheduler.Assignment, error) {
	result := make(map[string]scheduler.Assignment)
	if state.AppliedGeneration <= 0 || len(state.AppliedPlan) == 0 {
		return result, nil
	}
	plan, _, err := decodePersistedPlan(
		"applied", state.AppliedGeneration, state.AppliedPlan,
	)
	if err != nil {
		return nil, err
	}
	for _, route := range plan.Clients {
		tcp := candidateIDFromHandler(route.TCPOutbound, route.ClientID)
		if tcp == "" && route.TCPOutbound != "" {
			tcp = route.TCPOutbound
		}
		udp := candidateIDFromHandler(route.UDPOutbound, route.ClientID)
		if udp == "" && route.UDPOutbound != "" {
			udp = route.UDPOutbound
		}
		result[route.ClientID] = scheduler.Assignment{TCP: tcp, UDP: udp}
	}
	return result, nil
}

func candidateReferencesFromPlan(encoded []byte) []string {
	if len(encoded) == 0 {
		return nil
	}
	var plan dataplane.DesiredPlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return nil
	}
	references := make([]string, 0, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		candidateID := outbound.ID
		if marker := strings.Index(candidateID, "-profile-"); marker > 0 {
			candidateID = candidateID[:marker]
		}
		if strings.HasPrefix(candidateID, "cand_") {
			references = append(references, candidateID)
		}
	}
	return references
}

func validatePersistedPlanState(state store.PlanState) (dataplane.DesiredPlan, string, bool, error) {
	if state.DesiredGeneration < 0 || state.AppliedGeneration < 0 ||
		state.InvalidatedGeneration < 0 {
		return dataplane.DesiredPlan{}, "", false, corruptPlanState(
			"negative generations desired=%d applied=%d invalidated=%d",
			state.DesiredGeneration,
			state.AppliedGeneration,
			state.InvalidatedGeneration,
		)
	}
	if state.InvalidatedGeneration != 0 &&
		(state.DesiredGeneration != state.AppliedGeneration ||
			state.InvalidatedGeneration < state.DesiredGeneration) {
		return dataplane.DesiredPlan{}, "", false, corruptPlanState(
			"inconsistent invalidated generation %d for desired=%d applied=%d",
			state.InvalidatedGeneration,
			state.DesiredGeneration,
			state.AppliedGeneration,
		)
	}
	if state.DesiredGeneration == 0 {
		if state.AppliedGeneration != 0 ||
			len(state.DesiredPlan) != 0 ||
			len(state.AppliedPlan) != 0 {
			return dataplane.DesiredPlan{}, "", false, corruptPlanState(
				"zero desired generation has nonzero persisted state",
			)
		}
		return dataplane.DesiredPlan{}, "", false, nil
	}
	if state.AppliedGeneration > state.DesiredGeneration {
		return dataplane.DesiredPlan{}, "", false, corruptPlanState(
			"applied generation %d exceeds desired generation %d",
			state.AppliedGeneration,
			state.DesiredGeneration,
		)
	}
	desired, desiredDigest, err := decodePersistedPlan(
		"desired",
		state.DesiredGeneration,
		state.DesiredPlan,
	)
	if err != nil {
		return dataplane.DesiredPlan{}, "", false, err
	}
	if state.AppliedGeneration == 0 {
		if len(state.AppliedPlan) != 0 {
			return dataplane.DesiredPlan{}, "", false, corruptPlanState(
				"zero applied generation has applied plan bytes",
			)
		}
		return desired, desiredDigest, true, nil
	}
	_, appliedDigest, err := decodePersistedPlan(
		"applied",
		state.AppliedGeneration,
		state.AppliedPlan,
	)
	if err != nil {
		return dataplane.DesiredPlan{}, "", false, err
	}
	if state.AppliedGeneration == state.DesiredGeneration &&
		appliedDigest != desiredDigest {
		return dataplane.DesiredPlan{}, "", false, corruptPlanState(
			"equal desired and applied generations have different semantics",
		)
	}
	return desired, desiredDigest, true, nil
}

func decodePersistedPlan(
	kind string,
	generation int64,
	encoded []byte,
) (dataplane.DesiredPlan, string, error) {
	if len(encoded) == 0 {
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"%s generation %d has no plan bytes",
			kind,
			generation,
		)
	}
	type persistedPlanPayload struct {
		dataplane.DesiredPlan
		Digest string `json:"digest,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var payload persistedPlanPayload
	if err := decoder.Decode(&payload); err != nil {
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"decode %s plan: %v",
			kind,
			err,
		)
	}
	plan := payload.DesiredPlan
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return dataplane.DesiredPlan{}, "", corruptPlanState(
				"decode %s plan: trailing JSON value",
				kind,
			)
		}
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"decode %s plan trailing data: %v",
			kind,
			err,
		)
	}
	if plan.Generation != generation {
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"%s plan generation %d does not match state generation %d",
			kind,
			plan.Generation,
			generation,
		)
	}
	if err := plan.Validate(); err != nil {
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"validate %s plan: %v",
			kind,
			err,
		)
	}
	digest, err := plan.SemanticDigest()
	if err != nil {
		return dataplane.DesiredPlan{}, "", corruptPlanState(
			"digest %s plan: %v",
			kind,
			err,
		)
	}
	return plan, digest, nil
}

func corruptPlanState(format string, arguments ...any) error {
	return fmt.Errorf("corrupt plan state: "+format, arguments...)
}

func (engine *Engine) saveApplyAndMark(
	ctx context.Context,
	plan dataplane.DesiredPlan,
	reason PlacementReason,
	assignmentUpdates []store.AssignmentRecord,
	inventoryEpoch int64,
	expectations []store.CandidatePlanExpectation,
	mappings []store.RouteReserveMapping,
	commitPreview func(func() error) error,
	profileFence *planProfileFence,
	capacityCeiling ...int,
) error {
	if err := engine.validateActiveCriticalRouteCapacity(plan, capacityCeiling...); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if commitPreview != nil {
		if err := engine.store.ValidateCandidatePlanSnapshot(
			ctx, inventoryEpoch, expectations,
		); err != nil {
			return err
		}
	}
	release, err := acquireTorPlanFence(plan, profileFence)
	if err != nil {
		return err
	}
	defer release()
	publish := func() error {
		if engine.afterSchedulerPreviewPrepare != nil {
			engine.afterSchedulerPreviewPrepare()
		}
		return engine.store.SaveDesiredPlanSnapshotForCandidatesAndReservesWithReason(
			ctx, plan.Generation, encoded, string(reason), inventoryEpoch,
			expectations, mappings, assignmentUpdates,
		)
	}
	if commitPreview != nil {
		if err := commitPreview(publish); err != nil {
			return err
		}
	} else if err := publish(); err != nil {
		return err
	}
	return engine.applyPlan(ctx, plan, encoded)
}

func (engine *Engine) validateActiveCriticalRouteCapacity(
	plan dataplane.DesiredPlan,
	capacityCeiling ...int,
) error {
	if engine.activeCriticalRouteLimit <= 0 {
		return nil
	}
	limit := engine.activeCriticalRouteLimit
	if len(capacityCeiling) > 0 && capacityCeiling[0] > limit {
		limit = capacityCeiling[0]
	}
	planned := activeCriticalPlanCandidateCount(plan)
	if planned > limit {
		return &ActiveCriticalRouteLimitError{
			Planned: planned,
			Limit:   limit,
		}
	}
	return nil
}

func (engine *Engine) capturePlanProfiles() (ProfileProvider, *planProfileFence) {
	provider, ok := engine.profiles.(planProfileProvider)
	if !ok {
		return engine.profiles, nil
	}
	profiles, version, stable := provider.PlanProfiles()
	return staticProfileProvider(profiles), &planProfileFence{
		provider: provider, version: version, stable: stable,
	}
}

func acquireTorPlanFence(
	plan dataplane.DesiredPlan,
	fence *planProfileFence,
) (func(), error) {
	if !planReferencesTor(plan) || fence == nil {
		return func() {}, nil
	}
	if !fence.stable {
		return nil, store.CandidateEvidenceChangedError{}
	}
	release, ok := fence.provider.AcquirePlanCommit(fence.version)
	if !ok {
		return nil, store.CandidateEvidenceChangedError{}
	}
	return release, nil
}

func planReferencesTor(plan dataplane.DesiredPlan) bool {
	for _, outbound := range plan.Outbounds {
		if outbound.Protocol == dataplane.ProtocolTor {
			return true
		}
	}
	return false
}

func (engine *Engine) applyPlan(
	ctx context.Context,
	plan dataplane.DesiredPlan,
	encoded []byte,
) error {
	if err := engine.agent.Apply(ctx, plan); err != nil {
		return err
	}
	if err := engine.store.MarkAppliedPlan(ctx, plan.Generation, encoded); err != nil {
		return err
	}
	return nil
}

func (engine *Engine) updateActivity(ctx context.Context, now time.Time) error {
	peers, err := engine.agent.Activity(ctx)
	if err != nil {
		return err
	}
	clients, err := engine.store.ListClients(ctx)
	if err != nil {
		return err
	}
	byKey := make(map[string]store.ClientRecord, len(clients))
	for _, client := range clients {
		byKey[client.PublicKey] = client
	}
	for _, peer := range peers {
		client, exists := byKey[peer.PublicKey]
		if !exists {
			continue
		}
		if err := engine.store.RecordActivity(ctx, client.ID, now, peer.RXBytes, peer.TXBytes); err != nil {
			return err
		}
	}
	return nil
}

// SyncActivity refreshes client traffic counters without running placement.
// QoE uses this fast path so its active cadence does not depend on the much
// slower periodic placement cycle.
func (engine *Engine) SyncActivity(ctx context.Context, now time.Time) error {
	if engine.store == nil || engine.agent == nil {
		return errors.New("controller engine requires store and agent")
	}
	return engine.updateActivity(ctx, now)
}

func (engine *Engine) outbound(
	clientID, candidateID string,
	candidates map[string]store.Candidate,
	payloads map[string]string,
	profiles map[string]torpool.Profile,
	outbounds map[string]dataplane.Outbound,
) (string, error) {
	candidate, exists := candidates[candidateID]
	if !exists {
		return "", fmt.Errorf("candidate %s not found", candidateID)
	}
	payload, exists := payloads[candidateID]
	if !exists {
		return "", store.ErrCandidateEvidenceChanged
	}
	switch candidate.Kind {
	case sources.KindVLESS:
		if _, exists := outbounds[candidateID]; !exists {
			config, err := xrayconfig.VLESSOutbound(payload, candidateID)
			if err != nil {
				return "", err
			}
			encoded, _ := json.Marshal(config)
			outbounds[candidateID] = dataplane.Outbound{ID: candidateID, Protocol: dataplane.ProtocolVLESS, Config: encoded}
		}
		return candidateID, nil
	case sources.KindTorBridge:
		profile, exists := profiles[candidateID]
		if !exists {
			return "", fmt.Errorf("Tor candidate %s is not warm", candidateID)
		}
		// Include the warm slot in the handler identity. Promotion from the
		// explorer to a warm slot changes the SOCKS endpoint; a new tag lets the
		// reconciler add -> route -> remove without colliding with the live tag.
		outboundID := torProfileOutboundID(candidateID, profile, clientID)
		if _, exists := outbounds[outboundID]; !exists {
			config := xrayconfig.TorOutbound(profile.SocksAddr, outboundID, clientID, engine.torSecret)
			encoded, _ := json.Marshal(config)
			outbounds[outboundID] = dataplane.Outbound{ID: outboundID, Protocol: dataplane.ProtocolTor, Config: encoded}
		}
		return outboundID, nil
	default:
		return "", fmt.Errorf("unsupported candidate kind %s", candidate.Kind)
	}
}

func torProfileOutboundID(
	candidateID string,
	profile torpool.Profile,
	clientID string,
) string {
	identity := sha256.Sum256([]byte(fmt.Sprintf(
		"%d\x00%s", profile.Slot, profile.SocksAddr,
	)))
	return fmt.Sprintf(
		"%s-profile-%d-%x-client-%s",
		candidateID, profile.Slot, identity[:6], clientID,
	)
}
