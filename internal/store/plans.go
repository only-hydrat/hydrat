package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/sources"
)

type PlanState struct {
	DesiredGeneration     int64
	AppliedGeneration     int64
	InvalidatedGeneration int64
	DesiredReason         string
	DesiredPlan           []byte
	AppliedPlan           []byte
}

var ErrCandidateInventoryChanged = errors.New("candidate inventory changed")
var ErrCandidateNotFound = errors.New("candidate not found")

type CandidatePlanExpectation struct {
	Candidate      Candidate
	AllowDraining  bool
	EvidenceDigest string
}


func (store *Store) SaveDesiredPlan(ctx context.Context, generation int64, plan []byte) error {
	return store.SaveDesiredPlanWithReason(ctx, generation, plan, "legacy")
}

func (store *Store) SaveDesiredPlanWithReason(
	ctx context.Context,
	generation int64,
	plan []byte,
	reason string,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveDesiredPlanTx(ctx, tx, generation, plan, reason); err != nil {
		return err
	}
	if err := replaceDesiredRouteReservesTx(ctx, tx, generation, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) SaveDesiredPlanForCandidates(
	ctx context.Context,
	generation int64,
	plan []byte,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
) error {
	return store.SaveDesiredPlanForCandidatesAndReserves(
		ctx, generation, plan, expectedEpoch, expectations, nil,
	)
}

func (store *Store) SaveDesiredPlanForCandidatesAndReserves(
	ctx context.Context,
	generation int64,
	plan []byte,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
	mappings []RouteReserveMapping,
) error {
	if len(mappings) != 0 {
		return errors.New("route reserve mappings require a complete desired assignment snapshot")
	}
	return store.saveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, generation, plan, "legacy", expectedEpoch, expectations, mappings, nil, false,
	)
}

// SaveDesiredPlanSnapshotForCandidatesAndReserves is the controller publish
// boundary. It stores the complete desired assignment snapshot with the plan
// and reserve mapping before any external dataplane apply begins.
func (store *Store) SaveDesiredPlanSnapshotForCandidatesAndReserves(
	ctx context.Context,
	generation int64,
	plan []byte,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
	mappings []RouteReserveMapping,
	assignments []AssignmentRecord,
) error {
	return store.SaveDesiredPlanSnapshotForCandidatesAndReservesWithReason(
		ctx, generation, plan, "legacy", expectedEpoch, expectations,
		mappings, assignments,
	)
}

func (store *Store) SaveDesiredPlanSnapshotForCandidatesAndReservesWithReason(
	ctx context.Context,
	generation int64,
	plan []byte,
	reason string,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
	mappings []RouteReserveMapping,
	assignments []AssignmentRecord,
) error {
	return store.saveDesiredPlanSnapshotForCandidatesAndReserves(
		ctx, generation, plan, reason, expectedEpoch, expectations, mappings,
		assignments, true,
	)
}

func (store *Store) saveDesiredPlanSnapshotForCandidatesAndReserves(
	ctx context.Context,
	generation int64,
	plan []byte,
	reason string,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
	mappings []RouteReserveMapping,
	assignments []AssignmentRecord,
	persistAssignments bool,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := store.validateCandidatePlanTx(
		ctx, tx, expectedEpoch, expectations,
	); err != nil {
		return err
	}
	if err := validateRouteReserveMappingsTx(
		ctx, tx, mappings, expectations,
	); err != nil {
		return err
	}
	decodedPlan, err := validateDesiredPlanReserveBindings(
		plan, generation, expectations, mappings,
	)
	if err != nil {
		return err
	}
	var encodedAssignments []byte
	if persistAssignments {
		encodedAssignments, err = validateAndEncodeDesiredAssignmentSnapshotTx(
			ctx, tx, decodedPlan, expectations, assignments,
		)
		if err != nil {
			return err
		}
	}
	if err := saveDesiredPlanTx(ctx, tx, generation, plan, reason); err != nil {
		return err
	}
	if err := replaceDesiredRouteReservesTx(
		ctx, tx, generation, mappings,
	); err != nil {
		return err
	}
	if persistAssignments {
		if _, err := tx.ExecContext(ctx, `
			UPDATE plan_state
			SET desired_assignments_generation=?, desired_assignments=?
			WHERE singleton=1 AND desired_generation=?
		`, generation, encodedAssignments, generation); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type planHandlerBinding struct {
	candidateID string
	clientID    string
	protocol    dataplane.Protocol
}

func validateDesiredPlanReserveBindings(
	encoded []byte,
	generation int64,
	expectations []CandidatePlanExpectation,
	mappings []RouteReserveMapping,
) (dataplane.DesiredPlan, error) {
	var plan dataplane.DesiredPlan
	if !decodeStrictJSON(encoded, &plan) {
		return dataplane.DesiredPlan{}, errors.New("invalid desired plan encoding")
	}
	if plan.Generation != generation {
		return dataplane.DesiredPlan{}, errors.New("desired plan generation mismatch")
	}
	if err := plan.Validate(); err != nil {
		return dataplane.DesiredPlan{}, errors.New("invalid desired plan")
	}
	expectedCandidates := make(map[string]Candidate, len(expectations))
	for _, expectation := range expectations {
		expectedCandidates[expectation.Candidate.ID] = expectation.Candidate
	}
	handlers := make(map[string]planHandlerBinding, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		switch outbound.Protocol {
		case dataplane.ProtocolVLESS:
			candidate, exists := expectedCandidates[outbound.ID]
			if !exists || candidate.Kind != sources.KindVLESS {
				return dataplane.DesiredPlan{}, errors.New("desired VLESS handler is not bound to its candidate")
			}
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: candidate.ID, protocol: outbound.Protocol,
			}
		case dataplane.ProtocolTor:
			candidateID, clientID, ok := parseTorPlanHandler(outbound.ID)
			candidate, exists := expectedCandidates[candidateID]
			if !ok || !exists || candidate.Kind != sources.KindTorBridge {
				return dataplane.DesiredPlan{}, errors.New("desired Tor handler is not safely bound to its candidate")
			}
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: candidate.ID, clientID: clientID,
				protocol: outbound.Protocol,
			}
		}
	}

	expectedMappings, err := expectedRouteReserveMappings(plan, handlers)
	if err != nil {
		return dataplane.DesiredPlan{}, err
	}
	providedMappings := make(map[string]RouteReserveMapping, len(mappings))
	for _, mapping := range mappings {
		providedMappings[mapping.ClientID] = mapping
	}
	if len(providedMappings) != len(expectedMappings) {
		return dataplane.DesiredPlan{}, errors.New("desired route reserve mappings do not match the plan")
	}
	for clientID, expected := range expectedMappings {
		provided, exists := providedMappings[clientID]
		if !exists || provided != expected {
			return dataplane.DesiredPlan{}, errors.New("desired route reserve mapping does not match the plan")
		}
	}
	return plan, nil
}

func persistedPlanHandlers(
	plan dataplane.DesiredPlan,
) (map[string]planHandlerBinding, error) {
	handlers := make(map[string]planHandlerBinding, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		switch outbound.Protocol {
		case dataplane.ProtocolVLESS:
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: outbound.ID, protocol: outbound.Protocol,
			}
		case dataplane.ProtocolTor:
			candidateID, clientID, ok := parseTorPlanHandler(outbound.ID)
			if !ok {
				return nil, errors.New("persisted Tor handler is not safely bound to its candidate")
			}
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: candidateID, clientID: clientID,
				protocol: outbound.Protocol,
			}
		}
	}
	return handlers, nil
}

func expectedRouteReserveMappings(
	plan dataplane.DesiredPlan,
	handlers map[string]planHandlerBinding,
) (map[string]RouteReserveMapping, error) {
	expected := make(map[string]RouteReserveMapping)
	for _, route := range plan.Clients {
		mapping := RouteReserveMapping{ClientID: route.ClientID}
		var err error
		mapping.TCPReserveCandidateID, err = routeCandidateBinding(
			route.ClientID, route.TCPReserveOutbound, handlers,
		)
		if err != nil {
			return nil, err
		}
		mapping.UDPReserveCandidateID, err = routeCandidateBinding(
			route.ClientID, route.UDPReserveOutbound, handlers,
		)
		if err != nil {
			return nil, err
		}
		if mapping.TCPReserveCandidateID != "" {
			mapping.TCPPrimaryCandidateID, err = routeCandidateBinding(
				route.ClientID, route.TCPOutbound, handlers,
			)
			if err != nil {
				return nil, err
			}
		}
		if mapping.UDPReserveCandidateID != "" {
			mapping.UDPPrimaryCandidateID, err = routeCandidateBinding(
				route.ClientID, route.UDPOutbound, handlers,
			)
			if err != nil {
				return nil, err
			}
		}
		if mapping.TCPReserveCandidateID != "" || mapping.UDPReserveCandidateID != "" {
			expected[route.ClientID] = mapping
		}
	}
	return expected, nil
}

func parseTorPlanHandler(outboundID string) (string, string, bool) {
	candidateID, suffix, found := strings.Cut(outboundID, "-profile-")
	if !found || candidateID == "" {
		return "", "", false
	}
	profileIdentity, clientID, found := strings.Cut(suffix, "-client-")
	if !found || profileIdentity == "" || clientID == "" {
		return "", "", false
	}
	slotText, _, _ := strings.Cut(profileIdentity, "-")
	if _, err := strconv.ParseUint(slotText, 10, 31); err != nil {
		return "", "", false
	}
	return candidateID, clientID, true
}

func routeCandidateBinding(
	clientID string,
	outboundID string,
	handlers map[string]planHandlerBinding,
) (string, error) {
	if outboundID == "" {
		return "", nil
	}
	binding, exists := handlers[outboundID]
	if !exists {
		return "", errors.New("client route is not bound to a candidate handler")
	}
	if binding.clientID != "" && binding.clientID != clientID {
		return "", errors.New("client route references another client's handler")
	}
	return binding.candidateID, nil
}

func validateAndEncodeDesiredAssignmentSnapshotTx(
	ctx context.Context,
	tx sqlRowsQueryExecutor,
	plan dataplane.DesiredPlan,
	expectations []CandidatePlanExpectation,
	assignments []AssignmentRecord,
) ([]byte, error) {
	expectedCandidates := make(map[string]Candidate, len(expectations))
	for _, expectation := range expectations {
		expectedCandidates[expectation.Candidate.ID] = expectation.Candidate
	}
	handlers := make(map[string]planHandlerBinding, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		switch outbound.Protocol {
		case dataplane.ProtocolVLESS:
			candidate, exists := expectedCandidates[outbound.ID]
			if exists && candidate.Kind == sources.KindVLESS {
				handlers[outbound.ID] = planHandlerBinding{
					candidateID: candidate.ID, protocol: outbound.Protocol,
				}
			}
		case dataplane.ProtocolTor:
			candidateID, clientID, ok := parseTorPlanHandler(outbound.ID)
			candidate, exists := expectedCandidates[candidateID]
			if ok && exists && candidate.Kind == sources.KindTorBridge {
				handlers[outbound.ID] = planHandlerBinding{
					candidateID: candidate.ID, clientID: clientID,
					protocol: outbound.Protocol,
				}
			}
		}
	}
	type assignmentTarget struct {
		tcp string
		udp string
	}
	targets := make(map[string]assignmentTarget, len(plan.Clients))
	for _, route := range plan.Clients {
		tcp, err := routeCandidateBinding(route.ClientID, route.TCPOutbound, handlers)
		if err != nil {
			return nil, err
		}
		udp, err := routeCandidateBinding(route.ClientID, route.UDPOutbound, handlers)
		if err != nil {
			return nil, err
		}
		targets[route.ClientID] = assignmentTarget{tcp: tcp, udp: udp}
	}

	rows, err := tx.QueryContext(ctx, `SELECT id, paused FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make(map[string]bool)
	for rows.Next() {
		var clientID string
		var paused bool
		if err := rows.Scan(&clientID, &paused); err != nil {
			return nil, err
		}
		clients[clientID] = paused
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(assignments) != len(clients) {
		return nil, errors.New("desired assignment snapshot is incomplete")
	}
	normalized := make([]AssignmentRecord, len(assignments))
	copy(normalized, assignments)
	seen := make(map[string]bool, len(normalized))
	for _, assignment := range normalized {
		paused, exists := clients[assignment.ClientID]
		if !exists || seen[assignment.ClientID] {
			return nil, errors.New("desired assignment snapshot has an invalid client")
		}
		seen[assignment.ClientID] = true
		target, routed := targets[assignment.ClientID]
		if paused {
			if routed || assignment.TCPOutbound != "" || assignment.UDPOutbound != "" {
				return nil, errors.New("paused client assignment snapshot must be cleared")
			}
		} else if !routed || assignment.TCPOutbound != target.tcp ||
			assignment.UDPOutbound != target.udp {
			return nil, errors.New("desired assignment snapshot does not match the plan")
		}
	}
	sort.Slice(normalized, func(left, right int) bool {
		return normalized[left].ClientID < normalized[right].ClientID
	})
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, errors.New("encode desired assignment snapshot")
	}
	return encoded, nil
}

func validatePersistedAssignmentSnapshot(
	ctx context.Context,
	querier schemaQuerier,
	encodedPlan []byte,
	assignments []AssignmentRecord,
) error {
	var plan dataplane.DesiredPlan
	if !decodeStrictJSON(encodedPlan, &plan) || plan.Validate() != nil {
		return errors.New("desired assignment snapshot has an invalid plan")
	}
	handlers := make(map[string]planHandlerBinding, len(plan.Outbounds))
	for _, outbound := range plan.Outbounds {
		switch outbound.Protocol {
		case dataplane.ProtocolVLESS:
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: outbound.ID, protocol: outbound.Protocol,
			}
		case dataplane.ProtocolTor:
			candidateID, clientID, ok := parseTorPlanHandler(outbound.ID)
			if !ok {
				return errors.New("desired assignment snapshot has an invalid Tor handler")
			}
			handlers[outbound.ID] = planHandlerBinding{
				candidateID: candidateID, clientID: clientID,
				protocol: outbound.Protocol,
			}
		}
	}
	type assignmentTarget struct {
		tcp string
		udp string
	}
	targets := make(map[string]assignmentTarget, len(plan.Clients))
	for _, route := range plan.Clients {
		tcp, err := routeCandidateBinding(route.ClientID, route.TCPOutbound, handlers)
		if err != nil {
			return errors.New("desired assignment snapshot does not match the plan")
		}
		udp, err := routeCandidateBinding(route.ClientID, route.UDPOutbound, handlers)
		if err != nil {
			return errors.New("desired assignment snapshot does not match the plan")
		}
		targets[route.ClientID] = assignmentTarget{tcp: tcp, udp: udp}
	}
	rows, err := querier.QueryContext(ctx, `SELECT id, paused FROM clients`)
	if err != nil {
		return err
	}
	defer rows.Close()
	clients := make(map[string]bool)
	for rows.Next() {
		var clientID string
		var paused bool
		if err := rows.Scan(&clientID, &paused); err != nil {
			return err
		}
		clients[clientID] = paused
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(assignments) != len(clients) {
		return errors.New("desired assignment snapshot is incomplete")
	}
	seen := make(map[string]bool, len(assignments))
	for _, assignment := range assignments {
		paused, exists := clients[assignment.ClientID]
		if !exists || seen[assignment.ClientID] {
			return errors.New("desired assignment snapshot has an invalid client")
		}
		seen[assignment.ClientID] = true
		target, routed := targets[assignment.ClientID]
		if paused {
			if routed || assignment.TCPOutbound != "" || assignment.UDPOutbound != "" {
				return errors.New("paused client assignment snapshot must be cleared")
			}
		} else if !routed || assignment.TCPOutbound != target.tcp ||
			assignment.UDPOutbound != target.udp {
			return errors.New("desired assignment snapshot does not match the plan")
		}
	}
	return nil
}

func saveDesiredPlanTx(
	ctx context.Context,
	tx sqlExecutor,
	generation int64,
	plan []byte,
	reason string,
) error {
	if !validDesiredPlanReason(reason) {
		return errors.New("desired plan reason is invalid")
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE plan_state
		SET desired_generation=?, desired_plan=?, desired_reason=?,
		    desired_assignments_generation=0, desired_assignments=NULL,
		    invalidated_generation=0,
		    updated_at=?
		WHERE singleton=1 AND desired_generation < ?
		  AND invalidated_generation < ?
	`, generation, plan, reason, time.Now().Unix(), generation, generation)
	if err != nil {
		return err
	}
	return requireAffected(result, "new desired generation")
}

func validDesiredPlanReason(reason string) bool {
	switch reason {
	case "legacy", "hard_failure", "qoe_degraded", "manual_reassign",
		"client_lifecycle", "pool_promotion", "startup_normalization", "periodic":
		return true
	default:
		return false
	}
}

func validateRouteReserveMappingsTx(
	ctx context.Context,
	tx sqlQueryExecutor,
	mappings []RouteReserveMapping,
	expectations []CandidatePlanExpectation,
) error {
	expectedCandidates := make(map[string]Candidate, len(expectations))
	for _, expectation := range expectations {
		expectedCandidates[expectation.Candidate.ID] = expectation.Candidate
	}
	clients := make(map[string]bool, len(mappings))
	for _, mapping := range mappings {
		if mapping.ClientID == "" {
			return errors.New("route reserve client is required")
		}
		if clients[mapping.ClientID] {
			return errors.New("duplicate route reserve client")
		}
		clients[mapping.ClientID] = true
		var clientExists int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM clients WHERE id=?
		`, mapping.ClientID).Scan(&clientExists); err != nil {
			return err
		}
		if clientExists != 1 {
			return errors.New("route reserve client does not exist")
		}
		pairs := []struct {
			name    string
			primary string
			reserve string
			udp     bool
		}{
			{name: "TCP", primary: mapping.TCPPrimaryCandidateID, reserve: mapping.TCPReserveCandidateID},
			{name: "UDP", primary: mapping.UDPPrimaryCandidateID, reserve: mapping.UDPReserveCandidateID, udp: true},
		}
		hasPair := false
		for _, pair := range pairs {
			if pair.primary == "" && pair.reserve == "" {
				continue
			}
			hasPair = true
			if pair.primary == "" || pair.reserve == "" {
				return fmt.Errorf("route reserve %s pair is incomplete", pair.name)
			}
			if pair.primary == pair.reserve {
				return fmt.Errorf("route reserve %s equals primary", pair.name)
			}
			primary, primaryKnown := expectedCandidates[pair.primary]
			reserve, reserveKnown := expectedCandidates[pair.reserve]
			if !primaryKnown || !reserveKnown {
				return fmt.Errorf("route reserve %s candidate is not in the desired snapshot", pair.name)
			}
			if pair.udp && (primary.Kind != sources.KindVLESS || reserve.Kind != sources.KindVLESS) {
				return errors.New("route reserve UDP candidates must be VLESS")
			}
		}
		if !hasPair {
			return errors.New("empty route reserve mapping must be omitted")
		}
	}
	return nil
}

func replaceDesiredRouteReservesTx(
	ctx context.Context,
	tx sqlExecutor,
	generation int64,
	mappings []RouteReserveMapping,
) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM route_reserve_mappings WHERE stage='desired'
	`); err != nil {
		return err
	}
	for _, mapping := range mappings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO route_reserve_mappings(
			  stage, client_id, generation,
			  tcp_primary_candidate_id, tcp_reserve_candidate_id,
			  udp_primary_candidate_id, udp_reserve_candidate_id
			) VALUES ('desired', ?, ?, ?, ?, ?, ?)
		`, mapping.ClientID, generation,
			mapping.TCPPrimaryCandidateID, mapping.TCPReserveCandidateID,
			mapping.UDPPrimaryCandidateID, mapping.UDPReserveCandidateID,
		); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) ValidateCandidatePlanSnapshot(
	ctx context.Context,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := store.validateCandidatePlanTx(
		ctx, tx, expectedEpoch, expectations,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) validateCandidatePlanTx(
	ctx context.Context,
	tx *sql.Tx,
	expectedEpoch int64,
	expectations []CandidatePlanExpectation,
) error {
	evidenceBacked := len(expectations) == 0 || expectations[0].EvidenceDigest != ""
	for _, expectation := range expectations {
		if (expectation.EvidenceDigest != "") != evidenceBacked {
			return errors.New("candidate plan expectations mix evidence modes")
		}
	}
	if !evidenceBacked {
		var epoch int64
		if err := tx.QueryRowContext(ctx, `
			SELECT epoch FROM inventory_state WHERE singleton=1
		`).Scan(&epoch); err != nil {
			return err
		}
		if epoch != expectedEpoch {
			return ErrCandidateInventoryChanged
		}
	}
	for _, expectation := range expectations {
		if evidenceBacked {
			currentEvidence, err := store.loadCandidateRoutingEvidenceTx(
				ctx, tx, expectation.Candidate.ID,
			)
			if errors.Is(err, sql.ErrNoRows) {
				return CandidateEvidenceChangedError{
					CandidateID: expectation.Candidate.ID,
				}
			}
			if err != nil {
				return err
			}
			if currentEvidence.Digest != expectation.EvidenceDigest {
				return CandidateEvidenceChangedError{
					CandidateID: expectation.Candidate.ID,
				}
			}
		}
		current, err := candidateCurrentTx(ctx, tx, expectation.Candidate)
		if expectation.AllowDraining {
			current, err = candidateRoutableTx(
				ctx, tx, expectation.Candidate,
			)
		}
		if err != nil {
			return err
		}
		if !current {
			return ErrCandidateInventoryChanged
		}
	}
	return nil
}

func (store *Store) MarkAppliedPlan(ctx context.Context, generation int64, plan []byte) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var (
		desiredPlan                  []byte
		desiredAssignmentsGeneration int64
		desiredAssignments           []byte
		desiredReason                string
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT desired_plan, desired_assignments_generation, desired_assignments,
		       desired_reason
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredPlan, &desiredAssignmentsGeneration, &desiredAssignments,
		&desiredReason,
	); err != nil {
		return err
	}
	if !bytes.Equal(desiredPlan, plan) {
		return errors.New("applied plan does not match desired plan")
	}
	var desiredMappings int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings WHERE stage='desired'
	`).Scan(&desiredMappings); err != nil {
		return err
	}
	if desiredMappings != 0 && desiredAssignmentsGeneration != generation {
		return errors.New("desired route reserve mappings require an exact assignment snapshot")
	}
	var assignments []AssignmentRecord
	previousAssignments := make(map[string]AssignmentRecord)
	if desiredAssignmentsGeneration != 0 {
		if desiredAssignmentsGeneration != generation ||
			bytes.Equal(bytes.TrimSpace(desiredAssignments), []byte("null")) ||
			!decodeStrictJSON(desiredAssignments, &assignments) || assignments == nil {
			return errors.New("desired assignment snapshot generation mismatch")
		}
		if err := validatePersistedAssignmentSnapshot(
			ctx, tx, desiredPlan, assignments,
		); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT client_id, tcp_outbound, udp_outbound,
			       tcp_since, udp_since, updated_at
			FROM assignments
		`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var previous AssignmentRecord
			var tcpSince, udpSince, updatedAt int64
			if err := rows.Scan(
				&previous.ClientID, &previous.TCPOutbound, &previous.UDPOutbound,
				&tcpSince, &udpSince, &updatedAt,
			); err != nil {
				_ = rows.Close()
				return err
			}
			previous.TCPSince = time.Unix(tcpSince, 0)
			previous.UDPSince = time.Unix(udpSince, 0)
			previous.UpdatedAt = time.Unix(updatedAt, 0)
			previousAssignments[previous.ClientID] = previous
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	appliedAt := time.Now()
	result, err := tx.ExecContext(ctx, `
		UPDATE plan_state SET applied_generation=?, applied_plan=?, updated_at=?
		WHERE singleton=1 AND desired_generation=? AND applied_generation < ?
	`, generation, plan, appliedAt.Unix(), generation, generation)
	if err != nil {
		return err
	}
	if err := requireAffected(result, "desired generation"); err != nil {
		return err
	}
	var staleDesired int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings
		WHERE stage='desired' AND generation<>?
	`, generation).Scan(&staleDesired); err != nil {
		return err
	}
	if staleDesired != 0 {
		return errors.New("desired route reserve generation mismatch")
	}
	if desiredAssignmentsGeneration != 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM assignments`); err != nil {
			return err
		}
		for _, assignment := range assignments {
			if err := setAssignmentTx(ctx, tx, assignment); err != nil {
				return err
			}
		}
		if err := appendAssignmentMigrationEventsTx(
			ctx, tx, previousAssignments, assignments,
			desiredReason, appliedAt,
		); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM route_reserve_mappings WHERE stage='applied'
	`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO route_reserve_mappings(
		  stage, client_id, generation,
		  tcp_primary_candidate_id, tcp_reserve_candidate_id,
		  udp_primary_candidate_id, udp_reserve_candidate_id
		)
		SELECT 'applied', client_id, generation,
		       tcp_primary_candidate_id, tcp_reserve_candidate_id,
		       udp_primary_candidate_id, udp_reserve_candidate_id
		FROM route_reserve_mappings
		WHERE stage='desired' AND generation=?
	`, generation); err != nil {
		return err
	}
	return tx.Commit()
}

func appendAssignmentMigrationEventsTx(
	ctx context.Context,
	tx *sql.Tx,
	previous map[string]AssignmentRecord,
	next []AssignmentRecord,
	desiredReason string,
	at time.Time,
) error {
	reason := assignmentMigrationReason(desiredReason)
	for _, assignment := range next {
		old, exists := previous[assignment.ClientID]
		if !exists {
			continue
		}
		for _, change := range []struct {
			transport string
			from      string
			to        string
		}{
			{transport: "tcp", from: old.TCPOutbound, to: assignment.TCPOutbound},
			{transport: "udp", from: old.UDPOutbound, to: assignment.UDPOutbound},
		} {
			if change.from == "" || change.from == change.to {
				continue
			}
			message, err := json.Marshal(struct {
				Transport string `json:"transport"`
				From      string `json:"from"`
				To        string `json:"to"`
				Reason    string `json:"reason"`
			}{
				Transport: change.transport,
				From:      change.from,
				To:        change.to,
				Reason:    reason,
			})
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO events(kind, client_id, candidate_id, message, created_at)
				VALUES ('assignment.migrated', ?, ?, ?, ?)
			`, assignment.ClientID, change.to, string(message), at.Unix()); err != nil {
				return err
			}
		}
	}
	return nil
}

func assignmentMigrationReason(desiredReason string) string {
	switch desiredReason {
	case "hard_failure":
		return "hard_failure"
	case "manual_reassign":
		return "manual"
	case "qoe_degraded":
		return "qoe_degraded"
	case "periodic":
		return "quality_30_percent"
	default:
		return "capacity"
	}
}


func (store *Store) PlanGenerations(ctx context.Context) (desired, applied int64, err error) {
	err = store.db.QueryRowContext(ctx, `SELECT desired_generation, applied_generation FROM plan_state WHERE singleton=1`).Scan(&desired, &applied)
	return desired, applied, err
}

// RebaseUnsafeDesiredPlan invalidates a pending generation that predates the
// atomic assignment snapshot boundary. The next controller cycle must publish
// a fresh generation with a complete snapshot before touching the dataplane.
func (store *Store) RebaseUnsafeDesiredPlan(ctx context.Context) (bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	changed, err := rebaseUnsafeDesiredPlanTx(ctx, tx, false)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed, nil
}

func (store *Store) LoadPlanState(ctx context.Context) (PlanState, error) {
	var state PlanState
	err := store.db.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, invalidated_generation,
		       desired_reason, desired_plan, applied_plan
		FROM plan_state WHERE singleton=1
	`).Scan(
		&state.DesiredGeneration,
		&state.AppliedGeneration,
		&state.InvalidatedGeneration,
		&state.DesiredReason,
		&state.DesiredPlan,
		&state.AppliedPlan,
	)
	return state, err
}

