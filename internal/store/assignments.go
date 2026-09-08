package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type AssignmentRecord struct {
	ClientID    string    `json:"client_id"`
	TCPOutbound string    `json:"tcp_outbound"`
	UDPOutbound string    `json:"udp_outbound"`
	TCPSince    time.Time `json:"tcp_since"`
	UDPSince    time.Time `json:"udp_since"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RouteReserveMapping struct {
	ClientID              string `json:"client_id"`
	TCPPrimaryCandidateID string `json:"tcp_primary_candidate_id,omitempty"`
	TCPReserveCandidateID string `json:"tcp_reserve_candidate_id,omitempty"`
	UDPPrimaryCandidateID string `json:"udp_primary_candidate_id,omitempty"`
	UDPReserveCandidateID string `json:"udp_reserve_candidate_id,omitempty"`
}

type RouteTransport string

const (
	RouteTransportTCP RouteTransport = "tcp"
	RouteTransportUDP RouteTransport = "udp"
)


func (store *Store) AppliedReserveForFailure(
	ctx context.Context,
	clientID string,
	transport RouteTransport,
	currentPrimaryCandidateID string,
) (string, bool, error) {
	var primaryColumn, reserveColumn, assignmentColumn string
	switch transport {
	case RouteTransportTCP:
		primaryColumn = "tcp_primary_candidate_id"
		reserveColumn = "tcp_reserve_candidate_id"
		assignmentColumn = "tcp_outbound"
	case RouteTransportUDP:
		primaryColumn = "udp_primary_candidate_id"
		reserveColumn = "udp_reserve_candidate_id"
		assignmentColumn = "udp_outbound"
	default:
		return "", false, errors.New("invalid route transport")
	}
	if clientID == "" || currentPrimaryCandidateID == "" {
		return "", false, nil
	}
	query := `
		SELECT mappings.` + reserveColumn + `
		FROM route_reserve_mappings AS mappings
		JOIN plan_state AS plans ON plans.singleton=1
		JOIN assignments AS current ON current.client_id=mappings.client_id
		WHERE mappings.stage='applied'
		  AND mappings.client_id=?
		  AND mappings.generation=plans.applied_generation
		  AND mappings.` + primaryColumn + `=?
		  AND mappings.` + reserveColumn + `<>''
		  AND current.` + assignmentColumn + `=?
	`
	var reserve string
	err := store.db.QueryRowContext(
		ctx, query, clientID, currentPrimaryCandidateID, currentPrimaryCandidateID,
	).Scan(&reserve)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return reserve, true, nil
}

func (store *Store) ListAppliedReserveMappings(
	ctx context.Context,
) (int64, []RouteReserveMapping, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT applied_generation FROM plan_state WHERE singleton=1
	`).Scan(&generation); err != nil {
		return 0, nil, err
	}
	var stale int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM route_reserve_mappings
		WHERE stage='applied' AND generation<>?
	`, generation).Scan(&stale); err != nil {
		return 0, nil, err
	}
	if stale != 0 {
		return 0, nil, errors.New("applied route reserve generation mismatch")
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT client_id,
		       tcp_primary_candidate_id, tcp_reserve_candidate_id,
		       udp_primary_candidate_id, udp_reserve_candidate_id
		FROM route_reserve_mappings
		WHERE stage='applied' AND generation=?
		ORDER BY client_id
	`, generation)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	mappings := make([]RouteReserveMapping, 0)
	for rows.Next() {
		var mapping RouteReserveMapping
		if err := rows.Scan(
			&mapping.ClientID,
			&mapping.TCPPrimaryCandidateID,
			&mapping.TCPReserveCandidateID,
			&mapping.UDPPrimaryCandidateID,
			&mapping.UDPReserveCandidateID,
		); err != nil {
			return 0, nil, err
		}
		mappings = append(mappings, mapping)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}
	return generation, mappings, nil
}


func (store *Store) SetAssignment(ctx context.Context, assignment AssignmentRecord) error {
	return setAssignmentTx(ctx, store.db, assignment)
}

func setAssignmentTx(
	ctx context.Context,
	executor sqlExecutor,
	assignment AssignmentRecord,
) error {
	now := time.Now()
	if assignment.UpdatedAt.IsZero() {
		assignment.UpdatedAt = now
	}
	_, err := executor.ExecContext(ctx, `
        INSERT INTO assignments(client_id, tcp_outbound, udp_outbound, tcp_since, udp_since, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET tcp_outbound=excluded.tcp_outbound,
          udp_outbound=excluded.udp_outbound, tcp_since=excluded.tcp_since,
          udp_since=excluded.udp_since, updated_at=excluded.updated_at
    `, assignment.ClientID, assignment.TCPOutbound, assignment.UDPOutbound,
		assignment.TCPSince.Unix(), assignment.UDPSince.Unix(), assignment.UpdatedAt.Unix())
	return err
}

func (store *Store) ListAssignments(ctx context.Context) ([]AssignmentRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT client_id, tcp_outbound, udp_outbound, tcp_since, udp_since, updated_at FROM assignments ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AssignmentRecord, 0)
	for rows.Next() {
		var record AssignmentRecord
		var tcp, udp, updated int64
		if err := rows.Scan(&record.ClientID, &record.TCPOutbound, &record.UDPOutbound, &tcp, &udp, &updated); err != nil {
			return nil, err
		}
		record.TCPSince, record.UDPSince, record.UpdatedAt = time.Unix(tcp, 0), time.Unix(udp, 0), time.Unix(updated, 0)
		result = append(result, record)
	}
	return result, rows.Err()
}

