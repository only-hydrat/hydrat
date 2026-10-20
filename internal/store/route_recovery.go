package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/sources"
)

// RouteRecovery is debt for a confirmed failure of an actually applied primary,
// not an extension of a liveness proof. At most two rows exist per client.
type RouteRecovery struct {
	ClientID          string
	Transport         RouteTransport
	SourceCIDR        string
	ClientKey         string
	FailedOutbound    string
	CandidateID       string
	Fingerprint       string
	FailureGeneration int64
	AppliedGeneration int64
	ConfirmedAt       time.Time
}

func (store *Store) migrateRouteRecovery(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS route_recovery (
		client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
		transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
		source_cidr TEXT NOT NULL, client_key TEXT NOT NULL, failed_outbound TEXT NOT NULL,
		candidate_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
		failure_generation INTEGER NOT NULL, applied_generation INTEGER NOT NULL,
		confirmed_at INTEGER NOT NULL,
		PRIMARY KEY(client_id,transport)
	)`)
	return err
}

func appliedRecoveryPlanTx(ctx context.Context, tx sqlQueryExecutor) (dataplane.DesiredPlan, error) {
	var generation int64
	var encoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT applied_generation,applied_plan FROM plan_state WHERE singleton=1`).Scan(&generation, &encoded); err != nil {
		return dataplane.DesiredPlan{}, err
	}
	if generation == 0 {
		return dataplane.DesiredPlan{}, nil
	}
	var plan dataplane.DesiredPlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return plan, err
	}
	if plan.Generation != generation {
		return plan, fmt.Errorf("recovery applied generation mismatch")
	}
	return plan, nil
}

func recoveryCandidateID(outbound string) string {
	if candidate, _, tor := strings.Cut(outbound, "-profile-"); tor {
		return candidate
	}
	return sources.CandidateIDFromVLESSHandler(outbound)
}

func recordRouteRecoveriesTx(ctx context.Context, tx sqlQueryExecutor, candidate Candidate, at time.Time) error {
	plan, err := appliedRecoveryPlanTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, route := range plan.Clients {
		if route.Dormant {
			continue
		}
		for _, transport := range []RouteTransport{RouteTransportTCP, RouteTransportUDP} {
			outbound, blocked := route.TCPOutbound, route.BlockTCP
			if transport == RouteTransportUDP {
				outbound, blocked = route.UDPOutbound, route.BlockUDP
			}
			if blocked || recoveryCandidateID(outbound) != candidate.ID {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO route_recovery
				(client_id,transport,source_cidr,client_key,failed_outbound,candidate_id,fingerprint,failure_generation,applied_generation,confirmed_at)
				SELECT id,?,?,public_key,?,?,?,h.failure_generation,?,? FROM clients JOIN candidate_health h ON h.candidate_id=?
				WHERE id=? AND paused=0 AND address=?
				ON CONFLICT(client_id,transport) DO UPDATE SET
				source_cidr=excluded.source_cidr,client_key=excluded.client_key,failed_outbound=excluded.failed_outbound,
				candidate_id=excluded.candidate_id,fingerprint=excluded.fingerprint,
				failure_generation=excluded.failure_generation,applied_generation=excluded.applied_generation,
				confirmed_at=excluded.confirmed_at`,
				transport, route.SourceCIDR, outbound, candidate.ID, candidate.Fingerprint, plan.Generation, at.UnixMilli(), candidate.ID, route.ClientID, route.SourceCIDR); err != nil {
				return err
			}
		}
	}
	return nil
}

func clearRecoveredRouteDebtTx(ctx context.Context, tx sqlExecutor, candidate Candidate) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM route_recovery WHERE candidate_id=? AND fingerprint=? AND EXISTS (
		SELECT 1 FROM candidate_health h WHERE h.candidate_id=route_recovery.candidate_id
		AND h.available=1 AND h.active_success=1 AND h.active_hard_failure=0
		AND ((route_recovery.transport='tcp' AND h.tcp_qualified=1) OR (route_recovery.transport='udp' AND h.udp_qualified=1))
	)`, candidate.ID, candidate.Fingerprint)
	return err
}

// PendingRouteRecoveries prunes only identity/route changes and accepted healthy
// evidence. Age, a newer RPC reservation or another failure cannot forgive debt.
func (store *Store) PendingRouteRecoveries(ctx context.Context) ([]RouteRecovery, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := pendingRouteRecoveriesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func pendingRouteRecoveriesTx(ctx context.Context, tx *sql.Tx) ([]RouteRecovery, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM route_recovery)`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	plan, err := appliedRecoveryPlanTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	routes := make(map[string]dataplane.ClientRoute, len(plan.Clients))
	for _, route := range plan.Clients {
		routes[route.ClientID] = route
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.client_id,r.transport,r.source_cidr,r.client_key,r.failed_outbound,r.candidate_id,r.fingerprint,
		r.failure_generation,r.applied_generation,r.confirmed_at,
		COALESCE(c.fingerprint,''),COALESCE(h.available,0),COALESCE(h.active_hard_failure,0),COALESCE(h.active_success,0),COALESCE(h.tcp_qualified,0),COALESCE(h.udp_qualified,0),
		cl.paused,cl.address,cl.public_key,COALESCE(c.enabled,0),COALESCE(s.enabled,0)
		FROM route_recovery r JOIN clients cl ON cl.id=r.client_id
		LEFT JOIN candidates c ON c.id=r.candidate_id LEFT JOIN candidate_health h ON h.candidate_id=r.candidate_id
		LEFT JOIN sources s ON s.id=c.source_id
		ORDER BY r.client_id,r.transport`)
	if err != nil {
		return nil, err
	}
	var result, obsolete []RouteRecovery
	for rows.Next() {
		var debt RouteRecovery
		var confirmed int64
		var fingerprint, address, clientKey string
		var available, hard, success, tcpQualified, udpQualified, paused, candidateEnabled, sourceEnabled bool
		if err := rows.Scan(&debt.ClientID, &debt.Transport, &debt.SourceCIDR, &debt.ClientKey, &debt.FailedOutbound, &debt.CandidateID, &debt.Fingerprint, &debt.FailureGeneration, &debt.AppliedGeneration, &confirmed, &fingerprint, &available, &hard, &success, &tcpQualified, &udpQualified, &paused, &address, &clientKey, &candidateEnabled, &sourceEnabled); err != nil {
			_ = rows.Close()
			return nil, err
		}
		debt.ConfirmedAt = time.UnixMilli(confirmed)
		route, exists := routes[debt.ClientID]
		outbound, blocked := route.TCPOutbound, route.BlockTCP
		if debt.Transport == RouteTransportUDP {
			outbound, blocked = route.UDPOutbound, route.BlockUDP
		}
		// Operator revocation belongs to the ordinary source lifecycle, not a
		// retry loop that would keep trying to publish a disabled outbound.
		recovered := available && !hard && success && (debt.Transport == RouteTransportTCP && tcpQualified || debt.Transport == RouteTransportUDP && udpQualified)
		if !exists || !candidateEnabled || !sourceEnabled || plan.Generation < debt.AppliedGeneration || route.Dormant || paused || blocked || clientKey != debt.ClientKey || address != debt.SourceCIDR || route.SourceCIDR != debt.SourceCIDR || outbound != debt.FailedOutbound || fingerprint != debt.Fingerprint || recovered {
			obsolete = append(obsolete, debt)
		} else {
			result = append(result, debt)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, debt := range obsolete {
		if _, err := tx.ExecContext(ctx, `DELETE FROM route_recovery WHERE client_id=? AND transport=?`, debt.ClientID, debt.Transport); err != nil {
			return nil, err
		}
	}
	return result, nil
}
