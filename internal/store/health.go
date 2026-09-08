package store

import (
	"context"
	"database/sql"
	"time"
)

type CandidateHealth struct {
	CandidateID       string    `json:"candidate_id"`
	Score             float64   `json:"score"`
	TCPQualified      bool      `json:"tcp_qualified"`
	UDPQualified      bool      `json:"udp_qualified"`
	Available         bool      `json:"available"`
	LatencyMS         float64   `json:"latency_ms"`
	ThroughputMbps    float64   `json:"throughput_mbps"`
	UpdatedAt         time.Time `json:"updated_at"`
	ActiveObservedAt  time.Time `json:"active_observed_at,omitempty"`
	ActiveSuccess     bool      `json:"active_success"`
	ActiveCurrent     bool      `json:"active_current"`
	ActiveHardFailure bool      `json:"active_hard_failure"`
}

type ProbeSample struct {
	CandidateID     string
	Success         bool
	LatencyMS       float64
	ThroughputMbps  float64
	PacketDropRatio float64
	CreatedAt       time.Time
}


func (store *Store) SaveCandidateHealth(ctx context.Context, health CandidateHealth) error {
	return saveCandidateHealthTx(ctx, store.db, health)
}

// UpdateCandidateUDPQualified atomically changes only transport-specific UDP
// eligibility. It deliberately preserves the TCP score, availability and
// freshness written by full qualification.
func (store *Store) UpdateCandidateUDPQualified(
	ctx context.Context,
	candidateID string,
	qualified bool,
) (bool, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE candidate_health
		SET udp_qualified = ?
		WHERE candidate_id = ? AND observation_placeholder = 0
		  AND udp_qualified <> ?
	`, qualified, candidateID, qualified)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed > 0, err
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type sqlQueryExecutor interface {
	sqlExecutor
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqlRowsQueryExecutor interface {
	sqlQueryExecutor
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func saveCandidateHealthTx(ctx context.Context, executor sqlExecutor, health CandidateHealth) error {
	_, err := executor.ExecContext(ctx, `
        INSERT INTO candidate_health(candidate_id, score, tcp_qualified, udp_qualified, available, latency_ms, throughput_mbps, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(candidate_id) DO UPDATE SET score=excluded.score, tcp_qualified=excluded.tcp_qualified,
          udp_qualified=excluded.udp_qualified, available=excluded.available, latency_ms=excluded.latency_ms,
          throughput_mbps=excluded.throughput_mbps, updated_at=excluded.updated_at,
          active_hard_failure=CASE WHEN excluded.available=1 THEN 0 ELSE active_hard_failure END,
          active_success=CASE WHEN excluded.available=1 THEN 1 ELSE active_success END,
          active_observed_at=CASE WHEN excluded.available=1 THEN excluded.updated_at*1000 ELSE active_observed_at END,
          observation_placeholder=0
    `, health.CandidateID, health.Score, health.TCPQualified, health.UDPQualified, health.Available,
		health.LatencyMS, health.ThroughputMbps, health.UpdatedAt.Unix())
	return err
}

func (store *Store) ListCandidateHealth(ctx context.Context) ([]CandidateHealth, error) {
	rows, err := store.db.QueryContext(ctx, `
        SELECT h.candidate_id, h.score, h.tcp_qualified, h.udp_qualified,
               h.available, h.latency_ms, h.throughput_mbps, h.updated_at,
		       h.active_observed_at, h.active_success,
		       h.active_applied_seq, h.failure_generation,
		       h.active_failure_generation, h.active_hard_failure
        FROM candidate_health h
        WHERE h.observation_placeholder = 0
        ORDER BY h.score DESC, h.candidate_id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CandidateHealth, 0)
	for rows.Next() {
		var health CandidateHealth
		var updated int64
		var activeObserved sql.NullInt64
		var activeAppliedSeq int64
		var failureGeneration, activeFailureGeneration int64
		if err := rows.Scan(&health.CandidateID, &health.Score, &health.TCPQualified, &health.UDPQualified,
			&health.Available, &health.LatencyMS, &health.ThroughputMbps, &updated,
			&activeObserved, &health.ActiveSuccess,
			&activeAppliedSeq, &failureGeneration,
			&activeFailureGeneration, &health.ActiveHardFailure); err != nil {
			return nil, err
		}
		health.UpdatedAt = time.Unix(updated, 0)
		if activeObserved.Valid {
			health.ActiveObservedAt = time.UnixMilli(activeObserved.Int64)
		}
		health.ActiveCurrent = activeObserved.Valid &&
			activeAppliedSeq > 0 &&
			failureGeneration == activeFailureGeneration
		result = append(result, health)
	}
	return result, rows.Err()
}

func (store *Store) AppendProbeSample(ctx context.Context, sample ProbeSample) error {
	return appendProbeSampleTx(ctx, store.db, sample)
}

func appendProbeSampleTx(ctx context.Context, executor sqlExecutor, sample ProbeSample) error {
	_, err := executor.ExecContext(ctx, `
        INSERT INTO probe_samples(candidate_id, success, latency_ms, throughput_mbps, packet_drop_ratio, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `, sample.CandidateID, sample.Success, sample.LatencyMS, sample.ThroughputMbps, sample.PacketDropRatio, sample.CreatedAt.Unix())
	return err
}

