package store

import (
	"context"
	"time"

	"github.com/only-hydrat/hydrat/internal/sources"
)

// Plaintext stays inside the store; callers receive only fixed reason codes.
func (store *Store) CandidatePolicyExclusions(ctx context.Context, disallowRU bool) (map[string]string, error) {
	result := make(map[string]string)
	if !disallowRU {
		return result, nil
	}
	rows, err := store.db.QueryContext(ctx, `SELECT c.id,c.label,c.encrypted_payload FROM candidates c JOIN sources s ON s.id=c.source_id WHERE c.enabled=1 AND s.enabled=1 AND c.lifecycle='active' AND c.kind='vless'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, label string
		var encrypted []byte
		if err := rows.Scan(&id, &label, &encrypted); err != nil {
			return nil, err
		}
		payload, err := store.box.Open(id, encrypted)
		if err != nil {
			return nil, err
		}
		if sources.IsRussianEgress(label, string(payload)) {
			result[id] = "policy_ru_egress"
		}
	}
	return result, rows.Err()
}

type ProbeActivity struct {
	FullProbes         int `json:"full_probes"`
	DistinctCandidates int `json:"distinct_candidates"`
}

func (store *Store) ProbeActivitySince(ctx context.Context, since time.Time) (ProbeActivity, error) {
	var result ProbeActivity
	err := store.db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT candidate_id) FROM probe_samples WHERE created_at>=?`, since.Unix()).Scan(&result.FullProbes, &result.DistinctCandidates)
	return result, err
}
