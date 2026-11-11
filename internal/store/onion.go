package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

// Only handlers actually bound to onion routes protect a Tor profile. Keeping
// every outbound in old plans assigned would pin unused profiles indefinitely.
// Include both plans until acknowledgement of revocation reaches the controller.
func assignedOnionCandidatesTx(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	var desired, applied []byte
	if err := tx.QueryRowContext(ctx, `SELECT desired_plan, applied_plan FROM plan_state WHERE singleton=1`).Scan(&desired, &applied); err != nil {
		return nil, err
	}
	assigned := make(map[string]bool)
	for _, encoded := range [][]byte{desired, applied} {
		if len(encoded) == 0 {
			continue
		}
		// The retirement/profile snapshot caller has already validated these
		// plans, their generations, and handler references in this transaction.
		var plan dataplane.DesiredPlan
		if err := json.Unmarshal(encoded, &plan); err != nil {
			return nil, errors.New("invalid persisted onion plan")
		}
		for _, route := range plan.Clients {
			for _, id := range []string{route.OnionOutbound, route.OnionReserveOutbound} {
				if id != "" {
					assigned[normalizePersistedCandidateID(id)] = true
				}
			}
		}
	}
	return assigned, nil
}

func (store *Store) migrateOnionPermission(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('clients') WHERE name='onion_enabled'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE clients ADD COLUMN onion_enabled INTEGER NOT NULL DEFAULT 0 CHECK(onion_enabled IN (0,1))`); err != nil {
			return err
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('clients') WHERE name='i2p_enabled'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE clients ADD COLUMN i2p_enabled INTEGER NOT NULL DEFAULT 0 CHECK(i2p_enabled IN (0,1))`); err != nil {
			return err
		}
	}
	return tx.Commit()
}
