package store

import (
	"context"
	"database/sql"

	"github.com/only-hydrat/hydrat/internal/sources"
)

// SourceForRefresh reads the payload and its device override from one snapshot.
func (store *Store) SourceForRefresh(ctx context.Context, id string) (sources.Kind, string, string, error) {
	var kind sources.Kind
	var payload, hwid []byte
	if err := store.db.QueryRowContext(ctx, `
		SELECT s.kind, s.encrypted_payload, h.encrypted_value
		FROM sources s LEFT JOIN source_hwids h ON h.source_id=s.id
		WHERE s.id=? AND s.pending_delete=0
	`, id).Scan(&kind, &payload, &hwid); err != nil {
		return "", "", "", err
	}
	plain, err := store.box.Open(id, payload)
	if err != nil {
		return "", "", "", err
	}
	if hwid == nil {
		return kind, string(plain), "", nil
	}
	value, err := store.box.Open("source-hwid:"+id, hwid)
	return kind, string(plain), string(value), err
}

func (store *Store) SetSourceHWID(ctx context.Context, id, hwid string) error {
	return store.setSourceHWID(ctx, store.db, id, hwid)
}

func (store *Store) setSourceHWID(ctx context.Context, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, id, hwid string) error {
	if hwid == "" {
		_, err := db.ExecContext(ctx, `DELETE FROM source_hwids WHERE source_id=?`, id)
		return err
	}
	encrypted, err := store.box.Seal("source-hwid:"+id, []byte(hwid))
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `
		INSERT INTO source_hwids (source_id, encrypted_value)
		SELECT id, ? FROM sources WHERE id=? AND pending_delete=0 AND kind IN (?, ?, ?)
		ON CONFLICT(source_id) DO UPDATE SET encrypted_value=excluded.encrypted_value
	`, encrypted, id, sources.KindVLESSSubscription, sources.KindTorSubscription, sources.KindRemoteAuto)
	if err != nil {
		return err
	}
	return requireAffected(result, "subscription")
}
