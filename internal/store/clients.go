package store

import (
	"context"
	"fmt"
	"time"
)

type ClientRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	PublicKey     string `json:"public_key"`
	Paused        bool   `json:"paused"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	LastTrafficAt *int64 `json:"last_traffic_at,omitempty"`
	RXBytes       int64  `json:"rx_bytes"`
	TXBytes       int64  `json:"tx_bytes"`
}


func (store *Store) PutClient(ctx context.Context, client ClientRecord, wireGuardConfig string) error {
	if client.ID == "" || client.Name == "" || client.Address == "" || wireGuardConfig == "" {
		return fmt.Errorf("client ID, name, address and config are required")
	}
	encrypted, err := store.box.Seal("client:"+client.ID, []byte(wireGuardConfig))
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = store.db.ExecContext(ctx, `
        INSERT INTO clients(id, name, address, public_key, encrypted_config, paused, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name, address=excluded.address, public_key=excluded.public_key,
          encrypted_config=excluded.encrypted_config, paused=excluded.paused, updated_at=excluded.updated_at
    `, client.ID, client.Name, client.Address, client.PublicKey, encrypted, client.Paused, now, now)
	return err
}

func (store *Store) ListClients(ctx context.Context) ([]ClientRecord, error) {
	rows, err := store.db.QueryContext(ctx, `
        SELECT id, name, address, public_key, paused, created_at, updated_at, last_traffic_at, rx_bytes, tx_bytes
        FROM clients ORDER BY address, id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ClientRecord, 0)
	for rows.Next() {
		var client ClientRecord
		if err := rows.Scan(&client.ID, &client.Name, &client.Address, &client.PublicKey, &client.Paused,
			&client.CreatedAt, &client.UpdatedAt, &client.LastTrafficAt, &client.RXBytes, &client.TXBytes); err != nil {
			return nil, err
		}
		result = append(result, client)
	}
	return result, rows.Err()
}

func (store *Store) ClientConfig(ctx context.Context, id string) (string, error) {
	var encrypted []byte
	if err := store.db.QueryRowContext(ctx, `SELECT encrypted_config FROM clients WHERE id=?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	plain, err := store.box.Open("client:"+id, encrypted)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (store *Store) UpdateClient(ctx context.Context, id, name string, paused bool) error {
	result, err := store.db.ExecContext(ctx, `UPDATE clients SET name=?, paused=?, updated_at=? WHERE id=?`, name, paused, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return requireAffected(result, "client")
}

func (store *Store) DeleteClient(ctx context.Context, id string) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM clients WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireAffected(result, "client")
}

func (store *Store) RecordActivity(ctx context.Context, id string, at time.Time, rxBytes, txBytes int64) error {
	result, err := store.db.ExecContext(ctx, `
        UPDATE clients SET
          last_traffic_at=CASE WHEN activity_seen=1 AND (rx_bytes != ? OR tx_bytes != ?) THEN ? ELSE last_traffic_at END,
          activity_seen=1, rx_bytes=?, tx_bytes=?, updated_at=? WHERE id=?
    `, rxBytes, txBytes, at.Unix(), rxBytes, txBytes, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return requireAffected(result, "client")
}
