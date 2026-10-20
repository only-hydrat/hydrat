package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestRoutingEvidenceMigrationIsAdditiveAndBackupSafe(t *testing.T) {
	db, candidate := qoeCandidateStore(t)
	ctx := context.Background()
	if err := db.PutClient(ctx, ClientRecord{ID: "client", Name: "Client", Address: "10.44.0.2/32"}, "retained-config"); err != nil {
		t.Fatal(err)
	}
	// Existing healthy evidence must enter the new ranking scale immediately,
	// without waiting for another probe or replacing medians with a last sample.
	for i, speed := range []float64{8, 8, 8, 8, 100} {
		if _, _, err := db.RecordCandidateQoE(ctx, candidate, qoe.Observation{At: time.Now().Add(time.Duration(i) * time.Second), Success: true, TTFB: 200 * time.Millisecond, ThroughputMbps: speed, Bytes: 262144}, qoe.DefaultPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		`ALTER TABLE clients DROP COLUMN latest_handshake`,
		`ALTER TABLE candidate_qoe_state DROP COLUMN median_ttfb_ms`,
		`ALTER TABLE candidate_qoe_state DROP COLUMN median_throughput_mbps`,
		`DELETE FROM schema_migrations WHERE version=18`,
	} {
		if _, err := db.db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := db.migrateRoutingEvidence(ctx); err != nil {
			t.Fatal(err)
		}
	}
	prior, err := db.ListCandidateQoEStates(ctx)
	if err != nil || len(prior) != 1 || prior[0].MedianTTFB != 200*time.Millisecond || prior[0].MedianThroughputMbps != 8 {
		t.Fatalf("migration did not backfill window medians: %+v %v", prior, err)
	}
	config, err := db.ClientConfig(ctx, "client")
	if err != nil || config != "retained-config" {
		t.Fatalf("migration lost configuration: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := db.RecordCandidateQoE(ctx, candidate, qoe.Observation{At: time.Now().Add(time.Duration(i) * time.Second), Success: true, TTFB: 200 * time.Millisecond, ThroughputMbps: 8, Bytes: 262144}, qoe.DefaultPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	states, err := db.ListCandidateQoEStates(ctx)
	if err != nil || len(states) != 1 || states[0].MedianTTFB != 200*time.Millisecond || states[0].MedianThroughputMbps != 8 {
		t.Fatalf("window medians not persisted: %+v %v", states, err)
	}
	backup := filepath.Join(t.TempDir(), "routing.db")
	if err := db.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(backup, db.box); err != nil {
		t.Fatal(err)
	}
}
