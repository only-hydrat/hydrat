package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/only-hydrat/hydrat/internal/config"
)

func TestRestoreAfterInterruptedArchiveSetsAsideOrphanSQLiteFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Paths.Database = filepath.Join(dir, "hydrat.db")
	cfg.Paths.MasterKey = filepath.Join(dir, "master.key")
	backup := filepath.Join(dir, "backup.db")
	ctx := context.Background()
	if err := runBackup(ctx, cfg, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cfg.Paths.Database, cfg.Paths.Database+".interrupted"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(cfg.Paths.Database+suffix, []byte("previous database sidecar"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runRestore(ctx, cfg, backup); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(cfg.Paths.Database + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("old %s remains at live database path: %v", suffix, err)
		}
	}
	if err := runBackup(ctx, cfg, filepath.Join(dir, "after.db")); err != nil {
		t.Fatal(err)
	}
}
