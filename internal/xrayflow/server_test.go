package xrayflow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientBoundsConnectionTimeout(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "missing.sock"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Snapshot(ctx)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("unbounded missing socket request: %v", err)
	}
}

func privateSocketPath(t *testing.T) string {
	t.Helper()
	// Keep below Unix socket path limits even with long Go test TMPDIR/name.
	dir, err := os.MkdirTemp("", "hf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "flow.sock")
}
