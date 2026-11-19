package torpool

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeCheckRequiresWorkingBridgeProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := CheckRuntime(ctx, filepath.Join(t.TempDir(), "missing-tor"), "lyrebird"); err == nil {
		t.Fatal("expected missing Tor to fail smoke test")
	}
}
