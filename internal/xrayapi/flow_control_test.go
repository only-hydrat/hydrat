package xrayapi

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func TestAdapterPrivateFlowControl(t *testing.T) {
	dir, err := os.MkdirTemp("", "adapter-flow-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	registry := xrayflow.NewRegistry()
	server, err := xrayflow.Listen(path, registry)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	a := NewAdapter("", "", "", nil)
	if _, err := a.FlowSnapshot(t.Context()); err == nil {
		t.Fatal("unconfigured adapter accepted")
	}
	a.ConfigureFlowControl(path)
	var closed atomic.Bool
	_, finish := registry.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { closed.Store(true) })
	defer finish()
	s, err := a.FlowSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	n, err := a.ResetFlow(t.Context(), xrayflow.ResetRequest{Snapshot: s, Outbound: "old", Source: "10.44.0.2"})
	if err != nil || n != 1 || !closed.Load() {
		t.Fatalf("closed=%t count=%d err=%v", closed.Load(), n, err)
	}
}
