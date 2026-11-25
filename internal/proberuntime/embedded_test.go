package proberuntime

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type noOpResetter struct{}

func (noOpResetter) Reset(uint64) {}

func TestEmbeddedRuntimeRecyclesAnInstanceWithoutStoppingTheApp(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "p.sock")
	started := make(chan net.Listener, 2)
	manager, err := New(Config{
		ConfigPath: "probe.json", APIAddress: "unix://" + socket, MaxProbes: 1,
	}, noOpResetter{}, WithEmbeddedCore(func(_ context.Context, config string) (io.Closer, error) {
		if config != "probe.json" {
			t.Errorf("configuration path = %q", config)
		}
		listener, err := net.Listen("unix", socket)
		if err == nil {
			started <- listener
		}
		return listener, err
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := <-started
	lease, err := manager.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manager.Release(lease, nil)
	var second net.Listener
	select {
	case second = <-started:
	case <-ctx.Done():
		t.Fatal("probe instance did not recycle")
	}
	if err := first.Close(); err == nil {
		t.Fatal("old instance remained open")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err == nil {
		t.Fatal("replacement remained open after shutdown")
	}
}
