package device

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBackendStartsServingAndBothProbeRuntimes(t *testing.T) {
	binary := os.Getenv("HYDRAT_DEVICE_TEST_XRAY")
	if binary == "" {
		t.Skip("requires a pinned Xray binary and an isolated network namespace")
	}
	if os.Getenv("HYDRAT_DEVICE_TEST_NAMESPACE") == "" {
		command := exec.Command("unshare", "-Urn", "sh", "-c",
			"ip link set lo up && exec \"$1\" -test.run '^TestBackendStartsServingAndBothProbeRuntimes$'", "sh", os.Args[0])
		command.Env = append(os.Environ(), "HYDRAT_DEVICE_TEST_NAMESPACE=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("device namespace: %v\n%s", err, output)
		}
		return
	}
	root, err := os.MkdirTemp("", "hydrat-device-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	app, err := Open(context.Background(), filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend, err := StartProcesses(ctx, ProcessOptions{
		Xray: binary, Tor: "/bin/true", Lyrebird: "/bin/true", RuntimeDirectory: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err := backend.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := backend.ProbeRuntimeHealth(ctx); err != nil || snapshot.Status != "ready" {
		t.Fatalf("qualification runtime = %+v, %v", snapshot, err)
	}
	if snapshot, err := backend.ActiveProbeRuntimeHealth(ctx); err != nil || snapshot.Status != "ready" {
		t.Fatalf("active runtime = %+v, %v", snapshot, err)
	}
	if err := app.session(backend).engine.Cycle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
}
