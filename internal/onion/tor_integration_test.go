package onion

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in test using the project's actual Tor binary, without network access.
func TestTorControlIntegration(t *testing.T) {
	image := os.Getenv("HYDRAT_TOR_TEST_IMAGE")
	if image == "" {
		t.Skip("set HYDRAT_TOR_TEST_IMAGE to the pinned runtime image")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "torrc"), []byte("# isolated test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--network", "none", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", directory+":/state", "--entrypoint", "/usr/bin/tor", image, "-f", "/state/torrc", "--DataDirectory", "/state/data", "--ControlSocket", "/state/control", "--CookieAuthentication", "1", "--CookieAuthFile", "/state/data/control_auth_cookie", "--SocksPort", "0", "--DisableNetwork", "1", "--VirtualAddrNetworkIPv4", "198.18.0.0/15").CombinedOutput()
	if err != nil {
		t.Fatalf("start isolated Tor: %v: %s", err, output)
	}
	id := strings.TrimSpace(string(output))
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(cleanup, "docker", "rm", "-f", id).CombinedOutput(); err != nil {
			t.Errorf("cleanup Tor: %v: %s", err, out)
		}
	}()
	control := Control{Socket: filepath.Join(directory, "control"), CookieFile: filepath.Join(directory, "data", "control_auth_cookie")}
	for {
		err = control.Map(ctx, "198.18.0.1", testHost(9))
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("isolated Tor: %s", logs)
			t.Fatalf("Tor mapping not acknowledged: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	// Replaying a durable mapping is idempotent, as required after recovery.
	if err := control.Map(ctx, "198.18.0.1", testHost(9)); err != nil {
		t.Fatal(err)
	}
	// A reused production data directory can restore dormancy. Even without
	// network access Ready must wake Tor before checking its circuit state.
	if err := control.commands(ctx, [][2]string{{"SIGNAL DORMANT", "250 OK"}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := control.Ready(ctx); err == nil {
		t.Fatal("network-disabled Tor unexpectedly has a circuit")
	}
	if err := control.commands(ctx, [][2]string{{"GETINFO dormant", "250-dormant=0\r\n250 OK"}}); err != nil {
		t.Fatal("readiness did not wake Tor:", err)
	}
}
