package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrozenComposeRejectsDifferentRunningMountAndPinsProject(t *testing.T) {
	h, log := fakeDocker(t)
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HYDRAT_TEST_DOCKER_LOG"
if [ "$1" = inspect ]; then
  printf '[{"Type":"bind","Source":"%s","Destination":"/data","RW":true}]
' "$RUNNING_DATA"
  exit
fi
case " $* " in
  *" config --format json "*) printf '%s\n' '{"name":"original","services":{"gateway":{"volumes":[{"type":"bind","source":"/planned","target":"/data"}]},"controller":{"volumes":[{"type":"bind","source":"/planned","target":"/data"}]}}}' ;;
  *" ps -q "*) printf '%s\n' a-container ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(h.ProjectDir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	project, err := h.freezeCompose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tx := transaction{Project: project}
	frozen, err := h.transactionHost(tx)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNNING_DATA", "/actual")
	if err := frozen.checkMounts(context.Background()); err == nil || !strings.Contains(err.Error(), "/data") {
		t.Fatalf("wrong data mount accepted: %v", err)
	}
	t.Setenv("RUNNING_DATA", "/planned")
	if err := frozen.checkMounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(h.path(frozenComposeFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved Compose must be private: %v, %v", info, err)
	}
	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "--project-name original -f "+h.path(frozenComposeFile)) {
		t.Fatalf("commands did not use frozen project: %s", commands)
	}
}

func TestBundledUpgradeRejectsRuntimeMountsFromTheBaseCompose(t *testing.T) {
	h, _ := fakeDocker(t)
	docker := filepath.Join(h.ProjectDir, "docker")
	if err := os.WriteFile(docker, []byte(`#!/bin/sh
printf '{"services":{"gateway":{"volumes":[{"target":"/data"},{"target":"%s"}]}}}\n' "$BINARY_MOUNT"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{xrayPath, torPath, lyrebirdPath, "/usr/local/bin", "/"} {
		t.Setenv("BINARY_MOUNT", target)
		err := h.checkBundledMounts(context.Background(), "candidate.json")
		if err == nil || !strings.Contains(err.Error(), target) {
			t.Fatalf("bundled upgrade accepted mount at %s: %v", target, err)
		}
	}
	t.Setenv("BINARY_MOUNT", "/usr/local/share/xray")
	if err := h.checkBundledMounts(context.Background(), "candidate.json"); err != nil {
		t.Fatalf("ordinary data mounts must be preserved: %v", err)
	}
}
