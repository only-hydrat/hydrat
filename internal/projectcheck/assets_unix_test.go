//go:build unix

package projectcheck

import (
	"errors"

	"os"
	"os/exec"
	"path/filepath"

	"strings"
	"testing"
)

func TestDeploymentRequiresInContainerReadinessAfterComposeHealth(t *testing.T) {
	root := repositoryRoot(t)
	compose := readText(t, filepath.Join(root, "docker-compose.yml"))
	if !strings.Contains(
		compose,
		`test: ["CMD", "curl", "--fail", "--silent", "http://127.0.0.1:8080/api/health"]`,
	) {
		t.Fatal("Docker healthcheck must remain controller liveness /api/health")
	}
	if strings.Contains(compose, `http://127.0.0.1:8080/api/ready"]`) {
		t.Fatal("Docker healthcheck must not restart a live but unready controller")
	}
	path := filepath.Join(root, "scripts", "deploy.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("scripts/deploy.sh must be executable")
	}
	deploy := readText(t, path)
	for _, required := range []string{
		"ready_attempts=${HYDRAT_READY_ATTEMPTS:-360}",
		"docker compose up", "--wait", "--wait-timeout",
		"docker compose exec -T controller", "curl", "--fail-with-body", "--max-time",
		"http://127.0.0.1:8080/api/ready", "exit 1",
	} {
		if !strings.Contains(deploy, required) {
			t.Errorf("scripts/deploy.sh missing mandatory deploy gate %q", required)
		}
	}
	operations := readText(t, filepath.Join(root, "docs", "operations.md"))
	for _, required := range []string{
		"./scripts/deploy.sh", "/api/ready", "release rejected",
		"ROLLBACK_IMAGE", "BACKUP_PATH", "APPLIED_PLAN_BACKUP_PATH",
		"FAILED_APPLIED_PLAN_PATH", "PREVIOUS_CONFIG_SHA256",
		"sha256sum",
		"Принятый runtime состоит из image, встроенной конфигурации,",
	} {
		if !strings.Contains(operations, required) {
			t.Errorf("operations deploy/rollback gate missing %q", required)
		}
	}
}

func TestDeployCommandRejectsReleaseWhenReadinessNeverSucceeds(t *testing.T) {
	root := repositoryRoot(t)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "docker.log")
	dockerPath := filepath.Join(tempDir, "docker")
	if err := os.WriteFile(dockerPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >>"$HYDRAT_FAKE_DOCKER_LOG"
case "$*" in
  "compose up "*) exit 0 ;;
  "compose exec "*)
    printf '%s\n' '{"status":"controller unavailable: tcp_reserve_capacity"}'
    exit 22
    ;;
esac
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts", "deploy.sh"))
	command.Dir = root
	command.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HYDRAT_FAKE_DOCKER_LOG="+logPath,
		"HYDRAT_READY_ATTEMPTS=2",
		"HYDRAT_READY_DELAY_SECONDS=0",
		"HYDRAT_READY_MAX_TIME_SECONDS=1",
		"HYDRAT_COMPOSE_WAIT_TIMEOUT_SECONDS=1",
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("deploy err=%v output=%s, want exit 1", err, output)
	}
	if !strings.Contains(string(output), "release rejected") {
		t.Fatalf("deploy output=%s, want release rejected", output)
	}
	if !strings.Contains(string(output), "readiness pending at attempt 1/2") ||
		!strings.Contains(string(output), `"status":"controller unavailable: tcp_reserve_capacity"`) {
		t.Fatalf("deploy output=%s, want bounded readiness cause and attempt", output)
	}
	log := readText(t, logPath)
	if strings.Count(log, "compose up ") != 1 ||
		strings.Count(log, "compose exec ") != 2 ||
		!strings.Contains(log, "http://127.0.0.1:8080/api/ready") {
		t.Fatalf("docker calls=%q, want one compose wait and two ready attempts", log)
	}
}

func TestDeployCommandRejectsTransientSingleReadyResponse(t *testing.T) {
	root := repositoryRoot(t)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "docker.log")
	countPath := filepath.Join(tempDir, "ready-count")
	dockerPath := filepath.Join(tempDir, "docker")
	if err := os.WriteFile(dockerPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >>"$HYDRAT_FAKE_DOCKER_LOG"
case "$*" in
  "compose up "*) exit 0 ;;
  "compose exec "*)
    count=0
    if [ -f "$HYDRAT_FAKE_READY_COUNT" ]; then count=$(cat "$HYDRAT_FAKE_READY_COUNT"); fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$HYDRAT_FAKE_READY_COUNT"
    if [ "$count" -eq 1 ]; then exit 0; fi
    exit 1
    ;;
esac
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts", "deploy.sh"))
	command.Dir = root
	command.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HYDRAT_FAKE_DOCKER_LOG="+logPath,
		"HYDRAT_FAKE_READY_COUNT="+countPath,
		"HYDRAT_READY_ATTEMPTS=3",
		"HYDRAT_READY_CONSECUTIVE_SUCCESSES=2",
		"HYDRAT_READY_DELAY_SECONDS=0",
		"HYDRAT_READY_MAX_TIME_SECONDS=1",
		"HYDRAT_COMPOSE_WAIT_TIMEOUT_SECONDS=1",
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("deploy err=%v output=%s, want transient readiness rejection", err, output)
	}
	if strings.Count(readText(t, logPath), "compose exec ") != 3 {
		t.Fatalf("docker calls=%q, want all three readiness checks", readText(t, logPath))
	}
}
