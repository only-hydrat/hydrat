package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeDocker(t *testing.T) (*host, string) {
	t.Helper()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "docker.log")
	docker := filepath.Join(dir, "docker")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("HYDRAT_TEST_DOCKER_LOG", logFile)
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HYDRAT_TEST_DOCKER_LOG"
case "$1" in
  pull|rm) exit 0 ;;
  create) printf 'artifact\n'; exit 0 ;;
  cp) printf 'test-executable\n' > "$3"; exit 0 ;;
esac
case " $* " in
  *" up "*" gateway "*) exit 0 ;;
  *" exec "*" /api/ready "*) exit 0 ;;
  *" stop "*) exit 0 ;;
  *" restore "*) exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &host{HostConfig: HostConfig{ProjectDir: dir, StateDir: dir, Files: []string{"docker-compose.yml"}}}, logFile
}

func TestInterruptedFullUpgradeRestoresBeforeStartingServices(t *testing.T) {
	h, logFile := fakeDocker(t)
	previous := override{Services: map[string]serviceOverride{
		"gateway":    {Image: "hydrat-rollback:gateway"},
		"controller": {Image: "hydrat-rollback:controller"},
	}}
	if err := os.WriteFile(h.path(frozenComposeFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.save("pending.json", transaction{
		Project:  "rehearsal",
		Services: []string{"gateway", "controller"},
		Previous: previous, Backup: "20261118T150000.000000001Z", ComposeChanged: true,
	}, 0o600); err != nil {
		t.Fatal(err)
	}
	for file, contents := range map[string]string{
		"docker-compose.yml":   "# candidate compose",
		previousReleaseCompose: "# previous compose",
	} {
		if err := os.WriteFile(h.path(file), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The fake controller won't pass the readiness gate. The installed image
	// and database have already been restored and the journal must be retained.
	if err := os.Mkdir(h.path("ipc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path("ipc", "maintenance"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		done := make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log, _ := os.ReadFile(logFile)
					if strings.Count(string(log), "http://127.0.0.1:8080/api/ready") >= attempt {
						cancel()
						return
					}
				}
			}
		}()
		err := h.recover(ctx)
		cancel()
		<-done
		if !errors.Is(err, errRollbackWaiting) {
			t.Fatalf("expected rollback readiness error, got %v", err)
		}
	}
	if data, err := os.ReadFile(h.path("docker-compose.yml")); err != nil || string(data) != "# previous compose" {
		t.Fatalf("previous release Compose not restored: %q, %v", data, err)
	}
	var actual override
	if err := h.read("compose.json", &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Services["gateway"].Image != previous.Services["gateway"].Image {
		t.Fatalf("previous image not restored: %+v", actual)
	}
	log, _ := os.ReadFile(logFile)
	stop := strings.Index(string(log), " stop controller gateway")
	restore := strings.Index(string(log), " restore --input ")
	start := strings.Index(string(log), " up -d ")
	if stop < 0 || restore <= stop || start <= restore {
		t.Fatalf("unexpected rollback order: %s", log)
	}
	if !strings.Contains(string(log), "--entrypoint /hydrat-restore controller restore") {
		t.Fatal("rollback must run the current restore command, even on an older image")
	}
	if restoreCount := strings.Count(string(log), " restore --input "); restoreCount != 1 {
		t.Fatalf("recovery restored the same database %d times", restoreCount)
	}
	if _, err := os.Stat(h.path("ipc", "maintenance")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old services are running, maintenance must be cleared: %v", err)
	}
	var pending transaction
	if err := h.read("pending.json", &pending); err != nil || !pending.Restored || !pending.AwaitingReady {
		t.Fatalf("rollback checkpoint was not retained: %+v, %v", pending, err)
	}
	if strings.Contains(string(log), "--force-recreate") || strings.Count(string(log), " up -d ") != 1 {
		t.Fatal("retry must preserve restored containers that are already running")
	}
}
