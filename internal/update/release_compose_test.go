package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageReleaseComposePreservesFilesUntilCommit(t *testing.T) {
	h, logPath := fakeDocker(t)
	h.StateDir = t.TempDir()
	h.Files = []string{"docker-compose.yml", "docker-compose.updates.yml"}
	t.Setenv("HYDRAT_TEST_OFFICIAL_DIGEST", "sha256:"+strings.Repeat("a", 64))
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HYDRAT_TEST_DOCKER_LOG"
case " $* " in
  *" ps -q gateway "*) printf '%s\n' test-gateway ;;
  " inspect --format {{.Image}} test-gateway ") printf '%s\n' "$HYDRAT_TEST_OFFICIAL_DIGEST" ;;
  *" image inspect "*) printf 'ghcr.io/only-hydrat/hydrat@%s\n' "$HYDRAT_TEST_OFFICIAL_DIGEST" ;;
  *" /bin/cat ghcr.io/"*" /usr/local/share/hydrat/release/docker-compose.yml ") printf '# new compose\n' ;;
  *" /bin/cat "*" /usr/local/share/hydrat/release/docker-compose.yml ") printf '# old compose\n' ;;
  *" /bin/cat "*" /usr/local/share/hydrat/release/docker-compose.updates.yml ") printf '# stable override\n' ;;
  *" config --format json "*) printf '{"name":"rehearsal"}\n' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(h.ProjectDir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for file, contents := range map[string]string{"docker-compose.yml": "# old compose\n", "docker-compose.updates.yml": "# stable override\n"} {
		if err := os.WriteFile(filepath.Join(h.ProjectDir, file), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(h.path(frozenComposeFile), []byte(`{"name":"rehearsal"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	image := repository + "@sha256:" + strings.Repeat("b", 64)
	staged, err := h.stageReleaseCompose(ctx, image, "rehearsal")
	if err != nil {
		t.Fatal(err)
	}
	if staged.projectName != "rehearsal" || len(staged.Files) != 1 || staged.Files[0] != h.path(frozenCandidateCompose) {
		t.Fatalf("stage is not pinned: %+v", staged)
	}
	for path, want := range map[string]string{
		filepath.Join(h.ProjectDir, releaseCompose): "# old compose\n",
		h.path(previousReleaseCompose):              "# old compose\n",
		h.path(candidateReleaseCompose):             "# new compose\n",
	} {
		if contents, err := os.ReadFile(path); err != nil || string(contents) != want {
			t.Fatalf("%s contains %q, want %q (%v)", path, contents, want, err)
		}
	}
	commands, _ := os.ReadFile(logPath)
	if !strings.Contains(string(commands), "-f "+h.path(candidateReleaseCompose)+" -f docker-compose.updates.yml config --format json") {
		t.Fatalf("target Compose was not resolved with the active override: %s", commands)
	}
	if err := os.WriteFile(h.path(frozenComposeFile), []byte(`{"name":"rehearsal","volumes":{"db":{"name":"db"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.stageReleaseCompose(ctx, image, "rehearsal"); err == nil || !strings.Contains(err.Error(), "named volumes") {
		t.Fatalf("storage topology change was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.ProjectDir, releaseCompose), []byte("# local edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.stageReleaseCompose(ctx, image, "rehearsal"); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Fatalf("locally edited Compose was accepted: %v", err)
	}
}
