package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	releaseCompose          = "docker-compose.yml"
	previousReleaseCompose  = "previous-release-compose.yml"
	candidateReleaseCompose = "candidate-release-compose.yml"
	frozenCandidateCompose  = "candidate-resolved-compose.json"
)

func (h *host) stageReleaseCompose(ctx context.Context, image, project string) (*host, error) {
	running, local, err := h.currentRelease(ctx)
	if err != nil {
		return nil, err
	}
	wanted, err := h.readReleaseCompose(ctx, image, releaseCompose)
	if err != nil {
		return nil, err
	}
	for _, file := range h.Files[1:] {
		name := filepath.Base(file)
		switch name {
		case "docker-compose.updates.yml", "docker-compose.i2p.yml":
			local, err := h.matchReleaseCompose(ctx, running, file)
			if err != nil {
				return nil, err
			}
			wanted, err := h.readReleaseCompose(ctx, image, name)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(local, wanted) {
				return nil, fmt.Errorf("%s changes in the new release and requires a manual update", name)
			}
		}
	}

	if err := writeAtomic(h.path(previousReleaseCompose), local, 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(h.path(candidateReleaseCompose), wanted, 0o600); err != nil {
		return nil, err
	}

	staged := *h
	staged.Files = slices.Clone(h.Files)
	staged.Files[0] = h.path(candidateReleaseCompose)
	name, err := staged.freezeComposeAs(ctx, frozenCandidateCompose)
	if err != nil {
		return nil, err
	}
	if name != project {
		return nil, errors.New("the new Compose file changes the project name")
	}
	if err := h.checkReleaseTopology(); err != nil {
		return nil, err
	}
	staged.Files = []string{h.path(frozenCandidateCompose)}
	staged.projectName = project
	return &staged, nil
}

func (h *host) checkReleaseTopology() error {
	type topology struct {
		Networks, Volumes, Services map[string]json.RawMessage
	}
	var before, after topology
	for file, model := range map[string]*topology{frozenComposeFile: &before, frozenCandidateCompose: &after} {
		if err := h.read(file, model); err != nil {
			return err
		}
		delete(model.Services, "controller")
		delete(model.Services, "gateway")
	}
	sameJSON := func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }
	if !maps.EqualFunc(before.Volumes, after.Volumes, sameJSON) ||
		!maps.EqualFunc(before.Networks, after.Networks, sameJSON) ||
		!maps.EqualFunc(before.Services, after.Services, sameJSON) {
		return errors.New("changes to named volumes, networks or auxiliary services require a manual update")
	}
	return nil
}

func (h *host) currentRelease(ctx context.Context) (string, []byte, error) {
	if len(h.Files) == 0 || h.projectFile(h.Files[0]) != h.projectFile(releaseCompose) {
		return "", nil, errors.New("automatic updates require the release docker-compose.yml as the first Compose file")
	}
	for _, file := range h.Files[1:] {
		switch filepath.Base(file) {
		case "docker-compose.dev.yml", "docker-compose.i2p.dev.yml":
			return "", nil, errors.New("development Compose files require a manual update")
		}
	}
	running, err := h.inspect(ctx, "gateway", "{{.Image}}")
	if err != nil || !digestPattern.MatchString(running) {
		return "", nil, errors.New("cannot identify the current gateway image")
	}
	digests, err := h.docker(ctx, "image", "inspect", "--format", `{{join .RepoDigests "\n"}}`, running)
	if err != nil {
		return "", nil, err
	}
	if !slices.ContainsFunc(strings.Fields(digests), func(ref string) bool {
		digest, ok := strings.CutPrefix(ref, repository+"@")
		return ok && digestPattern.MatchString(digest)
	}) {
		return "", nil, errors.New("automatic updates require a published Hydrat gateway image")
	}

	local, err := h.matchReleaseCompose(ctx, running, releaseCompose)
	if err != nil {
		return "", nil, err
	}
	return running, local, nil
}

func (h *host) matchReleaseCompose(ctx context.Context, image, file string) ([]byte, error) {
	bundled, err := h.readReleaseCompose(ctx, image, filepath.Base(file))
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(h.projectFile(file))
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular Compose file", filepath.Base(file))
	}
	local, err := os.ReadFile(h.projectFile(file))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(local, bundled) {
		return nil, fmt.Errorf("%s has local changes; use the release files to update manually", filepath.Base(file))
	}
	return local, nil
}

func (h *host) readReleaseCompose(ctx context.Context, image, file string) ([]byte, error) {
	data, err := h.dockerOutput(ctx, "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--entrypoint", "/bin/cat", image, "/usr/local/share/hydrat/release/"+file)
	if err != nil || len(data) == 0 || len(data) > 128<<10 {
		return nil, fmt.Errorf("Hydrat image does not supply %s; use a release with bundled Compose files", file)
	}
	return data, nil
}

func (h *host) projectFile(file string) string {
	if !filepath.IsAbs(file) {
		file = filepath.Join(h.ProjectDir, file)
	}
	return filepath.Clean(file)
}

func (h *host) restoreComposeFile(source string) error {
	data, err := os.ReadFile(h.path(source))
	if err != nil {
		return err
	}
	return writeAtomic(h.projectFile(releaseCompose), data, 0o644)
}

func (h *host) clearComposeStaging() {
	for _, file := range []string{frozenComposeFile, frozenCandidateCompose, previousReleaseCompose, candidateReleaseCompose} {
		_ = os.Remove(h.path(file))
	}
}
