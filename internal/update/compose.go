package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
)

const frozenComposeFile = "pending-compose.json"

var projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func (h *host) freezeCompose(ctx context.Context) (string, error) {
	return h.freezeComposeAs(ctx, frozenComposeFile)
}

func (h *host) freezeComposeAs(ctx context.Context, file string) (string, error) {
	raw, err := h.composeUsing(ctx, "", "config", "--format", "json")
	if err != nil {
		return "", err
	}
	var model struct {
		Name string
	}
	if err := json.Unmarshal([]byte(raw), &model); err != nil || !projectNamePattern.MatchString(model.Name) {
		return "", errors.New("cannot identify resolved Compose project")
	}
	// Compose's canonical output already escapes literal dollars and resolves
	// service env files and relative paths. The model can contain credentials.
	if err := writeAtomic(h.path(file), []byte(raw), 0o600); err != nil {
		return "", err
	}
	return model.Name, nil
}

func (h *host) transactionHost(tx transaction) (*host, error) {
	if !projectNamePattern.MatchString(tx.Project) {
		return nil, errors.New("update journal has no frozen Compose project")
	}
	if _, err := os.Stat(h.path(frozenComposeFile)); err != nil {
		return nil, fmt.Errorf("frozen Compose project unavailable: %w", err)
	}
	frozen := *h
	frozen.Files = []string{h.path(frozenComposeFile)}
	frozen.projectName = tx.Project
	return &frozen, nil
}

func (h *host) checkMounts(ctx context.Context) error {
	raw, err := h.compose(ctx, "config", "--format", "json")
	if err != nil {
		return err
	}
	var model struct {
		Services map[string]struct{ Volumes []bind }
		Volumes  map[string]struct{ Name string }
	}
	if err := json.Unmarshal([]byte(raw), &model); err != nil {
		return errors.New("cannot read planned Compose mounts")
	}
	for _, service := range []string{"gateway", "controller"} {
		raw, err := h.inspect(ctx, service, "{{json .Mounts}}")
		if err != nil {
			return err
		}
		var mounted []struct {
			Type, Source, Name, Destination string
			RW                              bool
		}
		if err := json.Unmarshal([]byte(raw), &mounted); err != nil {
			return fmt.Errorf("cannot read running %s mounts", service)
		}
		running := make(map[string]bind, len(mounted))
		for _, mount := range mounted {
			if mount.Type != "bind" && mount.Type != "volume" {
				continue
			}
			source := mount.Source
			if mount.Type == "volume" {
				source = mount.Name
			}
			running[mount.Destination] = bind{Type: mount.Type, Source: source, Target: mount.Destination, ReadOnly: !mount.RW}
		}
		hasData := false
		for _, mount := range model.Services[service].Volumes {
			if mount.Type != "bind" && mount.Type != "volume" {
				return fmt.Errorf("unsupported %s mount type at %s", service, mount.Target)
			}
			if mount.Type == "volume" {
				mount.Source = model.Volumes[mount.Source].Name
			}
			if mount.Source == "" || running[mount.Target] != mount {
				return fmt.Errorf("running %s mount differs from Compose at %s", service, mount.Target)
			}
			hasData = hasData || mount.Target == "/data" && !mount.ReadOnly
			delete(running, mount.Target)
		}
		if !hasData || len(running) != 0 {
			return fmt.Errorf("running %s storage differs from Compose", service)
		}
	}
	return nil
}

func (h *host) checkBundledMounts(ctx context.Context, filename string) error {
	raw, err := h.composeUsing(ctx, filename, "config", "--format", "json")
	if err != nil {
		return err
	}
	var model struct {
		Services map[string]struct{ Volumes []bind }
	}
	if err := json.Unmarshal([]byte(raw), &model); err != nil {
		return errors.New("cannot verify the bundled runtime mounts")
	}
	for _, volume := range model.Services["gateway"].Volumes {
		target := path.Clean(volume.Target)
		prefix := strings.TrimRight(target, "/") + "/"
		for _, binary := range []string{xrayPath, torPath, lyrebirdPath} {
			if target == binary || strings.HasPrefix(binary, prefix) {
				return fmt.Errorf("full Hydrat update requires the bundled runtime, but Compose overrides it at %s", target)
			}
		}
	}
	return nil
}
