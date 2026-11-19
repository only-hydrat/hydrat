package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type override struct {
	Services map[string]serviceOverride `json:"services,omitempty"`
}

type serviceOverride struct {
	Image   string `json:"image,omitempty"`
	Volumes []bind `json:"volumes,omitempty"`
}

type bind struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type transaction struct {
	Project        string   `json:"project"`
	Services       []string `json:"services"`
	Previous       override `json:"previous"`
	Backup         string   `json:"backup,omitempty"`
	Restored       bool     `json:"restored,omitempty"`
	ComposeChanged bool     `json:"compose_changed,omitempty"`
	AwaitingReady  bool     `json:"awaiting_ready,omitempty"`
}

var transactionIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z$`)

func (h *host) install(parent context.Context, component string, requested Offer) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()

	_, offers, err := h.check(ctx)
	offer := offers["hydrat"]
	if component != "hydrat" || offer.Version == "" || offer.Manual || offer != requested {
		return errors.Join(errors.New("selected update is no longer available"), err)
	}
	if err := h.ready(ctx); err != nil {
		return errors.New("pre-update readiness check failed")
	}
	txID := time.Now().UTC().Format("20060102T150405.000000000Z")
	var before override
	if err := h.read("compose.json", &before); err != nil {
		return err
	}
	if before.Services == nil {
		before.Services = make(map[string]serviceOverride)
	}

	services := []string{"gateway", "controller"}
	for _, name := range services {
		running, err := h.inspect(ctx, name, "{{.Image}}")
		if err != nil || !digestPattern.MatchString(running) {
			return fmt.Errorf("cannot identify running %s image", name)
		}
		ref := "hydrat-rollback:" + strings.ToLower(txID) + "-" + name
		if _, err := h.docker(ctx, "image", "tag", running, ref); err != nil {
			return err
		}
		entry := before.Services[name]
		entry.Image = ref
		before.Services[name] = entry
	}
	project, err := h.freezeCompose(ctx)
	if err != nil {
		return err
	}
	tx := transaction{Project: project, Services: services, Previous: before}
	frozen, err := h.transactionHost(tx)
	if err != nil {
		return err
	}
	defer func() {
		if _, err := os.Stat(h.path("pending.json")); errors.Is(err, os.ErrNotExist) {
			h.clearComposeStaging()
		}
	}()
	if err := frozen.checkMounts(ctx); err != nil {
		return err
	}
	image, err := h.pullHydrat(ctx, offer.Version)
	if err != nil {
		return err
	}
	target, err := h.stageReleaseCompose(ctx, image, project)
	if err != nil {
		return err
	}
	tx.ComposeChanged = true
	candidate := override{Services: map[string]serviceOverride{
		"gateway": {Image: image}, "controller": {Image: image},
	}}
	if err := target.checkMounts(ctx); err != nil {
		return err
	}
	if err := target.verifyCandidate(ctx, candidate); err != nil {
		return err
	}
	if err := frozen.checkLayout(ctx); err != nil {
		return err
	}
	if err := frozen.ready(ctx); err != nil {
		return errors.New("routing became unready while preparing the update")
	}
	if err := h.save("pending.json", tx, 0o600); err != nil {
		return err
	}
	if err := frozen.apply(ctx, target, offer.Version, txID, candidate, &tx); err != nil {
		recoveryCtx, stop := context.WithTimeout(context.WithoutCancel(parent), 15*time.Minute)
		defer stop()
		if recoveryErr := h.recover(recoveryCtx); recoveryErr != nil {
			return errors.Join(errRollbackFailed, err, recoveryErr)
		}
		return errors.Join(errRolledBack, err)
	}
	return nil
}

func (h *host) apply(ctx context.Context, target *host, version, txID string, candidate override, tx *transaction) error {
	if err := writeAtomic(h.path("ipc", "maintenance"), nil, 0o644); err != nil {
		return err
	}
	// Freeze writes before taking a matched database and gateway plan snapshot.
	if _, err := h.compose(ctx, "stop", "controller"); err != nil {
		return err
	}
	if err := h.snapshot(ctx, txID, tx.Previous); err != nil {
		return err
	}
	tx.Backup = txID
	if err := h.save("pending.json", tx, 0o600); err != nil {
		return err
	}
	if err := h.restoreComposeFile(candidateReleaseCompose); err != nil {
		return err
	}
	if err := h.save("compose.json", candidate, 0o644); err != nil {
		return err
	}
	if err := target.up(ctx, tx.Services, true); err != nil {
		return err
	}
	if err := target.waitReady(ctx); err != nil {
		return err
	}
	installed, err := target.installed(ctx)
	if err != nil || installed.Hydrat != version {
		return errors.Join(errors.New("running version does not match the update"), err)
	}
	return h.clearPending()
}

func (h *host) recover(ctx context.Context) error {
	var tx transaction
	if err := h.read("pending.json", &tx); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			h.clearComposeStaging()
			return h.clearMaintenance()
		}
		return err
	}
	frozen, err := h.transactionHost(tx)
	if err != nil {
		return err
	}
	h = frozen
	if tx.AwaitingReady {
		finished, err := h.finishRollbackReadiness(ctx)
		if err != nil {
			return err
		}
		if finished {
			return nil
		}
		return errRollbackWaiting
	}
	if !tx.Restored {
		if tx.Backup != "" {
			if !transactionIDPattern.MatchString(tx.Backup) {
				return errors.New("invalid backup identifier")
			}
			if _, err := h.compose(ctx, "stop", "controller", "gateway"); err != nil {
				return err
			}
		}
		if tx.ComposeChanged {
			if err := h.restoreComposeFile(previousReleaseCompose); err != nil {
				return err
			}
		}
		if err := h.save("compose.json", tx.Previous, 0o644); err != nil {
			return err
		}
		if tx.Backup != "" {
			if err := h.restoreSnapshot(ctx, tx.Backup); err != nil {
				return err
			}
		}
		// Save this before starting any writers. A failed readiness check
		// must never cause a second restore over the running database.
		tx.Restored = true
		if err := h.save("pending.json", tx, 0o600); err != nil {
			return err
		}
	}
	if err := h.up(ctx, tx.Services, false); err != nil {
		return err
	}
	if err := h.clearMaintenance(); err != nil {
		return err
	}
	tx.AwaitingReady = true
	if err := h.save("pending.json", tx, 0o600); err != nil {
		return err
	}
	if err := h.waitReady(ctx); err != nil {
		return errors.Join(errRollbackWaiting, err)
	}
	return h.clearPending()
}

// finishRollbackReadiness is safe to run after the restore and container start
// have been saved. It does not touch the running containers or reload data.
func (h *host) finishRollbackReadiness(ctx context.Context) (bool, error) {
	var tx transaction
	if err := h.read("pending.json", &tx); err != nil {
		return false, err
	}
	if !tx.Restored || !tx.AwaitingReady {
		return false, errors.New("rollback has not finished restoring services")
	}
	frozen, err := h.transactionHost(tx)
	if err != nil {
		return false, err
	}
	if err := frozen.ready(ctx); err != nil {
		return false, nil
	}
	if err := h.clearPending(); err != nil {
		return false, err
	}
	return true, nil
}

func (h *host) clearPending() error {
	if err := os.Remove(h.path("pending.json")); err != nil {
		return err
	}
	if err := syncDir(h.StateDir); err != nil {
		return err
	}
	if err := h.clearMaintenance(); err != nil {
		return err
	}
	h.clearComposeStaging()
	return nil
}

func (h *host) clearMaintenance() error {
	err := os.Remove(h.path("ipc", "maintenance"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (h *host) read(name string, value any) error {
	data, err := os.ReadFile(h.path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func (h *host) up(ctx context.Context, services []string, forceRecreate bool) error {
	args := []string{"up", "-d", "--no-deps", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "180"}
	if forceRecreate {
		args = append(args, "--force-recreate")
	}
	_, err := h.compose(ctx, append(args, services...)...)
	return err
}

func (h *host) ready(ctx context.Context) error {
	_, err := h.compose(ctx, "exec", "-T", "controller", "curl", "-fsS", "--max-time", "2", "http://127.0.0.1:8080/api/ready")
	return err
}

func (h *host) waitReady(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 12*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	healthy := 0
	for {
		if h.ready(ctx) == nil {
			healthy++
			if healthy == 10 {
				return nil
			}
		} else {
			healthy = 0
		}
		select {
		case <-ctx.Done():
			return errors.New("updated routes did not become ready")
		case <-ticker.C:
		}
	}
}

func (h *host) pullHydrat(ctx context.Context, version string) (string, error) {
	ref := repository + ":" + version
	if _, err := h.docker(ctx, "pull", ref); err != nil {
		return "", err
	}
	label, err := h.docker(ctx, "image", "inspect", "--format", `{{index .Config.Labels "org.opencontainers.image.version"}}`, ref)
	if err != nil || label != version {
		return "", errors.New("published image version does not match release")
	}
	digests, err := h.docker(ctx, "image", "inspect", "--format", `{{join .RepoDigests "\n"}}`, ref)
	if err != nil {
		return "", err
	}
	for _, digest := range strings.Fields(digests) {
		if strings.HasPrefix(digest, repository+"@") && digestPattern.MatchString(strings.TrimPrefix(digest, repository+"@")) {
			return digest, nil
		}
	}
	return "", errors.New("published image has no registry digest")
}

func (h *host) verifyCandidate(ctx context.Context, candidate override) error {
	const stage = "candidate.json"
	if err := h.save(stage, candidate, 0o600); err != nil {
		return err
	}
	defer os.Remove(h.path(stage))
	if err := h.checkBundledMounts(ctx, stage); err != nil {
		return err
	}
	if err := h.runTorRuntimeCheck(ctx, candidate.Services["gateway"].Image); err != nil {
		return err
	}
	for _, file := range []string{xrayMainConfig, xrayProbeConfig, xrayActiveConfig} {
		if _, err := h.composeUsing(ctx, stage, "run", "--no-deps", "--rm", "-T", "--pull", "never", "--entrypoint", xrayPath,
			"gateway", "run", "-test", "-c", file); err != nil {
			return err
		}
	}
	return nil
}

func (h *host) runTorRuntimeCheck(ctx context.Context, image string) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	const checker = "/hydrat-tor-check"
	if _, err := h.docker(ctx, "run", "--rm", "--network", "none", "--pull", "never",
		"--volume", binary+":"+checker+":ro", "--entrypoint", checker, image, "tor-runtime-check"); err != nil {
		return fmt.Errorf("Tor bridge and Lyrebird check failed: %w", err)
	}
	return nil
}

func (h *host) snapshot(ctx context.Context, id string, previous override) error {
	const file = "snapshot-override.json"
	if err := h.save(file, previous, 0o600); err != nil {
		return err
	}
	defer os.Remove(h.path(file))
	db := "/data/controller/backups/update-" + id + ".db"
	if _, err := h.composeUsing(ctx, file, "run", "--no-deps", "--rm", "-T", "--pull", "never", "controller", "backup", "--output", db); err != nil {
		return err
	}
	_, err := h.compose(ctx, "exec", "-T", "gateway", "sh", "-eu", "-c",
		`umask 077; test -s "$1"; cp "$1" "$2"; sync -f "$2"`,
		"snapshot", appliedPlanPath, planBackupPath(id))
	return err
}

func (h *host) restoreSnapshot(ctx context.Context, id string) error {
	db := "/data/controller/backups/update-" + id + ".db"
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	const restoreBinary = "/hydrat-restore"
	// The previous image may ship a restore command that cannot resume
	// after an interruption between archiving the database and its WAL.
	if _, err := h.compose(ctx, "run", "--no-deps", "--rm", "-T", "--pull", "never",
		"--volume", binary+":"+restoreBinary+":ro", "--entrypoint", restoreBinary,
		"controller", "restore", "--input", db); err != nil {
		return err
	}
	_, err = h.compose(ctx, "run", "--no-deps", "--rm", "-T", "--entrypoint", "sh", "gateway", "-eu", "-c",
		`umask 077; test -s "$1"; cp "$1" "$2.restore"; mv "$2.restore" "$2"; sync -f "$2"`,
		"restore", planBackupPath(id), appliedPlanPath)
	return err
}

func planBackupPath(id string) string {
	return strings.TrimSuffix(appliedPlanPath, ".json") + ".update-" + id + ".json"
}
