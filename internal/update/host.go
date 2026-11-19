package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type HostConfig struct {
	ProjectDir string
	Files      []string
	StateDir   string
	SocketGID  int
}

type host struct {
	HostConfig
	client      *http.Client
	projectName string
}

// ServeHost runs outside Compose so recreation of the controller cannot stop the update.
func ServeHost(ctx context.Context, cfg HostConfig) error {
	if !filepath.IsAbs(cfg.ProjectDir) || !filepath.IsAbs(cfg.StateDir) || len(cfg.Files) == 0 || cfg.SocketGID < 1 {
		return errors.New("updater requires absolute project/state directories, Compose files and a socket group")
	}
	h := &host{HostConfig: cfg, client: &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if err := os.MkdirAll(cfg.StateDir, 0o711); err != nil {
		return err
	}
	lock, err := os.OpenFile(h.path("lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("updater state is already in use")
	}
	if _, err := os.Stat(h.path("compose.json")); errors.Is(err, os.ErrNotExist) {
		if err := h.save("compose.json", override{}, 0o644); err != nil {
			return err
		}
	}
	s := &service{
		ctx: ctx, check: h.check, install: h.install, finishRollback: h.finishRollbackReadiness,
		status: Status{Enabled: true},
	}
	recoveryContext, cancelRecovery := context.WithTimeout(ctx, 15*time.Minute)
	recoveryErr := h.recover(recoveryContext)
	cancelRecovery()
	if recoveryErr != nil {
		log.Printf("update rollback on startup: %v", recoveryErr)
		s.status.Result.State = "rollback_failed"
		if errors.Is(recoveryErr, errRollbackWaiting) {
			s.status.Result.State = "rollback_waiting"
		}
	}
	if err := os.MkdirAll(h.path("ipc"), 0o750); err != nil {
		return err
	}
	if err := os.Chown(h.path("ipc"), os.Geteuid(), cfg.SocketGID); err != nil {
		return err
	}
	if err := os.Chmod(h.path("ipc"), 0o750); err != nil {
		return err
	}
	socket := h.path("ipc", "update.sock")
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(socket, os.Geteuid(), cfg.SocketGID); err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		return err
	}
	server := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second}
	s.refresh()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		rollbackTicker := time.NewTicker(30 * time.Second)
		defer rollbackTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = server.Close()
				return
			case <-ticker.C:
				s.refresh()
			case <-rollbackTicker.C:
				s.refreshWhileRestoring()
			}
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *host) path(name ...string) string {
	return filepath.Join(append([]string{h.StateDir}, name...)...)
}

func (h *host) docker(ctx context.Context, args ...string) (string, error) {
	output, err := h.dockerOutput(ctx, args...)
	return strings.TrimSpace(string(output)), err
}

func (h *host) dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	binary := exec.CommandContext(ctx, "docker", args...)
	binary.Dir = h.ProjectDir
	output, err := binary.Output()
	if err != nil {
		// Compose diagnostics can contain interpolated environment values.
		return nil, fmt.Errorf("docker %s failed: %w", args[0], err)
	}
	return output, nil
}

func (h *host) composeUsing(ctx context.Context, filename string, args ...string) (string, error) {
	cmd := []string{"compose", "--project-directory", h.ProjectDir}
	if h.projectName != "" {
		cmd = append(cmd, "--env-file", "/dev/null", "--project-name", h.projectName)
	}
	for _, file := range h.Files {
		cmd = append(cmd, "-f", file)
	}
	if filename != "" {
		cmd = append(cmd, "-f", h.path(filename))
	}
	return h.docker(ctx, append(cmd, args...)...)
}

func (h *host) compose(ctx context.Context, args ...string) (string, error) {
	return h.composeUsing(ctx, "compose.json", args...)
}

func (h *host) inspect(ctx context.Context, service, format string) (string, error) {
	id, err := h.compose(ctx, "ps", "-q", service)
	if err != nil || id == "" || strings.ContainsAny(id, " \t\r\n") {
		return "", fmt.Errorf("expected one running %s container", service)
	}
	return h.docker(ctx, "inspect", "--format", format, id)
}

func (h *host) image(ctx context.Context, service string) (string, error) {
	const format = `{{index .Config.Labels "org.opencontainers.image.version"}}`
	return h.inspect(ctx, service, format)
}

func (h *host) installed(ctx context.Context) (Versions, error) {
	controller, err := h.image(ctx, "controller")
	if err != nil {
		return Versions{}, err
	}
	gateway, err := h.image(ctx, "gateway")
	if err != nil {
		return Versions{}, err
	}
	if !validVersion(controller) || controller != gateway {
		return Versions{}, errors.New("automatic updates require matching versioned Hydrat images")
	}
	return Versions{Hydrat: controller}, nil
}

func (h *host) check(ctx context.Context) (Versions, map[string]Offer, error) {
	if err := h.checkLayout(ctx); err != nil {
		return Versions{}, nil, err
	}
	current, runtimeErr := h.installed(ctx)
	offers, catalogErr := findOffers(ctx, h.client, current)
	if offer, found := offers["hydrat"]; found {
		if _, _, err := h.currentRelease(ctx); err != nil {
			offer.Manual = true
			offers["hydrat"] = offer
		}
	}
	return current, offers, errors.Join(runtimeErr, catalogErr)
}

func (h *host) save(name string, value any, mode os.FileMode) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(h.path(name), bytes, mode)
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
