package update

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/only-hydrat/hydrat/internal/config"
)

const (
	xrayPath         = "/usr/local/bin/xray"
	torPath          = "/usr/bin/tor"
	lyrebirdPath     = "/usr/local/bin/lyrebird"
	xrayMainConfig   = "/etc/hydrat/xray-main.json"
	xrayProbeConfig  = "/etc/hydrat/xray-probe.json"
	xrayActiveConfig = "/etc/hydrat/xray-active.json"
	appliedPlanPath  = "/data/agent/applied-plan.json"
	databasePath     = "/data/controller/hydrat.db"
)

func (h *host) checkLayout(ctx context.Context) error {
	const launchFields = `{"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}}}`
	for _, service := range []string{"gateway", "controller"} {
		command := service
		if service == "gateway" {
			command = "agent"
		}
		raw, err := h.inspect(ctx, service, launchFields)
		if err != nil {
			return err
		}
		var launch struct {
			Entrypoint []string
			Command    []string
		}
		if err := json.Unmarshal([]byte(raw), &launch); err != nil ||
			!slices.Equal(launch.Entrypoint, []string{"/usr/local/bin/hydrat"}) ||
			!slices.Equal(launch.Command, []string{command}) {
			return fmt.Errorf("unsupported entrypoint or command for %s", service)
		}
		// This is the same path selection used by Hydrat's standard entrypoint.
		raw, err = h.compose(ctx, "exec", "-T", service, "sh", "-eu", "-c",
			`cat -- "${HYDRAT_CONFIG:-/etc/hydrat/config.yml}"`)
		if err != nil {
			return fmt.Errorf("cannot read running %s config: %w", service, err)
		}
		cfg, err := config.Decode(strings.NewReader(raw))
		if err != nil {
			return fmt.Errorf("cannot decode running %s config", service)
		}
		if err := validateLayout(service, cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateLayout(service string, cfg config.Config) error {
	fields := [][3]string{{"paths.database", cfg.Paths.Database, databasePath}}
	if service == "gateway" {
		fields = [][3]string{
			{"paths.applied_plan", cfg.Paths.AppliedPlan, appliedPlanPath},
			{"xray.binary", cfg.Xray.Binary, xrayPath},
			{"tor.binary", cfg.Tor.Binary, torPath},
			{"tor.lyrebird_binary", cfg.Tor.LyrebirdBinary, lyrebirdPath},
			{"xray.main_config", cfg.Xray.MainConfig, xrayMainConfig},
			{"xray.probe_config", cfg.Xray.ProbeConfig, xrayProbeConfig},
			{"xray.active_config", cfg.Xray.ActiveConfig, xrayActiveConfig},
		}
	}
	for _, field := range fields {
		if field[1] != field[2] {
			return fmt.Errorf("automatic updates require the standard %s setting on %s", field[0], service)
		}
	}
	return nil
}
