package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/config"
)

func TestCheckRejectsUnsupportedRunningLayout(t *testing.T) {
	cfg, err := config.Load("../../config/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		service string
		change  func(*config.Config)
	}{
		{"xray.binary", "gateway", func(c *config.Config) { c.Xray.Binary = "/opt/xray" }},
		{"tor.binary", "gateway", func(c *config.Config) { c.Tor.Binary = "/opt/tor" }},
		{"xray.probe_config", "gateway", func(c *config.Config) { c.Xray.ProbeConfig = "/opt/probe.json" }},
		{"paths.applied_plan", "gateway", func(c *config.Config) { c.Paths.AppliedPlan = "/data/custom-plan.json" }},
		{"paths.database", "controller", func(c *config.Config) { c.Paths.Database = "/data/custom.db" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			modified := cfg
			tt.change(&modified)
			if err := validateLayout(tt.service, modified); err == nil || !strings.Contains(err.Error(), tt.name) {
				t.Fatalf("unsupported layout must identify %s, got %v", tt.name, err)
			}
		})
	}
	for _, name := range []string{"gateway", "controller"} {
		if err := validateLayout(name, cfg); err != nil {
			t.Fatalf("stock %s layout rejected: %v", name, err)
		}
	}
}

func TestReadLayoutUsesRunningContainerConfig(t *testing.T) {
	h, _ := fakeDocker(t)
	path := filepath.Join(h.ProjectDir, "docker")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
set -eu
if [ "$1" = inspect ]; then
  printf '%s\n' '{"entrypoint":["/usr/local/bin/hydrat"],"command":["agent"]}'
  exit 0
fi
case " $* " in
  *" ps -q gateway "*) printf 'gateway-container\n';;
  *" exec -T gateway sh "*) cat "$HYDRAT_TEST_LAYOUT";;
  *) exit 1;;
esac
`), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile("../../config/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	effective := filepath.Join(h.ProjectDir, "effective.yml")
	content = []byte(strings.Replace(string(content), "binary: /usr/local/bin/xray", "binary: /opt/custom-xray", 1))
	if err := os.WriteFile(effective, content, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HYDRAT_TEST_LAYOUT", effective)
	_, offers, err := h.check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "xray.binary") || len(offers) != 0 {
		t.Fatalf("unsupported running config still allows update offers: %v, %v", offers, err)
	}
}
