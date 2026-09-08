package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/only-hydrat/hydrat/internal/config"
)

type StoredRoutingConfig struct {
	DirectSuffixes   []string              `json:"direct_suffixes"`
	DirectDomains    []string              `json:"direct_domains"`
	DisallowRUEgress bool                  `json:"disallow_ru_egress"`
	GeoRules         config.GeoRulesConfig `json:"geo_rules"`
}

func LoadStoredRouting(path string) (*StoredRoutingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read stored routing: %w", err)
	}
	var stored StoredRoutingConfig
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decode stored routing: %w", err)
	}
	return &stored, nil
}

func SaveStoredRouting(path string, cfg StoredRoutingConfig) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("stored routing path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create routing config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stored routing: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write stored routing tmp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename stored routing: %w", err)
	}

	return nil
}
