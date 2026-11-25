//go:build linux && !android

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/device"
)

type settings struct {
	device.MobileSettings
	DNSPreset int
	GeoRules  bool
	HWID      string
}

type preferences struct {
	mu     sync.Mutex
	file   string
	value  settings
	geoMu  sync.Mutex
	assets string
	active string
}

func openPreferences(state, bundledGeo string, app *device.App) (*preferences, error) {
	p := &preferences{
		file: filepath.Join(state, "desktop.json"), assets: filepath.Join(state, "geo"),
		value: settings{GeoRules: true},
	}
	if data, err := os.ReadFile(p.file); err == nil {
		if err := json.Unmarshal(data, &p.value); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p.value = normalizeSettings(p.value)
	if err := app.SetHWID(p.value.HWID); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.assets, 0700); err != nil {
		return nil, err
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		dest := filepath.Join(p.assets, name)
		if _, err := os.Lstat(dest); errors.Is(err, os.ErrNotExist) {
			if err := os.Symlink(filepath.Join(bundledGeo, name), dest); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	return p, os.Setenv("XRAY_LOCATION_ASSET", p.assets)
}

func normalizeSettings(value settings) settings {
	value.DNSPreset = min(max(value.DNSPreset, 0), 3)
	value.MobileSettings = value.MobileSettings.Normalized()
	value.PauseOnScreenOff = false
	return value
}

func (p *preferences) get() settings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.value
}

func (p *preferences) set(app *device.App, value settings) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	value = normalizeSettings(value)
	if err := app.SetHWID(value.HWID); err != nil {
		return err
	}
	if err := writePreferences(p.file, value); err != nil {
		return errors.Join(err, app.SetHWID(p.value.HWID))
	}
	p.value = value
	return nil
}

func writePreferences(path string, value settings) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".desktop-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := errors.Join(json.NewEncoder(temp).Encode(value), temp.Close()); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func (p *preferences) tunnelOptions(options device.ProcessOptions) (device.MobileSettings, device.ProcessOptions, func(), error) {
	value := p.get()
	options.GeoRules = value.GeoRules
	options.DNSResolvers = device.DNSResolversForPreset(value.DNSPreset)
	if !value.GeoRules {
		return value.MobileSettings, options, func() {}, nil
	}
	p.geoMu.Lock()
	defer p.geoMu.Unlock()
	geo, err := xraycore.LoadDeviceGeo(p.assets)
	if err != nil {
		return value.MobileSettings, options, nil, err
	}
	rules, err := geo.Rules()
	if err != nil {
		return value.MobileSettings, options, nil, err
	}
	p.active = geo.Directory
	options.DeviceGeo = &rules
	return value.MobileSettings, options, func() {
		p.geoMu.Lock()
		defer p.geoMu.Unlock()
		p.active = ""
		xraycore.PruneDeviceGeo(p.assets, "")
	}, nil
}

func (p *preferences) geo() (xraycore.GeoSettings, error) {
	p.geoMu.Lock()
	defer p.geoMu.Unlock()
	geo, err := xraycore.LoadDeviceGeo(p.assets)
	return geo.GeoSettings, err
}

func (p *preferences) setGeo(ctx context.Context, geo xraycore.GeoSettings) error {
	p.geoMu.Lock()
	defer p.geoMu.Unlock()
	if err := xraycore.SaveDeviceGeo(ctx, p.assets, geo, nil); err != nil {
		return err
	}
	xraycore.PruneDeviceGeo(p.assets, p.active)
	return nil
}
