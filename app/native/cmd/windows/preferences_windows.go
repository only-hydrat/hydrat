package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

type connectionPreferences struct {
	device.MobileSettings
	DNSPreset int
	GeoRules  bool
	HWID      string
}

type preferences struct {
	mu      sync.Mutex
	dir     string
	value   connectionPreferences
	geoLock sync.Mutex
	active  string
	client  *http.Client
}

func openPreferences(dir string, client *http.Client) (*preferences, error) {
	p := &preferences{dir: dir, value: connectionPreferences{GeoRules: true}, client: client}
	body, err := os.ReadFile(filepath.Join(dir, "connection.json"))
	if err == nil {
		if err := json.Unmarshal(body, &p.value); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p.value.MobileSettings = p.value.MobileSettings.Normalized()
	p.value.PauseOnScreenOff = false
	p.value.DNSPreset = min(max(p.value.DNSPreset, 0), 3)
	return p, nil
}

func (p *preferences) load() connectionPreferences {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.value
}

func (p *preferences) save(app *device.App, value connectionPreferences) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	value.HWID = strings.TrimSpace(value.HWID)
	value.MobileSettings = value.MobileSettings.Normalized()
	value.PauseOnScreenOff = false
	if err := app.SetHWID(value.HWID); err != nil {
		return err
	}
	if err := p.write(value); err != nil {
		return errors.Join(err, app.SetHWID(p.value.HWID))
	}
	p.value = value
	return nil
}

func (p *preferences) write(value connectionPreferences) error {
	file, err := os.CreateTemp(p.dir, ".connection-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := errors.Join(json.NewEncoder(file).Encode(value), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(p.dir, "connection.json"))
}

func (p *preferences) geo() (xraycore.GeoSettings, error) {
	p.geoLock.Lock()
	defer p.geoLock.Unlock()
	geo, err := xraycore.LoadDeviceGeo(p.assets())
	return geo.GeoSettings, err
}

func (p *preferences) saveGeo(ctx context.Context, geo xraycore.GeoSettings) error {
	p.geoLock.Lock()
	defer p.geoLock.Unlock()
	if err := xraycore.SaveDeviceGeo(ctx, p.assets(), geo, p.client); err != nil {
		return err
	}
	xraycore.PruneDeviceGeo(p.assets(), p.active)
	return nil
}

func (p *preferences) acquireGeo() (*xrayapi.DeviceGeoRules, error) {
	p.geoLock.Lock()
	defer p.geoLock.Unlock()
	geo, err := xraycore.LoadDeviceGeo(p.assets())
	if err != nil {
		return nil, err
	}
	rules, err := geo.Rules()
	if err != nil {
		return nil, err
	}
	p.active = geo.Directory
	return &rules, nil
}

func (p *preferences) releaseGeo() {
	p.geoLock.Lock()
	defer p.geoLock.Unlock()
	p.active = ""
	xraycore.PruneDeviceGeo(p.assets(), "")
}

func (p *preferences) assets() string { return filepath.Join(p.dir, "geo") }

func copyBundledGeo(source, destination string) error {
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		input, output := filepath.Join(source, name), filepath.Join(destination, name)
		info, err := os.Stat(input)
		if err != nil {
			return err
		}
		if installed, err := os.Stat(output); err == nil &&
			installed.Size() == info.Size() && installed.ModTime().Equal(info.ModTime()) {
			continue
		}
		if err := copyGeoFile(input, output, info); err != nil {
			return err
		}
	}
	return nil
}

func copyGeoFile(source, destination string, info os.FileInfo) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".builtin-")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	_, err = io.Copy(output, input)
	if err := errors.Join(err, output.Close()); err != nil {
		return err
	}
	if err := os.Chtimes(output.Name(), info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	return os.Rename(output.Name(), destination)
}
