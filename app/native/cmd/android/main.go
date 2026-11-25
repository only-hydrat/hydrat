//go:build android && cgo

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/appupdate"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

var state struct {
	sync.Mutex
	app     *device.App
	options device.ProcessOptions
	cancel  context.CancelFunc
	ctx     context.Context
	failed  bool
}

var running atomic.Bool

var geoState struct {
	sync.Mutex
	assets string
	active string
}

//export hydratCheckUpdate
func hydratCheckUpdate() *C.char {
	result, err := appupdate.Check(context.Background(), appupdate.Android)
	if err != nil {
		return nil
	}
	body, _ := json.Marshal(result)
	return C.CString(string(body))
}

//export hydratOpen
func hydratOpen(directory, tor, lyrebird, assets *C.char) C.int {
	state.Lock()
	defer state.Unlock()
	if state.app != nil {
		return 0
	}
	root := C.GoString(directory)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	app, err := device.OpenMobile(ctx, filepath.Join(root, "state"))
	if err != nil {
		return 1
	}
	flow := filepath.Join(root, "flow.sock")
	for name, value := range map[string]string{
		xrayflow.SocketEnvironment: flow, "XRAY_LOCATION_ASSET": C.GoString(assets),
	} {
		if err := os.Setenv(name, value); err != nil {
			_ = app.Close()
			return 1
		}
	}
	state.options = device.ProcessOptions{
		Embedded: xraycore.Host{}, RuntimeDirectory: root, FlowSocket: flow,
		Tor: C.GoString(tor), Lyrebird: C.GoString(lyrebird), GeoRules: true,
	}
	geoState.Lock()
	geoState.assets = C.GoString(assets)
	geoState.Unlock()
	state.app = app
	return 0
}

//export hydratImport
func hydratImport(input *C.char, size C.int, hwid *C.char) *C.char {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil || hwid == nil || size < 0 || size > 4*1024*1024 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := app.ImportWithHWID(ctx, C.GoStringN(input, size), C.GoString(hwid))
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(result)
	return C.CString(string(b))
}

//export hydratSetSourceHWID
func hydratSetSourceHWID(id, hwid *C.char) *C.char {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil || id == nil || hwid == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := app.SetSourceHWID(ctx, C.GoString(id), C.GoString(hwid))
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(result)
	return C.CString(string(b))
}

//export hydratSourceHWID
func hydratSourceHWID(id *C.char) *C.char {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil || id == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hwid, err := app.SourceHWID(ctx, C.GoString(id))
	if err != nil {
		return nil
	}
	return C.CString(hwid)
}

//export hydratRemoveSource
func hydratRemoveSource(id *C.char) C.int {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil || id == nil {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := app.RemoveSource(ctx, C.GoString(id)); err != nil {
		return 1
	}
	return 0
}

//export hydratSetHWID
func hydratSetHWID(value *C.char) C.int {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil || value == nil || app.SetHWID(C.GoString(value)) != nil {
		return 1
	}
	return 0
}

//export hydratSetScreenInteractive
func hydratSetScreenInteractive(interactive C.int) {
	state.Lock()
	app := state.app
	state.Unlock()
	if app != nil {
		app.SetScreenInteractive(interactive != 0)
	}
}

//export hydratStatus
func hydratStatus() *C.char {
	state.Lock()
	app, failed := state.app, state.failed
	state.Unlock()
	if app == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := app.Status(ctx)
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(struct {
		device.Status
		Failed bool
	}{status, failed})
	return C.CString(string(b))
}

//export hydratRefresh
func hydratRefresh() *C.char {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	report, err := app.RefreshSources(ctx)
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(report)
	return C.CString(string(b))
}

//export hydratImportSuggested
func hydratImportSuggested() *C.char {
	state.Lock()
	app := state.app
	state.Unlock()
	if app == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report, err := app.ImportSuggested(ctx)
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(report)
	return C.CString(string(b))
}

//export hydratPrepare
func hydratPrepare() C.int {
	state.Lock()
	defer state.Unlock()
	if state.app == nil || state.cancel != nil {
		return 1
	}
	state.ctx, state.cancel = context.WithCancel(context.Background())
	state.failed = false
	return 0
}

//export hydratGeoSettings
func hydratGeoSettings() *C.char {
	geoState.Lock()
	defer geoState.Unlock()
	if geoState.assets == "" {
		return nil
	}
	current, err := xraycore.LoadDeviceGeo(geoState.assets)
	if err != nil {
		return nil
	}
	body, err := json.Marshal(current.GeoSettings)
	if err != nil {
		return nil
	}
	return C.CString(string(body))
}

//export hydratSaveGeoSettings
func hydratSaveGeoSettings(raw *C.char) *C.char {
	if raw == nil {
		return C.CString("geo_save")
	}
	var settings xraycore.GeoSettings
	if err := json.Unmarshal([]byte(C.GoString(raw)), &settings); err != nil {
		return C.CString("geo_save")
	}
	geoState.Lock()
	defer geoState.Unlock()
	if geoState.assets == "" {
		return C.CString("geo_save")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := xraycore.SaveDeviceGeo(ctx, geoState.assets, settings, nil); err != nil {
		return C.CString(err.Error())
	}
	xraycore.PruneDeviceGeo(geoState.assets, geoState.active)
	return C.CString("")
}

//export hydratRun
func hydratRun(tun, dnsPreset, geoRules C.int, rawSettings *C.char) C.int {
	if !running.CompareAndSwap(false, true) {
		return 1
	}
	defer running.Store(false)
	state.Lock()
	ctx, cancel := state.ctx, state.cancel
	app, options := state.app, state.options
	state.Unlock()
	if cancel == nil {
		return 1
	}
	defer func() {
		cancel()
		state.Lock()
		state.ctx, state.cancel = nil, nil
		state.Unlock()
	}()
	if ctx.Err() != nil {
		return 0
	}
	if tun <= 2 || os.Setenv("XRAY_TUN_FD", fmt.Sprint(tun)) != nil {
		return 1
	}

	var settings device.MobileSettings
	if rawSettings != nil {
		if err := json.Unmarshal([]byte(C.GoString(rawSettings)), &settings); err != nil {
			return 1
		}
	}
	settings = settings.Normalized()
	options.DNSResolvers = device.DNSResolversForPreset(int(dnsPreset))
	options.GeoRules = geoRules != 0
	if options.GeoRules {
		geoState.Lock()
		geo, err := xraycore.LoadDeviceGeo(geoState.assets)
		if err != nil {
			geoState.Unlock()
			return 1
		}
		rules, err := geo.Rules()
		if err != nil {
			geoState.Unlock()
			return 1
		}
		geoState.active = geo.Directory
		geoState.Unlock()
		options.DeviceGeo = &rules
		defer func() {
			geoState.Lock()
			defer geoState.Unlock()
			geoState.active = ""
			xraycore.PruneDeviceGeo(geoState.assets, "")
		}()
	}
	options.CriticalSlots = device.MobileCriticalSlots
	options.FastProbeWorkers = max(settings.FastWorkers, settings.BackgroundWorkers)
	options.MinVLESSScore = float64(settings.MinVLESSScore)
	backend, err := device.StartProcesses(ctx, options)
	if err == nil {
		err = app.RunMobileWithSettings(ctx, backend, settings, options.DNSResolvers...)
		if closeErr := backend.Close(); err == nil {
			err = closeErr
		}
	}
	state.Lock()
	defer state.Unlock()
	state.failed = err != nil && ctx.Err() == nil
	if state.failed {
		log.Print("device tunnel failed")
		return 1
	}
	return 0
}

//export hydratStop
func hydratStop() {
	state.Lock()
	defer state.Unlock()
	if state.cancel != nil {
		state.cancel()
	}
}

func main() {}
