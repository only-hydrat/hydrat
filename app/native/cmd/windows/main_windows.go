package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
	"golang.org/x/sys/windows"
)

func main() {
	runtime.LockOSThread()
	if err := run(os.Args[1:]); err != nil {
		if len(os.Args) > 1 {
			fmt.Fprintln(os.Stderr, err)
		} else {
			walk.MsgBox(nil, "Hydrat", err.Error(), walk.MsgBoxIconError)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	interfaceLanguage = windowsLanguage()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bundle := filepath.Dir(exe)
	options, err := bundleOptions(bundle)
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "--check" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"artifact": "Hydrat Windows x64", "bundle": "ok",
		})
	}
	if len(args) != 0 {
		return errors.New("usage: Hydrat.exe [--check]")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New(tr("Откройте Hydrat с правами администратора для системного VPN."))
	}
	mutex, err := windows.UTF16PtrFromString("Global\\Hydrat.Device.Tunnel")
	if err != nil {
		return err
	}
	handle, err := windows.CreateMutex(nil, false, mutex)
	if handle != 0 {
		defer windows.CloseHandle(handle)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.New(tr("Hydrat уже запущен."))
	}
	if err != nil {
		return err
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return err
	}
	stateDir := filepath.Join(local, "Hydrat")
	if saved := savedLanguage(stateDir); saved != "" {
		interfaceLanguage = saved
	}
	if err := xrayflow.MakePrivateWindowsDirectory(stateDir); err != nil {
		return err
	}
	// A separate private runtime directory keeps the Unix socket names short
	// and separates stale endpoints left by an interrupted process.
	runtimeDir := filepath.Join(stateDir, "r"+rand.Text()[:10])
	if err := xrayflow.MakePrivateWindowsDirectory(runtimeDir); err != nil {
		return err
	}
	defer os.RemoveAll(runtimeDir)
	options.RuntimeDirectory = runtimeDir
	options.FlowSocket = filepath.Join(runtimeDir, "f")
	if len(filepath.Join(runtimeDir, "rt-4294967295", "background.sock")) >= 108 {
		return errors.New(tr("Путь к профилю Windows слишком длинный для сокетов Hydrat."))
	}
	if err := os.Setenv(xrayflow.SocketEnvironment, options.FlowSocket); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(stateDir, "hydrat.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	underlay := xrayapi.DeviceUnderlay{Address: "127.0.0.1:28080", User: "hydrat-underlay", Password: rand.Text()}
	options.Underlay = &underlay
	transport := newSourceTransport(underlay)
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport}
	app, err := device.OpenSingleDevice(ctx, stateDir, client)
	if err != nil {
		return err
	}
	defer app.Close()
	prefs, err := openPreferences(stateDir, client)
	if err != nil {
		return err
	}
	if err := app.SetHWID(prefs.load().HWID); err != nil {
		return err
	}
	if err := copyBundledGeo(filepath.Join(bundle, "geo"), prefs.assets()); err != nil {
		return err
	}
	for _, name := range []string{"xray.location.asset", "XRAY_LOCATION_ASSET"} {
		if err := os.Setenv(name, prefs.assets()); err != nil {
			return err
		}
	}
	control := device.NewControl(ctx, app, func(session context.Context) (result error) {
		settings := prefs.load()
		sessionOptions := options
		sessionOptions.DNSResolvers = device.DNSResolversForPreset(settings.DNSPreset)
		sessionOptions.GeoRules = settings.GeoRules
		sessionOptions.FastProbeWorkers = max(settings.FastWorkers, settings.BackgroundWorkers)
		sessionOptions.MinVLESSScore = float64(settings.MinVLESSScore)
		if settings.GeoRules {
			rules, err := prefs.acquireGeo()
			if err != nil {
				return err
			}
			defer prefs.releaseGeo()
			sessionOptions.DeviceGeo = rules
		}
		backend, err := device.StartProcesses(session, sessionOptions)
		if err != nil {
			return err
		}
		transport.connected.Store(true)
		defer func() {
			result = errors.Join(result, backend.Close())
			transport.connected.Store(false)
			transport.proxy.CloseIdleConnections()
		}()
		err = app.RunMobileWithSettings(session, backend, settings.MobileSettings, sessionOptions.DNSResolvers...)
		if session.Err() != nil {
			return nil
		}
		return err
	})
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := control.Close(closeCtx); err != nil {
			log.Printf("stop Hydrat: %v", err)
		}
	}()
	return showWindow(ctx, control, app, prefs, filepath.Join(bundle, "icon.png"), logFile.Name())
}

func bundleOptions(directory string) (device.ProcessOptions, error) {
	tor := filepath.Join(directory, "tor", "tor.exe")
	lyrebird := filepath.Join(directory, "tor", "pluggable_transports", "lyrebird.exe")
	for _, path := range []string{filepath.Join(directory, "wintun.dll"), tor, lyrebird,
		filepath.Join(directory, "geo", "geoip.dat"), filepath.Join(directory, "geo", "geosite.dat")} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return device.ProcessOptions{}, fmt.Errorf(tr("Файл %s отсутствует. Распакуйте архив Hydrat целиком."), filepath.Base(path))
		}
	}
	return device.ProcessOptions{
		Embedded: xraycore.Host{}, Tor: tor, Lyrebird: lyrebird, AutomaticRoutes: true, GeoRules: true,
		CriticalSlots: device.MobileCriticalSlots,
	}, nil
}

type sourceTransport struct {
	connected atomic.Bool
	proxy     *http.Transport
}

func newSourceTransport(underlay xrayapi.DeviceUnderlay) *sourceTransport {
	proxy := &url.URL{Scheme: "socks5h", Host: underlay.Address, User: url.UserPassword(underlay.User, underlay.Password)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	return &sourceTransport{proxy: transport}
}

func (transport *sourceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.connected.Load() {
		return transport.proxy.RoundTrip(request)
	}
	return http.DefaultTransport.RoundTrip(request)
}
