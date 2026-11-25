package device

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/gateway"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

const (
	backgroundPort          = 28180
	criticalPort            = 28280
	defaultCriticalSlots    = 4
	defaultFastProbeWorkers = 2
)

type ProcessOptions struct {
	Xray             string
	Embedded         EmbeddedXray
	FlowSocket       string
	Tor              string
	Lyrebird         string
	RuntimeDirectory string
	AutomaticRoutes  bool
	GeoRules         bool
	DeviceGeo        *xrayapi.DeviceGeoRules
	Underlay         *xrayapi.DeviceUnderlay
	DNSResolvers     []string
	CriticalSlots    int
	FastProbeWorkers int
	MinVLESSScore    float64
}

// EmbeddedXray starts Xray instances within the app process and controls
// them without invoking the Xray executable.
type EmbeddedXray interface {
	xrayapi.Runner
	Start(context.Context, string) (io.Closer, error)
	Uplink(context.Context, string, string) (int64, error)
}

// ProcessBackend uses the production probe pipeline and reconciler with
// a private in-process control channel. Platforms own packet capture and
// the OS-level exclusion for the network processes and their children.
type ProcessBackend struct {
	*agentapi.Client
	main        *exec.Cmd
	embedded    EmbeddedXray
	instance    io.Closer
	done        chan struct{}
	mainErr     error
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
	background  *proberuntime.Manager
	critical    *proberuntime.Manager
	servingTor  *torpool.Manager
	probingTor  *torpool.Manager
	torMirror   *torpool.IsolatedProfileManager
	directory   string
	serveAPI    string
	binary      string
	activityMu  sync.Mutex
	statsRead   time.Time
	lastTraffic time.Time
	uplink      int64
}

func StartProcesses(ctx context.Context, options ProcessOptions) (_ *ProcessBackend, startErr error) {
	if (options.Xray == "" && options.Embedded == nil) || options.Tor == "" || options.Lyrebird == "" {
		return nil, errors.New("Xray, Tor and Lyrebird runtimes are required")
	}
	if options.Embedded != nil && options.FlowSocket == "" {
		return nil, errors.New("embedded Xray requires a private flow control socket")
	}
	dnsResolvers := options.DNSResolvers
	if len(dnsResolvers) == 0 {
		dnsResolvers = DNSResolversForPreset(0)
	}
	directory, err := os.MkdirTemp(options.RuntimeDirectory, "rt-")
	if err != nil {
		return nil, err
	}
	processCtx, cancel := context.WithCancel(ctx)
	backend := &ProcessBackend{directory: directory, cancel: cancel, binary: options.Xray, embedded: options.Embedded}
	defer func() {
		if startErr != nil {
			startErr = errors.Join(startErr, backend.Close())
		}
	}()
	mainSocket := filepath.Join(directory, "main.sock")
	backend.serveAPI = "unix://" + mainSocket
	adapter := xrayapi.NewAdapterWithResolvers(options.Xray, backend.serveAPI, dnsResolvers, options.Embedded)
	adapter.ConfigureDeviceTunnel()
	adapter.ConfigureRouting(directSuffixes, directDomains, options.GeoRules)
	if options.Underlay != nil {
		if err := adapter.ConfigureDeviceUnderlay(*options.Underlay); err != nil {
			return nil, err
		}
	}
	if options.DeviceGeo != nil {
		adapter.ConfigureDeviceGeo(*options.DeviceGeo)
	}
	flowSocket := options.FlowSocket
	if backend.embedded == nil {
		flowSocket = filepath.Join(directory, "flow.sock")
	}
	adapter.ConfigureFlowControl(flowSocket)
	config, err := adapter.DeviceConfig(xrayapi.DeviceTunnelOptions{
		Name: "hydrat-app", APISocket: mainSocket, AutomaticRoutes: options.AutomaticRoutes,
	})
	if err != nil {
		return nil, err
	}
	mainConfig := filepath.Join(directory, "main.json")
	if err := os.WriteFile(mainConfig, config, 0600); err != nil {
		return nil, err
	}
	reconciler, err := dataplane.NewReconciler(adapter, filepath.Join(directory, "applied.json"))
	if err != nil {
		return nil, err
	}

	backend.servingTor, err = newDeviceTor(options, directory, "tor", 28450)
	if err != nil {
		return nil, err
	}
	backend.probingTor, err = newDeviceTor(options, directory, "tor-probes", 28550)
	if err != nil {
		return nil, err
	}
	backend.torMirror, err = torpool.NewIsolatedProfileManager(backend.servingTor, backend.probingTor)
	if err != nil {
		return nil, err
	}
	criticalSlots := options.CriticalSlots
	if criticalSlots <= 0 {
		criticalSlots = defaultCriticalSlots
	}
	fastProbeWorkers := options.FastProbeWorkers
	if fastProbeWorkers <= 0 {
		fastProbeWorkers = defaultFastProbeWorkers
	}
	var background, critical *probexray.Control
	password := rand.Text()
	backend.background, background, err = startProbeProcess(processCtx, options, directory, "background", backgroundPort, gateway.TotalProbeSlots, password)
	if err != nil {
		return nil, err
	}
	backend.critical, critical, err = startProbeProcess(processCtx, options, directory, "critical", criticalPort, criticalSlots, password)
	if err != nil {
		return nil, err
	}
	quality := probe.NewQoEMeasurer(probe.QoEMeasurerConfig{DNSResolvers: dnsResolvers})
	prober, err := gateway.NewProber(background, backend.background, 2*time.Second, probe.Measurer{}, probe.Liveness{},
		quality, backend.probingTor, backgroundPort)
	if err != nil {
		return nil, err
	}
	active, err := gateway.NewCriticalActiveProber(critical, backend.critical, 2*time.Second, probe.Liveness{},
		backend.servingTor, criticalPort, criticalSlots, quality)
	if err != nil {
		return nil, err
	}
	prober.RequireLocalPassword(password)
	prober.SetMinVLESSScore(options.MinVLESSScore)
	active.RequireLocalPassword(password)

	if err := backend.startServing(processCtx, mainConfig, mainSocket, adapter); err != nil {
		return nil, err
	}
	handler := agentapi.NewServer(reconciler, 0,
		agentapi.WithProfileManager(backend.torMirror),
		agentapi.WithProbeRuntime(backend.background),
		agentapi.WithActiveProbeRuntime(backend.critical),
		agentapi.WithProbeRunner(prober),
		agentapi.WithCriticalActiveProbeRunner(active, criticalSlots),
		agentapi.WithProbeWorkers(fastProbeWorkers, 1, gateway.BackgroundActiveProbeSlots),
		agentapi.WithQoEProbeWorkers(1),
		agentapi.WithReadiness(func(context.Context) error {
			select {
			case <-backend.done:
				return errors.New("serving Xray has stopped")
			default:
				return nil
			}
		}))
	backend.Client = agentapi.NewLocalClient(handler)
	return backend, nil
}

func newDeviceTor(options ProcessOptions, directory, name string, port int) (*torpool.Manager, error) {
	config := torpool.Config{
		Binary: options.Tor, LyrebirdBinary: options.Lyrebird, DataDir: filepath.Join(directory, name),
		SocksPortBase: port, WarmProfiles: 1, ExplorerProfiles: 1,
		PrivateSocks: options.Embedded != nil && runtime.GOOS != "windows",
	}
	if options.Underlay != nil {
		config.UpstreamSOCKS = options.Underlay.Address
		config.UpstreamUser = options.Underlay.User
		config.UpstreamPassword = options.Underlay.Password
	}
	return torpool.NewManager(config, nil)
}

func startProbeProcess(ctx context.Context, options ProcessOptions, directory, role string, base, slots int, password string) (*proberuntime.Manager, *probexray.Control, error) {
	socket := filepath.Join(directory, role+".sock")
	endpoint := "unix://" + socket
	config := filepath.Join(directory, role+".json")
	inbounds := make([]map[string]any, 0, slots)
	for slot := range slots {
		inbounds = append(inbounds, map[string]any{
			"tag": fmt.Sprintf("probe-slot-%d", slot), "listen": "127.0.0.1", "port": base + slot,
			"protocol": "socks", "settings": map[string]any{
				"udp": true, "auth": "password",
				"accounts": []map[string]string{{"user": "hydrat-probe", "pass": password}},
			},
		})
	}
	body, err := json.Marshal(map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "warning"},
		"api": map[string]any{"tag": "api", "listen": socket,
			"services": []string{"HandlerService", "RoutingService"}},
		"inbounds":  inbounds,
		"outbounds": []map[string]any{{"tag": "block", "protocol": "blackhole"}, {"tag": "api", "protocol": "blackhole"}},
		"routing": map[string]any{"rules": []map[string]any{
			{"type": "field", "ruleTag": "probe-final", "network": "tcp,udp", "outboundTag": "block"},
		}},
	})
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(config, body, 0600); err != nil {
		return nil, nil, err
	}
	control := probexray.New(options.Xray, endpoint, slots, options.Embedded)
	var runtimeOptions []proberuntime.Option
	if options.Embedded != nil {
		runtimeOptions = append(runtimeOptions, proberuntime.WithEmbeddedCore(options.Embedded.Start))
	}
	manager, err := proberuntime.New(proberuntime.Config{
		Role: role, Binary: options.Xray, ConfigPath: config, APIAddress: endpoint,
		ReadinessTimeout: 10 * time.Second,
	}, control, runtimeOptions...)
	if err != nil {
		return nil, nil, err
	}
	if err := manager.Start(ctx); err != nil {
		return nil, nil, errors.Join(err, manager.Close())
	}
	return manager, control, nil
}

func (backend *ProcessBackend) startServing(ctx context.Context, config, socket string, adapter *xrayapi.Adapter) error {
	backend.done = make(chan struct{})
	if backend.embedded != nil {
		instance, err := backend.embedded.Start(ctx, config)
		if err != nil {
			close(backend.done)
			return err
		}
		backend.instance = instance
	} else if err := backend.startServingProcess(ctx, config); err != nil {
		close(backend.done)
		return err
	}
	return backend.waitServing(ctx, socket, adapter)
}

func (backend *ProcessBackend) startServingProcess(ctx context.Context, config string) error {
	command := exec.CommandContext(ctx, backend.binary, "run", "-config", config)
	command.Env = append(os.Environ(), xrayflow.SocketEnvironment+"="+filepath.Join(backend.directory, "flow.sock"))
	command.WaitDelay = 5 * time.Second
	if runtime.GOOS != "windows" {
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	}
	if err := command.Start(); err != nil {
		return err
	}
	backend.main = command
	go func() {
		backend.mainErr = command.Wait()
		close(backend.done)
	}()
	return nil
}

func (backend *ProcessBackend) waitServing(ctx context.Context, socket string, adapter *xrayapi.Adapter) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(deadline, "unix", socket)
		if err == nil {
			_ = connection.Close()
			if _, err := adapter.FlowSnapshot(deadline); err == nil {
				return nil
			}
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("start serving Xray: %w", deadline.Err())
		case <-backend.done:
			return fmt.Errorf("serving Xray exited during startup: %v", backend.mainErr)
		case <-ticker.C:
		}
	}
}

func (backend *ProcessBackend) Done() <-chan struct{} { return backend.done }

func (backend *ProcessBackend) LastTraffic() time.Time {
	backend.activityMu.Lock()
	defer backend.activityMu.Unlock()
	now := time.Now()
	if now.Sub(backend.statsRead) < time.Second {
		return backend.lastTraffic
	}
	backend.statsRead = now
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	pattern := "inbound>>>" + xrayapi.DeviceInboundTag + ">>>traffic>>>uplink"
	value, err := backend.readUplink(ctx, pattern)
	if err == nil {
		if value > backend.uplink {
			backend.lastTraffic = now
		}
		backend.uplink = value
	}
	return backend.lastTraffic
}

func (backend *ProcessBackend) readUplink(ctx context.Context, pattern string) (int64, error) {
	if backend.embedded != nil {
		return backend.embedded.Uplink(ctx, backend.serveAPI, pattern)
	}
	output, err := exec.CommandContext(ctx, backend.binary, "api", "statsquery",
		"--server="+backend.serveAPI, "--pattern="+pattern).Output()
	if err != nil {
		return 0, err
	}
	var result struct{ Stat []struct{ Value int64 } }
	if err := json.Unmarshal(output, &result); err != nil {
		return 0, err
	}
	if len(result.Stat) == 1 {
		return result.Stat[0].Value, nil
	}
	return 0, nil
}

func (backend *ProcessBackend) Close() error {
	backend.closeOnce.Do(func() {
		backend.cancel()
		if backend.instance != nil {
			backend.closeErr = backend.instance.Close()
			close(backend.done)
		}
		if backend.done != nil {
			<-backend.done
		}
		if backend.torMirror != nil {
			backend.torMirror.Close()
		}
		for _, manager := range []*torpool.Manager{backend.servingTor, backend.probingTor} {
			if manager != nil {
				backend.closeErr = errors.Join(backend.closeErr, manager.Close())
			}
		}
		for _, manager := range []*proberuntime.Manager{backend.critical, backend.background} {
			if manager != nil {
				backend.closeErr = errors.Join(backend.closeErr, manager.Close())
			}
		}
		if backend.closeErr == nil {
			backend.closeErr = os.RemoveAll(backend.directory)
		}
	})
	return backend.closeErr
}
