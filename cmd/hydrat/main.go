package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/config"
	"github.com/only-hydrat/hydrat/internal/controller"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/failoverbudget"
	"github.com/only-hydrat/hydrat/internal/gateway"
	"github.com/only-hydrat/hydrat/internal/portal"
	"github.com/only-hydrat/hydrat/internal/probe"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/refresh"
	"github.com/only-hydrat/hydrat/internal/retainedlog"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/supervisor"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

const serviceLogRetention = 72 * time.Hour

type serviceLogDirectoryPreparer func(string, int, int) error

type serviceLogOpener func(string) (*retainedlog.Writer, error)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	return runWithServiceLogOpener(openServiceLog)
}

func runWithServiceLogOpener(openLog serviceLogOpener) (runErr error) {
	if len(os.Args) < 2 {
		return errors.New("usage: hydrat <agent|controller|backup|restore>")
	}
	configPath := os.Getenv("HYDRAT_CONFIG")
	if configPath == "" {
		configPath = "/etc/hydrat/config.yml"
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	flags.StringVar(&configPath, "config", configPath, "Hydrat YAML config")
	var outputPath, inputPath string
	flags.StringVar(&outputPath, "output", "", "backup output path")
	flags.StringVar(&inputPath, "input", "", "restore input path")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	serviceLog, err := openLog(os.Args[1])
	if err != nil {
		return err
	}
	if serviceLog != nil {
		previousOutput := log.Writer()
		log.SetOutput(serviceLog)
		defer func() {
			if runErr != nil {
				log.Printf("hydrat command failed: %v", runErr)
			}
			log.SetOutput(previousOutput)
			runErr = errors.Join(runErr, serviceLog.Close())
		}()
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch os.Args[1] {
	case "agent":
		return runAgent(ctx, loaded)
	case "controller":
		return runController(ctx, loaded)
	case "backup":
		return runBackup(ctx, loaded, outputPath)
	case "restore":
		return runRestore(ctx, loaded, inputPath)
	default:
		return fmt.Errorf("unknown hydrat command %q", os.Args[1])
	}
}

func openServiceLog(command string) (*retainedlog.Writer, error) {
	return openServiceLogWithDirectoryPreparer(command, retainedlog.PrepareDirectory)
}

func openServiceLogWithDirectoryPreparer(
	command string,
	prepareDirectory serviceLogDirectoryPreparer,
) (*retainedlog.Writer, error) {
	service := map[string]string{"agent": "gateway", "controller": "controller"}[command]
	if service == "" {
		return nil, nil
	}
	directory := os.Getenv("HYDRAT_LOG_DIR")
	if directory == "" {
		return nil, errors.New("HYDRAT_LOG_DIR is required")
	}
	retention, err := time.ParseDuration(os.Getenv("HYDRAT_LOG_RETENTION"))
	if err != nil || retention != serviceLogRetention {
		return nil, errors.New("HYDRAT_LOG_RETENTION must be 72h")
	}
	if !filepath.IsAbs(directory) {
		return nil, errors.New("HYDRAT_LOG_DIR must be absolute")
	}
	if command == "agent" {
		if prepareDirectory == nil {
			return nil, errors.New("service log directory preparer is required")
		}
		for _, preparation := range []struct {
			path     string
			uid, gid int
		}{
			{path: directory, uid: 0, gid: 10001},
			{path: filepath.Join(directory, "gateway"), uid: 0, gid: 0},
			{path: filepath.Join(directory, "controller"), uid: 10001, gid: 10001},
		} {
			if err := prepareDirectory(preparation.path, preparation.uid, preparation.gid); err != nil {
				return nil, fmt.Errorf("prepare service log directory %s: %w", preparation.path, err)
			}
		}
	}
	return retainedlog.Open(retainedlog.Config{
		Directory:       filepath.Join(directory, service),
		Service:         service,
		Retention:       retention,
		SegmentDuration: time.Hour,
		CleanupInterval: time.Minute,
	})
}

func openState(cfg config.Config) (*store.Store, error) {
	key, err := secretbox.LoadOrCreateKey(cfg.Paths.MasterKey)
	if err != nil {
		return nil, err
	}
	box, err := secretbox.New(key)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.Paths.Database, box)
}

func runBackup(ctx context.Context, cfg config.Config, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(filepath.Dir(cfg.Paths.Database), "backups", "hydrat-"+time.Now().UTC().Format("20060102T150405Z")+".db")
	}
	database, err := openState(cfg)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Backup(ctx, outputPath); err != nil {
		return err
	}
	log.Printf("backup written to %s", outputPath)
	return nil
}

func runRestore(ctx context.Context, cfg config.Config, inputPath string) error {
	if inputPath == "" {
		return errors.New("restore requires --input")
	}
	key, err := secretbox.LoadOrCreateKey(cfg.Paths.MasterKey)
	if err != nil {
		return err
	}
	box, err := secretbox.New(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Paths.Database), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(cfg.Paths.Database), ".restore-*.db")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	input, err := os.Open(inputPath)
	if err != nil {
		_ = temporary.Close()
		return err
	}
	_, copyErr := io.Copy(temporary, input)
	_ = input.Close()
	if copyErr != nil {
		_ = temporary.Close()
		return copyErr
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	if err := store.ValidateBackup(temporaryPath, box); err != nil {
		return fmt.Errorf("validate backup: %w", err)
	}
	if _, err := os.Stat(cfg.Paths.Database); err == nil {
		previous := cfg.Paths.Database + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(cfg.Paths.Database, previous); err != nil {
			return err
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, sidecarErr := os.Stat(cfg.Paths.Database + suffix); sidecarErr == nil {
				if err := os.Rename(cfg.Paths.Database+suffix, previous+suffix); err != nil {
					return err
				}
			} else if !errors.Is(sidecarErr, os.ErrNotExist) {
				return sidecarErr
			}
		}
		log.Printf("previous database retained at %s", previous)
	}
	return os.Rename(temporaryPath, cfg.Paths.Database)
}

func runAgent(ctx context.Context, cfg config.Config) error {
	endpoint, err := resolveWireGuardEndpoint(cfg.WireGuard)
	if err != nil {
		return err
	}
	cfg.WireGuard.Endpoint = endpoint
	if err := prepareAgentStorage(ctx, cfg); err != nil {
		return err
	}
	bootstrap := gateway.Bootstrap{
		Interface: cfg.WireGuard.Interface, WireGuardConfig: cfg.WireGuard.Config, NFTConfig: cfg.Paths.NFTConfig,
	}
	if err := bootstrap.Apply(ctx); err != nil {
		return err
	}
	supervised := newXraySupervisor(log.Writer())
	dnsSupervisors, err := startDNSSupervisor(
		ctx, supervised, cfg.WireGuard.DNS, cfg.Xray.EffectiveDNSResolvers(),
	)
	if err != nil {
		return err
	}
	defer dnsSupervisors.StopAndWait()
	xraySupervisors := startXraySupervisors(ctx, supervised, cfg.Xray.Binary, cfg.Xray.MainConfig)
	defer xraySupervisors.StopAndWait()

	torManager, err := torpool.NewManager(torpool.Config{
		Binary: cfg.Tor.Binary, LyrebirdBinary: cfg.Tor.LyrebirdBinary, DataDir: cfg.Tor.DataDir,
		SocksPortBase: cfg.Tor.SocksPortBase, WarmProfiles: cfg.Tor.WarmProfiles, ExplorerProfiles: cfg.Tor.ExplorerProfiles,
	}, nil)
	if err != nil {
		return err
	}
	defer torManager.Close()
	torProbeManager, err := torpool.NewManager(torpool.Config{
		Binary: cfg.Tor.Binary, LyrebirdBinary: cfg.Tor.LyrebirdBinary,
		DataDir: cfg.Tor.ProbeDataDir, SocksPortBase: cfg.Tor.ProbeSocksPortBase,
		WarmProfiles: cfg.Tor.WarmProfiles, ExplorerProfiles: cfg.Tor.ExplorerProfiles,
	}, nil)
	if err != nil {
		return err
	}
	defer torProbeManager.Close()
	torProfileManager, err := torpool.NewIsolatedProfileManager(
		torManager, torProbeManager,
		torpool.WithProbeMirrorErrorReporter(func(err error) {
			log.Printf("isolated Tor probe mirror reconcile failed: %v", err)
		}),
	)
	if err != nil {
		return err
	}
	defer torProfileManager.Close()
	xray := xrayapi.NewAdapterWithResolvers(
		cfg.Xray.Binary, cfg.Xray.APIAddress, cfg.Xray.EffectiveDNSResolvers(), nil,
	)
	xray.ConfigureRouting(cfg.Routing.DirectSuffixes, cfg.Routing.DirectDomains, cfg.Routing.GeoRules.Enabled)
	reconciler, err := dataplane.NewReconciler(xray, cfg.Paths.AppliedPlan)
	if err != nil {
		return err
	}
	geoUpdater, err := gateway.NewGeoUpdater(gateway.GeoUpdaterConfig{
		Enabled:        cfg.Routing.GeoRules.Enabled,
		AutoUpdate:     cfg.Routing.GeoRules.AutoUpdate,
		GeoIPURL:       cfg.Routing.GeoRules.GeoIPURL,
		GeoSiteURL:     cfg.Routing.GeoRules.GeoSiteURL,
		UpdateInterval: cfg.Routing.GeoRules.UpdateInterval,
	})
	if err != nil {
		return err
	}
	if err := geoUpdater.Start(ctx); err != nil {
		return err
	}
	defer geoUpdater.Close()
	mainXrayReadiness := tcpReadiness(
		cfg.Xray.APIAddress, net.JoinHostPort(cfg.WireGuard.DNS, "53"),
	)
	xraySupervisors.StartRehydration(mainXrayReadiness, reconciler.InvalidateRuntime, reconciler.Rehydrate)
	if err := waitForReadiness(ctx, xraySupervisors.Readiness(mainXrayReadiness), 60*time.Second); err != nil {
		return err
	}
	probeControl := probexray.New(cfg.Xray.Binary, cfg.Xray.ProbeAPIAddress, gateway.TotalProbeSlots, nil)
	probeRuntime, err := proberuntime.New(agentProbeRuntimeConfig(cfg), probeControl)
	if err != nil {
		return err
	}
	activeControl := probexray.New(
		cfg.Xray.Binary, cfg.Xray.ActiveAPIAddress,
		cfg.Probes.ActiveWorkers, nil,
	)
	activeRuntime, err := proberuntime.New(
		agentActiveProbeRuntimeConfig(cfg), activeControl,
	)
	if err != nil {
		return errors.Join(err, probeRuntime.Close())
	}
	return runWithProbeRuntime(ctx, probeRuntime, func() error {
		return runWithProbeRuntime(ctx, activeRuntime, func() error {
			qoeMeasurer := probe.NewQoEMeasurer(agentQoEMeasurerConfig(cfg))
			gateConfig := probe.HTTPGateConfig{
				YouTubeURL:   cfg.Probes.GateEndpoints.YouTube,
				ChatGPTURL:   cfg.Probes.GateEndpoints.ChatGPT,
				OpenAIURL:    cfg.Probes.GateEndpoints.OpenAI,
				TelegramURL:  cfg.Probes.GateEndpoints.Telegram,
				InstagramURL: cfg.Probes.GateEndpoints.Instagram,
			}
			for _, cg := range cfg.Probes.CustomGates {
				gateConfig.CustomGates = append(gateConfig.CustomGates, probe.CustomGateCheck{
					Name:       cg.Name,
					URL:        cg.URL,
					Acceptable: probe.StatusesAcceptable(cg.AcceptableStatuses),
				})
			}
			prober, err := gateway.NewProber(
				probeControl,
				probeRuntime,
				cfg.ProbeRuntime.CleanupTimeout,
				probe.Measurer{GateConfig: gateConfig},
				probe.Liveness{},
				qoeMeasurer,
				torProbeManager,
				cfg.Xray.ProbeSocksPortBase,
			)
			if err != nil {
				return err
			}
			criticalActiveProber, err := gateway.NewCriticalActiveProber(
				activeControl, activeRuntime, cfg.ProbeRuntime.CleanupTimeout,
				probe.Liveness{ResponseBudget: 25 * time.Millisecond}, torManager,
				cfg.Xray.ActiveSocksPortBase,
				cfg.Probes.ActiveWorkers,
				qoeMeasurer,
			)
			if err != nil {
				return err
			}
			wgManager := wireguard.Manager{Config: wireguard.ManagerConfig{
				Interface: cfg.WireGuard.Interface, Endpoint: cfg.WireGuard.Endpoint, DNS: cfg.WireGuard.DNS, MTU: cfg.WireGuard.MTU,
			}}
			collector := wireguard.Collector{Interface: cfg.WireGuard.Interface}
			socketGID := 10001
			if value := os.Getenv("HYDRAT_SOCKET_GID"); value != "" {
				parsed, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("invalid HYDRAT_SOCKET_GID: %w", err)
				}
				socketGID = parsed
			}
			portalToken, err := gateway.LoadOrCreatePortalToken(cfg.Portal.InternalTokenPath, socketGID)
			if err != nil {
				return err
			}
			portalHandler, err := gateway.NewPortalProxy(cfg.Portal.ControllerURL, portalToken, nil)
			if err != nil {
				return err
			}
			portalListener, err := net.Listen("tcp", cfg.Portal.GatewayBind)
			if err != nil {
				return fmt.Errorf("listen portal proxy: %w", err)
			}
			defer portalListener.Close()
			portalServer := &http.Server{
				Handler: portalHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
			}
			go func() {
				if err := portalServer.Serve(portalListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Printf("portal proxy stopped: %v", err)
				}
			}()
			handler := agentapi.NewServer(reconciler, 4*1024*1024,
				agentapi.WithActivityProvider(collector), agentapi.WithPeerManager(wgManager), agentapi.WithProfileManager(torProfileManager),
				agentapi.WithProbeRuntime(probeRuntime),
				agentapi.WithActiveProbeRuntime(activeRuntime),
				agentapi.WithGeoManager(geoUpdater),
				agentapi.WithProbeRunner(prober), agentapi.WithProbeWorkers(cfg.Probes.FastWorkers, cfg.Probes.FullWorkers, gateway.BackgroundActiveProbeSlots),
				agentapi.WithCriticalActiveProbeRunner(criticalActiveProber, cfg.Probes.ActiveWorkers),
				agentapi.WithQoEProbeWorkers(cfg.QoE.Workers),
				agentapi.WithProbeDeadlines(cfg.Probes.FastDeadline, cfg.Probes.FullDeadline, cfg.Probes.ActiveDeadline),
				agentapi.WithQoEProbeDeadline(cfg.QoE.Deadline),
				agentapi.WithTorProbeDeadlines(cfg.Probes.TorFastDeadline, cfg.Probes.TorFullDeadline),
				agentapi.WithReadiness(func(ctx context.Context) error {
					if err := xraySupervisors.Readiness(mainXrayReadiness)(ctx); err != nil {
						return err
					}
					if err := torProfileManager.ProbeMirrorHealth(); err != nil {
						return err
					}
					return tcpReadiness(
						cfg.Xray.ProbeAPIAddress, cfg.Xray.ActiveAPIAddress,
					)(ctx)
				}))
			listener, err := listenUnix(cfg.Paths.AgentSock)
			if err != nil {
				return err
			}
			defer listener.Close()
			server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 60 * time.Second}
			go func() {
				<-ctx.Done()
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = portalServer.Shutdown(shutdown)
				_ = server.Shutdown(shutdown)
			}()
			log.Printf("hydrat agent listening on unix://%s", cfg.Paths.AgentSock)
			err = server.Serve(listener)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
	})
}

func resolveWireGuardEndpoint(cfg config.WireGuardConfig) (string, error) {
	endpoint := os.Getenv("WIREGUARD_ENDPOINT")
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}
	if endpoint == "" {
		return "", nil
	}
	port := cfg.ListenPort
	if port == 0 {
		port = 51820
	}
	if value := os.Getenv("WIREGUARD_PORT"); value != "" {
		var err error
		port, err = strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("invalid WIREGUARD_PORT %q: %w", value, err)
		}
	}
	return wireguard.NormalizeEndpoint(endpoint, port)
}

func agentQoEMeasurerConfig(cfg config.Config) probe.QoEMeasurerConfig {
	gateConfig := probe.HTTPGateConfig{
		YouTubeURL:   cfg.Probes.GateEndpoints.YouTube,
		ChatGPTURL:   cfg.Probes.GateEndpoints.ChatGPT,
		OpenAIURL:    cfg.Probes.GateEndpoints.OpenAI,
		TelegramURL:  cfg.Probes.GateEndpoints.Telegram,
		InstagramURL: cfg.Probes.GateEndpoints.Instagram,
	}
	for _, cg := range cfg.Probes.CustomGates {
		gateConfig.CustomGates = append(gateConfig.CustomGates, probe.CustomGateCheck{
			Name:       cg.Name,
			URL:        cg.URL,
			Acceptable: probe.StatusesAcceptable(cg.AcceptableStatuses),
		})
	}
	return probe.QoEMeasurerConfig{
		SampleBytes:  cfg.QoE.SampleBytes,
		Deadline:     cfg.QoE.Deadline,
		DNSResolvers: cfg.Xray.EffectiveDNSResolvers(),
		ApplicationGates: func(ctx context.Context, client *http.Client) probe.HTTPGateResult {
			return probe.CheckHTTPGatesWithConfig(ctx, client, gateConfig)
		},
		ApplicationControl: func(ctx context.Context, client *http.Client) probe.HTTPGateResult {
			return probe.CheckHTTPReachabilityWithConfig(ctx, client, gateConfig)
		},
	}
}

func agentProbeRuntimeConfig(cfg config.Config) proberuntime.Config {
	return proberuntime.Config{
		Binary:           cfg.Xray.Binary,
		ConfigPath:       cfg.Xray.ProbeConfig,
		APIAddress:       cfg.Xray.ProbeAPIAddress,
		MaxProbes:        cfg.ProbeRuntime.MaxProbes,
		MaxRSSBytes:      cfg.ProbeRuntime.MaxRSSMiB * 1024 * 1024,
		MaxFDs:           cfg.ProbeRuntime.MaxFDs,
		DrainTimeout:     cfg.ProbeRuntime.DrainTimeout,
		StopTimeout:      cfg.ProbeRuntime.StopTimeout,
		ReadinessTimeout: cfg.ProbeRuntime.ReadinessTimeout,
	}
}

func agentActiveProbeRuntimeConfig(cfg config.Config) proberuntime.Config {
	result := agentProbeRuntimeConfig(cfg)
	result.ConfigPath = cfg.Xray.ActiveConfig
	result.APIAddress = cfg.Xray.ActiveAPIAddress
	result.MaxProbes = proberuntime.UnlimitedProbes
	return result
}

type managedProbeRuntime interface {
	gateway.ProbeRuntime
	Start(context.Context) error
	Close() error
}

func runWithProbeRuntime(
	ctx context.Context,
	runtime managedProbeRuntime,
	run func() error,
) (runErr error) {
	if err := runtime.Start(ctx); err != nil {
		return errors.Join(err, runtime.Close())
	}
	defer func() {
		runErr = errors.Join(runErr, runtime.Close())
	}()
	return run()
}

func tcpReadiness(addresses ...string) func(context.Context) error {
	return func(ctx context.Context) error {
		dialer := net.Dialer{Timeout: 500 * time.Millisecond}
		for _, address := range addresses {
			connection, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				return fmt.Errorf("managed endpoint %s is not ready: %w", address, err)
			}
			_ = connection.Close()
		}
		return nil
	}
}

func waitForReadiness(ctx context.Context, check func(context.Context) error, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	var lastError error
	for {
		checkContext, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		lastError = check(checkContext)
		cancel()
		if lastError == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("managed dataplane readiness timeout: %w", lastError)
		case <-ticker.C:
		}
	}
}

type processSupervisorGroup struct {
	cancel  context.CancelFunc
	workers sync.WaitGroup
}

func startDNSSupervisor(
	ctx context.Context,
	managed supervisor.Supervisor,
	listenAddress string,
	resolvers []string,
) (*processSupervisorGroup, error) {
	args, err := dnsmasqArgs(listenAddress, resolvers)
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	group := &processSupervisorGroup{cancel: cancel}
	group.workers.Add(1)
	go func() {
		defer group.workers.Done()
		logSupervisor("dnsmasq", managed.Run(childCtx, supervisor.Spec{
			Name: "dnsmasq", Path: "/usr/sbin/dnsmasq", Args: args,
		}))
	}()
	return group, nil
}

func (group *processSupervisorGroup) StopAndWait() {
	if group == nil {
		return
	}
	group.cancel()
	group.workers.Wait()
}

func dnsmasqArgs(listenAddress string, resolvers []string) ([]string, error) {
	address := net.ParseIP(listenAddress)
	if address == nil || address.To4() == nil || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("DNS listener must be a usable IPv4 address")
	}
	if err := dataplane.ValidateDNSResolverPool(resolvers); err != nil {
		return nil, fmt.Errorf("DNS resolver pool: %w", err)
	}
	args := []string{
		"--keep-in-foreground", "--no-resolv", "--no-hosts",
		"--listen-address=" + listenAddress, "--port=53", "--bind-interfaces",
	}
	for _, resolver := range resolvers {
		args = append(args, "--server="+resolver)
	}
	return append(args,
		"--all-servers", "--cache-size=10000", "--min-cache-ttl=30",
		"--use-stale-cache=86400", "--fast-dns-retry=1000,10000",
		"--edns-packet-max=1232", "--log-facility=-",
	), nil
}

func prepareAgentStorage(ctx context.Context, cfg config.Config) error {
	dataRoot := filepath.Dir(filepath.Dir(cfg.Paths.Database))
	if dataRoot == "." || dataRoot == string(filepath.Separator) {
		return fmt.Errorf("unsafe controller data root %q", dataRoot)
	}
	if err := os.Chmod(dataRoot, 0o750); err != nil {
		return fmt.Errorf("make data root traversable: %w", err)
	}
	if err := os.Chown(dataRoot, -1, 10001); err != nil {
		return fmt.Errorf("set data root group: %w", err)
	}
	for _, directory := range []string{filepath.Dir(cfg.Paths.Database), filepath.Dir(cfg.Paths.MasterKey)} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return err
		}
		if err := os.Chown(directory, 10001, 10001); err != nil {
			return err
		}
	}
	if err := wireguard.EnsureServerConfig(ctx, cfg.WireGuard.Config, cfg.WireGuard.Network, cfg.WireGuard.ListenPort, nil); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Paths.AppliedPlan), 0o700); err != nil {
		return err
	}
	wgQuickPath := filepath.Join("/etc/wireguard", cfg.WireGuard.Interface+".conf")
	if err := os.MkdirAll(filepath.Dir(wgQuickPath), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(wgQuickPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink(cfg.WireGuard.Config, wgQuickPath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace existing %s", wgQuickPath)
	}
	return nil
}

func runController(ctx context.Context, cfg config.Config) error {
	endpoint, err := resolveWireGuardEndpoint(cfg.WireGuard)
	if err != nil {
		return err
	}
	ctx, cancelController := context.WithCancel(ctx)
	defer cancelController()
	adminPassword := os.Getenv("HYDRAT_ADMIN_PASSWORD")
	if adminPassword == "" {
		return errors.New("HYDRAT_ADMIN_PASSWORD is required")
	}
	key, err := secretbox.LoadOrCreateKey(cfg.Paths.MasterKey)
	if err != nil {
		return err
	}
	box, err := secretbox.New(key)
	if err != nil {
		return err
	}
	database, err := store.Open(cfg.Paths.Database, box)
	if err != nil {
		return err
	}
	defer database.Close()
	portalToken, err := gateway.ReadPortalToken(cfg.Portal.InternalTokenPath)
	if err != nil {
		return fmt.Errorf("read portal proxy token: %w", err)
	}
	agent := agentapi.NewClient(
		cfg.Paths.AgentSock,
		agentapi.WithClientProbeDeadlines(
			cfg.Probes.FastDeadline,
			cfg.Probes.FullDeadline,
			cfg.Probes.ActiveDeadline,
			cfg.Probes.TorFastDeadline,
			cfg.Probes.TorFullDeadline,
		),
		agentapi.WithClientQoEProbeDeadline(cfg.QoE.Deadline),
		agentapi.WithClientActiveResponseSlack(cfg.Probes.ActiveResponseSlack),
	)
	torProfiles := controller.NewTorCoordinator(agent)
	if err := torProfiles.Sync(ctx); err != nil {
		return fmt.Errorf("sync Tor profiles: %w", err)
	}
	policy := controllerSchedulerPolicy(cfg)
	placement := scheduler.New(policy)
	persistedExclusions, err := database.ListExclusions(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("load scheduler exclusions: %w", err)
	}
	for _, exclusion := range persistedExclusions {
		placement.Exclude(exclusion.ClientID, exclusion.CandidateID, exclusion.Until)
	}
	routingStatePath := filepath.Join(filepath.Dir(cfg.Paths.Database), "routing.json")
	if stored, err := controller.LoadStoredRouting(routingStatePath); err == nil && stored != nil {
		if len(stored.DirectSuffixes) > 0 {
			cfg.Routing.DirectSuffixes = stored.DirectSuffixes
		}
		if len(stored.DirectDomains) > 0 {
			cfg.Routing.DirectDomains = stored.DirectDomains
		}
		if stored.GeoRules.GeoIPURL != "" {
			cfg.Routing.GeoRules = stored.GeoRules
		}
		cfg.Routing.DisallowRUEgress = stored.DisallowRUEgress
	}
	engine := controller.NewEngine(
		database, agent, torProfiles, placement, key,
		controller.WithRouting(cfg.Routing.DirectSuffixes, cfg.Routing.DirectDomains),
		controller.WithDisallowRUEgress(cfg.Routing.DisallowRUEgress),
		controller.WithQoEEnabled(cfg.QoE.Enabled),
		controller.WithQoEPromotionEvidence(
			cfg.QoE.WindowSize, cfg.QoEPromotionFreshness(),
			cfg.QoEPromotionWindowFreshness(),
			cfg.QoEPromotionMaximumSampleGap(),
		),
		controller.WithDNSResolvers(cfg.Xray.EffectiveDNSResolvers()),
		controller.WithActiveProofFreshness(cfg.ActiveProofFreshness()),
		controller.WithActiveFailureFreshness(cfg.ActiveFailureFreshness()),
		controller.WithActiveCriticalRouteLimit(cfg.Probes.ActiveRouteLimit),
	)
	provisioner, err := controller.NewProvisioner(database, agent, cfg.WireGuard.Network)
	if err != nil {
		return err
	}
	refresher := refresh.New(
		database,
		&http.Client{Timeout: 20 * time.Second},
		4*1024*1024,
		cfg.Inventory.MaxCandidates,
	).WithRetirementGrace(cfg.Inventory.RetirementGrace).WithHWID(cfg.Inventory.HWID)
	promotionTrigger := make(chan struct{}, 1)
	qualification := controller.QualificationService{
		Store:            database,
		Agent:            agent,
		Tor:              torProfiles,
		DisallowRUEgress: cfg.Routing.DisallowRUEgress,
		PoolSize:         cfg.Inventory.WorkingPoolSize,
		PromotionRatio:   cfg.Tournament.PromotionRatio,
		ResetWindow:      cfg.Tournament.ResetWindow,
		FastWorkers:      cfg.Probes.FastWorkers, FullWorkers: cfg.Probes.FullWorkers,
		TorCandidatesPerCycle:  cfg.Tor.WarmProfiles + cfg.Tor.ExplorerProfiles,
		TorQualificationBudget: time.Duration(cfg.Controller.ProbeSeconds) * time.Second,
		TorMutationTimeout:     time.Minute,
		Promotions:             promotionTrigger,
	}
	hardFailureTrigger := controller.NewHardFailureMailbox()
	manualTrigger := make(chan struct{}, 1)
	clientLifecycleTrigger := make(chan struct{}, 1)
	sourceTrigger := make(chan struct{}, 1)
	capacityTrigger := make(chan struct{}, 1)
	activeMonitor := newControllerActiveMonitor(
		cfg, database, agent, engine, torProfiles,
		hardFailureTrigger, promotionTrigger, capacityTrigger,
	)
	qoeMonitor, qoeTrigger := controllerQoEMonitor(cfg, database, agent)
	if qoeMonitor != nil {
		qoeMonitor.SyncActivity = engine.SyncActivity
	}
	reassigner := controller.ManualReassigner{Store: database, Scheduler: placement, Trigger: manualTrigger}
	controllerReadiness := controller.NewReadinessLatch()
	routingManager := &controllerRoutingManager{
		cfg:           cfg.Routing,
		statePath:     routingStatePath,
		engine:        engine,
		agent:         agent,
		qualification: &qualification,
	}
	handler := portal.New(portal.ServerConfig{
		Store: database, Health: agent, AdminPassword: adminPassword, Refresher: refresher, Profiles: torProfiles,
		ProbeRuntime:        agent,
		ControllerReadiness: controllerReadiness,
		RetirementGrace:     cfg.Inventory.RetirementGrace,
		Provisioner:         provisioner, Reassigner: reassigner, SourceChanges: sourceTrigger,
		ClientChanges:     clientLifecycleTrigger,
		InternalToken:     portalToken,
		Routing:           routingManager,
		WireGuardEndpoint: endpoint,
	})
	server := &http.Server{Addr: cfg.Portal.Bind, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	refreshAll := func(ctx context.Context) error {
		listed, err := database.ListSources(ctx)
		if err != nil {
			return err
		}
		var firstError error
		for _, source := range listed {
			if !source.Enabled {
				continue
			}
			if err := refresher.Source(ctx, source.ID); err != nil {
				log.Printf("refresh source %s: %v", source.ID, err)
				if firstError == nil {
					firstError = err
				}
			}
		}
		return firstError
	}
	diagnosticRetention := controller.DiagnosticRetention{
		Store: database, Retention: 72 * time.Hour, BatchSize: 1_000,
	}
	candidateRetirement := controller.CandidateRetirement{
		Store: database, Tor: torProfiles,
		RetiredRetention: cfg.Inventory.RetiredRetention,
	}
	controllerRuntime := controller.Runtime{
		Maintenance: func(ctx context.Context, now time.Time) error {
			if err := diagnosticRetention.Run(ctx, now); err != nil {
				return err
			}
			return candidateRetirement.Run(ctx, now)
		},
		ProfileRepair: qualification.RepairRuntimeProfiles,
		Refresh:       refreshAll,
		Qualify:       qualification.Run,
		Active:        activeMonitor.Run,
		Place: func(ctx context.Context, now time.Time, reason controller.PlacementReason) error {
			if err := engine.CycleForReason(ctx, now, reason); err != nil {
				return err
			}
			if reason == controller.PlacementHardFailure {
				select {
				case promotionTrigger <- struct{}{}:
				default:
				}
			}
			return nil
		},
		StartupHardFailure: engine.HasStartupHardFailure,
		StartupNormalize:   engine.NormalizeActiveCriticalRoutes,
		RecoveryReady:      engine.ActiveCardinalityReady,
		CapacityReady: func(ctx context.Context, now time.Time) error {
			if err := activeMonitor.WarmTargets(ctx, now); err != nil {
				return err
			}
			return engine.CapacityReady(ctx, now)
		},
		HardFailureEvents: hardFailureTrigger, ManualReassigns: manualTrigger,
		ClientChanges: clientLifecycleTrigger,
		SourceChanges: sourceTrigger, CapacityChanges: capacityTrigger,
		Promotions:              promotionTrigger,
		SourceRefreshInterval:   time.Duration(cfg.Controller.SourceRefreshSeconds) * time.Second,
		QualificationInterval:   time.Duration(cfg.Controller.ProbeSeconds) * time.Second,
		PlacementInterval:       time.Duration(cfg.Controller.CycleSeconds) * time.Second,
		ActiveInterval:          cfg.Probes.ActiveInterval,
		ActiveDeadline:          cfg.Probes.ActiveDeadline + cfg.Probes.ActiveResponseSlack,
		ActivePlanningDeadline:  controller.ActiveCriticalCoveragePlanningBudget,
		ActiveOverlap:           cfg.Probes.ActiveOverlap,
		PlacementPreemptTimeout: cfg.Controller.PlacementPreemptTimeout,
		Unready:                 controllerReadiness.Unready,
		Ready:                   controllerReadiness.Ready,
		MaintenanceInterval:     time.Minute,
		ProfileRepairInterval:   2 * time.Second,
	}
	if qoeMonitor != nil {
		qoeMonitor.Profiles = torProfiles
		controllerRuntime.QoE = qoeMonitor.Run
		controllerRuntime.QoEInterval = controller.QoEWakeInterval(
			cfg.QoE.ActiveInterval,
			cfg.QoE.IdleInterval,
			cfg.QoE.DegradedInterval,
		)
		controllerRuntime.QoEDegradations = qoeTrigger
	}
	log.Printf("hydrat controller portal listening on %s", cfg.Portal.Bind)
	runtimeDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	go func() { runtimeDone <- controllerRuntime.Start(ctx) }()
	go func() { serverDone <- server.ListenAndServe() }()
	select {
	case runtimeErr := <-runtimeDone:
		cancelController()
		serverErr := <-serverDone
		if runtimeErr != nil {
			return fmt.Errorf("controller runtime: %w", runtimeErr)
		}
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			return serverErr
		}
		return nil
	case serverErr := <-serverDone:
		cancelController()
		runtimeErr := <-runtimeDone
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			return serverErr
		}
		if runtimeErr != nil {
			return fmt.Errorf("controller runtime: %w", runtimeErr)
		}
		return nil
	}
}

func newControllerActiveMonitor(
	cfg config.Config,
	database *store.Store,
	agent *agentapi.Client,
	targets controller.ActiveTargetProvider,
	profiles controller.ProfileProvider,
	hardFailures *controller.HardFailureMailbox,
	promotions chan<- struct{},
	capacityChanges chan<- struct{},
) *controller.ActiveMonitor {
	return &controller.ActiveMonitor{
		Store: database, Agent: agent, Slots: cfg.Probes.ActiveWorkers,
		CriticalLimit:    cfg.Probes.ActiveRouteLimit,
		PlanningDeadline: controller.ActiveCriticalCoveragePlanningBudget,
		ProbeDeadline:    cfg.Probes.ActiveDeadline + cfg.Probes.ActiveResponseSlack,
		ProofFreshness:   cfg.ActiveProofFreshness(),
		HardFailures:     hardFailures,
		HardFailureDeadline: cfg.Probes.ActiveDeadline +
			cfg.Probes.ActiveResponseSlack + cfg.Controller.HardFailoverBudget,
		ConfirmCompleteFailureInCycle: false,
		AvailabilityFailureThreshold:  failoverbudget.ActiveAvailabilityConfirmations,
		AvailabilityFailureFreshness: cfg.Probes.ActiveInterval +
			cfg.Probes.ActiveDeadline + cfg.Probes.ActiveResponseSlack,
		Targets: targets, Profiles: profiles,
		Promotions: promotions, CapacityChanges: capacityChanges,
	}
}

func controllerSchedulerPolicy(cfg config.Config) scheduler.Policy {
	policy := scheduler.PolicyDefaults()
	policy.MinimumImprovement = cfg.Scheduler.ImproveRatio
	policy.MaxPlannedMoves = cfg.Scheduler.MaxMoves
	policy.QoEAlternativeSpeedup = cfg.QoE.AlternativeSpeedup
	return policy
}

func controllerQoEMonitor(
	cfg config.Config,
	database *store.Store,
	agent *agentapi.Client,
) (*controller.QoEMonitor, <-chan struct{}) {
	if !cfg.QoE.Enabled {
		return nil, nil
	}
	trigger := make(chan struct{}, 1)
	return &controller.QoEMonitor{
		Store: database, Agent: agent, Profiles: agent,
		Policy: cfg.QoE.Policy(), ActiveInterval: cfg.QoE.ActiveInterval,
		IdleInterval: cfg.QoE.IdleInterval, DegradedInterval: cfg.QoE.DegradedInterval,
		Retention: cfg.QoE.Retention, Workers: cfg.QoE.Workers,
		StandbyCandidates: cfg.QoE.StandbyCandidates, Trigger: trigger,
	}, trigger
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if gidText := os.Getenv("HYDRAT_SOCKET_GID"); gidText != "" {
		gid, err := strconv.Atoi(gidText)
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("invalid HYDRAT_SOCKET_GID: %w", err)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

type controllerRoutingManager struct {
	mu            sync.Mutex
	cfg           config.RoutingConfig
	statePath     string
	engine        *controller.Engine
	agent         *agentapi.Client
	qualification *controller.QualificationService
	now           func() time.Time
}

func (m *controllerRoutingManager) GetRouting(ctx context.Context) (portal.RoutingState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	suffixes, domains := m.engine.Routing()
	geoStatus, err := m.agent.GeoStatus(ctx)
	if err != nil {
		geoStatus = agentapi.GeoAssetStatus{
			Enabled:        m.cfg.GeoRules.Enabled,
			AutoUpdate:     m.cfg.GeoRules.AutoUpdate,
			GeoIPURL:       m.cfg.GeoRules.GeoIPURL,
			GeoSiteURL:     m.cfg.GeoRules.GeoSiteURL,
			UpdateInterval: m.cfg.GeoRules.UpdateInterval.String(),
		}
	}
	return portal.RoutingState{
		DirectSuffixes:   suffixes,
		DirectDomains:    domains,
		DisallowRUEgress: m.cfg.DisallowRUEgress,
		GeoRules: portal.GeoRulesView{
			Enabled:        m.cfg.GeoRules.Enabled,
			AutoUpdate:     m.cfg.GeoRules.AutoUpdate,
			GeoIPURL:       m.cfg.GeoRules.GeoIPURL,
			GeoSiteURL:     m.cfg.GeoRules.GeoSiteURL,
			UpdateInterval: m.cfg.GeoRules.UpdateInterval.String(),
		},
		GeoStatus: geoStatus,
	}, nil
}

func (m *controllerRoutingManager) UpdateRouting(ctx context.Context, input portal.UpdateRoutingInput) (portal.RoutingState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg.DirectSuffixes = append([]string(nil), input.DirectSuffixes...)
	m.cfg.DirectDomains = append([]string(nil), input.DirectDomains...)
	if input.DisallowRUEgress != nil {
		m.cfg.DisallowRUEgress = *input.DisallowRUEgress
	}
	if input.GeoRules != nil {
		m.cfg.GeoRules.Enabled = input.GeoRules.Enabled
		m.cfg.GeoRules.AutoUpdate = input.GeoRules.AutoUpdate
		if input.GeoRules.GeoIPURL != "" {
			m.cfg.GeoRules.GeoIPURL = input.GeoRules.GeoIPURL
		}
		if input.GeoRules.GeoSiteURL != "" {
			m.cfg.GeoRules.GeoSiteURL = input.GeoRules.GeoSiteURL
		}
		if input.GeoRules.UpdateInterval != "" {
			if dur, err := time.ParseDuration(input.GeoRules.UpdateInterval); err == nil && dur > 0 {
				m.cfg.GeoRules.UpdateInterval = dur
			}
		}
	}

	_ = controller.SaveStoredRouting(m.statePath, controller.StoredRoutingConfig{
		DirectSuffixes:   m.cfg.DirectSuffixes,
		DirectDomains:    m.cfg.DirectDomains,
		DisallowRUEgress: m.cfg.DisallowRUEgress,
		GeoRules:         m.cfg.GeoRules,
	})

	m.engine.SetRouting(m.cfg.DirectSuffixes, m.cfg.DirectDomains)
	m.engine.SetDisallowRUEgress(m.cfg.DisallowRUEgress)
	if m.qualification != nil {
		m.qualification.DisallowRUEgress = m.cfg.DisallowRUEgress
	}

	geoReq := agentapi.GeoUpdateRequest{
		Enabled:        &m.cfg.GeoRules.Enabled,
		AutoUpdate:     &m.cfg.GeoRules.AutoUpdate,
		GeoIPURL:       &m.cfg.GeoRules.GeoIPURL,
		GeoSiteURL:     &m.cfg.GeoRules.GeoSiteURL,
		UpdateInterval: &m.cfg.GeoRules.UpdateInterval,
	}
	geoStatus, _ := m.agent.UpdateGeo(ctx, geoReq)

	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	_ = m.engine.CycleForReason(ctx, now, controller.PlacementManual)

	return portal.RoutingState{
		DirectSuffixes:   m.cfg.DirectSuffixes,
		DirectDomains:    m.cfg.DirectDomains,
		DisallowRUEgress: m.cfg.DisallowRUEgress,
		GeoRules: portal.GeoRulesView{
			Enabled:        m.cfg.GeoRules.Enabled,
			AutoUpdate:     m.cfg.GeoRules.AutoUpdate,
			GeoIPURL:       m.cfg.GeoRules.GeoIPURL,
			GeoSiteURL:     m.cfg.GeoRules.GeoSiteURL,
			UpdateInterval: m.cfg.GeoRules.UpdateInterval.String(),
		},
		GeoStatus: geoStatus,
	}, nil
}

func (m *controllerRoutingManager) TriggerGeoUpdate(ctx context.Context) (agentapi.GeoAssetStatus, error) {
	return m.agent.UpdateGeo(ctx, agentapi.GeoUpdateRequest{Force: true})
}
func logSupervisor(name string, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("%s supervisor stopped: %v", name, err)
	}
}
