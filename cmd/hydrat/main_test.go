package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/config"
	"github.com/only-hydrat/hydrat/internal/controller"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/retainedlog"
	"github.com/only-hydrat/hydrat/internal/supervisor"
)

func TestOpenServiceLogAgentWritesGatewaySegmentWithPreparedOwnership(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	type preparation struct {
		path     string
		uid, gid int
	}
	var preparations []preparation
	writer, err := openServiceLogWithDirectoryPreparer("agent", func(path string, uid, gid int) error {
		preparations = append(preparations, preparation{path: path, uid: uid, gid: gid})
		return os.Mkdir(path, 0o750)
	})
	if err != nil {
		t.Fatalf("openServiceLogWithDirectoryPreparer: %v", err)
	}
	writeServiceLogLine(t, writer, "agent retained line")

	wantPreparations := []preparation{
		{path: directory, uid: 0, gid: 10001},
		{path: filepath.Join(directory, "gateway"), uid: 0, gid: 0},
		{path: filepath.Join(directory, "controller"), uid: 10001, gid: 10001},
	}
	if fmt.Sprint(preparations) != fmt.Sprint(wantPreparations) {
		t.Fatalf("preparations=%v, want %v", preparations, wantPreparations)
	}
	requireServiceLogContains(t, filepath.Join(directory, "gateway"), "gateway", "agent retained line")
	requireNoServiceSegments(t, directory, "gateway")
	requireNoServiceSegments(t, filepath.Join(directory, "controller"), "gateway")
}

func TestOpenServiceLogAgentFailsClosedWhenOwnershipCannotBeSet(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")
	denied := errors.New("chown denied")

	writer, err := openServiceLogWithDirectoryPreparer("agent", func(string, int, int) error { return denied })
	if writer != nil {
		_ = writer.Close()
		t.Fatal("ownership failure returned a writer")
	}
	if !errors.Is(err, denied) {
		t.Fatalf("error=%v, want chown failure", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(directory, "gateway-*.log"))
	if globErr != nil {
		t.Fatalf("Glob: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("ownership failure created log segments: %v", matches)
	}
}

func TestOpenServiceLogControllerWritesControllerSegmentInPreparedDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	controllerDirectory := filepath.Join(directory, "controller")
	if err := os.MkdirAll(controllerDirectory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	writer, err := openServiceLog("controller")
	if err != nil {
		t.Fatalf("openServiceLog: %v", err)
	}
	writeServiceLogLine(t, writer, "controller retained line")
	requireServiceLogContains(t, controllerDirectory, "controller", "controller retained line")
	requireNoServiceSegments(t, directory, "controller")
	requireNoServiceSegments(t, filepath.Join(directory, "gateway"), "controller")
}

func TestOpenServiceLogControllerRequiresPrecreatedServiceDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	writer, err := openServiceLog("controller")
	if writer != nil {
		_ = writer.Close()
		t.Fatal("openServiceLog returned a writer without a precreated controller directory")
	}
	if err == nil {
		t.Fatal("openServiceLog created the controller directory")
	}
	if _, statErr := os.Lstat(filepath.Join(directory, "controller")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("controller directory exists after rejected open: %v", statErr)
	}
}

func TestOpenServiceLogRejectsInvalidConfiguration(t *testing.T) {
	absoluteDirectory := filepath.Join(t.TempDir(), "logs")
	for _, test := range []struct {
		name      string
		command   string
		directory string
		retention string
	}{
		{name: "wrong retention", command: "controller", directory: absoluteDirectory, retention: "71h"},
		{name: "relative directory", command: "controller", directory: "logs", retention: "72h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HYDRAT_LOG_DIR", test.directory)
			t.Setenv("HYDRAT_LOG_RETENTION", test.retention)
			writer, err := openServiceLog(test.command)
			if err == nil {
				if writer != nil {
					_ = writer.Close()
				}
				t.Fatal("openServiceLog succeeded, want error")
			}
		})
	}
}

func TestOpenServiceLogIgnoresUnsupportedCommand(t *testing.T) {
	t.Setenv("HYDRAT_LOG_DIR", "relative")
	t.Setenv("HYDRAT_LOG_RETENTION", "71h")
	writer, err := openServiceLog("backup")
	if err != nil {
		t.Fatalf("openServiceLog: %v", err)
	}
	if writer != nil {
		_ = writer.Close()
		t.Fatal("openServiceLog returned a writer for unsupported command")
	}
}

func TestRunInitializesServiceLogBeforeYAMLLoadThenRestoresAndClosesIt(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	controllerDirectory := filepath.Join(directory, "controller")
	if err := os.MkdirAll(controllerDirectory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")
	t.Setenv("HYDRAT_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))

	previousArgs := os.Args
	os.Args = []string{"hydrat", "controller"}
	t.Cleanup(func() { os.Args = previousArgs })

	var previous bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&previous)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	var opened *retainedlog.Writer
	err := runWithServiceLogOpener(func(command string) (*retainedlog.Writer, error) {
		var openErr error
		opened, openErr = openServiceLog(command)
		return opened, openErr
	})
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("run error=%v, want config load error", err)
	}
	if opened == nil {
		t.Fatal("service log was not opened before config load")
	}
	if log.Writer() != &previous {
		t.Fatal("run did not restore the previous logger output")
	}
	if _, err := opened.Write([]byte("after close")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after run error=%v, want os.ErrClosed", err)
	}
	requireServiceLogContains(t, controllerDirectory, "controller", "open config")
}

func writeServiceLogLine(t *testing.T, writer *retainedlog.Writer, line string) {
	t.Helper()
	previous := log.Writer()
	log.SetOutput(writer)
	log.Print(line)
	log.SetOutput(previous)
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func requireServiceLogContains(t *testing.T, directory, service, text string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, service+"-*.log"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	for _, path := range matches {
		if filepath.Base(path) == service+"-current.log" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", path, err)
		}
		if strings.Contains(string(contents), text) {
			return
		}
	}
	t.Fatalf("no %s log segment contains %q; matches=%v", service, text, matches)
}

func requireNoServiceSegments(t *testing.T, directory, service string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, service+"-*.log"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected %s log segments in %s: %v", service, directory, matches)
	}
}

func TestAgentQoEMeasurerUsesConfiguredBounds(t *testing.T) {
	cfg := config.Defaults()
	cfg.QoE.SampleBytes = 123456
	cfg.QoE.Deadline = 17 * time.Second

	got := agentQoEMeasurerConfig(cfg)
	if got.SampleBytes != cfg.QoE.SampleBytes || got.Deadline != cfg.QoE.Deadline ||
		!reflect.DeepEqual(got.DNSResolvers, cfg.Xray.EffectiveDNSResolvers()) ||
		got.ApplicationGates == nil || got.ApplicationControl == nil {
		t.Fatalf("QoE measurer config=%+v, want bytes=%d deadline=%s", got, cfg.QoE.SampleBytes, cfg.QoE.Deadline)
	}
}

func TestAgentProbeRuntimeConfigMapsFixedProductionBoundary(t *testing.T) {
	cfg := config.Defaults()
	cfg.Xray.Binary = "/usr/local/bin/xray"
	cfg.Xray.ProbeConfig = "/etc/hydrat/xray-probe.json"
	cfg.Xray.ProbeAPIAddress = "127.0.0.1:10086"

	got := agentProbeRuntimeConfig(cfg)
	want := proberuntime.Config{
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
	if got != want {
		t.Fatalf("probe runtime config=%+v, want %+v", got, want)
	}
}

func TestAgentActiveProbeRuntimeConfigUsesIsolatedContainerEndpoints(t *testing.T) {
	cfg := config.Defaults()
	got := agentActiveProbeRuntimeConfig(cfg)
	want := agentProbeRuntimeConfig(cfg)
	want.ConfigPath = cfg.Xray.ActiveConfig
	want.APIAddress = cfg.Xray.ActiveAPIAddress
	want.MaxProbes = proberuntime.UnlimitedProbes
	if got != want {
		t.Fatalf("active probe runtime config=%+v want=%+v", got, want)
	}
}

func TestRunAgentWiresDedicatedCriticalActiveRuntime(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"cfg.Xray.ActiveAPIAddress",
		"cfg.Xray.ActiveSocksPortBase",
		"agentActiveProbeRuntimeConfig(cfg)",
		"gateway.NewCriticalActiveProber(",
		"agentapi.WithCriticalActiveProbeRunner(criticalActiveProber, cfg.Probes.ActiveWorkers)",
		"agentapi.WithActiveProbeRuntime(activeRuntime)",
		"agentapi.WithProbeWorkers(cfg.Probes.FastWorkers, cfg.Probes.FullWorkers, gateway.BackgroundActiveProbeSlots)",
		"agentapi.WithClientActiveResponseSlack(cfg.Probes.ActiveResponseSlack)",
		"ActiveOverlap:           cfg.Probes.ActiveOverlap",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("dedicated active runtime wiring missing %q", required)
		}
	}
	if strings.Contains(body,
		"WithProbeWorkers(cfg.Probes.FastWorkers, cfg.Probes.FullWorkers, cfg.Probes.ActiveWorkers)") {
		t.Fatal("critical active workers are still assigned to the background endpoint")
	}
}

func TestRunWithProbeRuntimeClosesEveryOwnedChildPath(t *testing.T) {
	startFailure := errors.New("start failed")
	laterFailure := errors.New("later initialization failed")
	closeFailure := errors.New("close failed")
	panicValue := errors.New("later initialization panic")
	tests := []struct {
		name      string
		runtime   *lifecycleProbeRuntime
		run       func(*lifecycleProbeRuntime) error
		wantError []error
		wantPanic any
		wantCalls string
	}{
		{
			name:      "start rollback",
			runtime:   &lifecycleProbeRuntime{startErr: startFailure, closeErr: closeFailure},
			run:       func(*lifecycleProbeRuntime) error { return nil },
			wantError: []error{startFailure, closeFailure},
			wantCalls: "start,close",
		},
		{
			name:    "later initialization rollback",
			runtime: &lifecycleProbeRuntime{closeErr: closeFailure},
			run: func(runtime *lifecycleProbeRuntime) error {
				runtime.addCall("initialize")
				return laterFailure
			},
			wantError: []error{laterFailure, closeFailure},
			wantCalls: "start,initialize,close",
		},
		{
			name:    "normal close",
			runtime: &lifecycleProbeRuntime{},
			run: func(runtime *lifecycleProbeRuntime) error {
				runtime.addCall("serve")
				return nil
			},
			wantCalls: "start,serve,close",
		},
		{
			name:    "panic cleanup and repanic",
			runtime: &lifecycleProbeRuntime{},
			run: func(runtime *lifecycleProbeRuntime) error {
				runtime.addCall("initialize")
				panic(panicValue)
			},
			wantPanic: panicValue,
			wantCalls: "start,initialize,close",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				err       error
				recovered any
			)
			func() {
				defer func() { recovered = recover() }()
				err = runWithProbeRuntime(
					context.Background(),
					test.runtime,
					func() error { return test.run(test.runtime) },
				)
			}()
			for _, want := range test.wantError {
				if !errors.Is(err, want) {
					t.Fatalf("error=%v, want joined %v", err, want)
				}
			}
			if recovered != test.wantPanic {
				t.Fatalf("recovered=%v, want %v", recovered, test.wantPanic)
			}
			if got := test.runtime.callOrder(); got != test.wantCalls {
				t.Fatalf("calls=%s, want %s", got, test.wantCalls)
			}
		})
	}
}

func TestControllerPolicyMapsQoEAlternativeSpeedup(t *testing.T) {
	cfg := config.Defaults()
	cfg.QoE.AlternativeSpeedup = 2.25

	policy := controllerSchedulerPolicy(cfg)
	if policy.QoEAlternativeSpeedup != cfg.QoE.AlternativeSpeedup {
		t.Fatalf("QoE alternative speedup=%v, want %v", policy.QoEAlternativeSpeedup, cfg.QoE.AlternativeSpeedup)
	}
}

func TestControllerQoEWiringHonorsEnabledAndFullMonitorConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.QoE.ActiveInterval = 21 * time.Second
	cfg.QoE.IdleInterval = 7 * time.Minute
	cfg.QoE.DegradedInterval = 87 * time.Second
	cfg.QoE.Retention = 72 * time.Hour
	cfg.QoE.Workers = 3
	cfg.QoE.StandbyCandidates = 5

	monitor, degradations := controllerQoEMonitor(cfg, nil, nil)
	if monitor == nil || degradations == nil {
		t.Fatal("enabled QoE did not construct monitor wiring")
	}
	if monitor.Policy != cfg.QoE.Policy() ||
		monitor.ActiveInterval != cfg.QoE.ActiveInterval ||
		monitor.IdleInterval != cfg.QoE.IdleInterval ||
		monitor.DegradedInterval != cfg.QoE.DegradedInterval ||
		monitor.Retention != cfg.QoE.Retention || monitor.Workers != cfg.QoE.Workers ||
		monitor.StandbyCandidates != cfg.QoE.StandbyCandidates {
		t.Fatalf("QoE monitor=%+v, config=%+v", monitor, cfg.QoE)
	}
	monitor.Trigger <- struct{}{}
	select {
	case <-degradations:
	default:
		t.Fatal("QoE degradation trigger is not connected")
	}

	cfg.QoE.Enabled = false
	monitor, degradations = controllerQoEMonitor(cfg, nil, nil)
	if monitor != nil || degradations != nil {
		t.Fatalf("disabled QoE wiring monitor=%v degradations=%v", monitor, degradations)
	}
}

func TestMainInstallsQoEClientDeadlineAndEngineGate(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"probexray.New(cfg.Xray.Binary, cfg.Xray.ProbeAPIAddress, gateway.TotalProbeSlots, nil)",
		"probe.NewQoEMeasurer(agentQoEMeasurerConfig(cfg))",
		"agentapi.WithQoEProbeWorkers(cfg.QoE.Workers)",
		"agentapi.WithQoEProbeDeadline(cfg.QoE.Deadline)",
		"agentapi.WithClientQoEProbeDeadline(cfg.QoE.Deadline)",
		"controller.WithQoEEnabled(cfg.QoE.Enabled)",
		"controllerRuntime.QoEInterval = controller.QoEWakeInterval(",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("main controller wiring is missing %s", required)
		}
	}
}

func TestMainSharesControllerReadinessWithPortalHealth(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"controllerReadiness := controller.NewReadinessLatch()",
		"ControllerReadiness: controllerReadiness",
		"activeMonitor.WarmTargets(ctx, now)",
		"return engine.CapacityReady(ctx, now)",
		"RecoveryReady:      engine.ActiveCardinalityReady",
		"controllerReadiness.Unready",
		"controllerReadiness.Ready",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("main controller readiness wiring is missing %q", required)
		}
	}
}

func TestMainXraySupervisorCancelsAndJoinsBeforeOutputClose(t *testing.T) {
	output := &closeTrackingWriter{}
	previousOutput := log.Writer()
	log.SetOutput(output)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	runner := &blockingRunner{
		started:      make(chan string, 1),
		finalWritten: make(chan string, 1),
		finished:     make(chan string, 1),
		release:      make(chan struct{}),
		output:       output,
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(release)
	managed := supervisor.Supervisor{Runner: runner, Backoff: time.Hour}
	group := startXraySupervisors(context.Background(), managed, "xray", "main.json")

	var started string
	select {
	case started = <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("main Xray process did not start")
	}
	if started != "main.json" {
		t.Fatalf("started process=%q, want main.json", started)
	}
	select {
	case unexpected := <-runner.started:
		t.Fatalf("generic supervisor also started %q", unexpected)
	default:
	}

	joined := make(chan struct{})
	go func() {
		group.StopAndWait()
		close(joined)
	}()
	var finalWritten string
	select {
	case finalWritten = <-runner.finalWritten:
	case <-time.After(time.Second):
		t.Fatal("main Xray process did not write final output")
	}
	select {
	case <-joined:
		release()
		t.Fatal("Xray join returned before supervisor goroutine exited")
	default:
	}
	release()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("Xray supervisor did not stop while the parent context remained active")
	}

	var finished string
	select {
	case finished = <-runner.finished:
	case <-time.After(time.Second):
		t.Fatal("main Xray process did not finish")
	}
	if finalWritten != "main.json" || finished != "main.json" {
		t.Fatalf("final=%q finished=%q", finalWritten, finished)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("Close output: %v", err)
	}
	if output.writeAfterClose() {
		t.Fatal("Xray supervisor wrote after retained output closed")
	}
	if expected := "final main.json"; !strings.Contains(output.String(), expected) {
		t.Fatalf("output %q does not contain %q", output.String(), expected)
	}
}

func TestMainXrayRestartsInvalidateAndRehydrateLatestGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapter := newRestartRehydrateAdapter()
	reconciler, err := dataplane.NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{{
			ID: "live", Protocol: dataplane.ProtocolVLESS,
		}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "live", UDPOutbound: "live",
		}},
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	}
	if err := reconciler.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	adapter.wipeRuntime()

	runner := newRestartableXrayRunner()
	group := startXraySupervisors(ctx, supervisor.Supervisor{
		Runner: runner, Backoff: time.Millisecond,
	}, "xray", "main.json")
	defer group.StopAndWait()
	requireXrayStart(t, runner, 1)
	group.StartRehydration(adapter.readiness, reconciler.InvalidateRuntime, reconciler.Rehydrate)
	if err := waitForReadiness(ctx, group.Readiness(adapter.readiness), 3*time.Second); err != nil {
		t.Fatalf("initial generation readiness: %v", err)
	}
	requireRehydrateOperations(t, adapter.operationsSnapshot())

	adapter.setReady(false)
	adapter.wipeRuntime()
	startEntered, releaseStart := runner.blockNextStart()
	runner.restart(t)
	select {
	case <-startEntered:
	case <-time.After(time.Second):
		t.Fatal("replacement Xray start was not attempted")
	}
	beforeAdds := adapter.addAttempts()
	if err := reconciler.Apply(ctx, plan); !errors.Is(err, dataplane.ErrRuntimeRecovering) {
		t.Fatalf("Apply error=%v want ErrRuntimeRecovering while replacement Xray starts", err)
	}
	if adapter.addAttempts() != beforeAdds {
		t.Fatal("recovering Apply touched adapter while replacement Xray was starting")
	}
	close(releaseStart)
	requireXrayStart(t, runner, 2)
	requireXrayGeneration(t, group, 2)
	beforeAdds = adapter.addAttempts()
	if err := reconciler.Apply(ctx, plan); !errors.Is(err, dataplane.ErrRuntimeRecovering) {
		t.Fatalf("Apply error=%v want ErrRuntimeRecovering after restart", err)
	}
	if adapter.addAttempts() != beforeAdds {
		t.Fatal("recovering Apply touched adapter after restart")
	}
	if err := group.Readiness(adapter.readiness)(ctx); err == nil {
		t.Fatal("restarted generation was reported ready before rehydration")
	}
	adapter.setReady(true)
	if err := waitForReadiness(ctx, group.Readiness(adapter.readiness), 3*time.Second); err != nil {
		t.Fatalf("second generation readiness: %v", err)
	}
	requireRehydrateOperations(t, adapter.operationsSnapshot())

	adapter.setReady(false)
	adapter.wipeRuntime()
	runner.restart(t)
	requireXrayStart(t, runner, 3)
	requireXrayGeneration(t, group, 3)
	runner.restart(t)
	requireXrayStart(t, runner, 4)
	requireXrayGeneration(t, group, 4)
	adapter.setReady(true)
	if err := waitForReadiness(ctx, group.Readiness(adapter.readiness), 3*time.Second); err != nil {
		t.Fatalf("latest rapid-restart generation readiness: %v", err)
	}
	generation, readyGeneration := group.generationState()
	if generation != 4 || readyGeneration != generation {
		t.Fatalf("generation=%d readyGeneration=%d want latest generation ready", generation, readyGeneration)
	}
	requireRehydrateOperations(t, adapter.operationsSnapshot())
}

func TestMainXrayRehydrateFailureStaysNotReadyAndRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapter := newRestartRehydrateAdapter()
	reconciler, err := dataplane.NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := dataplane.DesiredPlan{
		Generation:     1,
		Outbounds:      []dataplane.Outbound{{ID: "live", Protocol: dataplane.ProtocolVLESS}},
		Clients:        []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "live", UDPOutbound: "live"}},
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	}
	if err := reconciler.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	adapter.wipeRuntime()
	addsBeforeRehydrate := adapter.addAttempts()
	_ = adapter.failNextAdd()
	rehydrateAttempts := make(chan error)

	runner := newRestartableXrayRunner()
	group := startXraySupervisors(ctx, supervisor.Supervisor{
		Runner: runner, Backoff: time.Millisecond,
	}, "xray", "main.json")
	defer group.StopAndWait()
	requireXrayStart(t, runner, 1)
	group.StartRehydration(adapter.readiness, reconciler.InvalidateRuntime,
		func(ctx context.Context) error {
			err := reconciler.Rehydrate(ctx)
			rehydrateAttempts <- err
			return err
		},
	)
	if err := <-rehydrateAttempts; err == nil {
		t.Fatal("first rehydrate attempt did not fail")
	}
	if err := group.Readiness(adapter.readiness)(ctx); err == nil {
		t.Fatal("failed rehydrate was reported ready")
	}
	if err := <-rehydrateAttempts; err != nil {
		t.Fatalf("rehydrate retry failed: %v", err)
	}
	if err := waitForReadiness(ctx, group.Readiness(adapter.readiness), 3*time.Second); err != nil {
		t.Fatalf("successful rehydrate retry was not reported ready: %v", err)
	}
	if attempts := adapter.addAttempts(); attempts < addsBeforeRehydrate+2 {
		t.Fatalf("add attempts=%d want at least %d after failed attempt and retry",
			attempts, addsBeforeRehydrate+2)
	}
	requireRehydrateOperations(t, adapter.operationsSnapshot())
}

func TestAgentXraySupervisorUsesRetainedWriter(t *testing.T) {
	var output bytes.Buffer
	managed := newXraySupervisor(&output)
	runner, ok := managed.Runner.(supervisor.ExecRunner)
	if !ok {
		t.Fatalf("runner type = %T, want supervisor.ExecRunner", managed.Runner)
	}
	if runner.Output != &output {
		t.Fatal("Xray supervisor runner did not receive the retained writer")
	}
}

func TestDNSMasqArgsBindOnlyWireGuardGatewayAndRaceIndependentResolvers(t *testing.T) {
	args, err := dnsmasqArgs("10.44.0.1", []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"})
	if err != nil {
		t.Fatalf("dnsmasqArgs: %v", err)
	}
	want := []string{
		"--keep-in-foreground", "--no-resolv", "--no-hosts",
		"--listen-address=10.44.0.1", "--port=53", "--bind-interfaces",
		"--server=1.1.1.1", "--server=9.9.9.9", "--server=8.8.8.8",
		"--all-servers", "--cache-size=10000", "--min-cache-ttl=30",
		"--use-stale-cache=86400", "--fast-dns-retry=1000,10000",
		"--edns-packet-max=1232", "--log-facility=-",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("dnsmasq args=%v\nwant=%v", args, want)
	}
}

func TestDNSMasqArgsRejectUnsafeListenerAndResolverPool(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		listen    string
		resolvers []string
	}{
		{name: "empty listener", resolvers: []string{"1.1.1.1"}},
		{name: "non IP listener", listen: "wg.example", resolvers: []string{"1.1.1.1"}},
		{name: "empty pool", listen: "10.44.0.1"},
		{name: "duplicate resolver", listen: "10.44.0.1", resolvers: []string{"1.1.1.1", "1.1.1.1"}},
		{name: "private resolver", listen: "10.44.0.1", resolvers: []string{"10.0.0.53"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := dnsmasqArgs(testCase.listen, testCase.resolvers); err == nil {
				t.Fatal("dnsmasqArgs accepted unsafe configuration")
			}
		})
	}
}

func TestDNSSupervisorCancelsAndJoinsIndependently(t *testing.T) {
	runner := &blockingRunner{
		executable:   make(chan string, 1),
		started:      make(chan string, 1),
		finalWritten: make(chan string, 1),
		finished:     make(chan string, 1),
		release:      make(chan struct{}),
		output:       io.Discard,
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(release)

	group, err := startDNSSupervisor(
		context.Background(),
		supervisor.Supervisor{Runner: runner, Backoff: time.Hour},
		"10.44.0.1",
		[]string{"1.1.1.1", "9.9.9.9", "8.8.8.8"},
	)
	if err != nil {
		t.Fatalf("startDNSSupervisor: %v", err)
	}
	select {
	case executable := <-runner.executable:
		if executable != "/usr/sbin/dnsmasq" {
			t.Fatalf("executable=%q, want /usr/sbin/dnsmasq", executable)
		}
	case <-time.After(time.Second):
		t.Fatal("dnsmasq did not start")
	}

	joined := make(chan struct{})
	go func() {
		group.StopAndWait()
		close(joined)
	}()
	select {
	case <-runner.finalWritten:
	case <-time.After(time.Second):
		t.Fatal("dnsmasq did not observe supervisor cancellation")
	}
	select {
	case <-joined:
		release()
		t.Fatal("DNS join returned before the supervised process exited")
	default:
	}
	release()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("DNS supervisor did not join after its process exited")
	}
}

func TestRunAgentSeparatesMainSupervisorFromOwnedProbeRuntime(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"supervised := newXraySupervisor(log.Writer())",
		"dnsSupervisors, err := startDNSSupervisor(",
		"defer dnsSupervisors.StopAndWait()",
		"xraySupervisors := startXraySupervisors(ctx, supervised,",
		"defer xraySupervisors.StopAndWait()",
		"xraySupervisors.StartRehydration(mainXrayReadiness, reconciler.InvalidateRuntime, reconciler.Rehydrate)",
		"waitForReadiness(ctx, xraySupervisors.Readiness(mainXrayReadiness), 60*time.Second)",
		"probeRuntime, err := proberuntime.New(",
		"return runWithProbeRuntime(ctx, probeRuntime, func() error {",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("runAgent Xray wiring is missing %q", required)
		}
	}
	if strings.Contains(string(source), "startXraySupervisors(ctx, supervised, cfg.Xray.Binary, cfg.Xray.MainConfig, cfg.Xray.ProbeConfig)") {
		t.Fatal("runAgent still gives probe Xray to the generic supervisor")
	}
	if strings.Contains(string(source), "if err := reconciler.Rehydrate(ctx); err != nil") {
		t.Fatal("runAgent still has a redundant one-time-only rehydrate path")
	}
}

func TestRunAgentSeparatesClientDNSFromXrayUpstreamResolver(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if !strings.Contains(body, "xrayapi.NewAdapterWithResolvers(") ||
		!strings.Contains(body, "cfg.Xray.Binary, cfg.Xray.APIAddress, cfg.Xray.EffectiveDNSResolvers(), nil") {
		t.Fatal("runAgent does not wire the dedicated external DNS resolver into Xray")
	}
	if !strings.Contains(body, "DNS: cfg.WireGuard.DNS") {
		t.Fatal("runAgent does not advertise the WireGuard gateway DNS in client profiles")
	}
	if !strings.Contains(body, "controller.WithDNSResolvers(cfg.Xray.EffectiveDNSResolvers())") {
		t.Fatal("controller engine does not materialize client DNS with the configured Xray resolver")
	}
	if !strings.Contains(body, "controller.WithActiveProofFreshness(cfg.ActiveProofFreshness())") {
		t.Fatal("controller engine reserve freshness is not derived from the failover window")
	}
	if !strings.Contains(body, "controller.WithActiveCriticalRouteLimit(cfg.Probes.ActiveRouteLimit)") {
		t.Fatal("controller engine active route admission is not wired to the monitor limit")
	}
	for _, required := range []string{
		"torProbeManager, err := torpool.NewManager",
		"DataDir: cfg.Tor.ProbeDataDir",
		"SocksPortBase: cfg.Tor.ProbeSocksPortBase",
		"torpool.NewIsolatedProfileManager(",
		"torManager, torProbeManager,",
		"probe.Liveness{ResponseBudget: 25 * time.Millisecond}, torManager,",
		"torProfileManager.ProbeMirrorHealth()",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("isolated Tor probe runtime wiring is missing %q", required)
		}
	}
	if !strings.Contains(body, "StartupHardFailure: engine.HasStartupHardFailure") {
		t.Fatal("controller runtime does not settle pending hard generations before freshness")
	}
	if !strings.Contains(body, "StartupNormalize:   engine.NormalizeActiveCriticalRoutes") {
		t.Fatal("controller runtime does not normalize legacy active routes before Active")
	}
	if !strings.Contains(body, "newControllerActiveMonitor(") {
		t.Fatal("active monitor does not probe and promote prospective engine reserves")
	}
	if !strings.Contains(body, "Slots: cfg.Probes.ActiveWorkers") {
		t.Fatal("active monitor does not use configured active_workers; W=1 fairness is unreachable")
	}
	for _, required := range []string{
		"torProfiles := controller.NewTorCoordinator(agent)",
		"if err := torProfiles.Sync(ctx); err != nil",
		"database, agent, torProfiles, placement, key",
		"Tor: torProfiles",
		"Profiles: torProfiles",
		"qoeMonitor.Profiles = torProfiles",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("controller Tor coordinator wiring is missing %q", required)
		}
	}
	if !strings.Contains(body, "StartupHardFailure: engine.HasStartupHardFailure") {
		t.Fatal("runtime does not recover pending or fresh hard failure before startup placement")
	}
	if strings.Contains(body, "go controllerRuntime.Start(ctx)") ||
		!strings.Contains(body, "runtimeDone <- controllerRuntime.Start(ctx)") ||
		!strings.Contains(body, `fmt.Errorf("controller runtime: %w", runtimeErr)`) ||
		!strings.Contains(body, "cancelController()") {
		t.Fatal("controller does not propagate runtime startup failure through safe service shutdown")
	}
	if !strings.Contains(body, "engine.CycleForReason(ctx, now, reason)") {
		t.Fatal("controller runtime discards hard-failure placement reason")
	}
	if !strings.Contains(body, "case promotionTrigger <- struct{}{}:") {
		t.Fatal("hard-failure placement does not enqueue reserve replenishment")
	}
	if strings.Contains(body, "xrayapi.NewAdapter(cfg.Xray.Binary, cfg.Xray.APIAddress, cfg.WireGuard.DNS, nil)") {
		t.Fatal("runAgent routes Xray DNS back to the client gateway and can self-loop")
	}

	cfg, err := config.Load(filepath.Join("..", "..", "config", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.DNS != "10.44.0.1" || cfg.Xray.DNSResolver != "1.1.1.1" {
		t.Fatalf("production DNS wiring=%q/%q, want client 10.44.0.1 and upstream 1.1.1.1",
			cfg.WireGuard.DNS, cfg.Xray.DNSResolver)
	}
	if len(cfg.Xray.EffectiveDNSResolvers()) != 3 {
		t.Fatalf("production resolver pool=%v, want three independent upstreams", cfg.Xray.EffectiveDNSResolvers())
	}
}

func TestRunAgentWiresIndependentActiveFreshnessWindows(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"controller.WithActiveProofFreshness(cfg.ActiveProofFreshness())",
		"controller.WithActiveFailureFreshness(cfg.ActiveFailureFreshness())",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("runAgent active freshness wiring is missing %q", required)
		}
	}
}

func TestControllerActiveMonitorWiresSingleConfiguredWorker(t *testing.T) {
	cfg := config.Config{
		Probes: config.ProbesConfig{
			ActiveWorkers: 1, ActiveDeadline: 550 * time.Millisecond,
			ActiveResponseSlack: 75 * time.Millisecond,
			ActiveInterval:      300 * time.Millisecond,
		},
		Controller: config.ControllerConfig{HardFailoverBudget: 950 * time.Millisecond},
	}
	hardFailures := controller.NewHardFailureMailbox()
	capacityChanges := make(chan struct{}, 1)
	monitor := newControllerActiveMonitor(
		cfg, nil, nil, nil, nil, hardFailures, nil, capacityChanges,
	)
	if monitor.Slots != 1 {
		t.Fatalf("ActiveMonitor slots=%d want configured active_workers=1", monitor.Slots)
	}
	if monitor.PlanningDeadline != controller.ActiveCriticalCoveragePlanningBudget ||
		monitor.ProbeDeadline != 625*time.Millisecond ||
		monitor.ProofFreshness != cfg.ActiveProofFreshness() {
		t.Fatalf("ActiveMonitor planning/probe/freshness=%s/%s/%s",
			monitor.PlanningDeadline, monitor.ProbeDeadline, monitor.ProofFreshness)
	}
	if monitor.HardFailures != hardFailures ||
		monitor.CapacityChanges != capacityChanges ||
		monitor.HardFailureDeadline != 1575*time.Millisecond ||
		monitor.ConfirmCompleteFailureInCycle {
		t.Fatalf("ActiveMonitor hard failure wiring=%p/%s", monitor.HardFailures,
			monitor.HardFailureDeadline)
	}
}

type lifecycleProbeRuntime struct {
	mu       sync.Mutex
	calls    []string
	startErr error
	closeErr error
}

func (runtime *lifecycleProbeRuntime) Start(context.Context) error {
	runtime.addCall("start")
	return runtime.startErr
}

func (runtime *lifecycleProbeRuntime) Close() error {
	runtime.addCall("close")
	return runtime.closeErr
}

func (*lifecycleProbeRuntime) Acquire(context.Context) (*proberuntime.Lease, error) {
	return nil, errors.New("unused")
}

func (*lifecycleProbeRuntime) Release(*proberuntime.Lease, error) {}

func (*lifecycleProbeRuntime) Snapshot() proberuntime.Snapshot {
	return proberuntime.Snapshot{}
}

func (runtime *lifecycleProbeRuntime) addCall(call string) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, call)
}

func (runtime *lifecycleProbeRuntime) callOrder() string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return strings.Join(runtime.calls, ",")
}

type blockingRunner struct {
	executable   chan string
	started      chan string
	finalWritten chan string
	finished     chan string
	release      chan struct{}
	output       io.Writer
}

type restartableXrayRunner struct {
	mu               sync.Mutex
	started          chan int
	current          chan struct{}
	starts           int
	nextStartBlock   <-chan struct{}
	nextStartEntered chan struct{}
}

func newRestartableXrayRunner() *restartableXrayRunner {
	return &restartableXrayRunner{started: make(chan int, 8)}
}

func (runner *restartableXrayRunner) Start(ctx context.Context, _ string, _ ...string) (supervisor.Process, error) {
	runner.mu.Lock()
	startBlock := runner.nextStartBlock
	startEntered := runner.nextStartEntered
	runner.nextStartBlock = nil
	runner.nextStartEntered = nil
	runner.mu.Unlock()
	if startBlock != nil {
		close(startEntered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-startBlock:
		}
	}
	exit := make(chan struct{})
	runner.mu.Lock()
	runner.starts++
	start := runner.starts
	runner.current = exit
	runner.mu.Unlock()
	runner.started <- start
	return restartableXrayProcess{ctx: ctx, exit: exit}, nil
}

func (runner *restartableXrayRunner) blockNextStart() (<-chan struct{}, chan<- struct{}) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	runner.nextStartEntered = entered
	runner.nextStartBlock = release
	return entered, release
}

func (runner *restartableXrayRunner) restart(t *testing.T) {
	t.Helper()
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.current == nil {
		t.Fatal("no current Xray process to restart")
	}
	close(runner.current)
	runner.current = nil
}

type restartableXrayProcess struct {
	ctx  context.Context
	exit <-chan struct{}
}

func (process restartableXrayProcess) Wait() error {
	select {
	case <-process.ctx.Done():
		return process.ctx.Err()
	case <-process.exit:
		return errors.New("simulated Xray exit")
	}
}

type restartRehydrateAdapter struct {
	mu          sync.Mutex
	ready       bool
	handlers    map[string]struct{}
	operations  []string
	adds        int
	failAdds    int
	addFailed   chan struct{}
	failureOnce sync.Once
}

func newRestartRehydrateAdapter() *restartRehydrateAdapter {
	return &restartRehydrateAdapter{
		ready:    true,
		handlers: make(map[string]struct{}),
	}
}

func (adapter *restartRehydrateAdapter) AddOutbound(_ context.Context, outbound dataplane.Outbound) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.adds++
	adapter.operations = append(adapter.operations, "add:"+outbound.ID)
	if !adapter.ready {
		return errors.New("simulated Xray API unavailable")
	}
	if adapter.failAdds > 0 {
		adapter.failAdds--
		adapter.failureOnce.Do(func() { close(adapter.addFailed) })
		return errors.New("simulated add failure")
	}
	adapter.handlers[outbound.ID] = struct{}{}
	return nil
}

func (*restartRehydrateAdapter) RouteClient(context.Context, dataplane.ClientRoute) error {
	return errors.New("unexpected per-client route")
}

func (adapter *restartRehydrateAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []dataplane.ClientRoute,
	desired []dataplane.ClientRoute,
	_ []dataplane.ClientRoute,
) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if !adapter.ready {
		return errors.New("simulated Xray API unavailable")
	}
	for _, route := range desired {
		if _, exists := adapter.handlers[route.TCPOutbound]; !route.BlockTCP && !exists {
			return fmt.Errorf("missing TCP outbound %s", route.TCPOutbound)
		}
		if _, exists := adapter.handlers[route.UDPOutbound]; !route.BlockUDP && !exists {
			return fmt.Errorf("missing UDP outbound %s", route.UDPOutbound)
		}
	}
	adapter.operations = append(adapter.operations, "stage", "final")
	return nil
}

func (*restartRehydrateAdapter) DrainOutbound(context.Context, string) error {
	return nil
}

func (adapter *restartRehydrateAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	delete(adapter.handlers, id)
	return nil
}

func (adapter *restartRehydrateAdapter) readiness(context.Context) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if !adapter.ready {
		return errors.New("simulated Xray API unavailable")
	}
	return nil
}

func (adapter *restartRehydrateAdapter) setReady(ready bool) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.ready = ready
}

func (adapter *restartRehydrateAdapter) wipeRuntime() {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.handlers = make(map[string]struct{})
	adapter.operations = nil
}

func (adapter *restartRehydrateAdapter) failNextAdd() <-chan struct{} {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.failAdds++
	adapter.addFailed = make(chan struct{})
	adapter.failureOnce = sync.Once{}
	return adapter.addFailed
}

func (adapter *restartRehydrateAdapter) addAttempts() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.adds
}

func (adapter *restartRehydrateAdapter) operationsSnapshot() []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.operations...)
}

func requireXrayStart(t *testing.T, runner *restartableXrayRunner, want int) {
	t.Helper()
	select {
	case got := <-runner.started:
		if got != want {
			t.Fatalf("Xray start=%d want=%d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("Xray start %d did not occur", want)
	}
}

func requireXrayGeneration(t *testing.T, group *xraySupervisorGroup, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		generation, _ := group.generationState()
		if generation == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	generation, _ := group.generationState()
	t.Fatalf("Xray generation=%d want=%d", generation, want)
}

func requireRehydrateOperations(t *testing.T, operations []string) {
	t.Helper()
	joined := strings.Join(operations, ",")
	for _, want := range []string{"add:live", "stage", "final"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("rehydrate operations=%v missing %q", operations, want)
		}
	}
}

func (runner *blockingRunner) Start(ctx context.Context, executable string, args ...string) (supervisor.Process, error) {
	if runner.executable != nil {
		runner.executable <- executable
	}
	path := args[len(args)-1]
	runner.started <- path
	return waitProcess{
		ctx:          ctx,
		path:         path,
		output:       runner.output,
		finalWritten: runner.finalWritten,
		finished:     runner.finished,
		release:      runner.release,
	}, nil
}

type waitProcess struct {
	ctx          context.Context
	path         string
	output       io.Writer
	finalWritten chan<- string
	finished     chan<- string
	release      <-chan struct{}
}

func (process waitProcess) Wait() error {
	<-process.ctx.Done()
	_, writeErr := fmt.Fprintf(process.output, "final %s\n", process.path)
	process.finalWritten <- process.path
	<-process.release
	process.finished <- process.path
	if writeErr != nil {
		return writeErr
	}
	return process.ctx.Err()
}

type closeTrackingWriter struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	closed    bool
	lateWrite bool
}

func (writer *closeTrackingWriter) Write(body []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		writer.lateWrite = true
		return 0, os.ErrClosed
	}
	return writer.buffer.Write(body)
}

func (writer *closeTrackingWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.closed = true
	return nil
}

func (writer *closeTrackingWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.String()
}

func (writer *closeTrackingWriter) writeAfterClose() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.lateWrite
}

func TestResolveWireGuardEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   string
		portEnv    string
		listenPort int
		want       string
		wantErr    bool
	}{
		{"IP without port with WIREGUARD_PORT", "203.0.113.10", "51820", 0, "203.0.113.10:51820", false},
		{"IP without port with standalone ListenPort", "203.0.113.10", "", 51820, "203.0.113.10:51820", false},
		{"IP without port with default fallback", "203.0.113.10", "", 0, "203.0.113.10:51820", false},
		{"explicit IPv4 port preserved", "203.0.113.10:51822", "51820", 0, "203.0.113.10:51822", false},
		{"explicit IPv6 port with brackets preserved", "[2001:db8::1]:51822", "51820", 0, "[2001:db8::1]:51822", false},
		{"IPv6 without port normalized with brackets", "2001:db8::1", "51820", 0, "[2001:db8::1]:51820", false},
		{"bracketed IPv6 without port normalized", "[2001:db8::1]", "51820", 0, "[2001:db8::1]:51820", false},
		{"empty endpoint returns empty", "", "51820", 0, "", false},
		{"reject invalid WIREGUARD_PORT zero", "203.0.113.10", "0", 0, "", true},
		{"reject invalid WIREGUARD_PORT out of range", "203.0.113.10", "70000", 0, "", true},
		{"reject invalid WIREGUARD_PORT non-numeric", "203.0.113.10", "abc", 0, "", true},
		{"reject invalid endpoint port zero", "203.0.113.10:0", "51820", 0, "", true},
		{"reject invalid endpoint port out of range", "203.0.113.10:70000", "51820", 0, "", true},
		{"reject invalid endpoint port non-numeric", "203.0.113.10:abc", "51820", 0, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WIREGUARD_ENDPOINT", tc.endpoint)
			if tc.portEnv != "" {
				t.Setenv("WIREGUARD_PORT", tc.portEnv)
			} else {
				_ = os.Unsetenv("WIREGUARD_PORT")
			}
			cfg := config.WireGuardConfig{
				ListenPort: tc.listenPort,
			}
			got, err := resolveWireGuardEndpoint(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveWireGuardEndpoint() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveWireGuardEndpoint() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolveWireGuardEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunAgentRejectsMalformedEndpointBeforeSideEffects(t *testing.T) {
	t.Setenv("WIREGUARD_ENDPOINT", "203.0.113.10:0")
	cfg := config.Defaults()
	err := runAgent(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "endpoint port") {
		t.Fatalf("runAgent() error=%v, want endpoint port validation before startup", err)
	}
}
