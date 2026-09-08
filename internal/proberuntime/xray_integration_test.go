//go:build xrayintegration && linux

package proberuntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/socks5"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

const (
	realXrayProbeAPI   = "127.0.0.1:22086"
	realXrayProbeSOCKS = "127.0.0.1:22080"
	realXrayMainSOCKS  = "127.0.0.1:22081"
	realXrayTestUser   = "11111111-1111-4111-8111-111111111111"
)

func TestRealXrayProbeRuntimeStabilizes(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("HYDRAT_XRAY_BINARY"))
	if binary == "" {
		t.Fatal("HYDRAT_XRAY_BINARY is required")
	}
	testCtx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	fixture := startRealXrayFixture(t, testCtx, binary)
	samples := fixture.RunChurn(t, 520, []string{"raw", "ws", "xhttp"})
	final := fixture.runtime.Snapshot()
	wantFinal := Snapshot{
		Status:            "ready",
		Epoch:             3,
		RSSBytes:          final.RSSBytes,
		FDCount:           final.FDCount,
		CompletedProbes:   20,
		RecycleCount:      2,
		LastRecycleReason: reasonProbeLimit,
	}
	if final != wantFinal {
		t.Fatalf("final snapshot=%+v, want %+v", final, wantFinal)
	}
	if len(samples) == 0 {
		t.Fatal("resource sample series is empty")
	}
	if samples[len(samples)-1] != final {
		t.Fatalf("last resource sample=%+v, want final snapshot %+v", samples[len(samples)-1], final)
	}
	if err := fixture.noPendingRecycle(); err != nil {
		t.Fatal(err)
	}
	for _, sample := range samples {
		if sample.RSSBytes <= 0 || sample.FDCount <= 0 {
			t.Fatalf("runtime metrics missing: %+v", sample)
		}
		if sample.RSSBytes >= 256<<20 || sample.FDCount >= 512 {
			t.Fatalf("runtime threshold breached: %+v", sample)
		}
	}
	if fixture.metrics.failures.Load() != 0 {
		t.Fatalf("production metric read failures=%d", fixture.metrics.failures.Load())
	}
	if fixture.OldEpochMutations() != 0 || fixture.ActiveProbeSOCKS() != 0 {
		t.Fatalf(
			"stale mutations=%d socks=%d",
			fixture.OldEpochMutations(),
			fixture.ActiveProbeSOCKS(),
		)
	}
	if fixture.mainFreedomChecks != fixture.Epochs()-1 {
		t.Fatalf(
			"main-Xray freedom checks=%d, want one for each of %d recycles",
			fixture.mainFreedomChecks,
			fixture.Epochs()-1,
		)
	}
	pendingArrivals, unexpectedArrivals := fixture.originArrivals.counts()
	if confirmed := fixture.originConfirmed.Load(); confirmed != 520 ||
		fixture.heldConfirmed.Load() != 2 ||
		pendingArrivals != 0 || unexpectedArrivals != 0 {
		t.Fatalf(
			"origin confirmed=%d held=%d pending=%d unexpected=%d, want 520/2/0/0",
			confirmed,
			fixture.heldConfirmed.Load(),
			pendingArrivals,
			unexpectedArrivals,
		)
	}
	t.Logf(
		"summary probes=520 epochs=%d recycles=%d samples=%d stale_mutations=%d active_probe_socks=%d main_freedom_checks=%d origin_confirmed=%d held_origin_confirmed=%d",
		fixture.Epochs(),
		fixture.runtime.Snapshot().RecycleCount,
		len(samples),
		fixture.OldEpochMutations(),
		fixture.ActiveProbeSOCKS(),
		fixture.mainFreedomChecks,
		fixture.originConfirmed.Load(),
		fixture.heldConfirmed.Load(),
	)
}

func TestRealXrayCriticalActiveLaneReachesHeldOriginAcrossAllFortyEightSlots(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("HYDRAT_XRAY_BINARY"))
	if binary == "" {
		t.Fatal("HYDRAT_XRAY_BINARY is required")
	}
	const (
		slots             = 48
		activeAPI         = "127.0.0.1:10087"
		activeSOCKSPort   = 12080
		observationWindow = 625 * time.Millisecond
	)
	testCtx, cancelTest := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTest()

	raw := startRealXrayChild(
		t, binary, filepath.Join("testdata", "server-raw.json"), "active raw VLESS",
	)
	defer raw.stop(t)
	waitForRealXrayTCP(t, raw, "127.0.0.1:22001", 8*time.Second)
	active := startRealXrayChild(
		t, binary, filepath.Join("..", "..", "config", "xray", "active.json"),
		"dedicated active",
	)
	defer active.stop(t)
	waitForRealXrayTCP(t, active, activeAPI, 8*time.Second)
	waitForRealXrayTCP(t, active, "127.0.0.1:12080", 8*time.Second)
	waitForRealXrayTCP(t, active, "127.0.0.1:12127", 8*time.Second)

	type arrival struct {
		slot int
		at   time.Time
	}
	arrivals := make(chan arrival, slots)
	releaseOrigin := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		var slot int
		if _, err := fmt.Sscanf(request.URL.Path, "/hold/%d", &slot); err != nil {
			http.Error(response, "invalid slot", http.StatusBadRequest)
			return
		}
		arrivals <- arrival{slot: slot, at: time.Now()}
		select {
		case <-releaseOrigin:
			response.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
	}))
	defer origin.Close()

	outbound, err := realXrayOutbound("raw")
	if err != nil {
		t.Fatal(err)
	}
	control := probexray.New(binary, activeAPI, slots, xrayapi.ExecRunner{})
	const epoch = uint64(1)
	control.Reset(epoch)

	type setupOutcome struct {
		slot    int
		elapsed time.Duration
		err     error
	}
	setupCtx, cancelSetup := context.WithTimeout(testCtx, 10*time.Second)
	defer cancelSetup()
	setupBarrier := make(chan struct{})
	setupResults := make(chan setupOutcome, slots)
	var setupReady sync.WaitGroup
	setupReady.Add(slots)
	for slot := 0; slot < slots; slot++ {
		slot := slot
		go func() {
			setupReady.Done()
			<-setupBarrier
			started := time.Now()
			probeRange := probexray.NewPriorityRange(control, slot, 1)
			err := probeRange.ConfigureEpoch(setupCtx, epoch, []probexray.SlotCandidate{{
				Slot: 0, Config: outbound,
			}})
			setupResults <- setupOutcome{slot: slot, elapsed: time.Since(started), err: err}
		}()
	}
	setupReady.Wait()
	close(setupBarrier)
	setupElapsed := make([]time.Duration, slots)
	var setupDiagnostics strings.Builder
	for range slots {
		item := <-setupResults
		setupElapsed[item.slot] = item.elapsed
		if item.err != nil {
			fmt.Fprintf(
				&setupDiagnostics, "slot=%02d setup=%s err=%v\n",
				item.slot, item.elapsed, item.err,
			)
		}
	}
	if setupDiagnostics.Len() > 0 {
		t.Fatalf(
			"failed to prewarm all dedicated active routes within setup timeout\n%sactive Xray: %s\nraw Xray: %s",
			setupDiagnostics.String(), active.output.String(), raw.output.String(),
		)
	}

	type outcome struct {
		slot      int
		stage     string
		completed time.Time
		elapsed   time.Duration
		err       error
	}
	startBarrier := make(chan struct{})
	results := make(chan outcome, slots)
	tracker := &connectionTracker{}
	var ready sync.WaitGroup
	ready.Add(slots)
	var startedAt, absoluteDeadline time.Time
	for slot := 0; slot < slots; slot++ {
		slot := slot
		go func() {
			ready.Done()
			<-startBarrier
			probeCtx, cancelProbe := context.WithDeadline(testCtx, absoluteDeadline)
			defer cancelProbe()
			client := realXrayHTTPClient(
				fmt.Sprintf("127.0.0.1:%d", activeSOCKSPort+slot), tracker,
			)
			defer client.CloseIdleConnections()
			request, err := http.NewRequestWithContext(
				probeCtx, http.MethodGet, fmt.Sprintf("%s/hold/%d", origin.URL, slot), nil,
			)
			if err != nil {
				completed := time.Now()
				results <- outcome{
					slot: slot, stage: "request-build", completed: completed,
					elapsed: completed.Sub(startedAt), err: err,
				}
				return
			}
			response, err := client.Do(request)
			if response != nil {
				_ = response.Body.Close()
			}
			stage := "complete"
			if err != nil {
				stage = "request"
			} else if response.StatusCode != http.StatusNoContent {
				stage = "status"
				err = fmt.Errorf("status=%d", response.StatusCode)
			}
			completed := time.Now()
			results <- outcome{
				slot: slot, stage: stage, completed: completed,
				elapsed: completed.Sub(startedAt), err: err,
			}
		}()
	}
	ready.Wait()
	startedAt = time.Now()
	absoluteDeadline = startedAt.Add(observationWindow)
	close(startBarrier)

	arrivedAt := make([]time.Time, slots)
	deadlineTimer := time.NewTimer(time.Until(absoluteDeadline))
	allArrived := false
	for arrived := 0; arrived < slots; {
		select {
		case item := <-arrivals:
			if item.slot >= 0 && item.slot < slots && arrivedAt[item.slot].IsZero() &&
				!item.at.After(absoluteDeadline) {
				arrivedAt[item.slot] = item.at
				arrived++
			}
			if arrived == slots {
				allArrived = true
			}
		case <-deadlineTimer.C:
			arrived = slots
		}
		if allArrived {
			if !deadlineTimer.Stop() {
				<-deadlineTimer.C
			}
			break
		}
	}
	close(releaseOrigin)

	outcomes := make([]outcome, slots)
	for range slots {
		item := <-results
		outcomes[item.slot] = item
	}
	for {
		select {
		case item := <-arrivals:
			if item.slot >= 0 && item.slot < slots && arrivedAt[item.slot].IsZero() &&
				!item.at.After(absoluteDeadline) {
				arrivedAt[item.slot] = item.at
			}
		default:
			goto arrivalsDrained
		}
	}

arrivalsDrained:
	arrived := 0
	completed := 0
	var diagnostics strings.Builder
	for slot, item := range outcomes {
		if !arrivedAt[slot].IsZero() {
			arrived++
		}
		if item.err == nil && item.stage == "complete" && !item.completed.After(absoluteDeadline) {
			completed++
		}
		fmt.Fprintf(
			&diagnostics,
			"slot=%02d arrived=%t stage=%s setup=%s elapsed=%s within-window=%t err=%v\n",
			slot, !arrivedAt[slot].IsZero(), item.stage,
			setupElapsed[slot], item.elapsed, !item.completed.After(absoluteDeadline), item.err,
		)
	}
	if arrived != slots || completed != slots {
		t.Fatalf(
			"dedicated active lane within %s: arrivals=%d/%d HTTP outcomes=%d/%d\n%sactive Xray: %s\nraw Xray: %s",
			observationWindow, arrived, slots, completed, slots, diagnostics.String(),
			active.output.String(), raw.output.String(),
		)
	}
	if !tracker.waitZero(3 * time.Second) {
		t.Fatalf("active probe SOCKS connections=%d after successful burst", tracker.active.Load())
	}
}

type realXrayFixture struct {
	ctx               context.Context
	binary            string
	origin            *httptest.Server
	originArrivals    *originArrivalRegistry
	originConfirmed   atomic.Uint64
	heldConfirmed     atomic.Uint64
	children          []*realXrayChild
	main              *realXrayChild
	control           *probexray.Control
	runner            *epochRecordingRunner
	metrics           *recordingRealXrayMetrics
	runtime           *Manager
	probeConnections  connectionTracker
	skipEpochReset    bool
	mainFreedomChecks uint64
}

func startRealXrayFixture(
	t *testing.T,
	ctx context.Context,
	binary string,
) *realXrayFixture {
	t.Helper()
	if info, err := os.Stat(binary); err != nil {
		t.Fatalf("stat Xray binary: %v", err)
	} else if info.Mode()&0o111 == 0 {
		t.Fatalf("Xray binary %s is not executable", binary)
	}

	fixture := &realXrayFixture{
		ctx:            ctx,
		binary:         binary,
		originArrivals: newOriginArrivalRegistry(),
	}
	fixture.origin = httptest.NewServer(http.HandlerFunc(fixture.serveOrigin))
	t.Cleanup(func() { fixture.close(t) })

	for _, server := range []struct {
		name, config, address string
	}{
		{name: "raw", config: "server-raw.json", address: "127.0.0.1:22001"},
		{name: "ws", config: "server-ws.json", address: "127.0.0.1:22002"},
		{name: "xhttp", config: "server-xhttp.json", address: "127.0.0.1:22003"},
	} {
		child := startRealXrayChild(
			t,
			binary,
			filepath.Join("testdata", server.config),
			"VLESS "+server.name,
		)
		fixture.children = append(fixture.children, child)
		waitForRealXrayTCP(t, child, server.address, 8*time.Second)
	}

	mainConfig := filepath.Join(t.TempDir(), "main-freedom.json")
	mainJSON := `{
  "log":{"access":"none","loglevel":"warning"},
  "inbounds":[{
    "tag":"main-socks",
    "listen":"127.0.0.1",
    "port":22081,
    "protocol":"socks",
    "settings":{"auth":"noauth","udp":false}
  }],
  "outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}],
  "routing":{"rules":[{
    "type":"field",
    "inboundTag":["main-socks"],
    "outboundTag":"direct"
  }]}
}`
	if err := os.WriteFile(mainConfig, []byte(mainJSON), 0o600); err != nil {
		t.Fatalf("write main-Xray fixture: %v", err)
	}
	fixture.main = startRealXrayChild(t, binary, mainConfig, "main freedom")
	waitForRealXrayTCP(t, fixture.main, realXrayMainSOCKS, 8*time.Second)
	if err := fixture.freedomRequest(ctx); err != nil {
		t.Fatalf("initial main-Xray freedom request: %v", err)
	}

	fixture.skipEpochReset = os.Getenv("HYDRAT_XRAY_STRESS_SKIP_EPOCH_RESET") == "1"
	fixture.runner = &epochRecordingRunner{delegate: xrayapi.ExecRunner{}}
	fixture.control = probexray.New(binary, realXrayProbeAPI, 1, fixture.runner)
	fixture.metrics = &recordingRealXrayMetrics{delegate: procMetricsReader{}}
	resetter := &realXrayResetter{
		control: fixture.control,
		runner:  fixture.runner,
		skip:    fixture.skipEpochReset,
	}
	runtime, err := New(Config{
		Binary:           binary,
		ConfigPath:       filepath.Join("testdata", "probe.json"),
		APIAddress:       realXrayProbeAPI,
		MaxProbes:        250,
		MaxRSSBytes:      256 << 20,
		MaxFDs:           512,
		DrainTimeout:     2 * time.Second,
		StopTimeout:      3 * time.Second,
		ReadinessTimeout: 8 * time.Second,
	}, resetter, withMetricsReader(fixture.metrics))
	if err != nil {
		t.Fatalf("construct probe runtime: %v", err)
	}
	fixture.runtime = runtime
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("start probe runtime: %v", err)
	}
	return fixture
}

func (fixture *realXrayFixture) RunChurn(
	t *testing.T,
	completed int,
	transports []string,
) []Snapshot {
	t.Helper()
	if completed < 520 {
		t.Fatalf("completed probe target=%d, want at least 520", completed)
	}
	if strings.Join(transports, ",") != "raw,ws,xhttp" {
		t.Fatalf("transports=%v, want raw, ws, xhttp", transports)
	}
	endpoints := []string{"ok", "slow", "cancel", "abort"}
	samples := make([]Snapshot, 0, completed/10)
	observedEpoch := fixture.Epochs()
	var sampledMetricReads uint64

	for probeNumber := 1; probeNumber <= completed; probeNumber++ {
		transport := transports[(probeNumber-1)%len(transports)]
		var held *heldRealXrayProbe
		if probeNumber == 250 || probeNumber == 500 {
			held = fixture.startHeldCancellation(t, transport)
		}

		outcome := fixture.runProbe(
			t,
			endpoints[(probeNumber-1)%len(endpoints)],
			transport,
		)
		if outcome.err != nil {
			for _, child := range fixture.children {
				t.Logf("%s Xray diagnostics: %s", child.name, child.output.String())
			}
			if outcome.stage == "configure" && outcome.epoch > observedEpoch {
				if !fixture.skipEpochReset || probeNumber != 251 ||
					observedEpoch != 1 || outcome.epoch != 2 {
					t.Fatalf(
						"unexpected post-recycle outbound failure: probe=%d observed_epoch=%d outcome=%+v",
						probeNumber,
						observedEpoch,
						outcome,
					)
				}
				if !errors.Is(outcome.err, probexray.ErrStaleEpoch) {
					t.Fatalf(
						"first post-recycle configure error=%v, want stale epoch sentinel",
						outcome.err,
					)
				}
				t.Fatalf(
					"first post-recycle outbound assertion: epoch=%d transport=%s: %v",
					outcome.epoch,
					transport,
					outcome.err,
				)
			}
			t.Fatalf(
				"probe=%d epoch=%d transport=%s endpoint=%s stage=%s: %v",
				probeNumber,
				outcome.epoch,
				transport,
				endpoints[(probeNumber-1)%len(endpoints)],
				outcome.stage,
				outcome.err,
			)
		}
		observedEpoch = outcome.epoch

		if probeNumber%10 == 0 {
			sample := fixture.runtime.Snapshot()
			metricReads := fixture.metrics.successes.Load()
			if metricReads-sampledMetricReads < 10 {
				t.Fatalf(
					"fresh production metric reads=%d over probes %d-%d, want at least 10",
					metricReads-sampledMetricReads,
					probeNumber-9,
					probeNumber,
				)
			}
			sampledMetricReads = metricReads
			samples = append(samples, sample)
			t.Logf(
				"sample completed=%d status=%s epoch=%d epoch_completed=%d recycles=%d rss_bytes=%d fds=%d reason=%s",
				probeNumber,
				sample.Status,
				sample.Epoch,
				sample.CompletedProbes,
				sample.RecycleCount,
				sample.RSSBytes,
				sample.FDCount,
				sample.LastRecycleReason,
			)
		}

		if held != nil {
			fixture.verifyRecycle(t, held, probeNumber)
		}
	}
	if len(samples) != completed/10 {
		t.Fatalf("resource samples=%d, want %d", len(samples), completed/10)
	}
	if !fixture.probeConnections.waitZero(3 * time.Second) {
		t.Fatalf("active probe SOCKS connections=%d", fixture.ActiveProbeSOCKS())
	}
	return samples
}

type probeOutcome struct {
	epoch uint64
	stage string
	err   error
}

func (fixture *realXrayFixture) runProbe(
	t *testing.T,
	endpoint, transport string,
) probeOutcome {
	t.Helper()
	acquireCtx, acquireCancel := context.WithTimeout(fixture.ctx, 10*time.Second)
	defer acquireCancel()
	lease, err := fixture.runtime.Acquire(acquireCtx)
	if err != nil {
		return probeOutcome{stage: "acquire", err: err}
	}
	outcome := probeOutcome{epoch: lease.Epoch}
	probeRange := probexray.NewRange(fixture.control, 0, 1)
	outbound, err := realXrayOutbound(transport)
	if err != nil {
		fixture.runtime.Release(lease, nil)
		outcome.stage, outcome.err = "outbound", err
		return outcome
	}
	configureCtx, configureCancel := context.WithTimeout(
		withExpectedEpoch(lease.Context, lease.Epoch),
		5*time.Second,
	)
	err = probeRange.ConfigureEpoch(configureCtx, lease.Epoch, []probexray.SlotCandidate{{
		Slot: 0, Config: outbound,
	}})
	configureCancel()
	if err != nil {
		fixture.runtime.Release(lease, nil)
		outcome.stage, outcome.err = "configure", err
		return outcome
	}

	requestErr := fixture.requestThroughProbe(lease.Context, endpoint)
	cleanupCtx, cleanupCancel := context.WithTimeout(
		withExpectedEpoch(context.Background(), lease.Epoch),
		5*time.Second,
	)
	clearErr := probeRange.ClearEpoch(cleanupCtx, lease.Epoch)
	cleanupCancel()
	fixture.runtime.Release(lease, clearErr)
	if clearErr != nil {
		outcome.stage, outcome.err = "cleanup", clearErr
		return outcome
	}
	if requestErr != nil {
		outcome.stage, outcome.err = "request", requestErr
	}
	return outcome
}

func (fixture *realXrayFixture) requestThroughProbe(
	parent context.Context,
	endpoint string,
) (resultErr error) {
	defer func() {
		if resultErr == nil {
			fixture.originConfirmed.Add(1)
		}
	}()
	client := realXrayHTTPClient(realXrayProbeSOCKS, &fixture.probeConnections)
	defer client.CloseIdleConnections()

	switch endpoint {
	case "cancel":
		return fixture.requestCanceledAtOrigin(parent, client)
	case "abort":
		return fixture.requestAbortedAtOrigin(parent, client)
	}
	request, err := http.NewRequestWithContext(
		parent,
		http.MethodGet,
		fixture.origin.URL+"/"+endpoint,
		nil,
	)
	if err != nil {
		return err
	}
	response, requestErr := client.Do(request)
	if requestErr != nil && response != nil {
		_ = response.Body.Close()
	}
	if requestErr != nil {
		return requestErr
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}
	return nil
}

type realXrayHTTPResult struct {
	response *http.Response
	err      error
}

func (fixture *realXrayFixture) requestCanceledAtOrigin(
	parent context.Context,
	client *http.Client,
) error {
	requestCtx, cancel := context.WithCancel(parent)
	defer cancel()
	arrival := fixture.originArrivals.register("/cancel")
	defer fixture.originArrivals.retire(arrival)
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		fixture.origin.URL+"/cancel?ack="+arrival.id,
		nil,
	)
	if err != nil {
		return err
	}
	done := runRealXrayHTTPRequest(client, request)
	if err := waitForOriginArrival(arrival, 3*time.Second); err != nil {
		cancelAndDrainRealXrayHTTPResult(cancel, done)
		return err
	}
	if err := parent.Err(); err != nil {
		cancel()
		return fmt.Errorf("cancel parent ended before explicit cancellation: %w", err)
	}
	cancel()
	result, err := waitForRealXrayHTTPResult(done, 3*time.Second)
	if err != nil {
		return err
	}
	closeRealXrayHTTPResponse(result.response)
	if result.err == nil {
		return errors.New("cancel endpoint unexpectedly completed")
	}
	if !errors.Is(result.err, context.Canceled) ||
		!errors.Is(requestCtx.Err(), context.Canceled) {
		return fmt.Errorf(
			"cancel request error=%v context=%v, want context canceled",
			result.err,
			requestCtx.Err(),
		)
	}
	return nil
}

func (fixture *realXrayFixture) requestAbortedAtOrigin(
	parent context.Context,
	client *http.Client,
) error {
	requestCtx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	arrival := fixture.originArrivals.register("/abort")
	defer fixture.originArrivals.retire(arrival)
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		fixture.origin.URL+"/abort?ack="+arrival.id,
		nil,
	)
	if err != nil {
		return err
	}
	done := runRealXrayHTTPRequest(client, request)
	if err := waitForOriginArrival(arrival, 3*time.Second); err != nil {
		cancelAndDrainRealXrayHTTPResult(cancel, done)
		return err
	}
	result, err := waitForRealXrayHTTPResult(done, 3*time.Second)
	if err != nil {
		return err
	}
	closeRealXrayHTTPResponse(result.response)
	if result.err == nil {
		return errors.New("abort endpoint unexpectedly returned an HTTP response")
	}
	if requestCtx.Err() != nil {
		return fmt.Errorf("abort request context ended: %v, request error=%w", requestCtx.Err(), result.err)
	}
	if !errors.Is(result.err, io.EOF) {
		return fmt.Errorf("abort request error=%w, want EOF", result.err)
	}
	return nil
}

func runRealXrayHTTPRequest(
	client *http.Client,
	request *http.Request,
) <-chan realXrayHTTPResult {
	done := make(chan realXrayHTTPResult, 1)
	go func() {
		response, err := client.Do(request)
		done <- realXrayHTTPResult{response: response, err: err}
	}()
	return done
}

func waitForRealXrayHTTPResult(
	done <-chan realXrayHTTPResult,
	timeout time.Duration,
) (realXrayHTTPResult, error) {
	select {
	case result := <-done:
		return result, nil
	case <-time.After(timeout):
		return realXrayHTTPResult{}, errors.New("timed out waiting for loopback HTTP result")
	}
}

func waitForOriginArrival(
	arrival *originArrivalAck,
	timeout time.Duration,
) error {
	select {
	case endpoint := <-arrival.arrived:
		if endpoint != arrival.endpoint {
			return fmt.Errorf(
				"origin arrival %s endpoint=%q, want %q",
				arrival.id,
				endpoint,
				arrival.endpoint,
			)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("origin arrival %s timed out after %s", arrival.id, timeout)
	}
}

func closeRealXrayHTTPResponse(response *http.Response) {
	if response != nil {
		_ = response.Body.Close()
	}
}

func cancelAndDrainRealXrayHTTPResult(
	cancel context.CancelFunc,
	done <-chan realXrayHTTPResult,
) {
	cancel()
	select {
	case result := <-done:
		closeRealXrayHTTPResponse(result.response)
	case <-time.After(time.Second):
	}
}

func (fixture *realXrayFixture) startHeldCancellation(
	t *testing.T,
	transport string,
) *heldRealXrayProbe {
	t.Helper()
	leaseParent, leaseParentCancel := context.WithCancel(fixture.ctx)
	lease, err := fixture.runtime.Acquire(leaseParent)
	if err != nil {
		leaseParentCancel()
		t.Fatalf("acquire held cancellation lease: %v", err)
	}
	probeRange := probexray.NewRange(fixture.control, 0, 1)
	outbound, err := realXrayOutbound(transport)
	if err != nil {
		fixture.runtime.Release(lease, nil)
		leaseParentCancel()
		t.Fatal(err)
		return nil
	}
	configureCtx, configureCancel := context.WithTimeout(
		withExpectedEpoch(lease.Context, lease.Epoch),
		5*time.Second,
	)
	err = probeRange.ConfigureEpoch(configureCtx, lease.Epoch, []probexray.SlotCandidate{{
		Slot: 0, Config: outbound,
	}})
	configureCancel()
	if err != nil {
		fixture.runtime.Release(lease, nil)
		leaseParentCancel()
		t.Fatalf("configure held cancellation epoch=%d: %v", lease.Epoch, err)
	}

	client := realXrayHTTPClient(realXrayProbeSOCKS, &fixture.probeConnections)
	requestCtx, requestCancel := context.WithCancelCause(lease.Context)
	arrival := fixture.originArrivals.register("/cancel")
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		fixture.origin.URL+"/cancel?ack="+arrival.id,
		nil,
	)
	if err != nil {
		requestCancel(context.Canceled)
		fixture.originArrivals.retire(arrival)
		client.CloseIdleConnections()
		fixture.runtime.Release(lease, nil)
		leaseParentCancel()
		t.Fatal(err)
		return nil
	}
	done := runRealXrayHTTPRequest(client, request)
	if err := waitForOriginArrival(arrival, 5*time.Second); err != nil {
		cancelAndDrainRealXrayHTTPResult(
			func() { requestCancel(context.Canceled) },
			done,
		)
		fixture.originArrivals.retire(arrival)
		client.CloseIdleConnections()
		fixture.runtime.Release(lease, nil)
		leaseParentCancel()
		t.Fatal(err)
		return nil
	}
	fixture.originArrivals.retire(arrival)
	fixture.heldConfirmed.Add(1)
	select {
	case result := <-done:
		closeRealXrayHTTPResponse(result.response)
		requestCancel(context.Canceled)
		client.CloseIdleConnections()
		fixture.runtime.Release(lease, nil)
		leaseParentCancel()
		t.Fatalf("held cancellation ended before recycle: %v", result.err)
		return nil
	default:
	}
	return &heldRealXrayProbe{
		lease:        lease,
		probeRange:   probeRange,
		client:       client,
		requestCtx:   requestCtx,
		cancel:       requestCancel,
		parentCancel: leaseParentCancel,
		done:         done,
	}
}

type heldRealXrayProbe struct {
	lease        *Lease
	probeRange   *probexray.Range
	client       *http.Client
	requestCtx   context.Context
	cancel       context.CancelCauseFunc
	parentCancel context.CancelFunc
	done         <-chan realXrayHTTPResult
}

func (fixture *realXrayFixture) verifyRecycle(
	t *testing.T,
	held *heldRealXrayProbe,
	probeNumber int,
) {
	t.Helper()
	oldEpoch := held.lease.Epoch
	expectedOldEpoch := uint64(probeNumber / 250)
	if probeNumber%250 != 0 || oldEpoch != expectedOldEpoch {
		t.Fatalf(
			"recycle trigger probe=%d old_epoch=%d, want production threshold epoch=%d",
			probeNumber,
			oldEpoch,
			expectedOldEpoch,
		)
	}
	fixture.waitForState(t, func(snapshot Snapshot) bool {
		return snapshot.Epoch == oldEpoch && snapshot.Status == "draining"
	}, "probe runtime to begin draining")
	draining := fixture.runtime.Snapshot()
	if draining.CompletedProbes != 250 ||
		draining.LastRecycleReason != reasonProbeLimit {
		t.Fatalf(
			"recycle trigger snapshot=%+v, want 250 completed probes and probe_limit",
			draining,
		)
	}

	if err := validateHeldRequestPending(held.requestCtx, held.done); err != nil {
		t.Fatalf("held probe epoch=%d before explicit cancellation: %v", oldEpoch, err)
	}
	if !fixture.leaseActive(held.lease) {
		t.Fatalf("held probe epoch=%d lease released before explicit cancellation", oldEpoch)
	}
	held.cancel(explicitHeldCancelCause)
	result, resultErr := waitForRealXrayHTTPResult(held.done, 5*time.Second)
	if resultErr != nil {
		t.Fatalf("held probe epoch=%d cancellation result: %v", oldEpoch, resultErr)
	}
	closeRealXrayHTTPResponse(result.response)
	if err := validateExplicitHeldCancellation(result.err, held.requestCtx); err != nil {
		t.Fatalf("held probe epoch=%d cancellation: %v", oldEpoch, err)
	}
	mainChecks := fixture.startMainFreedomChecks()
	fixture.waitForMainFreedomCount(t, mainChecks, 1)
	drainCheck := fixture.runtime.Snapshot()
	if drainCheck.Epoch != oldEpoch || drainCheck.Status != "draining" {
		mainChecks.cancel()
		<-mainChecks.done
		t.Fatalf(
			"main-Xray freedom check missed drain window: snapshot=%+v",
			drainCheck,
		)
	}
	if !fixture.leaseActive(held.lease) {
		mainChecks.cancel()
		<-mainChecks.done
		t.Fatalf("held probe epoch=%d lease released before main drain check", oldEpoch)
	}
	fixture.waitForState(t, func(snapshot Snapshot) bool {
		return snapshot.Epoch == oldEpoch+1 && snapshot.Status == "ready"
	}, "probe runtime replacement epoch")
	replacement := fixture.runtime.Snapshot()
	if replacement.RecycleCount != oldEpoch ||
		replacement.LastRecycleReason != reasonProbeLimit {
		t.Fatalf(
			"replacement snapshot=%+v, want recycle_count=%d and probe_limit",
			replacement,
			oldEpoch,
		)
	}
	fixture.finishMainFreedomChecks(t, oldEpoch, mainChecks)
	fixture.mainFreedomChecks++

	held.client.CloseIdleConnections()
	cleanupCtx, cleanupCancel := context.WithTimeout(
		withExpectedEpoch(context.Background(), oldEpoch),
		5*time.Second,
	)
	clearErr := held.probeRange.ClearEpoch(cleanupCtx, oldEpoch)
	cleanupCancel()
	fixture.runtime.Release(held.lease, clearErr)
	held.parentCancel()
	if fixture.skipEpochReset {
		if clearErr != nil {
			t.Fatalf("pre-fix old epoch %d cleanup error=%v, want nil", oldEpoch, clearErr)
		}
	} else if !errors.Is(clearErr, probexray.ErrStaleEpoch) {
		t.Fatalf("old epoch %d cleanup error=%v, want stale epoch", oldEpoch, clearErr)
	}
	if !fixture.probeConnections.waitZero(3 * time.Second) {
		t.Fatalf(
			"probe SOCKS connections after recycle %d=%d",
			oldEpoch,
			fixture.ActiveProbeSOCKS(),
		)
	}
	t.Logf(
		"recycle old_epoch=%d new_epoch=%d main_freedom=ok held_cancel=ok stale_mutations=%d active_probe_socks=%d",
		oldEpoch,
		fixture.Epochs(),
		fixture.OldEpochMutations(),
		fixture.ActiveProbeSOCKS(),
	)
}

func (fixture *realXrayFixture) waitForState(
	t *testing.T,
	accept func(Snapshot) bool,
	description string,
) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := fixture.runtime.Snapshot()
		if accept(snapshot) {
			return
		}
		select {
		case <-fixture.ctx.Done():
			t.Fatalf("%s: %v snapshot=%+v", description, fixture.ctx.Err(), snapshot)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("%s timed out: snapshot=%+v", description, fixture.runtime.Snapshot())
}

func (fixture *realXrayFixture) serveOrigin(
	response http.ResponseWriter,
	request *http.Request,
) {
	switch request.URL.Path {
	case "/ok":
		response.WriteHeader(http.StatusNoContent)
	case "/slow":
		select {
		case <-time.After(15 * time.Millisecond):
			response.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
	case "/cancel":
		if !fixture.originArrivals.signal(
			request.URL.Query().Get("ack"),
			request.URL.Path,
		) {
			http.Error(response, "unregistered cancel request", http.StatusConflict)
			return
		}
		<-request.Context().Done()
	case "/abort":
		if !fixture.originArrivals.signal(
			request.URL.Query().Get("ack"),
			request.URL.Path,
		) {
			http.Error(response, "unregistered abort request", http.StatusConflict)
			return
		}
		hijacker, ok := response.(http.Hijacker)
		if !ok {
			panic("loopback origin does not support hijacking")
		}
		connection, _, err := hijacker.Hijack()
		if err == nil {
			_ = connection.Close()
		}
	default:
		http.NotFound(response, request)
	}
}

func (fixture *realXrayFixture) freedomRequest(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := realXrayHTTPClient(realXrayMainSOCKS, nil)
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		fixture.origin.URL+"/ok",
		nil,
	)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, readErr := io.Copy(io.Discard, response.Body)
	if readErr != nil {
		return readErr
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}
	return nil
}

type mainFreedomLoop struct {
	cancel context.CancelFunc
	checks atomic.Uint64
	done   chan error
}

func (fixture *realXrayFixture) startMainFreedomChecks() *mainFreedomLoop {
	ctx, cancel := context.WithCancel(fixture.ctx)
	loop := &mainFreedomLoop{cancel: cancel, done: make(chan error, 1)}
	go func() {
		for {
			if err := ctx.Err(); err != nil {
				loop.done <- nil
				return
			}
			if err := fixture.freedomRequest(ctx); err != nil {
				if ctx.Err() != nil {
					loop.done <- nil
				} else {
					loop.done <- err
				}
				return
			}
			loop.checks.Add(1)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return loop
}

func (fixture *realXrayFixture) finishMainFreedomChecks(
	t *testing.T,
	oldEpoch uint64,
	loop *mainFreedomLoop,
) {
	t.Helper()
	beforePostRecycle := loop.checks.Load()
	fixture.waitForMainFreedomCount(t, loop, beforePostRecycle+1)
	loop.cancel()
	select {
	case err := <-loop.done:
		if err != nil {
			t.Fatalf("main-Xray freedom request across recycle %d: %v", oldEpoch, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("main-Xray freedom loop did not stop after recycle %d", oldEpoch)
	}
}

func (fixture *realXrayFixture) waitForMainFreedomCount(
	t *testing.T,
	loop *mainFreedomLoop,
	want uint64,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if loop.checks.Load() >= want {
			return
		}
		select {
		case err := <-loop.done:
			t.Fatalf("main-Xray freedom loop ended at %d checks: %v", loop.checks.Load(), err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	loop.cancel()
	select {
	case <-loop.done:
	case <-time.After(5 * time.Second):
	}
	t.Fatalf("main-Xray freedom checks=%d, want at least %d", loop.checks.Load(), want)
}

func (fixture *realXrayFixture) Epochs() uint64 {
	return fixture.runtime.Snapshot().Epoch
}

func (fixture *realXrayFixture) noPendingRecycle() error {
	fixture.runtime.mu.Lock()
	defer fixture.runtime.mu.Unlock()
	if !fixture.runtime.ready || fixture.runtime.draining ||
		fixture.runtime.starting || fixture.runtime.resetting ||
		len(fixture.runtime.active) != 0 ||
		len(fixture.runtime.recycleRequests) != 0 {
		return fmt.Errorf(
			"pending lifecycle state ready=%t draining=%t starting=%t resetting=%t active=%d queued_recycles=%d",
			fixture.runtime.ready,
			fixture.runtime.draining,
			fixture.runtime.starting,
			fixture.runtime.resetting,
			len(fixture.runtime.active),
			len(fixture.runtime.recycleRequests),
		)
	}
	return nil
}

func (fixture *realXrayFixture) leaseActive(lease *Lease) bool {
	fixture.runtime.mu.Lock()
	defer fixture.runtime.mu.Unlock()
	_, active := fixture.runtime.active[lease]
	return active
}

func (fixture *realXrayFixture) OldEpochMutations() uint64 {
	return fixture.runner.staleMutations.Load()
}

func (fixture *realXrayFixture) ActiveProbeSOCKS() int64 {
	return fixture.probeConnections.active.Load()
}

func (fixture *realXrayFixture) close(t *testing.T) {
	t.Helper()
	if fixture.runtime != nil {
		if err := fixture.runtime.Close(); err != nil {
			t.Errorf("close probe runtime: %v", err)
		}
	}
	if fixture.main != nil {
		fixture.main.stop(t)
	}
	for index := len(fixture.children) - 1; index >= 0; index-- {
		fixture.children[index].stop(t)
	}
	if fixture.origin != nil {
		fixture.origin.Close()
	}
}

func realXrayOutbound(transport string) (json.RawMessage, error) {
	var link string
	switch transport {
	case "raw":
		link = "vless://" + realXrayTestUser + "@127.0.0.1:22001?type=raw&security=none&encryption=none"
	case "ws":
		link = "vless://" + realXrayTestUser + "@127.0.0.1:22002?type=ws&security=none&encryption=none&path=%2Fws"
	case "xhttp":
		link = "vless://" + realXrayTestUser + "@127.0.0.1:22003?type=xhttp&security=none&encryption=none&path=%2Fxhttp&mode=stream-one"
	default:
		return nil, fmt.Errorf("unsupported test transport %q", transport)
	}
	outbound, err := xrayconfig.VLESSOutbound(link, "probe-outbound-0")
	if err != nil {
		return nil, err
	}
	return json.Marshal(outbound)
}

type expectedEpochContextKey struct{}

func withExpectedEpoch(ctx context.Context, epoch uint64) context.Context {
	return context.WithValue(ctx, expectedEpochContextKey{}, epoch)
}

type epochRecordingRunner struct {
	delegate       xrayapi.Runner
	currentEpoch   atomic.Uint64
	staleMutations atomic.Uint64
}

func (runner *epochRecordingRunner) Run(
	ctx context.Context,
	stdin, name string,
	args ...string,
) error {
	if expected, ok := ctx.Value(expectedEpochContextKey{}).(uint64); ok &&
		expected != runner.currentEpoch.Load() {
		runner.staleMutations.Add(1)
	}
	return runner.delegate.Run(ctx, stdin, name, args...)
}

type recordingRealXrayMetrics struct {
	delegate  metricsReader
	successes atomic.Uint64
	failures  atomic.Uint64
}

func (reader *recordingRealXrayMetrics) Read(pid int) (processMetrics, error) {
	metrics, err := reader.delegate.Read(pid)
	if err != nil {
		reader.failures.Add(1)
		return processMetrics{}, err
	}
	reader.successes.Add(1)
	return metrics, nil
}

type realXrayResetter struct {
	control *probexray.Control
	runner  *epochRecordingRunner
	skip    bool
}

func (resetter *realXrayResetter) Reset(epoch uint64) {
	resetter.runner.currentEpoch.Store(epoch)
	if resetter.skip && epoch > 1 {
		return
	}
	resetter.control.Reset(epoch)
}

type connectionTracker struct {
	active atomic.Int64
}

func (tracker *connectionTracker) dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	connection, err := (&net.Dialer{
		Timeout: 2 * time.Second,
	}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tracker.active.Add(1)
	return &trackedRealXrayConnection{
		Conn:  connection,
		close: func() { tracker.active.Add(-1) },
	}, nil
}

func (tracker *connectionTracker) waitZero(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tracker.active.Load() == 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return tracker.active.Load() == 0
}

type trackedRealXrayConnection struct {
	net.Conn
	once  sync.Once
	close func()
}

func (connection *trackedRealXrayConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.close)
	return err
}

func realXrayHTTPClient(
	proxyAddress string,
	tracker *connectionTracker,
) *http.Client {
	dialer := socks5.Dialer{ProxyAddress: proxyAddress}
	if tracker != nil {
		dialer.Dial = tracker.dial
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			IdleConnTimeout:       time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
		},
	}
}

type realXrayChild struct {
	name     string
	command  *exec.Cmd
	output   lockedRealXrayBuffer
	done     chan error
	stopOnce sync.Once
}

type lockedRealXrayBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *lockedRealXrayBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *lockedRealXrayBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func startRealXrayChild(
	t *testing.T,
	binary, configPath, name string,
) *realXrayChild {
	t.Helper()
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		t.Fatalf("resolve %s config: %v", name, err)
	}
	child := &realXrayChild{
		name: name,
		done: make(chan error, 1),
	}
	child.command = exec.Command(binary, "run", "-config", absoluteConfig)
	child.command.Stdout = &child.output
	child.command.Stderr = &child.output
	if err := child.command.Start(); err != nil {
		t.Fatalf("start %s Xray: %v", name, err)
	}
	go func() { child.done <- child.command.Wait() }()
	return child
}

func waitForRealXrayTCP(
	t *testing.T,
	child *realXrayChild,
	address string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		select {
		case exitErr := <-child.done:
			t.Fatalf(
				"%s Xray exited before readiness: %v output=%s",
				child.name,
				exitErr,
				child.output.String(),
			)
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	child.stop(t)
	t.Fatalf("%s Xray readiness timed out at %s: %s", child.name, address, child.output.String())
}

func (child *realXrayChild) stop(t *testing.T) {
	t.Helper()
	child.stopOnce.Do(func() {
		if child.command == nil || child.command.Process == nil {
			return
		}
		_ = child.command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-child.done:
			if err != nil && !strings.Contains(err.Error(), "signal: terminated") {
				t.Errorf("stop %s Xray: %v output=%s", child.name, err, child.output.String())
			}
		case <-time.After(3 * time.Second):
			_ = child.command.Process.Kill()
			select {
			case <-child.done:
			case <-time.After(3 * time.Second):
				t.Errorf("%s Xray did not exit after kill", child.name)
			}
		}
	})
}
