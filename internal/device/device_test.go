package device

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/refresh"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestLocalProfileHasNoWireGuardConfigAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	app, err := Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	const first = `vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls`
	report, err := app.Import(ctx, first)
	if err != nil || report.Imported != 1 || report.RefreshFailed != 0 {
		t.Fatalf("import = %+v, %v", report, err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	app, err = Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	profiles, err := app.database.ListClients(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].ID != profileID || profiles[0].PublicKey != "" {
		t.Fatalf("profiles = %+v, %v", profiles, err)
	}
	if config, err := app.database.ClientConfig(ctx, profileID); config != "" || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("local profile returned a WireGuard config: %v", err)
	}
	stats, err := app.Status(ctx)
	if err != nil || stats.Sources != 1 || stats.Candidates != 1 || stats.Connected {
		t.Fatalf("status = %+v, %v", stats, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "device.db")); err != nil {
		t.Fatal(err)
	}
}

func TestSuggestedSubscriptionsImportEightAndSkipDuplicates(t *testing.T) {
	ctx := context.Background()
	app, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	feeds := sources.SuggestedPublicSubscriptions()
	if len(feeds) != 8 {
		t.Fatalf("catalog size = %d", len(feeds))
	}
	bodies := make(map[string]string, len(feeds))
	for i, item := range feeds {
		bodies[item.Payload] = fmt.Sprintf("vless://11111111-1111-1111-1111-111111111111@node%d.example.org:443?security=tls", i)
	}
	app.refresher = refresh.New(app.database, &http.Client{Transport: catalogTransport(bodies)}, maxImportSize)
	first, err := app.ImportSuggested(ctx)
	if err != nil || first.Imported != 8 || first.RefreshFailed != 0 || first.Unavailable != 0 {
		t.Fatalf("first import = %+v, %v", first, err)
	}
	second, err := app.ImportSuggested(ctx)
	if err != nil || second.Imported != 0 || second.Skipped != 8 {
		t.Fatalf("repeat import = %+v, %v", second, err)
	}
	status, err := app.Status(ctx)
	if err != nil || status.Sources != 8 || status.Candidates != 8 {
		t.Fatalf("inventory = %+v, %v", status, err)
	}
}

type catalogTransport map[string]string

func (transport catalogTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, ok := transport[request.URL.String()]
	code := http.StatusOK
	if !ok {
		code = http.StatusNotFound
	}
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestStatusShowsAppliedRoutesAndSafeNodeMetadata(t *testing.T) {
	ctx := context.Background()
	app, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	const secret = "11111111-1111-1111-1111-111111111111"
	link := "vless://" + secret + "@example.org:443?security=tls&flow=xtls-rprx-vision#Test%20Node"
	if _, err := app.Import(ctx, link); err != nil {
		t.Fatal(err)
	}
	rows, err := app.database.ListCandidates(ctx, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("candidates = %d, %v", len(rows), err)
	}
	id := rows[0].ID
	if err := app.database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: id, TCPQualified: true, Available: true, LatencyMS: 38, Score: 92, UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	app.running.Store(true)
	handler := sources.VLESSHandlerID(id, link)
	app.route.Store(&dataplane.ClientRoute{
		ClientID: profileID, TCPOutbound: handler, UDPOutbound: handler, BlockUDP: true,
	})
	status, err := app.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Nodes) != 1 || status.Nodes[0].Role != "tcp" || status.Nodes[0].Protocol != "vless" ||
		status.Nodes[0].LatencyMS != 38 || status.Nodes[0].State != "available" {
		t.Fatalf("unexpected projected nodes: %+v", status.Nodes)
	}
	raw, err := json.Marshal(status)
	if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "vless://") {
		t.Fatalf("status projection contains credentials or failed to encode: %v", err)
	}

	if err := app.database.SaveCandidateHealth(ctx, store.CandidateHealth{
		CandidateID: id, TCPQualified: true, Available: false, UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	recovering, err := app.Status(ctx)
	if err != nil || !recovering.Recovering || len(recovering.Nodes) != 1 || recovering.Nodes[0].State != "unavailable" {
		t.Fatalf("failed primary should report recovery: %+v, %v", recovering, err)
	}

	app.running.Store(false)
	disconnected, err := app.Status(ctx)
	if err != nil || len(disconnected.Nodes) != 0 || disconnected.Connected {
		t.Fatalf("disconnected status advertises a route: %+v, %v", disconnected, err)
	}
}

func TestResolverPresetsAreValidAndDoNotShareStorage(t *testing.T) {
	for _, preset := range []int{0, 1, 2, 3, 99} {
		resolvers := DNSResolversForPreset(preset)
		if err := dataplane.ValidateDNSResolverPool(resolvers); err != nil {
			t.Fatalf("preset %d: %v", preset, err)
		}
		resolvers[0] = ""
		if DNSResolversForPreset(preset)[0] == "" {
			t.Fatal("preset shares mutable storage")
		}
	}
}

func TestMobileSettingsBoundWorkersAndPreserveDefaults(t *testing.T) {
	defaults := (MobileSettings{}).Normalized()
	if defaults.FastWorkers != 8 || defaults.BackgroundWorkers != 4 || defaults.MinVLESSScore != 75 ||
		defaults.BackgroundIntervalSeconds != 15 || defaults.SourceRefreshMinutes != 60 {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}
	custom := (MobileSettings{FastWorkers: 3, BackgroundWorkers: 7, MinVLESSScore: 80,
		BackgroundIntervalSeconds: 60, SourceRefreshMinutes: 30, PauseOnScreenOff: true}).Normalized()
	if custom.FastWorkers != 3 || custom.BackgroundWorkers != 7 || custom.MinVLESSScore != 80 ||
		custom.BackgroundIntervalSeconds != 60 || custom.SourceRefreshMinutes != 30 || !custom.PauseOnScreenOff {
		t.Fatalf("custom settings changed: %+v", custom)
	}
	bounded := (MobileSettings{FastWorkers: 16, BackgroundWorkers: -3, MinVLESSScore: 150}).Normalized()
	if bounded.FastWorkers != 8 || bounded.BackgroundWorkers != 1 || bounded.MinVLESSScore != 100 {
		t.Fatalf("settings exceed engine limits: %+v", bounded)
	}
}

func TestLocalSourceRemovalUpdatesStatusAndAllowsReimport(t *testing.T) {
	ctx := context.Background()
	app, err := OpenMobile(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	const source = "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls"
	if _, err := app.Import(ctx, source); err != nil {
		t.Fatal(err)
	}
	before, err := app.Status(ctx)
	if err != nil || before.Sources != 1 || len(before.Inventory) != 1 || before.Inventory[0].ID == "" {
		t.Fatalf("missing source identifier: %+v, %v", before, err)
	}
	if err := app.RemoveSource(ctx, before.Inventory[0].ID); err != nil {
		t.Fatal(err)
	}
	after, err := app.Status(ctx)
	if err != nil || after.Sources != 0 || len(after.Inventory) != 0 || after.Candidates != 0 {
		t.Fatalf("deleted source remains selectable: %+v, %v", after, err)
	}
	if report, err := app.Import(ctx, source); err != nil || report.Imported+report.Restored != 1 || report.RefreshFailed != 0 {
		t.Fatalf("source could not be reimported: %+v, %v", report, err)
	}
}

func TestCustomHWIDIsUsedForSubscriptionRequests(t *testing.T) {
	ctx := context.Background()
	headers := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("X-HWID")
		fmt.Fprint(w, "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls")
	}))
	defer server.Close()
	app, err := OpenMobile(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.refresher = refresh.New(app.database, server.Client(), maxImportSize)
	const override = "custom-device-1234"
	if err := app.SetHWID(override); err != nil {
		t.Fatal(err)
	}
	if err := app.SetHWID("invalid\r\nvalue"); err == nil {
		t.Fatal("invalid HWID was accepted")
	}
	if report, err := app.Import(ctx, server.URL+"/sub"); err != nil || report.RefreshFailed != 0 {
		t.Fatalf("subscription import failed: %+v, %v", report, err)
	}
	select {
	case first := <-headers:
		if first != override {
			t.Fatal("subscription did not receive the saved HWID")
		}
	default:
		t.Fatal("subscription was not requested")
	}
	if err := app.SetHWID(""); err != nil {
		t.Fatal(err)
	}
	if report, err := app.RefreshSources(ctx); err != nil || report.Updated != 1 {
		t.Fatalf("refresh after clearing HWID: %+v, %v", report, err)
	}
	select {
	case value := <-headers:
		if value == override {
			t.Fatal("cleared HWID was still sent")
		}
	default:
		t.Fatal("source was not refreshed")
	}
}

func TestSourceHWIDIsAppliedBeforeImportAndPersists(t *testing.T) {
	const globalHWID = "global-device-001"
	const sourceHWID = "source-device-001"
	headers := make(chan [2]string, 12)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- [2]string{r.URL.Path, r.Header.Get("X-HWID")}
		_, _ = io.WriteString(w, "vless://11111111-1111-1111-8111-111111111111@example.org:443?security=tls")
	}))
	defer server.Close()
	ctx := t.Context()
	dir := t.TempDir()
	open := func() *App {
		t.Helper()
		app, err := OpenSingleDevice(ctx, dir, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if err := app.SetHWID(globalHWID); err != nil {
			t.Fatal(err)
		}
		return app
	}
	app := open()
	expect := func(path, hwid string) {
		t.Helper()
		select {
		case header := <-headers:
			if header != [2]string{path, hwid} {
				t.Fatalf("request header = %v, want %s %s", header, path, hwid)
			}
		default:
			t.Fatalf("no request for %s", path)
		}
	}
	if _, err := app.ImportWithHWID(ctx, "http://example.org/insecure", sourceHWID); err == nil {
		t.Fatal("custom HWID was accepted for HTTP")
	}
	if _, err := app.ImportWithHWID(ctx, server.URL+"/one\n"+server.URL+"/two", sourceHWID); err == nil {
		t.Fatal("one explicit HWID was applied to a batch")
	}
	if report, err := app.ImportWithHWID(ctx, server.URL+"/one", sourceHWID); err != nil || report.Imported != 1 || report.RefreshFailed != 0 {
		t.Fatalf("import with override = %+v, %v", report, err)
	}
	expect("/one", sourceHWID)
	if report, err := app.Import(ctx, server.URL+"/two"); err != nil || report.Imported != 1 || report.RefreshFailed != 0 {
		t.Fatalf("import with default = %+v, %v", report, err)
	}
	expect("/two", globalHWID)
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	app = open()
	defer app.Close()
	one := "src_" + sources.PreviewInput(server.URL + "/one").Items[0].Fingerprint
	if got, err := app.SourceHWID(ctx, one); err != nil || got != sourceHWID {
		t.Fatalf("source editor did not load saved HWID: %v", err)
	}
	status, err := app.Status(ctx)
	if err != nil || len(status.Inventory) != 2 {
		t.Fatalf("source status = %+v, %v", status.Inventory, err)
	}
	for _, source := range status.Inventory {
		if source.CustomHWID != (source.ID == one) {
			t.Fatalf("wrong HWID status for source %s", source.ID)
		}
	}
	if _, err := app.Import(ctx, server.URL+"/one"); err != nil {
		t.Fatal(err)
	}
	expect("/one", sourceHWID)
	if report, err := app.SetSourceHWID(ctx, one, ""); err != nil || report.Updated != 1 {
		t.Fatalf("clear override = %+v, %v", report, err)
	}
	expect("/one", globalHWID)
}

func TestMobileBackgroundSearchAppliesSleepAndInterval(t *testing.T) {
	app := &App{}
	mode := app.mobileBackgroundMode(MobileSettings{PauseOnScreenOff: true, BackgroundIntervalSeconds: 60})
	now := time.Now()
	if got := mode(now); got != "paused" {
		t.Fatalf("screen off mode = %s", got)
	}
	app.SetScreenInteractive(true)
	if got := mode(now); got != "background" {
		t.Fatalf("screen on mode = %s", got)
	}
	if got := mode(now.Add(59 * time.Second)); got != "waiting" {
		t.Fatalf("mode inside the configured interval = %s", got)
	}
	if got := mode(now.Add(time.Minute)); got != "background" {
		t.Fatalf("mode after the interval = %s", got)
	}
}

func TestImportReportsProblemLinesWithoutDiscardingValidSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	app, err := Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	input := "\r\ninvalid input\r\nvless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls\r\n" + server.URL
	result, err := app.Import(t.Context(), input)
	if err != nil || result.Imported != 2 || result.Unavailable != 1 || result.RefreshFailed != 1 {
		t.Fatalf("result = %+v, %v", result, err)
	}
	if len(result.LineErrors) != 2 ||
		result.LineErrors[0] != (ImportLineError{Line: 2, Reason: "unsupported source format"}) ||
		result.LineErrors[1] != (ImportLineError{Line: 4, Reason: "source refresh failed"}) {
		t.Fatalf("line errors = %+v", result.LineErrors)
	}
	result, err = app.Import(t.Context(), "\ninvalid input")
	if err == nil || len(result.LineErrors) != 1 || result.LineErrors[0].Line != 2 {
		t.Fatalf("invalid-only import = %+v, %v", result, err)
	}
}
