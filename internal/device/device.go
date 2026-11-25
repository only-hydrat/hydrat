package device

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/refresh"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

const (
	profileID     = "local-device"
	TunnelCIDR    = xrayapi.DeviceTunnelAddress + "/32"
	maxImportSize = 4 * 1024 * 1024
)

type App struct {
	database          *store.Store
	refresher         *refresh.Refresher
	key               []byte
	refreshMu         sync.Mutex
	sourcesChanged    chan struct{}
	sourceRemoved     chan struct{}
	screenInteractive atomic.Bool
	search            atomic.Pointer[SearchStatus]
	running           atomic.Bool
	mobileStartedAt   atomic.Int64
	route             atomic.Pointer[dataplane.ClientRoute]
}

type ImportReport struct {
	Imported      int
	Restored      int
	Skipped       int
	RefreshFailed int
	Unavailable   int
	LineErrors    []ImportLineError `json:"-"`
}

type ImportLineError struct {
	Line   int
	Reason string
}

func Open(ctx context.Context, directory string) (*App, error) {
	return open(ctx, directory, false, nil)
}

func OpenMobile(ctx context.Context, directory string) (*App, error) {
	return open(ctx, directory, true, nil)
}

func OpenSingleDevice(ctx context.Context, directory string, client *http.Client) (*App, error) {
	return open(ctx, directory, true, client)
}

func open(ctx context.Context, directory string, mobile bool, client *http.Client) (*App, error) {
	if directory == "" {
		return nil, errors.New("local state directory is required")
	}
	key, err := secretbox.LoadOrCreateKey(filepath.Join(directory, "device.key"))
	if err != nil {
		return nil, err
	}
	box, err := secretbox.New(key)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "device.db")
	database, err := store.Open(path, box)
	if err != nil {
		return nil, err
	}
	if err := database.EnsureLocalDevice(ctx, profileID, "Hydrat App", TunnelCIDR); err != nil {
		_ = database.Close()
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	refresher := refresh.New(database, client, maxImportSize)
	if mobile {
		refresher.WithFullPublicInventory()
	}
	app := &App{
		database: database, refresher: refresher, key: key,
		sourcesChanged: make(chan struct{}, 1), sourceRemoved: make(chan struct{}, 1),
	}
	app.screenInteractive.Store(true)
	return app, nil
}

// Close is called after the Run context has been canceled and Run has returned.
func (app *App) Close() error { return app.database.Close() }

func (app *App) SetHWID(value string) error {
	app.refreshMu.Lock()
	defer app.refreshMu.Unlock()
	return app.refresher.SetHWID(value)
}

func (app *App) RemoveSource(ctx context.Context, id string) error {
	app.refreshMu.Lock()
	defer app.refreshMu.Unlock()
	if err := app.database.DeleteSource(ctx, id); err != nil {
		return err
	}
	select {
	case app.sourceRemoved <- struct{}{}:
	default:
	}
	return nil
}

func (app *App) Import(ctx context.Context, input string) (ImportReport, error) {
	return app.ImportWithHWID(ctx, input, "")
}

var ErrSourceHWIDRequiresHTTPS = errors.New("custom HWID requires one HTTPS subscription")

func (app *App) ImportWithHWID(ctx context.Context, input, hwid string) (ImportReport, error) {
	if len(input) > maxImportSize {
		return ImportReport{}, errors.New("subscription input exceeds the size limit")
	}
	preview := sources.PreviewInput(input)
	hwid, err := refresh.NormalizeHWID(hwid)
	if err != nil {
		return ImportReport{}, err
	}
	if hwid != "" && (len(preview.Items) != 1 || preview.ValidCount != 1 ||
		!supportsSourceHWID(preview.Items[0].Kind, preview.Items[0].Payload)) {
		return ImportReport{}, ErrSourceHWIDRequiresHTTPS
	}
	if preview.ValidCount == 0 {
		return invalidImportLines(preview), errors.New("input contains no supported sources")
	}
	return app.importPreview(ctx, preview, hwid)
}

func (app *App) ImportSuggested(ctx context.Context) (ImportReport, error) {
	preview, err := app.refresher.CheckSuggestedPublicSources(ctx)
	if err != nil {
		return ImportReport{}, err
	}
	return app.importPreview(ctx, preview, "")
}

func invalidImportLines(preview sources.Preview) ImportReport {
	report := ImportReport{Unavailable: preview.ErrorCount}
	for _, item := range preview.Items {
		if item.Error != "" {
			report.LineErrors = append(report.LineErrors, ImportLineError{Line: item.Line, Reason: item.Error})
		}
	}
	return report
}

func (app *App) importPreview(ctx context.Context, preview sources.Preview, hwid string) (ImportReport, error) {
	app.refreshMu.Lock()
	defer app.refreshMu.Unlock()
	var result store.ImportResult
	var err error
	if hwid == "" {
		result, err = app.database.ImportSources(ctx, preview.Items)
	} else {
		result, err = app.database.ImportSourceWithHWID(ctx, preview.Items[0], hwid)
	}
	if err != nil {
		return ImportReport{}, err
	}
	report := invalidImportLines(preview)
	report.Imported, report.Restored, report.Skipped = result.Imported, result.Restored, result.Skipped-preview.ErrorCount
	for _, item := range preview.Items {
		if item.Error != "" || item.Duplicate {
			continue
		}
		if err := app.refresher.Source(ctx, "src_"+item.Fingerprint); err != nil {
			report.RefreshFailed++
			report.LineErrors = append(report.LineErrors, ImportLineError{Line: item.Line, Reason: "source refresh failed"})
		}
	}
	sort.Slice(report.LineErrors, func(i, j int) bool { return report.LineErrors[i].Line < report.LineErrors[j].Line })
	select {
	case app.sourcesChanged <- struct{}{}:
	default:
	}
	return report, ctx.Err()
}

type RefreshReport struct {
	Updated int
	Failed  int
}

func supportsSourceHWID(kind sources.Kind, payload string) bool {
	switch kind {
	case sources.KindVLESSSubscription, sources.KindTorSubscription, sources.KindRemoteAuto:
		return strings.HasPrefix(strings.ToLower(payload), "https://")
	default:
		return false
	}
}

func (app *App) SourceHWID(ctx context.Context, id string) (string, error) {
	_, _, hwid, err := app.database.SourceForRefresh(ctx, id)
	return hwid, err
}

func (app *App) SetSourceHWID(ctx context.Context, id, hwid string) (RefreshReport, error) {
	hwid, err := refresh.NormalizeHWID(hwid)
	if err != nil {
		return RefreshReport{}, err
	}
	app.refreshMu.Lock()
	defer app.refreshMu.Unlock()
	kind, payload, _, err := app.database.SourceForRefresh(ctx, id)
	if err != nil {
		return RefreshReport{}, err
	}
	if !supportsSourceHWID(kind, payload) {
		return RefreshReport{}, ErrSourceHWIDRequiresHTTPS
	}
	if err := app.database.SetSourceHWID(ctx, id, hwid); err != nil {
		return RefreshReport{}, err
	}
	if err := app.refresher.Source(ctx, id); err != nil {
		return RefreshReport{Failed: 1}, nil
	}
	return RefreshReport{Updated: 1}, nil
}

// RefreshSources refreshes enabled subscriptions and wakes qualification.
func (app *App) RefreshSources(ctx context.Context) (RefreshReport, error) {
	report, err := app.refreshEnabledSources(ctx)
	select {
	case app.sourcesChanged <- struct{}{}:
	default:
	}
	return report, err
}

func (app *App) refreshSources(ctx context.Context) error {
	_, err := app.refreshEnabledSources(ctx)
	return err
}

func (app *App) refreshEnabledSources(ctx context.Context) (RefreshReport, error) {
	var report RefreshReport
	app.refreshMu.Lock()
	defer app.refreshMu.Unlock()
	rows, err := app.database.ListSources(ctx)
	if err != nil {
		return report, err
	}
	for _, source := range rows {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if !source.Enabled || source.PendingDelete {
			continue
		}
		if err := app.refresher.Source(ctx, source.ID); err != nil {
			report.Failed++
		} else {
			report.Updated++
		}
	}
	return report, ctx.Err()
}
