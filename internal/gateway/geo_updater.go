package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
)

type GeoUpdaterConfig struct {
	Enabled        bool
	AutoUpdate     bool
	GeoIPURL       string
	GeoSiteURL     string
	UpdateInterval time.Duration
	TargetDir      string
	HTTPClient     *http.Client
}

type GeoAssetStatus = agentapi.GeoAssetStatus

type GeoUpdater struct {
	cfg        GeoUpdaterConfig
	client     *http.Client
	targetDir  string
	cancel     context.CancelFunc
	done       chan struct{}
	mu         sync.Mutex
	lastUpdate time.Time
}

func NewGeoUpdater(cfg GeoUpdaterConfig) (*GeoUpdater, error) {
	targetDir := cfg.TargetDir
	if targetDir == "" {
		targetDir = "/data/geo"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 60 * time.Second,
		}
	}
	interval := cfg.UpdateInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	cfg.UpdateInterval = interval

	return &GeoUpdater{
		cfg:       cfg,
		client:    client,
		targetDir: targetDir,
	}, nil
}

func (u *GeoUpdater) TargetDir() string {
	return u.targetDir
}

func (u *GeoUpdater) Status() GeoAssetStatus {
	u.mu.Lock()
	defer u.mu.Unlock()

	status := GeoAssetStatus{
		Enabled:        u.cfg.Enabled,
		AutoUpdate:     u.cfg.AutoUpdate,
		GeoIPURL:       u.cfg.GeoIPURL,
		GeoSiteURL:     u.cfg.GeoSiteURL,
		UpdateInterval: u.cfg.UpdateInterval.String(),
		LastUpdate:     u.lastUpdate,
	}
	if info, err := os.Stat(filepath.Join(u.targetDir, "geoip.dat")); err == nil {
		status.GeoIPExists = true
		status.GeoIPSize = info.Size()
		status.GeoIPModified = info.ModTime()
	}
	if info, err := os.Stat(filepath.Join(u.targetDir, "geosite.dat")); err == nil {
		status.GeoSiteExists = true
		status.GeoSiteSize = info.Size()
		status.GeoSiteModified = info.ModTime()
	}
	return status
}

func (u *GeoUpdater) UpdateConfig(enabled, autoUpdate bool, geoIPURL, geoSiteURL string, updateInterval time.Duration) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if geoIPURL != "" {
		u.cfg.GeoIPURL = geoIPURL
	}
	if geoSiteURL != "" {
		u.cfg.GeoSiteURL = geoSiteURL
	}
	if updateInterval > 0 {
		u.cfg.UpdateInterval = updateInterval
	}
	u.cfg.Enabled = enabled
	u.cfg.AutoUpdate = autoUpdate
	return nil
}

func (u *GeoUpdater) Start(ctx context.Context) error {
	u.mu.Lock()
	if u.cancel != nil {
		u.mu.Unlock()
		return errors.New("geo updater already started")
	}
	ctx, u.cancel = context.WithCancel(ctx)
	u.done = make(chan struct{})
	u.mu.Unlock()

	go u.run(ctx)
	return nil
}

func (u *GeoUpdater) run(ctx context.Context) {
	defer close(u.done)

	// Perform initial update check
	if err := u.UpdateOnce(ctx); err != nil {
		log.Printf("geo updater initial download failed: %v", err)
	}

	ticker := time.NewTicker(u.cfg.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.UpdateOnce(ctx); err != nil {
				log.Printf("geo updater periodic download failed: %v", err)
			}
		}
	}
}

func (u *GeoUpdater) Close() error {
	u.mu.Lock()
	if u.cancel == nil {
		u.mu.Unlock()
		return nil
	}
	cancel := u.cancel
	done := u.done
	u.cancel = nil
	u.mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (u *GeoUpdater) UpdateOnce(ctx context.Context) error {
	u.mu.Lock()
	enabled := u.cfg.Enabled && u.cfg.AutoUpdate
	u.mu.Unlock()
	if !enabled {
		return nil
	}
	return u.ForceUpdate(ctx)
}

func (u *GeoUpdater) ForceUpdate(ctx context.Context) error {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
	}
	u.mu.Lock()
	geoIPURL := u.cfg.GeoIPURL
	geoSiteURL := u.cfg.GeoSiteURL
	targetDir := u.targetDir
	u.mu.Unlock()

	if geoIPURL == "" || geoSiteURL == "" {
		return errors.New("geoip_url and geosite_url must not be empty")
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create geo asset dir %q: %w", targetDir, err)
	}

	geoIPDest := filepath.Join(targetDir, "geoip.dat")
	if err := u.downloadAsset(ctx, geoIPURL, geoIPDest); err != nil {
		return fmt.Errorf("download geoip: %w", err)
	}

	geoSiteDest := filepath.Join(targetDir, "geosite.dat")
	if err := u.downloadAsset(ctx, geoSiteURL, geoSiteDest); err != nil {
		return fmt.Errorf("download geosite: %w", err)
	}

	u.mu.Lock()
	u.lastUpdate = time.Now()
	u.mu.Unlock()

	return nil
}

func (u *GeoUpdater) downloadAsset(ctx context.Context, sourceURL, destPath string) (downloadErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("http get %s: %w", sourceURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http get %s status: %d", sourceURL, resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %q: %w", destPath, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if downloadErr != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	written, err := io.Copy(writer, resp.Body)
	if err != nil {
		return fmt.Errorf("write asset %q: %w", tmpPath, err)
	}
	if written < 100 {
		return fmt.Errorf("downloaded asset %q is suspiciously small (%d bytes)", sourceURL, written)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync temp file %q: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("atomic rename %q -> %q: %w", tmpPath, destPath, err)
	}

	return nil
}
