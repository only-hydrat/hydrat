// Package appupdate checks the independent Hydrat App release channel.
package appupdate

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	Android = "android-arm64"
	Windows = "windows-amd64"
	Linux   = "linux-amd64"

	releaseCatalog = "https://api.github.com/repos/only-hydrat/hydrat/releases"
	downloadBase   = "https://github.com/only-hydrat/hydrat/releases/download/"
	perPage        = 100
	maxPages       = 5
	maxPageBytes   = 8 << 20
)

//go:embed version.txt
var builtInVersion string

// version can be overridden by the Linux and Windows packaging scripts.
var version string

func CurrentVersion() string {
	if version != "" {
		return version
	}
	return strings.TrimSpace(builtInVersion)
}

type Result struct {
	Current     string
	Latest      string
	DownloadURL string
}

type release struct {
	Tag        string `json:"tag_name"`
	Draft      bool
	Prerelease bool
	Assets     []struct {
		Name  string
		State string
		URL   string `json:"browser_download_url"`
	}
}

func Check(ctx context.Context, platform string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return check(ctx, client, platform, CurrentVersion())
}

func check(ctx context.Context, client *http.Client, platform, current string) (Result, error) {
	result := Result{Current: current}
	installed, ok := versionNumber(current)
	if !ok || assetName(platform, current) == "" {
		return result, errors.New("invalid application release settings")
	}
	best := -1
	for page := 1; page <= maxPages; page++ {
		releases, err := fetchPage(ctx, client, page)
		if err != nil {
			return Result{Current: current}, err
		}
		for _, item := range releases {
			v, app := strings.CutPrefix(item.Tag, "app-v")
			number, valid := versionNumber(v)
			if !app || !valid || item.Draft || item.Prerelease || number <= best {
				continue
			}
			name := assetName(platform, v)
			expectedURL := downloadBase + item.Tag + "/" + name
			for _, asset := range item.Assets {
				if asset.Name == name && asset.State == "uploaded" && asset.URL == expectedURL {
					result.Latest, best = v, number
					if number > installed {
						result.DownloadURL = expectedURL
					}
					break
				}
			}
		}
		if len(releases) < perPage {
			return result, nil
		}
	}
	return Result{Current: current}, errors.New("application release catalog exceeded its page limit")
}

func fetchPage(ctx context.Context, client *http.Client, page int) ([]release, error) {
	url := fmt.Sprintf("%s?per_page=%d&page=%d", releaseCatalog, perPage, page)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("load application releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("application release catalog returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil || len(body) > maxPageBytes {
		return nil, errors.New("could not read the application release catalog")
	}
	var releases []release
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, errors.New("invalid application release catalog")
	}
	return releases, nil
}

func versionNumber(v string) (int, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, false
	}
	var number int
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 999 || strconv.Itoa(n) != part {
			return 0, false
		}
		number = number*1000 + n
	}
	return number, true
}

func assetName(platform, version string) string {
	switch platform {
	case Android:
		return "Hydrat-android-arm64-" + version + ".apk"
	case Windows:
		return "Hydrat-windows-x64-" + version + ".msi"
	case Linux:
		return "hydrat-app_" + version + "_amd64.deb"
	default:
		return ""
	}
}
