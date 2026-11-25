package xraycore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/xrayapi"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
)

const (
	geoSettingsFile = "mobile-geo.json"
	customGeoPrefix = "custom-geo-"
	maxGeoAssetSize = 128 << 20
)

var geoTag = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}(@[a-zA-Z0-9_-]{1,80})*$`)

type GeoSettings struct {
	IPURL, SiteURL         string
	TunnelIP, DirectIP     string
	TunnelSite, DirectSite string
}

type DeviceGeo struct {
	GeoSettings
	Directory string
}

func LoadDeviceGeo(assets string) (DeviceGeo, error) {
	data, err := os.ReadFile(filepath.Join(assets, geoSettingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return DeviceGeo{GeoSettings: GeoSettings{
			TunnelIP: "ru-blocked, facebook", DirectIP: "ru",
			TunnelSite: "ru-blocked, meta", DirectSite: "category-ru, ru-available-only-inside",
		}}, nil
	}
	if err != nil {
		return DeviceGeo{}, err
	}
	var result DeviceGeo
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.Directory != "" && !validGeoDirectory(result.Directory) {
		return result, errors.New("invalid_geo_settings")
	}
	return result, nil
}

func validGeoDirectory(name string) bool {
	return strings.HasPrefix(name, customGeoPrefix) && filepath.Base(name) == name
}

func (geo DeviceGeo) Rules() (xrayapi.DeviceGeoRules, error) {
	var rules xrayapi.DeviceGeoRules
	for _, list := range []struct {
		value, prefix, asset, sourceURL string
		target                          *[]string
	}{
		{geo.TunnelIP, "ip", "geoip.dat", geo.IPURL, &rules.TunnelIP},
		{geo.DirectIP, "ip", "geoip.dat", geo.IPURL, &rules.DirectIP},
		{geo.TunnelSite, "site", "geosite.dat", geo.SiteURL, &rules.TunnelSite},
		{geo.DirectSite, "site", "geosite.dat", geo.SiteURL, &rules.DirectSite},
	} {
		asset := list.asset
		if list.sourceURL != "" {
			asset = filepath.Join(geo.Directory, asset)
		}
		seen := make(map[string]bool)
		for _, raw := range strings.FieldsFunc(list.value, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r'
		}) {
			tag := strings.ToLower(strings.TrimSpace(raw))
			if tag == "" || seen[tag] {
				continue
			}
			if !geoTag.MatchString(tag) || len(tag) > 120 ||
				(list.prefix == "ip" && strings.Contains(tag, "@")) || len(*list.target) >= 32 {
				return rules, errors.New("invalid_geo_tags")
			}
			seen[tag] = true
			*list.target = append(*list.target, "ext-"+list.prefix+":"+asset+":"+tag)
		}
	}
	return rules, nil
}

func SaveDeviceGeo(ctx context.Context, assets string, settings GeoSettings, client *http.Client) error {
	settings.IPURL = strings.TrimSpace(settings.IPURL)
	settings.SiteURL = strings.TrimSpace(settings.SiteURL)
	for _, source := range []string{settings.IPURL, settings.SiteURL} {
		if source != "" && !validGeoURL(source) {
			return errors.New("invalid_geo_url")
		}
	}
	geo := DeviceGeo{GeoSettings: settings}
	if settings.IPURL != "" || settings.SiteURL != "" {
		directory, err := os.MkdirTemp(assets, customGeoPrefix)
		if err != nil {
			return errors.New("geo_save")
		}
		geo.Directory = filepath.Base(directory)
	}
	var saved bool
	defer func() {
		if !saved && geo.Directory != "" {
			_ = os.RemoveAll(filepath.Join(assets, geo.Directory))
		}
	}()
	rules, err := geo.Rules()
	if err != nil {
		return err
	}
	if settings.IPURL != "" && len(rules.DirectIP)+len(rules.TunnelIP) == 0 ||
		settings.SiteURL != "" && len(rules.DirectSite)+len(rules.TunnelSite) == 0 {
		return errors.New("missing_geo_tags")
	}
	if settings.IPURL != "" {
		if err := downloadGeo(ctx, client, settings.IPURL, filepath.Join(assets, geo.Directory, "geoip.dat")); err != nil {
			return errors.New("geoip_download")
		}
	}
	if settings.SiteURL != "" {
		if err := downloadGeo(ctx, client, settings.SiteURL, filepath.Join(assets, geo.Directory, "geosite.dat")); err != nil {
			return errors.New("geosite_download")
		}
	}

	ips, err := geodata.ParseIPRules(append(rules.TunnelIP, rules.DirectIP...))
	if err == nil && len(ips) > 0 {
		_, err = router.NewIPMatcher(ips, router.MatcherAsType_Target)
	}
	if err != nil {
		return errors.New("geoip_groups")
	}
	sites, err := geodata.ParseDomainRules(append(rules.TunnelSite, rules.DirectSite...), geodata.Domain_Domain)
	if err == nil && len(sites) > 0 {
		_, err = router.NewDomainMatcher(sites)
	}
	if err != nil {
		return errors.New("geosite_groups")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(geo)
	if err != nil {
		return errors.New("geo_save")
	}
	pending, err := os.CreateTemp(assets, ".mobile-geo-")
	if err != nil {
		return errors.New("geo_save")
	}
	defer os.Remove(pending.Name())
	_, err = pending.Write(body)
	if closeErr := pending.Close(); err != nil || closeErr != nil {
		return errors.New("geo_save")
	}
	if err := os.Rename(pending.Name(), filepath.Join(assets, geoSettingsFile)); err != nil {
		return errors.New("geo_save")
	}
	saved = true
	return nil
}

func validGeoURL(value string) bool {
	parsed, err := url.Parse(value)
	return len(value) <= 4096 && err == nil && parsed.Scheme == "https" &&
		parsed.Hostname() != "" && parsed.User == nil
}

func downloadGeo(ctx context.Context, client *http.Client, source, path string) error {
	if client == nil {
		client = http.DefaultClient
	}
	scoped := *client
	scoped.Timeout = 75 * time.Second
	scoped.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !validGeoURL(request.URL.String()) {
			return errors.New("invalid_geo_redirect")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	response, err := scoped.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxGeoAssetSize {
		return errors.New("invalid_geo_response")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	count, copyErr := io.Copy(file, io.LimitReader(response.Body, maxGeoAssetSize+1))
	closeErr := file.Close()
	if count == 0 || count > maxGeoAssetSize {
		return errors.New("invalid_geo_size")
	}
	return errors.Join(copyErr, closeErr)
}

// Keep both the saved configuration and the assets referenced by a running tunnel.
func PruneDeviceGeo(assets, active string) {
	current, err := LoadDeviceGeo(assets)
	if err != nil {
		return
	}
	entries, err := os.ReadDir(assets)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && validGeoDirectory(name) && name != current.Directory && name != active {
			_ = os.RemoveAll(filepath.Join(assets, name))
		}
	}
}
