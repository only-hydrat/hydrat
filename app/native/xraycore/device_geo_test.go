package xraycore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestDeviceGeoValidatesAndCommitsBothDatabases(t *testing.T) {
	assets := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", assets)
	ctx := context.Background()

	ips, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "LOCAL", Cidr: []*geodata.CIDR{{Ip: []byte{192, 0, 2, 0}, Prefix: 24}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sites, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "WORK", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "example.net"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			_, _ = w.Write(ips)
		case "/site":
			_, _ = w.Write(sites)
		case "/broken-site":
			_, _ = w.Write([]byte("unavailable"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	settings := GeoSettings{IPURL: server.URL + "/ip", SiteURL: server.URL + "/site", DirectIP: "local", TunnelSite: "work"}
	if err := SaveDeviceGeo(ctx, assets, settings, server.Client()); err != nil {
		t.Fatal(err)
	}
	before, err := LoadDeviceGeo(assets)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := before.Rules()
	if err != nil || len(rules.DirectIP) != 1 || !strings.HasSuffix(rules.DirectIP[0], "geoip.dat:local") ||
		len(rules.TunnelSite) != 1 || !strings.HasSuffix(rules.TunnelSite[0], "geosite.dat:work") ||
		len(rules.TunnelIP) != 0 || len(rules.DirectSite) != 0 {
		t.Fatalf("unexpected rules: %+v, %v", rules, err)
	}
	invalid := settings
	invalid.SiteURL = server.URL + "/broken-site"
	if err := SaveDeviceGeo(ctx, assets, invalid, server.Client()); err == nil || err.Error() != "geosite_groups" {
		t.Fatalf("invalid database: want geosite_groups, got %v", err)
	}
	after, err := LoadDeviceGeo(assets)
	if err != nil || after != before {
		t.Fatalf("invalid download replaced saved settings: %+v, %v", after, err)
	}

	if err := SaveDeviceGeo(ctx, assets, GeoSettings{}, server.Client()); err != nil {
		t.Fatal(err)
	}
	PruneDeviceGeo(assets, before.Directory)
	if _, err := os.Stat(filepath.Join(assets, before.Directory, "geoip.dat")); err != nil {
		t.Fatal(err)
	}
	PruneDeviceGeo(assets, "")
	if _, err := os.Stat(filepath.Join(assets, before.Directory)); !os.IsNotExist(err) {
		t.Fatalf("directory retained after tunnel closed: %v", err)
	}
}

func TestDeviceGeoRejectsCleartextAndInvalidTags(t *testing.T) {
	assets := t.TempDir()
	for _, test := range []struct {
		settings GeoSettings
		code     string
	}{
		{GeoSettings{IPURL: "http://example.net/ip.dat", TunnelIP: "ru"}, "invalid_geo_url"},
		{GeoSettings{TunnelIP: "../file:ru"}, "invalid_geo_tags"},
	} {
		err := SaveDeviceGeo(context.Background(), assets, test.settings, nil)
		if err == nil || err.Error() != test.code {
			t.Fatalf("expected %s, got %v", test.code, err)
		}
	}
}
