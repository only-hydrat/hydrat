package xrayapi

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func TestDeviceTunnelKeepsTransportAndDNSRulesAcrossReconciliation(t *testing.T) {
	a := NewAdapter("xray", "", "1.1.1.1", nil)
	a.ConfigureDeviceTunnel()
	a.ConfigureRouting([]string{".ru", ".su"}, []string{"habr.com"}, true)
	a.SetGeoAssetsPresent(true)
	rendered, err := a.routeDocument([]dataplane.ClientRoute{{
		ClientID: "local-device", SourceCIDR: "10.231.90.2/32",
		TCPOutbound: "tor", BlockUDP: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routing struct {
			Rules []struct {
				RuleTag     string   `json:"ruleTag"`
				OutboundTag string   `json:"outboundTag"`
				InboundTag  []string `json:"inboundTag"`
				Source      []string `json:"source"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatal(err)
	}
	indices := map[string]int{}
	for i, rule := range doc.Routing.Rules {
		indices[rule.RuleTag] = i
		if len(rule.Source) != 0 {
			t.Fatalf("TUN rule depends on a peer IP: %+v", rule)
		}
	}
	assertPrecedes := func(first, second string) {
		a, firstOK := indices[first]
		b, secondOK := indices[second]
		if !firstOK || !secondOK || a >= b {
			t.Fatalf("%s must precede %s: %s", first, second, rendered)
		}
	}
	assertPrecedes("hydrat-device-ipv6-block", "hydrat-device-dns")
	assertPrecedes("hydrat-device-dns", "hydrat-client-local-device-udp")
	assertPrecedes("hydrat-client-local-device-blocked-geosite", "hydrat-direct-ru")
	assertPrecedes("hydrat-direct-ru", "hydrat-client-local-device-tcp")
	assertPrecedes("hydrat-client-local-device-tcp", "hydrat-fail-closed")
	if _, found := indices["hydrat-client-local-device-dns"]; found {
		t.Fatal("found server DNS rule in the local profile")
	}
}

func TestDeviceConfigAcceptsOnlyPrivateSocketAndParsesInXray(t *testing.T) {
	adapter := NewAdapterWithResolvers("xray", "", []string{"1.1.1.1", "9.9.9.9"}, nil)
	adapter.ConfigureDeviceTunnel()
	if _, err := adapter.DeviceConfig(DeviceTunnelOptions{Name: "hydrat-test", APISocket: "127.0.0.1:10085"}); err == nil {
		t.Fatal("local gRPC listener must use a private filesystem socket")
	}
	dir := t.TempDir()
	config, err := adapter.DeviceConfig(DeviceTunnelOptions{Name: "hydrat-test", APISocket: filepath.Join(dir, "api.sock"), AutomaticRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("HYDRAT_DEVICE_TEST_XRAY")
	if binary == "" {
		return
	}
	path := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("Xray rejected device configuration: %v\n%s", err, output)
	}
}

func TestDeviceBlockedGeoRulesUseTheSelectedTransportOrBlock(t *testing.T) {
	adapter := NewAdapter("xray", "", "1.1.1.1", nil)
	adapter.ConfigureDeviceTunnel()
	adapter.ConfigureRouting(nil, nil, true)
	adapter.SetGeoAssetsPresent(true)
	for _, test := range []struct {
		routes []dataplane.ClientRoute
		want   map[string]string
	}{
		{nil, map[string]string{"tcp": "block", "udp": "block"}},
		{[]dataplane.ClientRoute{{ClientID: "local-device", SourceCIDR: DeviceTunnelAddress + "/32", TCPOutbound: "tor", UDPOutbound: "vless"}}, map[string]string{"tcp": "tor", "udp": "vless"}},
	} {
		document, err := adapter.routeDocument(test.routes)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Routing struct {
				Rules []struct {
					Network     string
					RuleTag     string
					OutboundTag string
				}
			}
		}
		if err := json.Unmarshal([]byte(document), &parsed); err != nil {
			t.Fatal(err)
		}
		matched := map[string]string{}
		for _, rule := range parsed.Routing.Rules {
			if strings.Contains(rule.RuleTag, "-blocked-geosite") {
				matched[rule.Network] = rule.OutboundTag
			}
		}
		if !maps.Equal(matched, test.want) {
			t.Fatalf("geo blocking routes = %v, want %v", matched, test.want)
		}
	}
}

func TestDeviceTunnelStartsAndExposesPrivateControlInNetworkNamespace(t *testing.T) {
	binary := os.Getenv("HYDRAT_DEVICE_TEST_XRAY")
	if binary == "" || runtime.GOOS != "linux" {
		t.Skip("requires an Xray binary and a Linux network namespace")
	}
	dir, err := os.MkdirTemp("", "hydrat-tun-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api.sock")
	adapter := NewAdapter(binary, "unix://"+socket, "1.1.1.1", nil)
	adapter.ConfigureDeviceTunnel()
	config, err := adapter.DeviceConfig(DeviceTunnelOptions{Name: "hydrat-test", APISocket: socket})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	routes, err := adapter.routeDocument([]dataplane.ClientRoute{{
		ClientID: "local-device", SourceCIDR: DeviceTunnelAddress + "/32", BlockTCP: true, BlockUDP: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	routesPath := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(routesPath, []byte(routes), 0600); err != nil {
		t.Fatal(err)
	}
	const script = `
set -eu
ip link set lo up
"$1" run -config "$2" > "$2.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' EXIT
for i in $(seq 1 30); do
  if [ -S "$3" ] && ip link show dev hydrat-test >/dev/null 2>&1; then
    "$1" api statsquery --timeout=2 --server="unix://$3"
    "$1" api adrules --timeout=2 --server="unix://$3" "$4"
    exit 0
  fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.1
done
cat "$2.log"
exit 1
`
	command := exec.CommandContext(ctx, "unshare", "-Urn", "sh", "-c", script, "sh", binary, path, socket, routesPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated TUN startup: %v\n%s", err, output)
	}
}

func TestDeviceGeoOverridesKeepTunnelRulesAheadOfDirect(t *testing.T) {
	a := NewAdapter("unused", "unused", "1.1.1.1", nil)
	a.ConfigureDeviceTunnel()
	a.ConfigureRouting(nil, nil, true)
	a.SetGeoAssetsPresent(true)
	a.ConfigureDeviceGeo(DeviceGeoRules{
		TunnelIP:   []string{"ext-ip:geo-new/geoip.dat:custom"},
		DirectSite: []string{"ext-site:geo-new/geosite.dat:local"},
	})
	doc, err := a.routeDocument(nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := strings.Index(doc, "ext-ip:geo-new/geoip.dat:custom")
	direct := strings.Index(doc, "ext-site:geo-new/geosite.dat:local")
	if tunnel < 0 || direct < tunnel || strings.Contains(doc, "geosite:meta") {
		t.Fatalf("unexpected GeoIP/GeoSite rules: %s", doc)
	}
}

func TestDeviceUnderlayIsAuthenticatedAndSurvivesReconciliation(t *testing.T) {
	adapter := NewAdapter("xray", "", "1.1.1.1", nil)
	adapter.ConfigureDeviceTunnel()
	for _, settings := range []DeviceUnderlay{
		{Address: "0.0.0.0:28080", User: "test", Password: "test-password"},
		{Address: "127.0.0.1:28080", User: "test"},
		{Address: "127.0.0.1:0", User: "test", Password: "test-password"},
	} {
		if err := adapter.ConfigureDeviceUnderlay(settings); err == nil {
			t.Fatal("accepted an unauthenticated or non-local underlay")
		}
	}
	if err := adapter.ConfigureDeviceUnderlay(DeviceUnderlay{
		Address: "127.0.0.1:28080", User: "test", Password: "test-password",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := adapter.DeviceConfig(DeviceTunnelOptions{
		Name: "hydrat-test", APISocket: filepath.Join(t.TempDir(), "api.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Tag, Listen, Protocol string
			Port                  int
			Settings              struct {
				Auth     string
				Accounts []struct{ User, Pass string }
			}
		}
	}
	if err := json.Unmarshal(config, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 2 {
		t.Fatalf("device inbound count: %d", len(doc.Inbounds))
	}
	inbound := doc.Inbounds[1]
	if inbound.Tag != deviceUnderlayTag || inbound.Listen != "127.0.0.1" ||
		inbound.Protocol != "socks" || inbound.Port != 28080 || inbound.Settings.Auth != "password" ||
		len(inbound.Settings.Accounts) != 1 || inbound.Settings.Accounts[0].User != "test" ||
		inbound.Settings.Accounts[0].Pass != "test-password" {
		t.Fatal("the underlay is missing its dedicated loopback socket or authentication")
	}
	for _, routes := range [][]dataplane.ClientRoute{
		nil,
		{{ClientID: "local-device", SourceCIDR: DeviceTunnelAddress + "/32", TCPOutbound: "vless-test", BlockUDP: true}},
	} {
		rendered, err := adapter.routeDocument(routes)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Routing struct {
				Rules []struct {
					RuleTag, OutboundTag string
					InboundTag           []string
				}
			}
		}
		if err := json.Unmarshal([]byte(rendered), &doc); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rule := range doc.Routing.Rules {
			if rule.RuleTag == "hydrat-underlay" {
				found = rule.OutboundTag == "direct" && len(rule.InboundTag) == 1 && rule.InboundTag[0] == deviceUnderlayTag
				break
			}
			if rule.RuleTag == "hydrat-fail-closed" {
				break
			}
		}
		if !found {
			t.Fatal("underlay traffic must go directly before the catch-all block")
		}
	}
}
