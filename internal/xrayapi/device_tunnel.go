package xrayapi

import (
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

const (
	DeviceInboundTag    = "hydrat-device-tun"
	DeviceTunnelAddress = "10.231.90.2"
	deviceDNSIn         = "hydrat-device-dns-upstream"
	deviceDNSOut        = "hydrat-device-dns-out"
	deviceUnderlayTag   = "hydrat-device-underlay"
)

func (adapter *Adapter) ConfigureDeviceTunnel() { adapter.deviceTunnel = true }

func deviceInfrastructureRules() []map[string]any {
	return []map[string]any{
		{"type": "field", "ruleTag": "hydrat-device-ipv6-block", "inboundTag": []string{DeviceInboundTag},
			"ip": []string{"::/0"}, "outboundTag": "block"},
		{"type": "field", "ruleTag": "hydrat-device-dns", "inboundTag": []string{DeviceInboundTag},
			"network": "tcp,udp", "port": "53", "outboundTag": deviceDNSOut},
		{"type": "field", "ruleTag": "hydrat-device-dns-upstream", "inboundTag": []string{deviceDNSIn},
			"outboundTag": "direct"},
	}
}

// DeviceGeoRules holds the Xray matchers for the local device. Empty lists
// omit that route class. Other gateway profiles continue using built-in rules.
type DeviceGeoRules struct {
	TunnelIP   []string
	TunnelSite []string
	DirectIP   []string
	DirectSite []string
}

func (adapter *Adapter) ConfigureDeviceGeo(rules DeviceGeoRules) {
	adapter.deviceGeo = &rules
}

func (adapter *Adapter) effectiveDeviceGeo() DeviceGeoRules {
	if adapter.deviceTunnel && adapter.deviceGeo != nil {
		return *adapter.deviceGeo
	}
	return DeviceGeoRules{
		TunnelIP:   []string{"geoip:ru-blocked", "geoip:facebook"},
		TunnelSite: []string{"geosite:ru-blocked", "geosite:meta"},
		DirectIP:   []string{"geoip:ru"},
		DirectSite: []string{"geosite:category-ru", "geosite:ru-available-only-inside"},
	}
}

func deviceBlockedGeoRules(routes []dataplane.ClientRoute, geo DeviceGeoRules) []map[string]any {
	name := "hydrat-device"
	tcp, udp := "block", "block"
	if len(routes) == 1 {
		route := routes[0]
		name = "hydrat-client-" + route.ClientID
		if !route.BlockTCP && route.TCPOutbound != "" {
			tcp = route.TCPOutbound
		}
		if !route.BlockUDP && route.UDPOutbound != "" {
			udp = route.UDPOutbound
		}
	}
	rules := make([]map[string]any, 0, 4)
	for _, group := range []struct {
		tag, field string
		matchers   []string
	}{{"geosite", "domain", geo.TunnelSite}, {"geoip", "ip", geo.TunnelIP}} {
		if len(group.matchers) == 0 {
			continue
		}
		tag := name + "-blocked-" + group.tag
		rules = append(rules,
			map[string]any{"type": "field", "ruleTag": tag, "inboundTag": []string{DeviceInboundTag},
				group.field: group.matchers, "network": "tcp", "outboundTag": tcp},
			map[string]any{"type": "field", "ruleTag": tag + "-udp", "inboundTag": []string{DeviceInboundTag},
				group.field: group.matchers, "network": "udp", "outboundTag": udp})
	}
	return rules
}

// DeviceUnderlay is an authenticated loopback SOCKS listener for the desktop
// app's own auxiliary processes. It shares Xray's physical interface binding.
type DeviceUnderlay struct {
	Address, User, Password string
}

func (adapter *Adapter) ConfigureDeviceUnderlay(settings DeviceUnderlay) error {
	address, err := netip.ParseAddrPort(settings.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("127.0.0.1") ||
		address.Port() == 0 || settings.User == "" || settings.Password == "" {
		return errors.New("device underlay requires authenticated IPv4 loopback")
	}
	adapter.deviceUnderlay = &settings
	return nil
}

type DeviceTunnelOptions struct {
	Name            string
	APISocket       string
	AutomaticRoutes bool
}

// DeviceConfig renders the initial routing rules. The caller owns the private
// API listener and, on Android, the TUN descriptor.
func (adapter *Adapter) DeviceConfig(options DeviceTunnelOptions) ([]byte, error) {
	if !adapter.deviceTunnel || options.Name == "" || !filepath.IsAbs(options.APISocket) {
		return nil, errors.New("device tunnel needs a name and a private Xray API listener")
	}
	if err := dataplane.ValidateDNSResolverPool(adapter.dnsResolvers); err != nil {
		return nil, err
	}
	if adapter.useGeoRules && !adapter.geoAssetsPresent() {
		return nil, errors.New("device tunnel requires the GeoIP and GeoSite databases")
	}
	rules, err := adapter.routeDocument(nil)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(rules), &config); err != nil {
		return nil, err
	}
	tun := map[string]any{"name": options.Name, "mtu": 1500}
	if options.AutomaticRoutes {
		tun["gateway"] = []string{DeviceTunnelAddress + "/30", "fd24:6b91:e70d::2/126"}
		tun["autoSystemRoutingTable"] = []string{"0.0.0.0/0", "::/0"}
		tun["autoOutboundsInterface"] = "auto"
		tun["dns"] = []string{DeviceTunnelAddress}
		tun["autoSystemDnsToGateway"] = true
		tun["autoSystemWfpBlockLeak"] = []string{"dns", "misconfigtun"}
	}
	config["log"] = map[string]any{"access": "none", "loglevel": "warning"}
	config["api"] = map[string]any{"tag": "api", "listen": options.APISocket,
		"services": []string{"HandlerService", "RoutingService", "StatsService"}}
	config["stats"] = map[string]any{}
	config["policy"] = map[string]any{"system": map[string]bool{"statsInboundUplink": true}}
	config["dns"] = map[string]any{"tag": deviceDNSIn, "queryStrategy": "UseIPv4", "servers": adapter.dnsResolvers}
	inbounds := []map[string]any{{
		"tag": DeviceInboundTag, "protocol": "tun", "settings": tun,
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
	}}
	if uplink := adapter.deviceUnderlay; uplink != nil {
		address := netip.MustParseAddrPort(uplink.Address)
		inbounds = append(inbounds, map[string]any{
			"tag": deviceUnderlayTag, "listen": address.Addr().String(), "port": address.Port(), "protocol": "socks",
			"settings": map[string]any{"auth": "password", "accounts": []map[string]string{{"user": uplink.User, "pass": uplink.Password}}},
		})
	}
	config["inbounds"] = inbounds
	config["outbounds"] = []map[string]any{
		{"tag": "block", "protocol": "blackhole"},
		{"tag": "api", "protocol": "blackhole"},
		{"tag": "direct", "protocol": "freedom", "settings": map[string]string{"domainStrategy": "UseIPv4"}},
		{"tag": deviceDNSOut, "protocol": "dns"},
	}
	return json.Marshal(config)
}
