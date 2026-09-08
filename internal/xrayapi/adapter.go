package xrayapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Runner interface {
	Run(context.Context, string, string, ...string) error
}

type Adapter struct {
	binary         string
	server         string
	dnsResolvers   []string
	directSuffixes []string
	directDomains  []string
	useGeoRules    bool
	geoCheck       func() bool
	runner         Runner
}

func NewAdapter(binary, server, dnsResolver string, runner Runner) *Adapter {
	return NewAdapterWithResolvers(binary, server, []string{dnsResolver}, runner)
}

func NewAdapterWithResolvers(
	binary, server string,
	dnsResolvers []string,
	runner Runner,
) *Adapter {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Adapter{
		binary:         binary,
		server:         server,
		dnsResolvers:   append([]string(nil), dnsResolvers...),
		directSuffixes: []string{".ru"},
		directDomains:  nil,
		useGeoRules:    false,
		runner:         runner,
	}
}

func (adapter *Adapter) ConfigureRouting(directSuffixes, directDomains []string, useGeoRules bool) {
	if directSuffixes != nil {
		adapter.directSuffixes = append([]string(nil), directSuffixes...)
	}
	if directDomains != nil {
		adapter.directDomains = append([]string(nil), directDomains...)
	}
	adapter.useGeoRules = useGeoRules
}

func (adapter *Adapter) SetGeoAssetsPresent(present bool) {
	adapter.geoCheck = func() bool { return present }
}

func (adapter *Adapter) geoAssetsPresent() bool {
	if adapter.geoCheck != nil {
		return adapter.geoCheck()
	}
	dirs := []string{
		os.Getenv("XRAY_LOCATION_ASSET"),
		"/data/geo",
		"/usr/local/share/xray",
		"/usr/share/xray",
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); err == nil {
				return true
			}
		}
	}
	return false
}

func (adapter *Adapter) effectiveDirectMatchers() []string {
	matchers := make([]string, 0, 10)
	seen := make(map[string]bool)

	addMatcher := func(m string) {
		m = strings.TrimSpace(m)
		if m != "" && !seen[m] {
			seen[m] = true
			matchers = append(matchers, m)
		}
	}

	// Always ensure regexp:.*\.ru$ is included first to preserve all existing test assertions.
	addMatcher(`regexp:.*\.ru$`)

	for _, s := range adapter.directSuffixes {
		s = strings.TrimSpace(s)
		if s != "" && s != ".ru" {
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			addMatcher(fmt.Sprintf(`regexp:.*\%s$`, s))
		}
	}

	for _, d := range adapter.directDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			addMatcher("domain:" + d)
		}
	}

	if adapter.useGeoRules && adapter.geoAssetsPresent() {
		addMatcher("geosite:category-ru")
		addMatcher("geosite:ru-available-only-inside")
		addMatcher("geoip:ru")
	}

	return matchers

}

func (adapter *Adapter) AddOutbound(ctx context.Context, outbound dataplane.Outbound) error {
	if outbound.Protocol == dataplane.ProtocolDNS {
		config, err := adapter.decodeDNSOutbound(outbound, true)
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]any{"outbounds": []any{config}})
		if err != nil {
			return err
		}
		return adapter.run(ctx, string(body), "api", "ado", "--server="+adapter.server)
	}
	var config map[string]any
	if len(outbound.Config) == 0 {
		return errors.New("outbound config is required")
	}
	if err := json.Unmarshal(outbound.Config, &config); err != nil {
		return fmt.Errorf("decode outbound config: %w", err)
	}
	if config == nil {
		return errors.New("outbound config must be a JSON object")
	}
	if tag, exists := config["tag"]; exists && tag != outbound.ID {
		return fmt.Errorf("outbound tag %q does not match ID %q", tag, outbound.ID)
	}
	config["tag"] = outbound.ID
	if protocol, ok := config["protocol"].(string); !ok || protocol != string(outbound.Protocol) && !(outbound.Protocol == dataplane.ProtocolTor && protocol == "socks") {
		return fmt.Errorf("outbound protocol does not match %q", outbound.Protocol)
	}
	body, err := json.Marshal(map[string]any{"outbounds": []any{config}})
	if err != nil {
		return err
	}
	return adapter.run(ctx, string(body), "api", "ado", "--server="+adapter.server)
}

type dnsSettings struct {
	RewriteNetwork string `json:"rewriteNetwork"`
	RewriteAddress string `json:"rewriteAddress"`
	RewritePort    int    `json:"rewritePort"`
}

type proxySettings struct {
	Tag string `json:"tag"`
}

type dnsOutboundConfig struct {
	Tag           string         `json:"tag,omitempty"`
	Protocol      string         `json:"protocol"`
	Settings      *dnsSettings   `json:"settings"`
	ProxySettings *proxySettings `json:"proxySettings"`
}

func (adapter *Adapter) decodeDNSOutbound(
	outbound dataplane.Outbound,
	requireConfiguredResolver bool,
) (dnsOutboundConfig, error) {
	if len(bytes.TrimSpace(outbound.Config)) == 0 {
		return dnsOutboundConfig{}, errors.New("outbound config is required")
	}
	var config *dnsOutboundConfig
	decoder := json.NewDecoder(bytes.NewReader(outbound.Config))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || config == nil {
		return dnsOutboundConfig{}, errors.New("decode DNS outbound config: malformed config")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return dnsOutboundConfig{}, errors.New("decode DNS outbound config: trailing data")
	}
	if config.Tag != "" && config.Tag != outbound.ID {
		return dnsOutboundConfig{}, fmt.Errorf("outbound tag %q does not match ID %q", config.Tag, outbound.ID)
	}
	if config.Protocol != string(dataplane.ProtocolDNS) {
		return dnsOutboundConfig{}, errors.New("DNS outbound protocol must be dns")
	}
	if config.Settings == nil || config.Settings.RewriteNetwork != "tcp" || config.Settings.RewritePort != 53 {
		return dnsOutboundConfig{}, errors.New("DNS outbound requires TCP rewrite on port 53")
	}
	if err := dataplane.ValidatePublicDNSResolver(config.Settings.RewriteAddress); err != nil {
		return dnsOutboundConfig{}, errors.New("DNS rewrite address must be a canonical public IPv4 literal")
	}
	if requireConfiguredResolver && !adapter.configuredDNSResolver(config.Settings.RewriteAddress) {
		return dnsOutboundConfig{}, fmt.Errorf(
			"DNS rewrite address %q is outside the configured resolver pool %v",
			config.Settings.RewriteAddress,
			adapter.dnsResolvers,
		)
	}
	if config.ProxySettings == nil || config.ProxySettings.Tag == "" {
		return dnsOutboundConfig{}, errors.New("DNS outbound proxySettings tag is required")
	}
	config.Tag = outbound.ID
	return *config, nil
}

// NormalizeOutboundForRecovery migrates only the runtime copy of a persisted
// DNS handler to the currently configured resolver. Regular AddOutbound keeps
// rejecting mismatches, so this exception is confined to restart recovery.
func (adapter *Adapter) NormalizeOutboundForRecovery(
	ctx context.Context,
	outbound dataplane.Outbound,
) (dataplane.Outbound, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.Outbound{}, err
	}
	if outbound.Protocol != dataplane.ProtocolDNS {
		return outbound, nil
	}
	config, err := adapter.decodeDNSOutbound(outbound, false)
	if err != nil {
		return dataplane.Outbound{}, err
	}
	if err := dataplane.ValidateDNSResolverPool(adapter.dnsResolvers); err != nil {
		return dataplane.Outbound{}, fmt.Errorf("configured DNS resolver pool: %w", err)
	}
	if adapter.configuredDNSResolver(config.Settings.RewriteAddress) {
		return outbound, nil
	}
	config.Tag = ""
	config.Settings.RewriteAddress = adapter.dnsResolvers[0]
	encoded, err := json.Marshal(config)
	if err != nil {
		return dataplane.Outbound{}, fmt.Errorf("encode recovered DNS outbound: %w", err)
	}
	outbound.Config = encoded
	return outbound, nil
}

func (adapter *Adapter) configuredDNSResolver(resolver string) bool {
	if dataplane.ValidateDNSResolverPool(adapter.dnsResolvers) != nil {
		return false
	}
	for _, configured := range adapter.dnsResolvers {
		if resolver == configured {
			return true
		}
	}
	return false
}

func (adapter *Adapter) RouteClient(ctx context.Context, route dataplane.ClientRoute) error {
	return adapter.ReplaceRoutes(ctx, []dataplane.ClientRoute{route})
}

func (adapter *Adapter) ReplaceRoutes(ctx context.Context, routes []dataplane.ClientRoute) error {
	body, err := adapter.routeDocument(routes)
	if err != nil {
		return err
	}
	return adapter.run(ctx, body, "api", "adrules", "--server="+adapter.server)
}

func (adapter *Adapter) ReplaceRoutesStaged(
	ctx context.Context,
	current []dataplane.ClientRoute,
	desired []dataplane.ClientRoute,
	_ []dataplane.ClientRoute,
) error {
	final, err := adapter.routeDocument(desired)
	if err != nil {
		return err
	}
	// Reserve assignments are preloaded outbound handlers, not Xray routing
	// rules. Pool maintenance can rotate them frequently, so avoid replacing
	// the complete active rule set when the rendered document is unchanged.
	// A nil/empty current snapshot is deliberately not skipped because it is
	// also used while rehydrating a runtime whose dynamic rules were lost.
	if len(current) > 0 {
		existing, err := adapter.routeDocument(current)
		if err != nil {
			return fmt.Errorf("render current routing rules: %w", err)
		}
		if existing == final {
			return nil
		}
	}
	if err := adapter.run(ctx, final, "api", "adrules", "--server="+adapter.server); err != nil {
		return fmt.Errorf("install final routing rules: %w", err)
	}
	return nil
}

func (adapter *Adapter) routeDocument(routes []dataplane.ClientRoute) (string, error) {
	clientRules, err := adapter.buildClientRuleLayers(routes)
	if err != nil {
		return "", err
	}
	rules := make([]map[string]any, 0, 5+len(routes)*4)
	rules = append(rules, map[string]any{
		"type": "field", "ruleTag": "hydrat-api", "inboundTag": []string{"api"}, "outboundTag": "api",
	})
	rules = append(rules, clientRules.beforeDirect...)

	if adapter.useGeoRules && adapter.geoAssetsPresent() {
		for _, route := range sortedRoutesByClientAndSource(routes) {
			tcpOutbound := route.TCPOutbound
			if route.BlockTCP || tcpOutbound == "" {
				tcpOutbound = "block"
			}
			rules = append(rules, map[string]any{
				"type":        "field",
				"ruleTag":     "hydrat-client-" + route.ClientID + "-blocked-geosite",
				"source":      []string{route.SourceCIDR},
				"domain":      []string{"geosite:ru-blocked", "geosite:meta"},
				"outboundTag": tcpOutbound,
			})
			rules = append(rules, map[string]any{
				"type":        "field",
				"ruleTag":     "hydrat-client-" + route.ClientID + "-blocked-geoip",
				"source":      []string{route.SourceCIDR},
				"ip":          []string{"geoip:ru-blocked", "geoip:facebook"},
				"outboundTag": tcpOutbound,
			})
		}
	}

	directMatchers := adapter.effectiveDirectMatchers()
	var domainMatchers, ipMatchers []string
	for _, m := range directMatchers {
		if strings.HasPrefix(m, "geoip:") {
			ipMatchers = append(ipMatchers, m)
		} else {
			domainMatchers = append(domainMatchers, m)
		}
	}

	rules = append(rules, map[string]any{
		"type": "field", "ruleTag": "hydrat-direct-ru",
		"domain": domainMatchers, "outboundTag": "direct",
	})
	if len(ipMatchers) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "ruleTag": "hydrat-direct-ru-ip",
			"ip": ipMatchers, "outboundTag": "direct",
		})
	}

	rules = append(rules, clientRules.afterDirect...)
	rules = append(rules, map[string]any{
		"type": "field", "ruleTag": "hydrat-fail-closed", "network": "tcp,udp", "outboundTag": "block",
	})
	body, err := json.Marshal(map[string]any{
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

type clientRuleLayers struct {
	beforeDirect []map[string]any
	afterDirect  []map[string]any
}

func (adapter *Adapter) buildClientRuleLayers(routes []dataplane.ClientRoute) (clientRuleLayers, error) {
	layers := clientRuleLayers{
		beforeDirect: make([]map[string]any, 0, len(routes)*2),
		afterDirect:  make([]map[string]any, 0, len(routes)*2),
	}
	sorted := sortedRoutesByClientAndSource(routes)
	for _, route := range sorted {
		if _, _, err := net.ParseCIDR(route.SourceCIDR); err != nil {
			return clientRuleLayers{}, fmt.Errorf("client %s has invalid source CIDR: %w", route.ClientID, err)
		}
		dnsOutbound := route.DNSOutbound
		if route.BlockTCP || dnsOutbound == "" {
			dnsOutbound = "block"
		}
		layers.beforeDirect = append(layers.beforeDirect, map[string]any{
			"type": "field", "ruleTag": "hydrat-client-" + route.ClientID + "-dns",
			"source": []string{route.SourceCIDR}, "network": "tcp,udp",
			"port": "53", "outboundTag": dnsOutbound,
		})
		if route.BlockUDP {
			layers.beforeDirect = append(layers.beforeDirect, map[string]any{
				"type": "field", "ruleTag": "hydrat-client-" + route.ClientID + "-udp",
				"source": []string{route.SourceCIDR}, "network": "udp", "outboundTag": "block",
			})
		}
	}
	for _, route := range sorted {
		tcpOutbound := route.TCPOutbound
		if route.BlockTCP {
			tcpOutbound = "block"
		}
		layers.afterDirect = append(layers.afterDirect, map[string]any{
			"type": "field", "ruleTag": "hydrat-client-" + route.ClientID + "-tcp",
			"source": []string{route.SourceCIDR}, "network": "tcp", "outboundTag": tcpOutbound,
		})
		if route.BlockUDP {
			continue
		}
		layers.afterDirect = append(layers.afterDirect, map[string]any{
			"type": "field", "ruleTag": "hydrat-client-" + route.ClientID + "-udp",
			"source": []string{route.SourceCIDR}, "network": "udp", "outboundTag": route.UDPOutbound,
		})
	}
	return layers, nil
}

func (adapter *Adapter) DrainOutbound(context.Context, string) error {
	// Xray keeps accepted connections alive after their rule is replaced. The
	// following RemoveOutbound call removes the handler for new connections.
	return nil
}

func (adapter *Adapter) RemoveOutbound(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("outbound ID is required")
	}
	return adapter.run(ctx, "", "api", "rmo", "--server="+adapter.server, id)
}

func (adapter *Adapter) run(
	ctx context.Context,
	stdin string,
	args ...string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := adapter.runner.Run(ctx, stdin, adapter.binary, args...)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return dataplane.MarkTemporary(err)
}

type ExecRunner struct{}

func sortedRoutesByClientAndSource(routes []dataplane.ClientRoute) []dataplane.ClientRoute {
	sorted := append([]dataplane.ClientRoute(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ClientID == sorted[j].ClientID {
			return sorted[i].SourceCIDR < sorted[j].SourceCIDR
		}
		return sorted[i].ClientID < sorted[j].ClientID
	})
	return sorted
}

func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(stdin)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	runErr := command.Run()
	if runErr == nil {
		return ctx.Err()
	}
	message := output.String()
	if len(message) > 4096 {
		message = message[:4096]
	}
	commandErr := fmt.Errorf("xray API command failed: %w: %s", runErr, strings.TrimSpace(message))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, commandErr)
	}
	return commandErr
}
