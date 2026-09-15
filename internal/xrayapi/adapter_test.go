package xrayapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func TestAdapterUsesXrayHandlerAndRoutingAPIsWithoutRestart(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("/usr/local/bin/xray", "127.0.0.1:10085", "1.1.1.1", runner)
	outboundConfig := json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"example.net","port":443}]}}`)
	if err := adapter.AddOutbound(context.Background(), dataplane.Outbound{ID: "candidate-a", Protocol: dataplane.ProtocolVLESS, Config: outboundConfig}); err != nil {
		t.Fatal(err)
	}
	routes := []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "candidate-a", UDPOutbound: "candidate-a"}}
	if err := adapter.ReplaceRoutes(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	if err := adapter.RemoveOutbound(context.Background(), "candidate-a"); err != nil {
		t.Fatal(err)
	}

	wantArgs := [][]string{
		{"api", "ado", "--server=127.0.0.1:10085"},
		{"api", "adrules", "--timeout=20", "--server=127.0.0.1:10085"},
		{"api", "rmo", "--server=127.0.0.1:10085", "candidate-a"},
	}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("args=%v want=%v", runner.args, wantArgs)
	}
	for _, args := range runner.args {
		if strings.Contains(strings.Join(args, " "), "restart") || strings.Contains(strings.Join(args, " "), "run") {
			t.Fatalf("adapter restarted Xray: %v", args)
		}
	}
	if !strings.Contains(runner.stdin[0], `"tag":"candidate-a"`) || !strings.Contains(runner.stdin[1], `"source":["10.44.0.2/32"]`) {
		t.Fatalf("unexpected API configs: %+v", runner.stdin)
	}
	if !strings.Contains(runner.stdin[1], `"domain":["regexp:.*\\.ru$"]`) || !strings.Contains(runner.stdin[1], `"outboundTag":"block"`) {
		t.Fatalf("routing does not enforce .ru-direct/fail-closed: %s", runner.stdin[1])
	}
}

func TestAdapterRejectsOutboundTagMismatchAndMissingClientCIDR(t *testing.T) {
	adapter := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", &recordingRunner{})
	if err := adapter.AddOutbound(context.Background(), dataplane.Outbound{ID: "safe", Protocol: dataplane.ProtocolVLESS, Config: json.RawMessage(`{"tag":"different","protocol":"vless"}`)}); err == nil {
		t.Fatal("tag mismatch must be rejected")
	}
	if err := adapter.ReplaceRoutes(context.Background(), []dataplane.ClientRoute{{ClientID: "alice", TCPOutbound: "safe", UDPOutbound: "safe"}}); err == nil {
		t.Fatal("missing source CIDR must be rejected")
	}
}

func TestAdapterMarksOnlyValidCommandExecutionFailuresTemporary(t *testing.T) {
	isTemporary := func(err error) bool {
		var temporary dataplane.TemporaryError
		return errors.As(err, &temporary) && temporary.Temporary()
	}
	runnerFailure := errors.New("xray API socket reset")
	runner := &faultRunner{failCall: 1, err: runnerFailure}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	err := adapter.ReplaceRoutes(context.Background(), []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "primary", UDPOutbound: "primary",
	}})
	if !errors.Is(err, runnerFailure) || !isTemporary(err) {
		t.Fatalf("runner execution error=%v was not typed temporary", err)
	}

	runner.calls = 0
	err = adapter.ReplaceRoutes(context.Background(), []dataplane.ClientRoute{{
		ClientID: "alice", TCPOutbound: "primary", UDPOutbound: "primary",
	}})
	if err == nil || isTemporary(err) || runner.calls != 0 {
		t.Fatalf("validation error=%v temporary=%v runner_calls=%d",
			err, isTemporary(err), runner.calls)
	}

	runner.calls = 0
	runner.err = context.Canceled
	err = adapter.ReplaceRoutes(context.Background(), []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "primary", UDPOutbound: "primary",
	}})
	if !errors.Is(err, context.Canceled) || isTemporary(err) {
		t.Fatalf("cancellation error=%v was wrapped as temporary", err)
	}

	runner.calls = 0
	runner.err = runnerFailure
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = adapter.ReplaceRoutes(canceled, []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "primary", UDPOutbound: "primary",
	}})
	if !errors.Is(err, context.Canceled) || isTemporary(err) || runner.calls != 0 {
		t.Fatalf("pre-canceled command error=%v temporary=%v runner_calls=%d",
			err, isTemporary(err), runner.calls)
	}
}

func TestAddOutboundRejectsNullConfigWithoutCommand(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", runner)
	err := adapter.AddOutbound(context.Background(), dataplane.Outbound{
		ID:       "safe",
		Protocol: dataplane.ProtocolVLESS,
		Config:   json.RawMessage(`null`),
	})
	if err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("error=%v want non-secret JSON object error", err)
	}
	if len(runner.args) != 0 || len(runner.stdin) != 0 {
		t.Fatalf("null config had partial command side effects: args=%v stdin=%v", runner.args, runner.stdin)
	}
}

func TestAdapterAddsActiveAndReserveDNSOutboundsWithExactResolver(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	for _, outbound := range []dataplane.Outbound{
		{
			ID: "hydrat-dns-active", Protocol: dataplane.ProtocolDNS,
			Config: dnsAdapterConfig("9.9.9.9", "active-handler"),
		},
		{
			ID: "hydrat-dns-reserve", Protocol: dataplane.ProtocolDNS,
			Config: dnsAdapterConfig("9.9.9.9", "reserve-handler"),
		},
	} {
		if err := adapter.AddOutbound(context.Background(), outbound); err != nil {
			t.Fatalf("AddOutbound(%s): %v", outbound.ID, err)
		}
	}
	if len(runner.stdin) != 2 {
		t.Fatalf("DNS ado calls=%d", len(runner.stdin))
	}
	for index, want := range []struct {
		tag   string
		proxy string
	}{
		{tag: "hydrat-dns-active", proxy: "active-handler"},
		{tag: "hydrat-dns-reserve", proxy: "reserve-handler"},
	} {
		var document struct {
			Outbounds []struct {
				Tag      string `json:"tag"`
				Protocol string `json:"protocol"`
				Settings struct {
					RewriteNetwork string `json:"rewriteNetwork"`
					RewriteAddress string `json:"rewriteAddress"`
					RewritePort    int    `json:"rewritePort"`
				} `json:"settings"`
				ProxySettings struct {
					Tag string `json:"tag"`
				} `json:"proxySettings"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(runner.stdin[index]), &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Outbounds) != 1 {
			t.Fatalf("outbounds=%+v", document.Outbounds)
		}
		got := document.Outbounds[0]
		if got.Tag != want.tag || got.Protocol != "dns" ||
			got.Settings.RewriteNetwork != "tcp" ||
			got.Settings.RewriteAddress != "9.9.9.9" || got.Settings.RewritePort != 53 ||
			got.ProxySettings.Tag != want.proxy {
			t.Fatalf("DNS outbound=%+v want tag=%s proxy=%s", got, want.tag, want.proxy)
		}
	}
}

func TestAdapterAcceptsConfiguredResolverPoolAndRejectsOutsideResolver(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapterWithResolvers(
		"xray", "127.0.0.1:10085",
		[]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}, runner,
	)
	for index, resolver := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		err := adapter.AddOutbound(context.Background(), dataplane.Outbound{
			ID: fmt.Sprintf("dns-%d", index), Protocol: dataplane.ProtocolDNS,
			Config: dnsAdapterConfig(resolver, "active"),
		})
		if err != nil {
			t.Fatalf("configured resolver %s rejected: %v", resolver, err)
		}
	}
	err := adapter.AddOutbound(context.Background(), dataplane.Outbound{
		ID: "dns-outside", Protocol: dataplane.ProtocolDNS,
		Config: dnsAdapterConfig("1.0.0.1", "active"),
	})
	if err == nil {
		t.Fatal("resolver outside configured pool was accepted")
	}
	if len(runner.args) != 3 {
		t.Fatalf("commands=%d want only configured resolvers", len(runner.args))
	}
}

func TestAdapterRejectsDNSResolverMismatchAndUnknownFieldsBeforeCommand(t *testing.T) {
	tests := []struct {
		name     string
		resolver string
		config   json.RawMessage
	}{
		{name: "configured resolver mismatch", config: dnsAdapterConfig("1.1.1.1", "active")},
		{name: "special-use resolver", resolver: "198.51.100.1", config: dnsAdapterConfig("198.51.100.1", "active")},
		{name: "top level unknown", config: json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"9.9.9.9","rewritePort":53},"proxySettings":{"tag":"active"},"unknown":true}`)},
		{name: "settings unknown", config: json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"9.9.9.9","rewritePort":53,"unknown":true},"proxySettings":{"tag":"active"}}`)},
		{name: "proxy unknown", config: json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"9.9.9.9","rewritePort":53},"proxySettings":{"tag":"active","unknown":true}}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingRunner{}
			resolver := test.resolver
			if resolver == "" {
				resolver = "9.9.9.9"
			}
			adapter := NewAdapter("xray", "127.0.0.1:10085", resolver, runner)
			err := adapter.AddOutbound(context.Background(), dataplane.Outbound{
				ID: "dns", Protocol: dataplane.ProtocolDNS, Config: test.config,
			})
			if err == nil {
				t.Fatal("unsafe DNS outbound was accepted")
			}
			if len(runner.stdin) != 0 || len(runner.args) != 0 {
				t.Fatalf("rejected DNS outbound issued command: %+v", runner.args)
			}
		})
	}
}

func TestAdapterNormalizesOnlyPersistedDNSResolverDuringRecovery(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	persisted := dataplane.Outbound{
		ID: "old-dns-tag", Protocol: dataplane.ProtocolDNS,
		Config: dnsAdapterConfig("1.1.1.1", "tcp-handler"),
	}
	if err := adapter.AddOutbound(context.Background(), persisted); err == nil {
		t.Fatal("regular Add accepted persisted resolver mismatch")
	}
	normalized, err := adapter.NormalizeOutboundForRecovery(context.Background(), persisted)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ID != persisted.ID || normalized.Protocol != persisted.Protocol {
		t.Fatalf("normalization changed identity: %+v", normalized)
	}
	var config dnsOutboundConfig
	if err := json.Unmarshal(normalized.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Tag != "" || config.Protocol != "dns" || config.Settings == nil ||
		config.Settings.RewriteNetwork != "tcp" || config.Settings.RewritePort != 53 ||
		config.Settings.RewriteAddress != "9.9.9.9" || config.ProxySettings == nil ||
		config.ProxySettings.Tag != "tcp-handler" {
		t.Fatalf("normalized config=%+v", config)
	}
	if err := adapter.AddOutbound(context.Background(), normalized); err != nil {
		t.Fatalf("normalized recovery outbound rejected: %v", err)
	}

	nonDNS := dataplane.Outbound{ID: "candidate", Protocol: dataplane.ProtocolVLESS, Config: json.RawMessage(`{"protocol":"vless"}`)}
	unchanged, err := adapter.NormalizeOutboundForRecovery(context.Background(), nonDNS)
	if err != nil || !reflect.DeepEqual(unchanged, nonDNS) {
		t.Fatalf("non-DNS recovery normalization=%+v error=%v", unchanged, err)
	}
	malformed := persisted
	malformed.Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"udp"}}`)
	if _, err := adapter.NormalizeOutboundForRecovery(context.Background(), malformed); err == nil {
		t.Fatal("malformed persisted DNS was normalized")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.NormalizeOutboundForRecovery(canceled, persisted); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled normalization error=%v", err)
	}
}

func TestAdapterRecoveryPreservesResolverAlreadyAllowedByPool(t *testing.T) {
	adapter := NewAdapterWithResolvers(
		"xray", "127.0.0.1:10085",
		[]string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}, &recordingRunner{},
	)
	persisted := dataplane.Outbound{
		ID: "dns", Protocol: dataplane.ProtocolDNS,
		Config: dnsAdapterConfig("9.9.9.9", "tcp-handler"),
	}
	normalized, err := adapter.NormalizeOutboundForRecovery(context.Background(), persisted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalized, persisted) {
		t.Fatalf("allowed resolver changed during recovery: got=%+v want=%+v", normalized, persisted)
	}
}

func TestAdapterRoutesClientDNSBeforeDirectWithoutDirectFallback(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	routes := []dataplane.ClientRoute{
		{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "tor", DNSOutbound: "dns-alice", BlockUDP: true,
		},
		{
			ClientID: "bob", SourceCIDR: "10.44.0.3/32",
			BlockTCP: true, UDPOutbound: "vless",
		},
	}
	if err := adapter.ReplaceRoutes(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	document := decodeRuleDocument(t, runner.stdin[0])
	assertRuleBefore(t, document, "hydrat-client-alice-dns", "hydrat-direct-ru")
	assertRuleBefore(t, document, "hydrat-client-bob-dns", "hydrat-direct-ru")
	assertRuleOutbound(t, document, "hydrat-client-alice-dns", "dns-alice")
	assertRuleOutbound(t, document, "hydrat-client-bob-dns", "block")
	for _, clientID := range []string{"alice", "bob"} {
		rule := requireDecodedRule(t, document, "hydrat-client-"+clientID+"-dns")
		if rule.Network != "tcp,udp" || rule.Port != "53" || len(rule.Source) != 1 ||
			rule.OutboundTag == "direct" || len(rule.IP) != 0 {
			t.Fatalf("client %s DNS rule=%+v", clientID, rule)
		}
	}
}

func TestAdapterCompleteReplacementKeepsUnaffectedClientDNSOnItsHandler(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	aliceOld := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "old", UDPOutbound: "old", DNSOutbound: "dns-old",
	}
	aliceNew := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "new", UDPOutbound: "new", DNSOutbound: "dns-new",
	}
	bob := dataplane.ClientRoute{
		ClientID: "bob", SourceCIDR: "10.44.0.3/32",
		TCPOutbound: "tor", DNSOutbound: "dns-bob", BlockUDP: true,
	}
	if err := adapter.ReplaceRoutesStaged(
		context.Background(), []dataplane.ClientRoute{aliceOld, bob},
		[]dataplane.ClientRoute{aliceNew, bob}, []dataplane.ClientRoute{aliceOld},
	); err != nil {
		t.Fatal(err)
	}
	if len(runner.stdin) != 1 {
		t.Fatalf("logical replacement used %d physical calls, want one", len(runner.stdin))
	}
	final := decodeRuleDocument(t, runner.stdin[0])
	assertRuleOutbound(t, final, "hydrat-client-bob-dns", "dns-bob")
	if requireDecodedRule(t, final, "hydrat-client-bob-dns").OutboundTag == "direct" {
		t.Fatal("unaffected client DNS fell back to direct")
	}
}

func TestAdapterSkipsRouteReplacementWhenOnlyPreloadedReservesChange(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	current := []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "active", UDPOutbound: "active", DNSOutbound: "dns-active",
		TCPReserveOutbound: "reserve-old", UDPReserveOutbound: "reserve-old",
	}}
	desired := []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "active", UDPOutbound: "active", DNSOutbound: "dns-active",
		TCPReserveOutbound: "reserve-new", UDPReserveOutbound: "reserve-new",
	}}

	if err := adapter.ReplaceRoutesStaged(context.Background(), current, desired, desired); err != nil {
		t.Fatal(err)
	}
	if len(runner.args) != 0 || len(runner.stdin) != 0 {
		t.Fatalf("reserve-only update rewrote active routes: args=%v stdin=%v", runner.args, runner.stdin)
	}
}

func dnsAdapterConfig(resolver, proxy string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":%q,"rewritePort":53},"proxySettings":{"tag":%q}}`,
		resolver, proxy,
	))
}

func TestAdapterUsesExplicitProtocolBlocksForIndependentRoute(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	err := adapter.ReplaceRoutes(context.Background(), []dataplane.ClientRoute{{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "tor", DNSOutbound: "dns-alice", BlockUDP: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := runner.stdin[0]
	if !strings.Contains(body, `"network":"tcp","outboundTag":"tor"`) ||
		!strings.Contains(body, `"network":"udp","outboundTag":"block"`) {
		t.Fatalf("routes=%s", body)
	}
	if !strings.Contains(body, `"ruleTag":"hydrat-client-alice-dns"`) ||
		!strings.Contains(body, `"network":"tcp,udp"`) ||
		!strings.Contains(body, `"port":"53"`) ||
		!strings.Contains(body, `"outboundTag":"dns-alice"`) ||
		strings.Contains(body, `"ip":["9.9.9.9"]`) {
		t.Fatalf("TCP-only client has no constrained DNS route: %s", body)
	}
	var config struct {
		Routing struct {
			Rules []struct {
				RuleTag string `json:"ruleTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	positions := make(map[string]int)
	for index, rule := range config.Routing.Rules {
		positions[rule.RuleTag] = index
	}
	if positions["hydrat-client-alice-dns"] >= positions["hydrat-direct-ru"] ||
		positions["hydrat-client-alice-udp"] >= positions["hydrat-direct-ru"] ||
		positions["hydrat-client-alice-tcp"] <= positions["hydrat-direct-ru"] {
		t.Fatalf("TCP-only route does not block non-DNS UDP before .ru direct: positions=%v body=%s", positions, body)
	}
}

func TestAdapterSwitchesAffectedClientsWithOneCompleteRuleReplacement(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	current := []dataplane.ClientRoute{
		{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old", UDPOutbound: "old"},
		{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
	}
	desired := []dataplane.ClientRoute{
		{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", UDPOutbound: "new"},
		{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
	}
	if err := adapter.ReplaceRoutesStaged(context.Background(), current, desired, []dataplane.ClientRoute{current[0]}); err != nil {
		t.Fatal(err)
	}
	if len(runner.stdin) != 1 {
		t.Fatalf("adrules calls=%d want=1", len(runner.stdin))
	}
	for index, args := range runner.args {
		if !reflect.DeepEqual(args, []string{"api", "adrules", "--timeout=20", "--server=127.0.0.1:10085"}) {
			t.Fatalf("call %d args=%v", index, args)
		}
	}

	final := decodeRuleDocument(t, runner.stdin[0])
	if strings.Contains(runner.stdin[0], `"ruleTag":"hydrat-stage-`) {
		t.Fatalf("replacement contains a temporary blocking stage: %s", runner.stdin[0])
	}
	assertRuleOutbound(t, final, "hydrat-client-alice-tcp", "new")
	assertRuleOutbound(t, final, "hydrat-client-alice-udp", "new")
	assertRuleOutbound(t, final, "hydrat-client-bob-tcp", "stable")
	assertRuleOutbound(t, final, "hydrat-client-bob-udp", "stable")
	assertRuleOutbound(t, final, "hydrat-fail-closed", "block")
}

func TestAdapterRouteReplacementAllowsLoadedXrayToFinish(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	route := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "route", UDPOutbound: "route",
	}

	if err := adapter.ReplaceRoutesStaged(context.Background(), nil, []dataplane.ClientRoute{route}, []dataplane.ClientRoute{route}); err != nil {
		t.Fatal(err)
	}
	want := []string{"api", "adrules", "--timeout=20", "--server=127.0.0.1:10085"}
	if !reflect.DeepEqual(runner.args[0], want) {
		t.Fatalf("adrules args=%v want=%v", runner.args[0], want)
	}
}

func TestAdapterReturnsUnknownFinalOutcomeAfterOneCall(t *testing.T) {
	route := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "new", UDPOutbound: "new",
	}
	runner := &faultRunner{failCall: 1, err: context.Canceled}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	err := adapter.ReplaceRoutesStaged(
		context.Background(), nil, []dataplane.ClientRoute{route},
		[]dataplane.ClientRoute{route},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
	if runner.calls != 1 {
		t.Fatalf("calls=%d want=1", runner.calls)
	}
}

func TestAdapterFinalRulesUseUniqueTagsAfterClientCIDRChange(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	oldRoute := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "old", UDPOutbound: "old",
	}
	newRoute := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.22/32",
		TCPOutbound: "new", UDPOutbound: "new",
	}
	if err := adapter.ReplaceRoutesStaged(
		context.Background(),
		[]dataplane.ClientRoute{oldRoute},
		[]dataplane.ClientRoute{newRoute},
		[]dataplane.ClientRoute{oldRoute, newRoute},
	); err != nil {
		t.Fatal(err)
	}
	stage := decodeRuleDocument(t, runner.stdin[0])
	seen := make(map[string]struct{}, len(stage.Routing.Rules))
	for _, rule := range stage.Routing.Rules {
		if _, exists := seen[rule.RuleTag]; exists {
			t.Fatalf("duplicate staging ruleTag %q", rule.RuleTag)
		}
		seen[rule.RuleTag] = struct{}{}
	}
}

func TestAdapterCompleteReplacementPreservesUnchangedTCPOnlyClientRulesExactly(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "9.9.9.9", runner)
	aliceOld := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "old", UDPOutbound: "old",
	}
	aliceNew := dataplane.ClientRoute{
		ClientID: "alice", SourceCIDR: "10.44.0.2/32",
		TCPOutbound: "new", UDPOutbound: "new",
	}
	bob := dataplane.ClientRoute{
		ClientID: "bob", SourceCIDR: "10.44.0.3/32",
		TCPOutbound: "tor", DNSOutbound: "dns-bob", BlockUDP: true,
	}
	if err := adapter.ReplaceRoutesStaged(
		context.Background(),
		[]dataplane.ClientRoute{aliceOld, bob},
		[]dataplane.ClientRoute{aliceNew, bob},
		[]dataplane.ClientRoute{aliceOld},
	); err != nil {
		t.Fatal(err)
	}
	final := decodeRuleDocument(t, runner.stdin[0])
	assertRuleOutbound(t, final, "hydrat-client-alice-tcp", "new")
	assertRuleOutbound(t, final, "hydrat-client-alice-udp", "new")
	assertRuleOutbound(t, final, "hydrat-client-bob-dns", "dns-bob")
	assertRuleOutbound(t, final, "hydrat-client-bob-udp", "block")
	assertRuleOutbound(t, final, "hydrat-client-bob-tcp", "tor")
	assertRuleBefore(t, final, "hydrat-client-bob-dns", "hydrat-client-bob-udp")
	assertRuleBefore(t, final, "hydrat-client-bob-udp", "hydrat-direct-ru")
	assertRuleBefore(t, final, "hydrat-direct-ru", "hydrat-client-bob-tcp")
	dnsRule := requireDecodedRule(t, final, "hydrat-client-bob-dns")
	if dnsRule.Network != "tcp,udp" || dnsRule.Port != "53" ||
		!reflect.DeepEqual(dnsRule.Source, []string{"10.44.0.3/32"}) ||
		len(dnsRule.IP) != 0 {
		t.Fatalf("staged Bob DNS rule does not preserve full match semantics: %+v", dnsRule)
	}
}

func TestMainXrayUsesStaticAPIAndFailClosedDefaultOutbound(t *testing.T) {
	data, err := os.ReadFile("../../config/xray/main.json")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		API struct {
			Listen string `json:"listen"`
		} `json:"api"`
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.API.Listen != "127.0.0.1:10085" {
		t.Fatalf("api.listen=%q", config.API.Listen)
	}
	if len(config.Outbounds) == 0 || config.Outbounds[0].Tag != "block" || config.Outbounds[0].Protocol != "blackhole" {
		t.Fatalf("default outbound is not static fail-closed: %+v", config.Outbounds)
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "api" {
			t.Fatal("routed API inbound defeats static API reachability")
		}
	}
}

func TestExecRunnerReturnsContextCanceledForKilledInFlightProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- (ExecRunner{}).Run(ctx, "", "/bin/sh", "-c", "exec sleep 10")
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled subprocess did not exit")
	}
}

func TestExecRunnerReturnsDeadlineExceededForKilledProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := (ExecRunner{}).Run(ctx, "", "/bin/sh", "-c", "exec sleep 10")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error=%v want context.DeadlineExceeded", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("deadline did not terminate subprocess promptly: %s", time.Since(started))
	}
}

type decodedRule struct {
	RuleTag     string   `json:"ruleTag"`
	OutboundTag string   `json:"outboundTag"`
	Network     string   `json:"network"`
	Port        string   `json:"port"`
	Source      []string `json:"source"`
	Domain      []string `json:"domain"`
	IP          []string `json:"ip"`
}

type ruleDocument struct {
	Routing struct {
		Rules []decodedRule `json:"rules"`
	} `json:"routing"`
}

func decodeRuleDocument(t *testing.T, body string) ruleDocument {
	t.Helper()
	var document ruleDocument
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func assertRuleBefore(t *testing.T, document ruleDocument, first, second string) {
	t.Helper()
	positions := make(map[string]int)
	for index, rule := range document.Routing.Rules {
		positions[rule.RuleTag] = index
	}
	firstPosition, firstExists := positions[first]
	secondPosition, secondExists := positions[second]
	if !firstExists || !secondExists || firstPosition >= secondPosition {
		t.Fatalf("rule order %s=%d/%t %s=%d/%t", first, firstPosition, firstExists, second, secondPosition, secondExists)
	}
}

func assertRuleOutbound(t *testing.T, document ruleDocument, ruleTag, outboundTag string) {
	t.Helper()
	for _, rule := range document.Routing.Rules {
		if rule.RuleTag == ruleTag {
			if rule.OutboundTag != outboundTag {
				t.Fatalf("rule %s outbound=%q want=%q", ruleTag, rule.OutboundTag, outboundTag)
			}
			return
		}
	}
	t.Fatalf("missing rule %s", ruleTag)
}

func requireDecodedRule(t *testing.T, document ruleDocument, ruleTag string) decodedRule {
	t.Helper()
	for _, rule := range document.Routing.Rules {
		if rule.RuleTag == ruleTag {
			return rule
		}
	}
	t.Fatalf("missing rule %s", ruleTag)
	return decodedRule{}
}

type faultRunner struct {
	calls    int
	failCall int
	err      error
}

func (runner *faultRunner) Run(_ context.Context, _ string, _ string, _ ...string) error {
	runner.calls++
	if runner.calls == runner.failCall {
		return runner.err
	}
	return nil
}

type recordingRunner struct {
	args  [][]string
	stdin []string
}

func (runner *recordingRunner) Run(_ context.Context, stdin string, _ string, args ...string) error {
	runner.args = append(runner.args, append([]string(nil), args...))
	runner.stdin = append(runner.stdin, stdin)
	return nil
}

func TestSmartRoutingWithMultiSuffixesAndDomains(t *testing.T) {
	runner := &recordingRunner{}
	adapter := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", runner)
	adapter.ConfigureRouting(
		[]string{".ru", ".su", ".xn--p1ai"},
		[]string{"thecode.media", "habr.com"},
		false,
	)

	routes := []dataplane.ClientRoute{
		{
			ClientID:    "alice",
			SourceCIDR:  "10.44.0.2/32",
			TCPOutbound: "vless-1",
			UDPOutbound: "vless-1",
		},
	}
	if err := adapter.ReplaceRoutes(context.Background(), routes); err != nil {
		t.Fatal(err)
	}

	rawDoc := runner.stdin[0]
	for _, expected := range []string{
		`domain:thecode.media`,
		`domain:habr.com`,
		`regexp:.*\\.ru$`,
		`regexp:.*\\.su$`,
		`regexp:.*\\.xn--p1ai$`,
	} {
		if !strings.Contains(rawDoc, expected) {
			t.Fatalf("routing document missing %q; got: %s", expected, rawDoc)
		}
	}

	doc := decodeRuleDocument(t, rawDoc)
	directRule := requireDecodedRule(t, doc, "hydrat-direct-ru")
	if directRule.OutboundTag != "direct" {
		t.Fatalf("outboundTag = %q, want direct", directRule.OutboundTag)
	}
	if len(directRule.Domain) < 5 || directRule.Domain[0] != `regexp:.*\.ru$` {
		t.Fatalf("first direct matcher must be regexp:.*\\.ru$, got: %v", directRule.Domain)
	}
}

func TestSmartRoutingWithGeoRules(t *testing.T) {
	t.Run("geo rules enabled and assets present", func(t *testing.T) {
		runner := &recordingRunner{}
		adapter := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", runner)
		adapter.ConfigureRouting(
			[]string{".ru", ".su"},
			[]string{"thecode.media", "habr.com"},
			true,
		)
		adapter.SetGeoAssetsPresent(true)

		routes := []dataplane.ClientRoute{
			{
				ClientID:    "alice",
				SourceCIDR:  "10.44.0.2/32",
				TCPOutbound: "vless-active",
				UDPOutbound: "vless-active",
			},
		}
		if err := adapter.ReplaceRoutes(context.Background(), routes); err != nil {
			t.Fatal(err)
		}

		rawDoc := runner.stdin[0]
		doc := decodeRuleDocument(t, rawDoc)

		assertRuleBefore(t, doc, "hydrat-client-alice-blocked-geosite", "hydrat-direct-ru")
		blockedGeosite := requireDecodedRule(t, doc, "hydrat-client-alice-blocked-geosite")
		if blockedGeosite.OutboundTag != "vless-active" || !reflect.DeepEqual(blockedGeosite.Domain, []string{"geosite:ru-blocked", "geosite:meta"}) {
			t.Fatalf("unexpected blocked geosite rule: %+v", blockedGeosite)
		}

		blockedGeoIP := requireDecodedRule(t, doc, "hydrat-client-alice-blocked-geoip")
		if blockedGeoIP.OutboundTag != "vless-active" || !reflect.DeepEqual(blockedGeoIP.IP, []string{"geoip:ru-blocked", "geoip:facebook"}) {
			t.Fatalf("unexpected blocked geoip rule: %+v", blockedGeoIP)
		}

		directRule := requireDecodedRule(t, doc, "hydrat-direct-ru")
		foundCategoryRU := false
		for _, d := range directRule.Domain {
			if d == "geosite:category-ru" {
				foundCategoryRU = true
			}
		}
		if !foundCategoryRU {
			t.Fatalf("hydrat-direct-ru missing geosite:category-ru: %v", directRule.Domain)
		}

		directIPRule := requireDecodedRule(t, doc, "hydrat-direct-ru-ip")
		if directIPRule.OutboundTag != "direct" || !reflect.DeepEqual(directIPRule.IP, []string{"geoip:ru"}) {
			t.Fatalf("unexpected direct IP rule: %+v", directIPRule)
		}
	})

	t.Run("geo rules enabled but assets absent", func(t *testing.T) {
		runner := &recordingRunner{}
		adapter := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", runner)
		adapter.ConfigureRouting(
			[]string{".ru", ".su"},
			[]string{"thecode.media"},
			true,
		)
		adapter.SetGeoAssetsPresent(false)

		routes := []dataplane.ClientRoute{
			{
				ClientID:    "alice",
				SourceCIDR:  "10.44.0.2/32",
				TCPOutbound: "vless-active",
				UDPOutbound: "vless-active",
			},
		}
		if err := adapter.ReplaceRoutes(context.Background(), routes); err != nil {
			t.Fatal(err)
		}

		rawDoc := runner.stdin[0]
		if strings.Contains(rawDoc, "geosite:") || strings.Contains(rawDoc, "geoip:") {
			t.Fatalf("expected geo rules to be omitted when assets absent, got: %s", rawDoc)
		}
	})
}
