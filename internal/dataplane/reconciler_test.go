package dataplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriteAppliedPlanSyncsParentDirectoryAfterRename(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "applied.json")
	syncCalls := 0
	err := writeAppliedPlanWithSync(path, AppliedPlan{
		DesiredPlan: DesiredPlan{Generation: 7}, Digest: "digest",
	}, func(got string) error {
		syncCalls++
		if got != directory {
			t.Fatalf("synced directory=%q want=%q", got, directory)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("plan was not renamed before directory sync: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if syncCalls != 1 {
		t.Fatalf("directory sync calls=%d want=1", syncCalls)
	}
}

func TestBuildDNSOutboundUsesDeterministicCollisionSafeTargetDigest(t *testing.T) {
	target := Outbound{
		ID: "active", Protocol: ProtocolVLESS,
		Config: json.RawMessage(`{"protocol":"vless","settings":{"address":"example.net"}}`),
	}
	first, err := BuildDNSOutbound("alice", target, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDNSOutbound("alice", target, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("deterministic DNS outbound differs: first=%+v second=%+v", first, second)
	}
	const prefix = "hydrat-dns-"
	if !strings.HasPrefix(first.ID, prefix) || len(first.ID) != len(prefix)+64 {
		t.Fatalf("DNS tag=%q", first.ID)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(first.ID, prefix)); err != nil {
		t.Fatalf("DNS tag digest: %v", err)
	}
	if first.Protocol != ProtocolDNS {
		t.Fatalf("DNS protocol=%q", first.Protocol)
	}
	var config struct {
		Protocol string `json:"protocol"`
		Settings struct {
			RewriteNetwork string `json:"rewriteNetwork"`
			RewriteAddress string `json:"rewriteAddress"`
			RewritePort    int    `json:"rewritePort"`
		} `json:"settings"`
		StreamSettings struct {
			Sockopt struct {
				DialerProxy string `json:"dialerProxy"`
			} `json:"sockopt"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(first.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Protocol != "dns" || config.Settings.RewriteNetwork != "tcp" ||
		config.Settings.RewriteAddress != "9.9.9.9" || config.Settings.RewritePort != 53 ||
		config.StreamSettings.Sockopt.DialerProxy != target.ID {
		t.Fatalf("DNS config=%+v", config)
	}

	reserve, err := BuildDNSOutbound("alice", Outbound{
		ID: "reserve", Protocol: ProtocolTor,
		Config: json.RawMessage(`{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19050}]}}`),
	}, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if reserve.ID == first.ID {
		t.Fatal("active and reserve DNS handlers collided")
	}
	left, err := BuildDNSOutbound("a", Outbound{ID: "bc", Protocol: ProtocolVLESS}, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildDNSOutbound("ab", Outbound{ID: "c", Protocol: ProtocolVLESS}, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if left.ID == right.ID {
		t.Fatal("length-ambiguous client/target inputs collided")
	}
	changedTarget := target
	changedTarget.Config = json.RawMessage(`{"protocol":"vless","settings":{"address":"other.example"}}`)
	changed, err := BuildDNSOutbound("alice", changedTarget, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if changed.ID == first.ID {
		t.Fatal("target semantic change reused DNS handler tag")
	}
	otherResolver, err := BuildDNSOutbound("alice", target, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if otherResolver.ID == first.ID {
		t.Fatal("resolver semantic change reused DNS handler tag")
	}
	formattedTarget := target
	formattedTarget.Config = json.RawMessage("{\n  \"settings\": {\"address\": \"example.net\"},\n  \"protocol\": \"vless\"\n}")
	formatted, err := BuildDNSOutbound("alice", formattedTarget, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if formatted.ID != first.ID {
		t.Fatal("JSON formatting changed DNS handler tag")
	}
}

func TestSelectDNSResolverIsStableAndDistributesCandidates(t *testing.T) {
	resolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	first, err := SelectDNSResolver("candidate-a", resolvers)
	if err != nil {
		t.Fatal(err)
	}
	again, err := SelectDNSResolver("candidate-a", resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("unstable resolver selection: first=%q again=%q", first, again)
	}
	seen := map[string]bool{first: true}
	for index := 0; index < 100; index++ {
		resolver, err := SelectDNSResolver(fmt.Sprintf("candidate-%d", index), resolvers)
		if err != nil {
			t.Fatal(err)
		}
		seen[resolver] = true
	}
	if len(seen) != len(resolvers) {
		t.Fatalf("resolver selection used %v, want all %v", seen, resolvers)
	}
	for _, testCase := range []struct {
		name      string
		candidate string
		resolvers []string
	}{
		{name: "missing candidate", resolvers: resolvers},
		{name: "empty pool", candidate: "candidate"},
		{name: "duplicate", candidate: "candidate", resolvers: []string{"1.1.1.1", "1.1.1.1"}},
		{name: "private", candidate: "candidate", resolvers: []string{"10.0.0.1"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := SelectDNSResolver(testCase.candidate, testCase.resolvers); err == nil {
				t.Fatal("invalid resolver selection input was accepted")
			}
		})
	}
}

func TestSemanticDigestIgnoresGenerationAndSetOrderingWithoutMutation(t *testing.T) {
	plan := semanticTestPlan()
	before := cloneSemanticTestPlan(t, plan)
	reordered := cloneSemanticTestPlan(t, plan)
	reordered.Generation = 99
	reordered.Outbounds[0], reordered.Outbounds[1] = reordered.Outbounds[1], reordered.Outbounds[0]
	reordered.Clients[0], reordered.Clients[1] = reordered.Clients[1], reordered.Clients[0]
	reordered.DirectSuffixes[0], reordered.DirectSuffixes[1] = reordered.DirectSuffixes[1], reordered.DirectSuffixes[0]
	reorderedBefore := cloneSemanticTestPlan(t, reordered)

	first, err := plan.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := reordered.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantic digests differ for reordered plan: %s != %s", first, second)
	}
	if !reflect.DeepEqual(plan, before) {
		t.Fatalf("SemanticDigest mutated input:\nbefore=%+v\nafter=%+v", before, plan)
	}
	if !reflect.DeepEqual(reordered, reorderedBefore) {
		t.Fatalf("SemanticDigest sorted caller slices in place:\nbefore=%+v\nafter=%+v", reorderedBefore, reordered)
	}
}

func TestSemanticDigestChangesForEveryOutboundRouteAndPolicyField(t *testing.T) {
	base := semanticTestPlan()
	baseDigest, err := base.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*DesiredPlan)
	}{
		{name: "outbound ID", change: func(plan *DesiredPlan) { plan.Outbounds[0].ID = "changed" }},
		{name: "outbound protocol", change: func(plan *DesiredPlan) { plan.Outbounds[0].Protocol = ProtocolTor }},
		{name: "outbound config", change: func(plan *DesiredPlan) {
			plan.Outbounds[0].Config = json.RawMessage(`{"marker":"changed","nested":{"enabled":true}}`)
		}},
		{name: "client ID", change: func(plan *DesiredPlan) { plan.Clients[0].ClientID = "changed" }},
		{name: "source CIDR", change: func(plan *DesiredPlan) { plan.Clients[0].SourceCIDR = "10.44.0.9/32" }},
		{name: "TCP route", change: func(plan *DesiredPlan) { plan.Clients[0].TCPOutbound = "vless-b" }},
		{name: "UDP route", change: func(plan *DesiredPlan) { plan.Clients[0].UDPOutbound = "vless-b" }},
		{name: "DNS route", change: func(plan *DesiredPlan) { plan.Clients[0].DNSOutbound = "dns-b" }},
		{name: "TCP reserve", change: func(plan *DesiredPlan) { plan.Clients[0].TCPReserveOutbound = "vless-b" }},
		{name: "UDP reserve", change: func(plan *DesiredPlan) { plan.Clients[0].UDPReserveOutbound = "vless-b" }},
		{name: "TCP block", change: func(plan *DesiredPlan) { plan.Clients[0].BlockTCP = true }},
		{name: "UDP block", change: func(plan *DesiredPlan) { plan.Clients[0].BlockUDP = true }},
		{name: "direct suffix", change: func(plan *DesiredPlan) { plan.DirectSuffixes[0] = ".net" }},
		{name: "direct domain", change: func(plan *DesiredPlan) { plan.DirectDomains = []string{"added.com"} }},
		{name: "fail closed", change: func(plan *DesiredPlan) { plan.FailClosed = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneSemanticTestPlan(t, base)
			test.change(&changed)
			digest, err := changed.SemanticDigest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseDigest {
				t.Fatalf("semantic digest ignored %s change", test.name)
			}
		})
	}
}

func TestSemanticDigestCanonicalizesOutboundJSONAndRejectsInvalidJSON(t *testing.T) {
	first := semanticTestPlan()
	second := cloneSemanticTestPlan(t, first)
	second.Outbounds[0].Config = json.RawMessage("{\n  \"nested\": {\"enabled\": true},\n  \"marker\": \"a\"\n}")
	firstDigest, err := first.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("JSON formatting changed semantic digest: %s != %s", firstDigest, secondDigest)
	}

	invalid := semanticTestPlan()
	invalid.Outbounds[0].Config = json.RawMessage(`{"marker":`)
	if _, err := invalid.SemanticDigest(); err == nil {
		t.Fatal("invalid outbound JSON produced a semantic digest")
	}
	trailing := semanticTestPlan()
	trailing.Outbounds[0].Config = json.RawMessage(`{} {}`)
	if _, err := trailing.SemanticDigest(); err == nil {
		t.Fatal("multiple outbound JSON values produced a semantic digest")
	}
}

func semanticTestPlan() DesiredPlan {
	return DesiredPlan{
		Generation: 7,
		Outbounds: []Outbound{
			{ID: "vless-a", Protocol: ProtocolVLESS, Config: json.RawMessage(`{"marker":"a","nested":{"enabled":true}}`)},
			{ID: "vless-b", Protocol: ProtocolVLESS, Config: json.RawMessage(`{"marker":"b","nested":{"enabled":false}}`)},
			{ID: "dns-a", Protocol: ProtocolDNS, Config: dnsTestConfig("vless-a")},
			{ID: "dns-b", Protocol: ProtocolDNS, Config: dnsTestConfig("vless-b")},
		},
		Clients: []ClientRoute{
			{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "vless-a", UDPOutbound: "vless-a", DNSOutbound: "dns-a"},
			{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "vless-b", UDPOutbound: "vless-b", DNSOutbound: "dns-b"},
		},
		DirectSuffixes: []string{".ru", ".example"},
		FailClosed:     true,
	}
}

func dnsTestConfig(proxy string) json.RawMessage {
	return dnsTestConfigResolver(proxy, "1.1.1.1")
}

func dnsTestConfigResolver(proxy, resolver string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":%q,"rewritePort":53},"streamSettings":{"sockopt":{"dialerProxy":%q}}}`,
		resolver, proxy,
	))
}

func TestPlanValidatesDNSAndReserveHandlerGraphBeforeSideEffects(t *testing.T) {
	valid := DesiredPlan{
		Generation: 1,
		Outbounds: []Outbound{
			{ID: "primary", Protocol: ProtocolVLESS},
			{ID: "tcp-reserve", Protocol: ProtocolTor},
			{ID: "udp-reserve", Protocol: ProtocolVLESS},
			{ID: "dns", Protocol: ProtocolDNS, Config: dnsTestConfig("primary")},
		},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "primary", UDPOutbound: "primary", DNSOutbound: "dns",
			TCPReserveOutbound: "tcp-reserve", UDPReserveOutbound: "udp-reserve",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid DNS reserve plan: %v", err)
	}

	tests := []struct {
		name   string
		change func(*DesiredPlan)
	}{
		{name: "unknown DNS", change: func(plan *DesiredPlan) { plan.Clients[0].DNSOutbound = "missing" }},
		{name: "non-DNS route", change: func(plan *DesiredPlan) { plan.Clients[0].DNSOutbound = "primary" }},
		{name: "unknown TCP reserve", change: func(plan *DesiredPlan) { plan.Clients[0].TCPReserveOutbound = "missing" }},
		{name: "TCP reserve equals primary", change: func(plan *DesiredPlan) { plan.Clients[0].TCPReserveOutbound = "primary" }},
		{name: "unknown UDP reserve", change: func(plan *DesiredPlan) { plan.Clients[0].UDPReserveOutbound = "missing" }},
		{name: "UDP reserve equals primary", change: func(plan *DesiredPlan) { plan.Clients[0].UDPReserveOutbound = "primary" }},
		{name: "Tor UDP reserve", change: func(plan *DesiredPlan) { plan.Clients[0].UDPReserveOutbound = "tcp-reserve" }},
		{name: "DNS missing config", change: func(plan *DesiredPlan) { plan.Outbounds[3].Config = nil }},
		{name: "DNS null config", change: func(plan *DesiredPlan) { plan.Outbounds[3].Config = json.RawMessage(`null`) }},
		{name: "DNS malformed config", change: func(plan *DesiredPlan) { plan.Outbounds[3].Config = json.RawMessage(`{"protocol":`) }},
		{name: "DNS wrong protocol", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"freedom","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS missing proxy", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53}}`)
		}},
		{name: "DNS self reference", change: func(plan *DesiredPlan) { plan.Outbounds[3].Config = dnsTestConfig("dns") }},
		{name: "DNS unknown reference", change: func(plan *DesiredPlan) { plan.Outbounds[3].Config = dnsTestConfig("missing") }},
		{name: "DNS chain cycle", change: func(plan *DesiredPlan) {
			plan.Outbounds = append(plan.Outbounds,
				Outbound{ID: "dns-two", Protocol: ProtocolDNS, Config: dnsTestConfig("dns")},
			)
			plan.Outbounds[3].Config = dnsTestConfig("dns-two")
		}},
		{name: "DNS UDP rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"udp","rewriteAddress":"1.1.1.1","rewritePort":53},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS non-53 rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":853},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS hostname rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"resolver.example","rewritePort":53},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS private rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"10.44.0.1","rewritePort":53},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS shared address space rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfigResolver("primary", "100.64.0.1")
		}},
		{name: "DNS documentation rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfigResolver("primary", "192.0.2.1")
		}},
		{name: "DNS benchmark rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfigResolver("primary", "198.18.0.1")
		}},
		{name: "DNS test net two rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfigResolver("primary", "198.51.100.1")
		}},
		{name: "DNS test net three rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfigResolver("primary", "203.0.113.1")
		}},
		{name: "DNS mapped rewrite", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"::ffff:1.1.1.1","rewritePort":53},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS top-level unknown", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53},"proxySettings":{"tag":"primary"},"unknown":true}`)
		}},
		{name: "DNS settings unknown", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53,"unknown":true},"proxySettings":{"tag":"primary"}}`)
		}},
		{name: "DNS proxy unknown", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = json.RawMessage(`{"protocol":"dns","settings":{"rewriteNetwork":"tcp","rewriteAddress":"1.1.1.1","rewritePort":53},"proxySettings":{"tag":"primary","unknown":true}}`)
		}},
		{name: "DNS proxy differs from client TCP", change: func(plan *DesiredPlan) {
			plan.Outbounds[3].Config = dnsTestConfig("udp-reserve")
		}},
		{name: "reserve without primary", change: func(plan *DesiredPlan) { plan.Clients[0].TCPOutbound = ""; plan.Clients[0].BlockTCP = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := cloneSemanticTestPlan(t, valid)
			test.change(&plan)
			adapter := &recordingAdapter{}
			reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := reconciler.Apply(context.Background(), plan); err == nil {
				t.Fatal("invalid plan was accepted")
			} else if len(plan.Outbounds[3].Config) != 0 &&
				strings.Contains(err.Error(), string(plan.Outbounds[3].Config)) {
				t.Fatalf("validation error exposed outbound config: %v", err)
			}
			if len(adapter.operations) != 0 {
				t.Fatalf("invalid plan touched dataplane: %v", adapter.operations)
			}
		})
	}
}

func TestPlanAllowsUnreferencedPreloadedReserveDNSHandler(t *testing.T) {
	plan := DesiredPlan{
		Generation: 1,
		Outbounds: []Outbound{
			{ID: "primary", Protocol: ProtocolVLESS},
			{ID: "reserve", Protocol: ProtocolTor},
			{ID: "dns-primary", Protocol: ProtocolDNS, Config: dnsTestConfig("primary")},
			{ID: "dns-reserve", Protocol: ProtocolDNS, Config: dnsTestConfig("reserve")},
		},
		Clients: []ClientRoute{{
			ClientID: "alice", TCPOutbound: "primary", BlockUDP: true,
			DNSOutbound: "dns-primary", TCPReserveOutbound: "reserve",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("preloaded reserve DNS handler rejected: %v", err)
	}
}

func cloneSemanticTestPlan(t *testing.T, plan DesiredPlan) DesiredPlan {
	t.Helper()
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var clone DesiredPlan
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestReconcileUsesAddRouteDrainRemoveOrderAndPersistsGeneration(t *testing.T) {
	adapter := &recordingAdapter{}
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, err := NewReconciler(adapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	first := DesiredPlan{
		Generation:     1,
		Outbounds:      []Outbound{{ID: "old", Protocol: ProtocolVLESS}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "old", UDPOutbound: "old"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil

	second := DesiredPlan{
		Generation:     2,
		Outbounds:      []Outbound{{ID: "new", Protocol: ProtocolVLESS}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "new", UDPOutbound: "new"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	want := []string{"add:new", "route:alice:new:new", "drain:old", "remove:old"}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("operations=%v want=%v", adapter.operations, want)
	}

	adapter.operations = nil
	restarted, err := NewReconciler(adapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want = []string{"add:new", "route:alice:new:new"}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("restart did not rehydrate dataplane: operations=%v want=%v", adapter.operations, want)
	}
	adapter.operations = nil
	if err := restarted.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if len(adapter.operations) != 0 {
		t.Fatalf("idempotent apply emitted operations after rehydration: %v", adapter.operations)
	}
}

func TestRehydrateAppliesPersistedPlanWithoutNewGeneration(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "applied.json")
	firstAdapter := &recordingAdapter{}
	first, _ := NewReconciler(firstAdapter, statePath)
	plan := DesiredPlan{
		Generation: 3,
		Outbounds:  []Outbound{{ID: "live", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{{
			ClientID: "alice", TCPOutbound: "live", UDPOutbound: "live",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	restartedAdapter := &recordingAdapter{}
	restarted, err := NewReconciler(restartedAdapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"add:live", "route:alice:live:live"}
	if !reflect.DeepEqual(restartedAdapter.operations, want) {
		t.Fatalf("operations=%v want=%v", restartedAdapter.operations, want)
	}
}

func TestRehydrateForgetsTrackedRuntimeHandlersAfterXrayRestart(t *testing.T) {
	adapter := &recordingAdapter{}
	reconciler, _ := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	plan := DesiredPlan{
		Generation:     1,
		Outbounds:      []Outbound{{ID: "live", Protocol: ProtocolVLESS}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "live", UDPOutbound: "live"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil
	if err := reconciler.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"add:live", "route:alice:live:live"}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("rehydrate operations=%v want=%v", adapter.operations, want)
	}
}

func TestInvalidateRuntimePreventsSameGenerationNoOp(t *testing.T) {
	adapter := &recordingAdapter{}
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := DesiredPlan{
		Generation:     1,
		Outbounds:      []Outbound{{ID: "live", Protocol: ProtocolVLESS}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "live", UDPOutbound: "live"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil

	reconciler.InvalidateRuntime()
	if err := reconciler.Apply(context.Background(), plan); !errors.Is(err, ErrRuntimeRecovering) {
		t.Fatalf("Apply error=%v want ErrRuntimeRecovering", err)
	}
	if len(adapter.operations) != 0 {
		t.Fatalf("recovering Apply touched adapter: %v", adapter.operations)
	}
	if err := reconciler.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"add:live", "route:alice:live:live"}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("rehydrate operations=%v want=%v", adapter.operations, want)
	}
}

func TestRuntimeRecoveryRejectsConcurrentApplyUntilSuccessfulRehydrate(t *testing.T) {
	adapter := newDuplicateRejectingRecoveryAdapter()
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, err := NewReconciler(adapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	persisted := singleRoutePlan(1, "live", nil)
	if err := reconciler.Apply(context.Background(), persisted); err != nil {
		t.Fatal(err)
	}
	adapter.restartRuntimeAndBlockRoute(false)
	reconciler.InvalidateRuntime()

	rehydrateResult := make(chan error, 1)
	go func() {
		rehydrateResult <- reconciler.Rehydrate(context.Background())
	}()
	select {
	case <-adapter.routeEntered:
	case <-time.After(time.Second):
		t.Fatal("Rehydrate did not reach route replacement")
	}

	concurrentPlan := singleRoutePlan(2, "next", nil)
	applyResult := make(chan error, 1)
	go func() {
		applyResult <- reconciler.Apply(context.Background(), concurrentPlan)
	}()
	select {
	case err := <-applyResult:
		t.Fatalf("Apply returned while Rehydrate owned the mutex: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if adapter.hasOperation("add:next") {
		t.Fatal("concurrent Apply touched adapter while Rehydrate was active")
	}

	close(adapter.releaseRoute)
	if err := <-rehydrateResult; err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if err := <-applyResult; !errors.Is(err, ErrRuntimeRecovering) {
		t.Fatalf("concurrent Apply error=%v want ErrRuntimeRecovering", err)
	}
	if adapter.hasOperation("add:next") {
		t.Fatal("recovering Apply performed an adapter command")
	}
	loaded, err := NewReconciler(&recordingAdapter{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.applied.Generation != persisted.Generation {
		t.Fatalf(
			"recovering Apply persisted generation=%d want=%d",
			loaded.applied.Generation,
			persisted.Generation,
		)
	}
	if adds := adapter.addCount("live"); adds != 1 {
		t.Fatalf("acknowledged live handler adds=%d want=1", adds)
	}
	if err := reconciler.Apply(context.Background(), concurrentPlan); err != nil {
		t.Fatalf("Apply after recovery: %v", err)
	}
	if !adapter.hasOperation("add:next") {
		t.Fatal("Apply after recovery did not reach adapter")
	}
}

func TestRuntimeRecoveryCachesAcknowledgedAddsAcrossFailedRehydrate(t *testing.T) {
	adapter := newDuplicateRejectingRecoveryAdapter()
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	persisted := singleRoutePlan(1, "live", nil)
	if err := reconciler.Apply(context.Background(), persisted); err != nil {
		t.Fatal(err)
	}
	adapter.restartRuntimeAndBlockRoute(true)
	close(adapter.releaseRoute)
	reconciler.InvalidateRuntime()

	if err := reconciler.Rehydrate(context.Background()); err == nil {
		t.Fatal("first Rehydrate unexpectedly succeeded")
	}
	operationsBeforeApply := adapter.operationsSnapshot()
	if err := reconciler.Apply(context.Background(), singleRoutePlan(2, "next", nil)); !errors.Is(err, ErrRuntimeRecovering) {
		t.Fatalf("Apply error=%v want ErrRuntimeRecovering", err)
	}
	if got := adapter.operationsSnapshot(); !reflect.DeepEqual(got, operationsBeforeApply) {
		t.Fatalf("recovering Apply touched adapter: before=%v after=%v", operationsBeforeApply, got)
	}
	if err := reconciler.Rehydrate(context.Background()); err != nil {
		t.Fatalf("retry Rehydrate: %v", err)
	}
	if adds := adapter.addCount("live"); adds != 1 {
		t.Fatalf("acknowledged live handler adds=%d want=1", adds)
	}
}

func TestReconcileRejectsUnsafePlanBeforeTouchingDataplane(t *testing.T) {
	adapter := &recordingAdapter{}
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	torOnUDP := DesiredPlan{
		Generation:     1,
		Outbounds:      []Outbound{{ID: "tor", Protocol: ProtocolTor}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "tor", UDPOutbound: "tor"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), torOnUDP); err == nil {
		t.Fatal("Tor UDP plan must be rejected")
	}
	if len(adapter.operations) != 0 {
		t.Fatalf("invalid plan touched dataplane: %v", adapter.operations)
	}
}

func TestPlanValidatesTCPAndUDPIndependently(t *testing.T) {
	tcpOnly := DesiredPlan{
		Generation: 1,
		Outbounds:  []Outbound{{ID: "tor", Protocol: ProtocolTor}},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "tor", BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := tcpOnly.Validate(); err != nil {
		t.Fatalf("TCP-only plan: %v", err)
	}
	udpOnly := DesiredPlan{
		Generation: 1,
		Outbounds:  []Outbound{{ID: "vless", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			BlockTCP: true, UDPOutbound: "vless",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := udpOnly.Validate(); err != nil {
		t.Fatalf("UDP-only plan: %v", err)
	}
	unsafe := tcpOnly
	unsafe.Clients[0].BlockUDP = false
	if err := unsafe.Validate(); err == nil {
		t.Fatal("missing UDP route without explicit block was accepted")
	}
}

func TestFailedApplyDoesNotAdvanceAppliedSnapshot(t *testing.T) {
	adapter := &recordingAdapter{routeError: errors.New("xray route failed")}
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, _ := NewReconciler(adapter, statePath)
	plan := DesiredPlan{
		Generation:     1,
		Outbounds:      []Outbound{{ID: "vless", Protocol: ProtocolVLESS}},
		Clients:        []ClientRoute{{ClientID: "alice", TCPOutbound: "vless", UDPOutbound: "vless"}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), plan); err == nil {
		t.Fatal("expected adapter error")
	}
	adapter.routeError = nil
	adapter.operations = nil
	if err := reconciler.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(adapter.operations) == 0 {
		t.Fatal("failed generation was incorrectly considered applied")
	}
}

func TestReconcileUsesAtomicRouteBatchWhenAdapterSupportsIt(t *testing.T) {
	adapter := &batchingAdapter{recordingAdapter: recordingAdapter{}}
	reconciler, _ := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	plan := DesiredPlan{
		Generation: 1,
		Outbounds:  []Outbound{{ID: "vless", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{
			{ClientID: "alice", TCPOutbound: "vless", UDPOutbound: "vless"},
			{ClientID: "bob", TCPOutbound: "vless", UDPOutbound: "vless"},
		},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if adapter.batches != 1 {
		t.Fatalf("route batches=%d", adapter.batches)
	}
	for _, operation := range adapter.operations {
		if len(operation) >= 6 && operation[:6] == "route:" {
			t.Fatalf("per-client route call used with batch adapter: %v", adapter.operations)
		}
	}
}

func TestReconcileStagesAffectedClientsBeforeFinalRulesAndRemoval(t *testing.T) {
	adapter := &stagedBatchingAdapter{}
	reconciler, _ := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	first := DesiredPlan{
		Generation: 1,
		Outbounds: []Outbound{
			{ID: "old", Protocol: ProtocolVLESS},
			{ID: "stable", Protocol: ProtocolVLESS},
		},
		Clients: []ClientRoute{
			{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old", UDPOutbound: "old"},
			{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
		},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil

	second := DesiredPlan{
		Generation: 2,
		Outbounds: []Outbound{
			{ID: "new", Protocol: ProtocolVLESS},
			{ID: "stable", Protocol: ProtocolVLESS},
		},
		Clients: []ClientRoute{
			{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", UDPOutbound: "new"},
			{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
		},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add:new",
		"stage:alice",
		"final:alice,bob",
		"drain:old",
		"remove:old",
	}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("operations=%v want=%v", adapter.operations, want)
	}
}

func TestReconcileStagedFailureDoesNotAcknowledgeOrRemoveAndRetryConverges(t *testing.T) {
	adapter := &stagedBatchingAdapter{}
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, _ := NewReconciler(adapter, statePath)
	first := DesiredPlan{
		Generation: 1,
		Outbounds: []Outbound{
			{ID: "old", Protocol: ProtocolVLESS},
			{ID: "stable", Protocol: ProtocolVLESS},
		},
		Clients: []ClientRoute{
			{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "old", UDPOutbound: "old"},
			{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
		},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil
	adapter.failFinal = true
	adapter.finalError = context.Canceled
	second := DesiredPlan{
		Generation: 2,
		Outbounds: []Outbound{
			{ID: "new", Protocol: ProtocolVLESS},
			{ID: "stable", Protocol: ProtocolVLESS},
		},
		Clients: []ClientRoute{
			{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", UDPOutbound: "new"},
			{ClientID: "bob", SourceCIDR: "10.44.0.3/32", TCPOutbound: "stable", UDPOutbound: "stable"},
		},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	if err := reconciler.Apply(context.Background(), second); !errors.Is(err, context.Canceled) {
		t.Fatalf("final replacement fault=%v want cancellation", err)
	}
	if got := adapter.operations; !reflect.DeepEqual(got, []string{"add:new", "stage:alice", "final:alice,bob"}) {
		t.Fatalf("failed apply operations=%v", got)
	}
	persisted, err := NewReconciler(&recordingAdapter{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.applied.Generation != 1 {
		t.Fatalf("failed staged apply acknowledged generation=%d", persisted.applied.Generation)
	}

	adapter.operations = nil
	adapter.failFinal = false
	adapter.finalError = nil
	if err := reconciler.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	want := []string{"stage:alice,bob", "final:alice,bob", "drain:old", "remove:old"}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("retry operations=%v want=%v", adapter.operations, want)
	}
}

func TestReconcileOrdersCandidateDNSRoutesAndDependencyRemovalLayers(t *testing.T) {
	adapter := newDNSLayerAdapter()
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(context.Background(), dnsLayerPlan(1, "z-old-candidate", "a-old-dns")); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil

	desired := dnsLayerPlanWithReserve(2)
	if err := reconciler.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add-candidate:y-reserve-candidate",
		"add-candidate:z-active-candidate",
		"add-dns:a-active-dns",
		"add-dns:b-reserve-dns",
		"replace-routes",
		"drain-dns:a-old-dns",
		"remove-dns:a-old-dns",
		"drain-candidate:z-old-candidate",
		"remove-candidate:z-old-candidate",
	}
	if !reflect.DeepEqual(adapter.operations, want) {
		t.Fatalf("layered operations=%v want=%v", adapter.operations, want)
	}
	if adapter.missingDependency {
		t.Fatal("layered reconcile referenced or removed an outbound before its dependency")
	}
	if got := countOperations(adapter.operations, "replace-routes"); got != 1 {
		t.Fatalf("logical ReplaceRoutes phases=%d want=1", got)
	}
}

func TestReconcileDNSLayersFailureAndCancellationRetryConverge(t *testing.T) {
	for _, failure := range []string{
		"add-candidate:y-reserve-candidate",
		"add-dns:a-active-dns",
		"replace-routes",
		"remove-dns:a-old-dns",
		"remove-candidate:z-old-candidate",
	} {
		for _, injected := range []struct {
			name string
			err  error
		}{
			{name: "failure", err: errors.New("injected failure")},
			{name: "cancellation", err: context.Canceled},
		} {
			t.Run(failure+"/"+injected.name, func(t *testing.T) {
				adapter := newDNSLayerAdapter()
				statePath := filepath.Join(t.TempDir(), "applied.json")
				reconciler, err := NewReconciler(adapter, statePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := reconciler.Apply(context.Background(), dnsLayerPlan(1, "z-old-candidate", "a-old-dns")); err != nil {
					t.Fatal(err)
				}
				adapter.operations = nil
				adapter.failOperation = failure
				adapter.failError = injected.err

				desired := dnsLayerPlanWithReserve(2)
				err = reconciler.Apply(context.Background(), desired)
				if !errors.Is(err, injected.err) {
					t.Fatalf("Apply error=%v want=%v", err, injected.err)
				}
				persisted, err := NewReconciler(newDNSLayerAdapter(), statePath)
				if err != nil {
					t.Fatal(err)
				}
				if persisted.applied.Generation != 1 {
					t.Fatalf("failed apply acknowledged generation=%d", persisted.applied.Generation)
				}
				if adapter.missingDependency || adapter.directDNS {
					t.Fatalf("failed apply violated fail-closed dependencies: missing=%t directDNS=%t", adapter.missingDependency, adapter.directDNS)
				}

				adapter.failOperation = ""
				adapter.failError = nil
				if err := reconciler.Apply(context.Background(), desired); err != nil {
					t.Fatalf("retry Apply: %v", err)
				}
				if adapter.missingDependency || adapter.directDNS {
					t.Fatalf("retry violated dependencies: missing=%t directDNS=%t", adapter.missingDependency, adapter.directDNS)
				}
				if got, want := adapter.handlerIDs(), []string{
					"a-active-dns", "b-reserve-dns", "y-reserve-candidate", "z-active-candidate",
				}; !reflect.DeepEqual(got, want) {
					t.Fatalf("converged handlers=%v want=%v", got, want)
				}
				persisted, err = NewReconciler(newDNSLayerAdapter(), statePath)
				if err != nil {
					t.Fatal(err)
				}
				if persisted.applied.Generation != 2 {
					t.Fatalf("retry persisted generation=%d", persisted.applied.Generation)
				}
			})
		}
	}
}

func TestReconcileDNSLayersAmbiguousPostEffectOutcomesRetryConverge(t *testing.T) {
	for _, failure := range []string{
		"add-candidate:y-reserve-candidate",
		"add-dns:a-active-dns",
		"remove-dns:a-old-dns",
		"remove-candidate:z-old-candidate",
	} {
		for _, injected := range []struct {
			name string
			err  error
		}{
			{name: "failure", err: errors.New("response lost after effect")},
			{name: "cancellation", err: context.Canceled},
		} {
			t.Run(failure+"/"+injected.name, func(t *testing.T) {
				adapter := newDNSLayerAdapter()
				adapter.rejectDuplicate = true
				adapter.rejectMissing = true
				statePath := filepath.Join(t.TempDir(), "applied.json")
				reconciler, err := NewReconciler(adapter, statePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := reconciler.Apply(context.Background(), dnsLayerPlan(1, "z-old-candidate", "a-old-dns")); err != nil {
					t.Fatal(err)
				}
				adapter.operations = nil
				adapter.failOperation = failure
				adapter.failError = injected.err
				adapter.failAfterEffect = true
				adapter.failAfterEffectCount = 2

				desired := dnsLayerPlanWithReserve(2)
				for attempt := 1; attempt <= 2; attempt++ {
					err = reconciler.Apply(context.Background(), desired)
					if !errors.Is(err, injected.err) {
						t.Fatalf("ambiguous attempt %d error=%v want=%v operations=%v", attempt, err, injected.err, adapter.operations)
					}
				}
				adapter.failOperation = ""
				adapter.failError = nil
				if err := reconciler.Apply(context.Background(), desired); err != nil {
					t.Fatalf("retry after repeated ambiguous outcomes: %v; operations=%v", err, adapter.operations)
				}
				if got, want := adapter.handlerIDs(), []string{
					"a-active-dns", "b-reserve-dns", "y-reserve-candidate", "z-active-candidate",
				}; !reflect.DeepEqual(got, want) {
					t.Fatalf("converged handlers=%v want=%v", got, want)
				}
				if adapter.missingDependency || adapter.directDNS {
					t.Fatalf("ambiguous retry violated fail-closed graph: missing=%t direct=%t", adapter.missingDependency, adapter.directDNS)
				}
				persisted, err := NewReconciler(newDNSLayerAdapter(), statePath)
				if err != nil {
					t.Fatal(err)
				}
				if persisted.applied.Generation != 2 {
					t.Fatalf("converged generation=%d", persisted.applied.Generation)
				}
			})
		}
	}
}

func TestReconcileNormalizesPendingAddWhenNextDesiredDropsItsID(t *testing.T) {
	adapter := newDNSLayerAdapter()
	adapter.rejectDuplicate = true
	adapter.rejectMissing = true
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(context.Background(), dnsLayerPlan(1, "z-old-candidate", "a-old-dns")); err != nil {
		t.Fatal(err)
	}
	adapter.failOperation = "add-candidate:y-reserve-candidate"
	adapter.failError = context.Canceled
	if err := reconciler.Apply(context.Background(), dnsLayerPlanWithReserve(2)); !errors.Is(err, context.Canceled) {
		t.Fatalf("failed intermediate Apply error=%v", err)
	}
	adapter.failOperation = ""
	adapter.failError = nil

	latest := dnsLayerPlan(3, "x-latest-candidate", "x-latest-dns")
	if err := reconciler.Apply(context.Background(), latest); err != nil {
		t.Fatalf("Apply dropping pending ID: %v; operations=%v", err, adapter.operations)
	}
	if got, want := adapter.handlerIDs(), []string{"x-latest-candidate", "x-latest-dns"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("handlers after dropping pending ID=%v want=%v", got, want)
	}
}

func TestReconcileNormalizesPendingRemoveBeforeIDReappears(t *testing.T) {
	adapter := newDNSLayerAdapter()
	adapter.rejectDuplicate = true
	adapter.rejectMissing = true
	reconciler, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := dnsLayerPlan(1, "z-old-candidate", "a-old-dns")
	if err := reconciler.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	adapter.failOperation = "remove-candidate:z-old-candidate"
	adapter.failError = context.Canceled
	adapter.failAfterEffect = true
	adapter.failAfterEffectCount = 1
	if err := reconciler.Apply(context.Background(), dnsLayerPlanWithReserve(2)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ambiguous removal error=%v", err)
	}
	adapter.failOperation = ""
	adapter.failError = nil
	reappeared := old
	reappeared.Generation = 3
	if err := reconciler.Apply(context.Background(), reappeared); err != nil {
		t.Fatalf("Apply reappearing ID: %v; operations=%v", err, adapter.operations)
	}
	if got, want := adapter.handlerIDs(), []string{"a-old-dns", "z-old-candidate"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("handlers after reappearance=%v want=%v", got, want)
	}
}

func TestRehydrateRestoresCandidateBeforeDNSAndThenRoutes(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "applied.json")
	firstAdapter := newDNSLayerAdapter()
	first, err := NewReconciler(firstAdapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	plan := dnsLayerPlanWithReserve(1)
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}

	restartedAdapter := newDNSLayerAdapter()
	restarted, err := NewReconciler(restartedAdapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add-candidate:y-reserve-candidate",
		"add-candidate:z-active-candidate",
		"add-dns:a-active-dns",
		"add-dns:b-reserve-dns",
		"replace-routes",
	}
	if !reflect.DeepEqual(restartedAdapter.operations, want) {
		t.Fatalf("rehydrate operations=%v want=%v", restartedAdapter.operations, want)
	}
	if restartedAdapter.missingDependency || restartedAdapter.directDNS {
		t.Fatalf("rehydrate violated dependencies: missing=%t directDNS=%t", restartedAdapter.missingDependency, restartedAdapter.directDNS)
	}
	restartedAdapter.operations = nil
	if err := restarted.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(restartedAdapter.operations) != 0 {
		t.Fatalf("post-rehydrate apply was not idempotent: %v", restartedAdapter.operations)
	}
}

func TestRehydrateMigratesPersistedDNSResolverBeforeNextGeneration(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "applied.json")
	target := Outbound{ID: "stable-candidate", Protocol: ProtocolVLESS}
	oldDNS, err := BuildDNSOutbound("alice", target, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	oldPlan := DesiredPlan{
		Generation: 1,
		Outbounds:  []Outbound{target, oldDNS},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: target.ID, UDPOutbound: target.ID, DNSOutbound: oldDNS.ID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	first, err := NewReconciler(newDNSLayerAdapter(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(context.Background(), oldPlan); err != nil {
		t.Fatal(err)
	}

	recoveryAdapter := &dnsRecoveryAdapter{dnsLayerAdapter: newDNSLayerAdapter(), resolver: "9.9.9.9"}
	restarted, err := NewReconciler(recoveryAdapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dnsResolverFromTestConfig(t, recoveryAdapter.handlers[oldDNS.ID].Config); got != "9.9.9.9" {
		t.Fatalf("rehydrated DNS resolver=%q", got)
	}
	if len(recoveryAdapter.lastRoutes) != 1 || recoveryAdapter.lastRoutes[0].DNSOutbound != oldDNS.ID {
		t.Fatalf("rehydrated routes=%+v want old DNS tag %s", recoveryAdapter.lastRoutes, oldDNS.ID)
	}
	persistedAfterRecovery, err := NewReconciler(newDNSLayerAdapter(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsResolverFromTestConfig(t, persistedAfterRecovery.applied.Outbounds[1].Config); got != "1.1.1.1" {
		t.Fatalf("Rehydrate rewrote persisted desired resolver=%q", got)
	}

	newDNS, err := BuildDNSOutbound("alice", target, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if newDNS.ID == oldDNS.ID {
		t.Fatal("resolver migration reused DNS tag")
	}
	newPlan := oldPlan
	newPlan.Generation = 2
	newPlan.Outbounds = []Outbound{target, newDNS}
	newPlan.Clients = append([]ClientRoute(nil), oldPlan.Clients...)
	newPlan.Clients[0].DNSOutbound = newDNS.ID
	if err := restarted.Apply(context.Background(), newPlan); err != nil {
		t.Fatalf("apply current resolver generation: %v", err)
	}
	if got, want := recoveryAdapter.handlerIDs(), []string{newDNS.ID, target.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("post-migration handlers=%v want=%v", got, want)
	}
}

func TestRehydrateResolverNormalizationCancellationRetriesWithoutSideEffects(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "applied.json")
	target := Outbound{ID: "stable-candidate", Protocol: ProtocolVLESS}
	dns, err := BuildDNSOutbound("alice", target, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	plan := DesiredPlan{
		Generation: 1, Outbounds: []Outbound{target, dns},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: target.ID, UDPOutbound: target.ID, DNSOutbound: dns.ID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
	first, err := NewReconciler(newDNSLayerAdapter(), statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}

	adapter := &dnsRecoveryAdapter{
		dnsLayerAdapter:          newDNSLayerAdapter(),
		resolver:                 "9.9.9.9",
		normalizeFailures:        2,
		normalizeFailureResponse: context.Canceled,
	}
	restarted, err := NewReconciler(adapter, statePath)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := restarted.Rehydrate(context.Background()); !errors.Is(err, context.Canceled) {
			t.Fatalf("normalization attempt %d error=%v", attempt, err)
		}
		if len(adapter.handlers) != 0 || len(adapter.lastRoutes) != 0 {
			t.Fatalf("failed normalization had side effects: handlers=%v routes=%v", adapter.handlerIDs(), adapter.lastRoutes)
		}
	}
	if err := restarted.Rehydrate(context.Background()); err != nil {
		t.Fatalf("normalization retry: %v", err)
	}
	if got, want := adapter.handlerIDs(), []string{dns.ID, target.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rehydrated handlers=%v want=%v", got, want)
	}
}

func dnsResolverFromTestConfig(t *testing.T, encoded json.RawMessage) string {
	t.Helper()
	var config struct {
		Settings struct {
			RewriteAddress string `json:"rewriteAddress"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	return config.Settings.RewriteAddress
}

func dnsLayerPlan(generation int64, candidateID, dnsID string) DesiredPlan {
	return DesiredPlan{
		Generation: generation,
		Outbounds: []Outbound{
			{ID: candidateID, Protocol: ProtocolVLESS},
			{ID: dnsID, Protocol: ProtocolDNS, Config: dnsTestConfig(candidateID)},
		},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: candidateID, UDPOutbound: candidateID, DNSOutbound: dnsID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
}

func dnsLayerPlanWithReserve(generation int64) DesiredPlan {
	return DesiredPlan{
		Generation: generation,
		Outbounds: []Outbound{
			{ID: "z-active-candidate", Protocol: ProtocolVLESS},
			{ID: "y-reserve-candidate", Protocol: ProtocolTor},
			{ID: "a-active-dns", Protocol: ProtocolDNS, Config: dnsTestConfig("z-active-candidate")},
			{ID: "b-reserve-dns", Protocol: ProtocolDNS, Config: dnsTestConfig("y-reserve-candidate")},
		},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "z-active-candidate", UDPOutbound: "z-active-candidate",
			DNSOutbound: "a-active-dns", TCPReserveOutbound: "y-reserve-candidate",
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
}

func countOperations(operations []string, target string) int {
	count := 0
	for _, operation := range operations {
		if operation == target {
			count++
		}
	}
	return count
}

func TestReconcileSerializesConcurrentGenerationsWithoutInterleaving(t *testing.T) {
	adapter := newControlledConcurrentAdapter()
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, _ := NewReconciler(adapter, statePath)
	if err := reconciler.Apply(context.Background(), singleRoutePlan(1, "g1", nil)); err != nil {
		t.Fatal(err)
	}
	adapter.resetOperations()

	g2Result := make(chan error, 1)
	go func() {
		g2Result <- reconciler.Apply(context.Background(), singleRoutePlan(2, "g2", nil))
	}()
	select {
	case <-adapter.g2Entered:
	case <-time.After(time.Second):
		t.Fatal("generation 2 did not enter staged replacement")
	}
	g3Result := make(chan error, 1)
	go func() {
		g3Result <- reconciler.Apply(context.Background(), singleRoutePlan(3, "g3", nil))
	}()

	interleaved := false
	select {
	case <-adapter.g3Touched:
		interleaved = true
	case <-time.After(150 * time.Millisecond):
	}
	close(adapter.releaseG2)
	if err := <-g2Result; err != nil {
		t.Fatalf("generation 2: %v", err)
	}
	if err := <-g3Result; err != nil {
		t.Fatalf("generation 3: %v", err)
	}
	if interleaved {
		t.Fatal("generation 3 touched the adapter while generation 2 transaction was in progress")
	}
	if adapter.missingReference {
		t.Fatal("staged transaction referenced a handler that was not loaded")
	}
	if reconciler.applied.Generation != 3 || adapter.lastRoute != "g3" {
		t.Fatalf("runtime generation=%d route=%q want generation=3 route=g3", reconciler.applied.Generation, adapter.lastRoute)
	}
	persisted, err := NewReconciler(&recordingAdapter{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.applied.Generation != 3 {
		t.Fatalf("persisted generation=%d want=3", persisted.applied.Generation)
	}
	if got := adapter.handlerIDs(); !reflect.DeepEqual(got, []string{"g3"}) {
		t.Fatalf("runtime handlers=%v want=[g3]", got)
	}
	wantOperations := []string{
		"add:g2", "stage:g2", "final:g2", "drain:g1", "remove:g1",
		"add:g3", "stage:g3", "final:g3", "drain:g2", "remove:g2",
	}
	if operations := adapter.operationsSnapshot(); !reflect.DeepEqual(operations, wantOperations) {
		t.Fatalf("operation generations interleaved: got=%v want=%v", operations, wantOperations)
	}
}

func TestReconcileRejectsChangedImmutableOutboundBeforeSideEffects(t *testing.T) {
	adapter := &recordingAdapter{}
	statePath := filepath.Join(t.TempDir(), "applied.json")
	reconciler, _ := NewReconciler(adapter, statePath)
	firstConfig := json.RawMessage(`{"protocol":"vless","settings":{"address":"one.example","port":443}}`)
	if err := reconciler.Apply(context.Background(), singleRoutePlan(1, "stable-id", firstConfig)); err != nil {
		t.Fatal(err)
	}
	adapter.operations = nil

	changedConfig := json.RawMessage(`{"settings":{"port":443,"address":"two.example"},"protocol":"vless"}`)
	err := reconciler.Apply(context.Background(), singleRoutePlan(2, "stable-id", changedConfig))
	if err == nil || !strings.Contains(err.Error(), `outbound ID "stable-id" is immutable`) {
		t.Fatalf("changed same-ID config error=%v", err)
	}
	if len(adapter.operations) != 0 {
		t.Fatalf("immutable-ID rejection touched dataplane: %v", adapter.operations)
	}
	persisted, err := NewReconciler(&recordingAdapter{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.applied.Generation != 1 {
		t.Fatalf("rejected plan persisted generation=%d", persisted.applied.Generation)
	}

	semanticConfig := json.RawMessage("{\n  \"settings\": {\"port\": 443, \"address\": \"one.example\"},\n  \"protocol\": \"vless\"\n}")
	if err := reconciler.Apply(context.Background(), singleRoutePlan(2, "stable-id", semanticConfig)); err != nil {
		t.Fatalf("semantically identical config rejected: %v", err)
	}
	for _, operation := range adapter.operations {
		if strings.HasPrefix(operation, "add:") || strings.HasPrefix(operation, "remove:") {
			t.Fatalf("semantically identical config churned handler: %v", adapter.operations)
		}
	}
}

func singleRoutePlan(generation int64, outboundID string, config json.RawMessage) DesiredPlan {
	return DesiredPlan{
		Generation: generation,
		Outbounds:  []Outbound{{ID: outboundID, Protocol: ProtocolVLESS, Config: config}},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: outboundID, UDPOutbound: outboundID,
		}},
		DirectSuffixes: []string{".ru"}, FailClosed: true,
	}
}

type recordingAdapter struct {
	operations []string
	routeError error
}

type dnsLayerAdapter struct {
	handlers             map[string]Outbound
	operations           []string
	failOperation        string
	failError            error
	failAfterEffect      bool
	failAfterEffectCount int
	rejectDuplicate      bool
	rejectMissing        bool
	missingDependency    bool
	directDNS            bool
	lastRoutes           []ClientRoute
}

func newDNSLayerAdapter() *dnsLayerAdapter {
	return &dnsLayerAdapter{handlers: make(map[string]Outbound)}
}

func (adapter *dnsLayerAdapter) AddOutbound(_ context.Context, outbound Outbound) error {
	kind := "candidate"
	if outbound.Protocol == ProtocolDNS {
		kind = "dns"
	}
	operation := "add-" + kind + ":" + outbound.ID
	adapter.operations = append(adapter.operations, operation)
	if operation == adapter.failOperation && !adapter.failAfterEffect {
		return adapter.failError
	}
	if outbound.Protocol == ProtocolDNS {
		proxy, err := validateDNSOutboundConfig(outbound.Config)
		if err != nil {
			return err
		}
		if _, exists := adapter.handlers[proxy]; !exists {
			adapter.missingDependency = true
			return fmt.Errorf("DNS dependency %s is not loaded", proxy)
		}
	}
	if adapter.rejectDuplicate {
		if _, exists := adapter.handlers[outbound.ID]; exists {
			return fmt.Errorf("duplicate outbound %s", outbound.ID)
		}
	}
	adapter.handlers[outbound.ID] = outbound
	if operation == adapter.failOperation && adapter.failAfterEffect && adapter.failAfterEffectCount > 0 {
		adapter.failAfterEffectCount--
		return adapter.failError
	}
	return nil
}

func (*dnsLayerAdapter) RouteClient(context.Context, ClientRoute) error {
	return errors.New("unexpected per-client route")
}

func (adapter *dnsLayerAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []ClientRoute,
	desired []ClientRoute,
	_ []ClientRoute,
) error {
	adapter.operations = append(adapter.operations, "replace-routes")
	if adapter.failOperation == "replace-routes" {
		return adapter.failError
	}
	for _, route := range desired {
		if route.BlockTCP {
			if route.DNSOutbound != "" {
				adapter.directDNS = true
			}
			continue
		}
		for _, id := range []string{route.TCPOutbound, route.DNSOutbound} {
			if id == "" {
				adapter.directDNS = true
				continue
			}
			if _, exists := adapter.handlers[id]; !exists {
				adapter.missingDependency = true
			}
		}
	}
	adapter.lastRoutes = append([]ClientRoute(nil), desired...)
	return nil
}

type dnsRecoveryAdapter struct {
	*dnsLayerAdapter
	resolver                 string
	normalizeFailures        int
	normalizeFailureResponse error
}

func (adapter *dnsRecoveryAdapter) NormalizeOutboundForRecovery(
	ctx context.Context,
	outbound Outbound,
) (Outbound, error) {
	if err := ctx.Err(); err != nil {
		return Outbound{}, err
	}
	if outbound.Protocol != ProtocolDNS {
		return outbound, nil
	}
	if _, err := validateDNSOutboundConfig(outbound.Config); err != nil {
		return Outbound{}, err
	}
	if adapter.normalizeFailures > 0 {
		adapter.normalizeFailures--
		return Outbound{}, adapter.normalizeFailureResponse
	}
	var config struct {
		Protocol string `json:"protocol"`
		Settings struct {
			RewriteNetwork string `json:"rewriteNetwork"`
			RewriteAddress string `json:"rewriteAddress"`
			RewritePort    int    `json:"rewritePort"`
		} `json:"settings"`
		StreamSettings struct {
			Sockopt struct {
				DialerProxy string `json:"dialerProxy"`
			} `json:"sockopt"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(outbound.Config, &config); err != nil {
		return Outbound{}, err
	}
	config.Settings.RewriteAddress = adapter.resolver
	encoded, err := json.Marshal(config)
	if err != nil {
		return Outbound{}, err
	}
	outbound.Config = encoded
	return outbound, nil
}

func (adapter *dnsLayerAdapter) DrainOutbound(_ context.Context, id string) error {
	outbound, exists := adapter.handlers[id]
	if !exists {
		return fmt.Errorf("drain unknown outbound %s", id)
	}
	adapter.operations = append(adapter.operations, "drain-"+outboundKind(outbound)+":"+id)
	return nil
}

func (adapter *dnsLayerAdapter) RemoveOutbound(_ context.Context, id string) error {
	outbound, exists := adapter.handlers[id]
	if !exists {
		if adapter.rejectMissing {
			return fmt.Errorf("remove missing outbound %s", id)
		}
		return fmt.Errorf("remove unknown outbound %s", id)
	}
	operation := "remove-" + outboundKind(outbound) + ":" + id
	adapter.operations = append(adapter.operations, operation)
	if operation == adapter.failOperation && !adapter.failAfterEffect {
		return adapter.failError
	}
	if outbound.Protocol != ProtocolDNS {
		for _, other := range adapter.handlers {
			if other.Protocol != ProtocolDNS {
				continue
			}
			proxy, err := validateDNSOutboundConfig(other.Config)
			if err != nil {
				return err
			}
			if proxy == id {
				adapter.missingDependency = true
				return fmt.Errorf("candidate %s still has a DNS dependent", id)
			}
		}
	}
	delete(adapter.handlers, id)
	if operation == adapter.failOperation && adapter.failAfterEffect && adapter.failAfterEffectCount > 0 {
		adapter.failAfterEffectCount--
		return adapter.failError
	}
	return nil
}

func (adapter *dnsLayerAdapter) handlerIDs() []string {
	ids := make([]string, 0, len(adapter.handlers))
	for id := range adapter.handlers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func outboundKind(outbound Outbound) string {
	if outbound.Protocol == ProtocolDNS {
		return "dns"
	}
	return "candidate"
}

type duplicateRejectingRecoveryAdapter struct {
	mu           sync.Mutex
	handlers     map[string]struct{}
	operations   []string
	blockRoute   bool
	failRoute    bool
	routeEntered chan struct{}
	releaseRoute chan struct{}
	routeOnce    sync.Once
}

func newDuplicateRejectingRecoveryAdapter() *duplicateRejectingRecoveryAdapter {
	return &duplicateRejectingRecoveryAdapter{handlers: make(map[string]struct{})}
}

func (adapter *duplicateRejectingRecoveryAdapter) AddOutbound(_ context.Context, outbound Outbound) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.operations = append(adapter.operations, "add:"+outbound.ID)
	if _, exists := adapter.handlers[outbound.ID]; exists {
		return fmt.Errorf("duplicate outbound %s", outbound.ID)
	}
	adapter.handlers[outbound.ID] = struct{}{}
	return nil
}

func (*duplicateRejectingRecoveryAdapter) RouteClient(context.Context, ClientRoute) error {
	return errors.New("unexpected per-client route")
}

func (adapter *duplicateRejectingRecoveryAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []ClientRoute,
	desired []ClientRoute,
	_ []ClientRoute,
) error {
	adapter.mu.Lock()
	target := desired[0].TCPOutbound
	adapter.operations = append(adapter.operations, "route:"+target)
	block := adapter.blockRoute
	fail := adapter.failRoute
	if fail {
		adapter.failRoute = false
	}
	adapter.mu.Unlock()
	if block {
		adapter.routeOnce.Do(func() { close(adapter.routeEntered) })
		<-adapter.releaseRoute
	}
	if fail {
		return errors.New("simulated route failure after acknowledged add")
	}
	return nil
}

func (*duplicateRejectingRecoveryAdapter) DrainOutbound(context.Context, string) error {
	return nil
}

func (adapter *duplicateRejectingRecoveryAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	delete(adapter.handlers, id)
	adapter.operations = append(adapter.operations, "remove:"+id)
	return nil
}

func (adapter *duplicateRejectingRecoveryAdapter) restartRuntimeAndBlockRoute(fail bool) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.handlers = make(map[string]struct{})
	adapter.operations = nil
	adapter.blockRoute = true
	adapter.failRoute = fail
	adapter.routeEntered = make(chan struct{})
	adapter.releaseRoute = make(chan struct{})
	adapter.routeOnce = sync.Once{}
}

func (adapter *duplicateRejectingRecoveryAdapter) operationsSnapshot() []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.operations...)
}

func (adapter *duplicateRejectingRecoveryAdapter) hasOperation(operation string) bool {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	for _, got := range adapter.operations {
		if got == operation {
			return true
		}
	}
	return false
}

func (adapter *duplicateRejectingRecoveryAdapter) addCount(id string) int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	count := 0
	for _, operation := range adapter.operations {
		if operation == "add:"+id {
			count++
		}
	}
	return count
}

type controlledConcurrentAdapter struct {
	mu               sync.Mutex
	handlers         map[string]struct{}
	operations       []string
	lastRoute        string
	missingReference bool
	g2Entered        chan struct{}
	releaseG2        chan struct{}
	g3Touched        chan struct{}
	g2Once           sync.Once
	g3Once           sync.Once
}

func newControlledConcurrentAdapter() *controlledConcurrentAdapter {
	return &controlledConcurrentAdapter{
		handlers:  make(map[string]struct{}),
		g2Entered: make(chan struct{}),
		releaseG2: make(chan struct{}),
		g3Touched: make(chan struct{}),
	}
}

func (adapter *controlledConcurrentAdapter) AddOutbound(_ context.Context, outbound Outbound) error {
	adapter.mu.Lock()
	adapter.handlers[outbound.ID] = struct{}{}
	adapter.operations = append(adapter.operations, "add:"+outbound.ID)
	adapter.mu.Unlock()
	if outbound.ID == "g3" {
		adapter.g3Once.Do(func() { close(adapter.g3Touched) })
	}
	return nil
}

func (adapter *controlledConcurrentAdapter) RouteClient(context.Context, ClientRoute) error {
	return errors.New("unexpected per-client route")
}

func (adapter *controlledConcurrentAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []ClientRoute,
	desired []ClientRoute,
	_ []ClientRoute,
) error {
	target := desired[0].TCPOutbound
	adapter.mu.Lock()
	adapter.operations = append(adapter.operations, "stage:"+target)
	if _, exists := adapter.handlers[target]; !exists {
		adapter.missingReference = true
	}
	adapter.mu.Unlock()
	if target == "g2" {
		adapter.g2Once.Do(func() { close(adapter.g2Entered) })
		<-adapter.releaseG2
	}
	adapter.mu.Lock()
	adapter.operations = append(adapter.operations, "final:"+target)
	if _, exists := adapter.handlers[target]; !exists {
		adapter.missingReference = true
	}
	adapter.lastRoute = target
	adapter.mu.Unlock()
	return nil
}

func (adapter *controlledConcurrentAdapter) DrainOutbound(_ context.Context, id string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.operations = append(adapter.operations, "drain:"+id)
	return nil
}

func (adapter *controlledConcurrentAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	delete(adapter.handlers, id)
	adapter.operations = append(adapter.operations, "remove:"+id)
	return nil
}

func (adapter *controlledConcurrentAdapter) resetOperations() {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.operations = nil
}

func (adapter *controlledConcurrentAdapter) operationsSnapshot() []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.operations...)
}

func (adapter *controlledConcurrentAdapter) handlerIDs() []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	ids := make([]string, 0, len(adapter.handlers))
	for id := range adapter.handlers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

type batchingAdapter struct {
	recordingAdapter
	batches int
}

type stagedBatchingAdapter struct {
	recordingAdapter
	failStage  bool
	failFinal  bool
	finalError error
}

func (adapter *stagedBatchingAdapter) ReplaceRoutesStaged(
	_ context.Context,
	_ []ClientRoute,
	desired []ClientRoute,
	affected []ClientRoute,
) error {
	adapter.operations = append(adapter.operations, "stage:"+routeClientIDs(affected))
	if adapter.failStage {
		return errors.New("staging replacement failed")
	}
	adapter.operations = append(adapter.operations, "final:"+routeClientIDs(desired))
	if adapter.failFinal {
		if adapter.finalError != nil {
			return adapter.finalError
		}
		return errors.New("final replacement outcome unknown")
	}
	return nil
}

func routeClientIDs(routes []ClientRoute) string {
	ids := make([]string, 0, len(routes))
	for _, route := range routes {
		ids = append(ids, route.ClientID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func (adapter *batchingAdapter) ReplaceRoutes(_ context.Context, routes []ClientRoute) error {
	adapter.batches++
	adapter.operations = append(adapter.operations, fmt.Sprintf("routes:%d", len(routes)))
	return nil
}

func (adapter *recordingAdapter) AddOutbound(_ context.Context, outbound Outbound) error {
	adapter.operations = append(adapter.operations, "add:"+outbound.ID)
	return nil
}

func (adapter *recordingAdapter) RouteClient(_ context.Context, route ClientRoute) error {
	adapter.operations = append(adapter.operations, "route:"+route.ClientID+":"+route.TCPOutbound+":"+route.UDPOutbound)
	return adapter.routeError
}

func (adapter *recordingAdapter) DrainOutbound(_ context.Context, id string) error {
	adapter.operations = append(adapter.operations, "drain:"+id)
	return nil
}

func (adapter *recordingAdapter) RemoveOutbound(_ context.Context, id string) error {
	adapter.operations = append(adapter.operations, "remove:"+id)
	return nil
}

func TestPlanValidatesDirectSuffixesAndDomains(t *testing.T) {
	valid := DesiredPlan{
		Generation: 1,
		Outbounds:  []Outbound{{ID: "vless", Protocol: ProtocolVLESS}},
		Clients: []ClientRoute{{
			ClientID: "alice", SourceCIDR: "10.44.0.2/32",
			TCPOutbound: "vless", UDPOutbound: "vless",
		}},
		DirectSuffixes: []string{".ru", ".su", ".xn--p1ai"},
		DirectDomains:  []string{"thecode.media", "habr.com"},
		FailClosed:     true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid multi-suffix plan: %v", err)
	}

	invalidSuffixes := [][]string{
		{},
		{""},
		{"ru"},
		{"."},
	}
	for _, s := range invalidSuffixes {
		plan := valid
		plan.DirectSuffixes = s
		if err := plan.Validate(); err == nil {
			t.Fatalf("expected error for suffixes %v", s)
		}
	}

	invalidDomains := [][]string{
		{""},
		{"https://habr.com"},
		{"habr.com/path"},
		{"habr.com:443"},
	}
	for _, d := range invalidDomains {
		plan := valid
		plan.DirectDomains = d
		if err := plan.Validate(); err == nil {
			t.Fatalf("expected error for domains %v", d)
		}
	}
}
