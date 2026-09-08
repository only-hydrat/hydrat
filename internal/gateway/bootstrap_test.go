package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapPreservesExistingWireGuardInterface(t *testing.T) {
	runner := &bootstrapRunner{}
	bootstrap := Bootstrap{Runner: runner, Interface: "wg0", WireGuardConfig: "/data/wireguard/wg0.conf", NFTConfig: "/etc/hydrat/nftables.nft"}
	if err := bootstrap.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "link", "show", "dev", "wg0"},
		{"ip", "-4", "-o", "rule", "show", "priority", "10000"},
		{"ip", "-4", "rule", "add", "priority", "10000", "fwmark", "1", "lookup", "100"},
		{"ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"nft", "-f", "/etc/hydrat/nftables.nft"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
}

func TestBootstrapCreatesMissingWireGuardInterfaceOnce(t *testing.T) {
	runner := &bootstrapRunner{linkError: errors.New("not found")}
	bootstrap := Bootstrap{Runner: runner, Interface: "wg0", WireGuardConfig: "/data/wireguard/wg0.conf", NFTConfig: "/etc/hydrat/nftables.nft"}
	if err := bootstrap.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "link", "show", "dev", "wg0"},
		{"wg-quick", "up", "/data/wireguard/wg0.conf"},
		{"ip", "-4", "-o", "rule", "show", "priority", "10000"},
		{"ip", "-4", "rule", "add", "priority", "10000", "fwmark", "1", "lookup", "100"},
		{"ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"nft", "-f", "/etc/hydrat/nftables.nft"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
}

func TestBootstrapNFTAIsIdempotentWhenPolicyRuleExists(t *testing.T) {
	runner := &bootstrapRunner{}
	bootstrap := Bootstrap{Runner: runner, Interface: "wg0", WireGuardConfig: "/data/wireguard/wg0.conf", NFTConfig: "/etc/hydrat/nftables.nft"}
	if err := bootstrap.Apply(context.Background()); err != nil {
		t.Fatalf("first Apply() failed: %v", err)
	}
	if err := bootstrap.Apply(context.Background()); err != nil {
		t.Fatalf("second Apply() failed: %v", err)
	}
	var nftLoads int
	for _, call := range runner.calls {
		if reflect.DeepEqual(call, []string{"nft", "-f", "/etc/hydrat/nftables.nft"}) {
			nftLoads++
		}
	}
	if nftLoads != 2 {
		t.Fatalf("nft loads=%d, want one declarative load per Apply", nftLoads)
	}
	var policyQueries, policyAdds int
	for _, call := range runner.calls {
		if len(call) > 0 && call[0] == "nft" &&
			!reflect.DeepEqual(call, []string{"nft", "-f", "/etc/hydrat/nftables.nft"}) {
			t.Fatalf("bootstrap performs non-atomic nft command outside the policy asset: %v", call)
		}
		if reflect.DeepEqual(call, []string{"ip", "-4", "-o", "rule", "show", "priority", "10000"}) {
			policyQueries++
		}
		if reflect.DeepEqual(call, []string{"ip", "-4", "rule", "add", "priority", "10000", "fwmark", "1", "lookup", "100"}) {
			policyAdds++
		}
	}
	if policyQueries != 2 || policyAdds != 1 {
		t.Fatalf("policy queries/adds=%d/%d, want 2/1: calls=%v", policyQueries, policyAdds, runner.calls)
	}
}

func TestBootstrapRejectsConflictingOwnedPolicyPriorityWithoutMutation(t *testing.T) {
	runner := &bootstrapRunner{policyRule: "10000: from all lookup main\n"}
	bootstrap := Bootstrap{Runner: runner, Interface: "wg0", WireGuardConfig: "/data/wireguard/wg0.conf", NFTConfig: "/etc/hydrat/nftables.nft"}
	err := bootstrap.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "priority 10000") {
		t.Fatalf("Apply() error=%v, want owned-priority conflict", err)
	}
	for _, call := range runner.calls {
		if reflect.DeepEqual(call, []string{"ip", "-4", "rule", "add", "priority", "10000", "fwmark", "1", "lookup", "100"}) {
			t.Fatalf("conflicting policy rule was mutated: calls=%v", runner.calls)
		}
	}
}

func TestBootstrapVerifiesOwnedPolicyRuleAfterAddEEXIST(t *testing.T) {
	runner := &bootstrapRunner{addRuleErr: errors.New("RTNETLINK answers: File exists")}
	bootstrap := Bootstrap{Runner: runner, Interface: "wg0", WireGuardConfig: "/data/wireguard/wg0.conf", NFTConfig: "/etc/hydrat/nftables.nft"}
	if err := bootstrap.Apply(context.Background()); err != nil {
		t.Fatalf("Apply() failed after verified EEXIST race: %v", err)
	}
	var policyQueries int
	for _, call := range runner.calls {
		if reflect.DeepEqual(call, []string{"ip", "-4", "-o", "rule", "show", "priority", "10000"}) {
			policyQueries++
		}
	}
	if policyQueries != 2 {
		t.Fatalf("policy queries=%d, want initial query plus EEXIST verification", policyQueries)
	}
}

func TestBootstrapNFTAInterceptsClientDNSBeforeGatewayDrop(t *testing.T) {
	path := filepath.Join("..", "..", "config", "nftables", "hydrat.nft")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := string(data)
	if !strings.HasPrefix(rules, "add table inet hydrat\ndelete table inet hydrat\n") {
		t.Fatal("nftables asset must atomically replace only the Hydrat table")
	}
	drop := `iifname "wg0" ip daddr 10.44.0.1 drop`
	udpDNS := `iifname "wg0" udp dport 53 accept`
	tcpDNS := `iifname "wg0" tcp dport 53 accept`
	dropPosition := strings.Index(rules, drop)
	if dropPosition < 0 {
		t.Fatalf("nftables asset missing gateway local drop %q", drop)
	}
	for _, rule := range []string{udpDNS, tcpDNS} {
		position := strings.Index(rules, rule)
		if position < 0 {
			t.Errorf("nftables asset missing destination-independent DNS intercept %q", rule)
			continue
		}
		if position >= dropPosition {
			t.Errorf("DNS intercept appears after gateway local drop: %q", rule)
		}
		if strings.Contains(rule, "ip daddr") {
			t.Errorf("DNS intercept unexpectedly restricts the resolver destination: %q", rule)
		}
	}
	for _, redirect := range []string{
		`iifname "wg0" udp dport 53 redirect to :53`,
		`iifname "wg0" tcp dport 53 redirect to :53`,
	} {
		if !strings.Contains(rules, redirect) {
			t.Errorf("nftables asset missing client DNS redirect %q", redirect)
		}
	}
	if strings.Contains(rules, `dport 53 tproxy`) {
		t.Fatal("client DNS must not create transparent UDP sessions in the shared TPROXY inbound")
	}
}

type bootstrapRunner struct {
	calls      [][]string
	linkError  error
	policyRule string
	addRuleErr error
}

func (runner *bootstrapRunner) Run(_ context.Context, name string, args ...string) error {
	runner.calls = append(runner.calls, append([]string{name}, args...))
	if name == "ip" && len(args) > 0 && args[0] == "link" {
		return runner.linkError
	}
	if name == "ip" && reflect.DeepEqual(args, []string{"-4", "rule", "add", "priority", "10000", "fwmark", "1", "lookup", "100"}) {
		runner.policyRule = "10000: from all fwmark 0x1 lookup 100\n"
		if runner.addRuleErr != nil {
			return runner.addRuleErr
		}
	}
	return nil
}

func (runner *bootstrapRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{name}, args...))
	if name == "ip" && reflect.DeepEqual(args, []string{"-4", "-o", "rule", "show", "priority", "10000"}) {
		return []byte(runner.policyRule), nil
	}
	return nil, nil
}
