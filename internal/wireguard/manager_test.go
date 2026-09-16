package wireguard

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestManagerCreatesPersistsPausesAndResumesPeer(t *testing.T) {
	runner := &managerRunner{outputs: map[string]string{
		"wg genkey":              "private-key\n",
		"wg pubkey":              "client-public\n",
		"wg show wg0 public-key": "server-public\n",
	}}
	manager := Manager{Runner: runner, Config: ManagerConfig{
		Interface: "wg0", Endpoint: "vpn.example.net:51820", DNS: "10.44.0.1", MTU: 1420,
	}}
	peer, config, err := manager.Create(context.Background(), "phone", "10.44.0.3/32")
	if err != nil {
		t.Fatal(err)
	}
	if peer.PublicKey != "client-public" || !strings.Contains(config, "PrivateKey = private-key") || !strings.Contains(config, "AllowedIPs = 0.0.0.0/0") || strings.Contains(config, "::/0") {
		t.Fatalf("peer=%+v config=%s", peer, config)
	}
	if !strings.Contains(config, "\nDNS = 10.44.0.1\n") {
		t.Fatalf("client config does not use the in-container gateway DNS:\n%s", config)
	}
	if err := manager.SetPaused(context.Background(), peer, true); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetPaused(context.Background(), peer, false); err != nil {
		t.Fatal(err)
	}
	wantTail := [][]string{
		{"wg", "set", "wg0", "peer", "client-public", "remove"},
		{"wg-quick", "save", "wg0"},
		{"wg", "set", "wg0", "peer", "client-public", "allowed-ips", "10.44.0.3/32"},
		{"wg-quick", "save", "wg0"},
	}
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-4:], wantTail) {
		t.Fatalf("calls=%v", runner.calls)
	}
}

func TestManagerDNSIsRequiredForClientProfiles(t *testing.T) {
	manager := Manager{Runner: &managerRunner{}, Config: ManagerConfig{
		Interface: "wg0", Endpoint: "vpn.example.net:51820",
	}}
	if _, _, err := manager.Create(context.Background(), "phone", "10.44.0.3/32"); err == nil ||
		!strings.Contains(err.Error(), "DNS") {
		t.Fatalf("Create() error=%v, want required DNS error", err)
	}
}

func TestManagerDNSRequiresCanonicalIPv4ForClientProfiles(t *testing.T) {
	for _, dns := range []string{" 10.44.0.1", "::ffff:10.44.0.1", "fd00::1", "not-an-ip"} {
		t.Run(dns, func(t *testing.T) {
			manager := Manager{Runner: &managerRunner{}, Config: ManagerConfig{
				Interface: "wg0", Endpoint: "vpn.example.net:51820", DNS: dns,
			}}
			if _, _, err := manager.Create(context.Background(), "phone", "10.44.0.3/32"); err == nil ||
				!strings.Contains(err.Error(), "DNS") {
				t.Fatalf("Create() error=%v, want canonical IPv4 DNS error", err)
			}
		})
	}
}

func TestManagerRejectsIPv6AndNonHostAddress(t *testing.T) {
	manager := Manager{Runner: &managerRunner{}, Config: ManagerConfig{Interface: "wg0", Endpoint: "endpoint"}}
	for _, address := range []string{"2001:db8::1/128", "10.44.0.0/24"} {
		if _, _, err := manager.Create(context.Background(), "bad", address); err == nil {
			t.Fatalf("accepted unsafe client address %s", address)
		}
	}
}
func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		defaultPort int
		want        string
		wantErr     bool
	}{
		{"IPv4 without port", "203.0.113.10", 51820, "203.0.113.10:51820", false},
		{"hostname without port", "vpn.example.com", 51820, "vpn.example.com:51820", false},
		{"IPv6 without port", "2001:db8::1", 51820, "[2001:db8::1]:51820", false},
		{"bracketed IPv6 without port", "[2001:db8::1]", 51820, "[2001:db8::1]:51820", false},
		{"explicit IPv4 port preserved", "203.0.113.10:51822", 51820, "203.0.113.10:51822", false},
		{"explicit IPv6 port with brackets preserved", "[2001:db8::1]:51822", 51820, "[2001:db8::1]:51822", false},
		{"explicit hostname port preserved", "vpn.example.com:443", 51820, "vpn.example.com:443", false},
		{"reject zero port", "203.0.113.10:0", 51820, "", true},
		{"reject out-of-range port high", "203.0.113.10:65536", 51820, "", true},
		{"reject negative port", "203.0.113.10:-1", 51820, "", true},
		{"reject non-numeric port", "203.0.113.10:abc", 51820, "", true},
		{"reject empty endpoint", "", 51820, "", true},
		{"reject whitespace endpoint", "   ", 51820, "", true},
		{"reject empty host", ":51820", 51820, "", true},
		{"reject malformed colon-separated address", "2001:db8::1:99999", 51820, "", true},
		{"reject whitespace in hostname", "bad\thost", 51820, "", true},
		{"reject invalid defaultPort zero", "203.0.113.10", 0, "", true},
		{"reject invalid defaultPort out of range", "203.0.113.10", 70000, "", true},
		{"reject invalid defaultPort negative", "203.0.113.10", -1, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tc.raw, tc.defaultPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeEndpoint(%q, %d) = %q, want error", tc.raw, tc.defaultPort, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEndpoint(%q, %d) unexpected error: %v", tc.raw, tc.defaultPort, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeEndpoint(%q, %d) = %q, want %q", tc.raw, tc.defaultPort, got, tc.want)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	valid := []string{
		"203.0.113.10:51820",
		"[2001:db8::1]:51820",
		"vpn.example.com:51820",
	}
	for _, ep := range valid {
		if err := ValidateEndpoint(ep); err != nil {
			t.Fatalf("ValidateEndpoint(%q) error=%v, want nil", ep, err)
		}
	}
	invalid := []string{
		"203.0.113.10",
		"vpn.example.com",
		"[2001:db8::1]",
		"2001:db8::1",
		"203.0.113.10:0",
		"203.0.113.10:65536",
		"203.0.113.10:xyz",
		"",
		":51820",
	}
	for _, ep := range invalid {
		if err := ValidateEndpoint(ep); err == nil {
			t.Fatalf("ValidateEndpoint(%q) = nil, want error", ep)
		}
	}
}

func TestManagerRejectsMalformedZeroOrOutOfRangeEndpointBeforeSideEffects(t *testing.T) {
	invalidEndpoints := []string{
		"203.0.113.10",       // missing port
		"203.0.113.10:0",     // zero port
		"203.0.113.10:70000", // out-of-range port
		"203.0.113.10:abc",   // malformed port
		"vpn.example.com",    // missing port
		"[2001:db8::1]",      // missing port
	}
	for _, ep := range invalidEndpoints {
		t.Run(ep, func(t *testing.T) {
			runner := &managerRunner{}
			manager := Manager{Runner: runner, Config: ManagerConfig{
				Interface: "wg0", Endpoint: ep, DNS: "10.44.0.1", MTU: 1420,
			}}
			_, _, err := manager.Create(context.Background(), "phone", "10.44.0.3/32")
			if err == nil {
				t.Fatalf("Create() accepted invalid endpoint %q", ep)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("Create() executed runner calls %v for invalid endpoint %q before validation", runner.calls, ep)
			}
		})
	}
}

func TestReplaceEndpoint(t *testing.T) {
	orig := "[Interface]\nPrivateKey = privkey123\nAddress = 10.44.0.2/32\nDNS = 10.44.0.1\nMTU = 1420\n\n[Peer]\nPublicKey = pubkey456\nEndpoint = 203.0.113.10\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	want := "[Interface]\nPrivateKey = privkey123\nAddress = 10.44.0.2/32\nDNS = 10.44.0.1\nMTU = 1420\n\n[Peer]\nPublicKey = pubkey456\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"

	got := ReplaceEndpoint(orig, "203.0.113.10:51820")
	if got != want {
		t.Fatalf("ReplaceEndpoint() =\n%s\nwant:\n%s", got, want)
	}

	// Without Endpoint line: unchanged
	noEndpoint := "[Interface]\nPrivateKey = privkey123\n"
	if got := ReplaceEndpoint(noEndpoint, "203.0.113.10:51820"); got != noEndpoint {
		t.Fatalf("ReplaceEndpoint without Endpoint line modified content: %s", got)
	}

	// With empty newEndpoint: unchanged
	if got := ReplaceEndpoint(orig, ""); got != orig {
		t.Fatalf("ReplaceEndpoint with empty newEndpoint modified content: %s", got)
	}
}

type managerRunner struct {
	outputs map[string]string
	calls   [][]string
}

func (runner *managerRunner) RunInput(_ context.Context, input, name string, args ...string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{name}, args...))
	key := strings.Join(append([]string{name}, args...), " ")
	if key == "wg pubkey" && strings.TrimSpace(input) != "private-key" {
		return nil, fmt.Errorf("unexpected private key input")
	}
	return []byte(runner.outputs[key]), nil
}
