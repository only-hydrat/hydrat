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
