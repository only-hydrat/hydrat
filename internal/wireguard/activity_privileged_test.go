package wireguard

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run in a disposable network namespace, never against a host firewall:
// unshare --user --map-root-user --net env HYDRAT_PRIVILEGED_NFT_ACTIVITY=1 go test ./internal/wireguard -run TestClientActivityNFT
func TestClientActivityNFT(t *testing.T) {
	if os.Getenv("HYDRAT_PRIVILEGED_NFT_ACTIVITY") != "1" {
		t.Skip("requires an isolated namespace with CAP_NET_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v %s", err, output)
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "config", "nftables", "hydrat.nft"))
	if err != nil {
		t.Fatal(err)
	}
	// Loopback supplies decrypted IP packets without requiring a live WG peer.
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader(strings.ReplaceAll(string(policy), `"wg0"`, `"lo"`))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("apply isolated policy: %v %s", err, output)
	}
	read := func() map[string]time.Time {
		t.Helper()
		output, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "hydrat", "client_activity").Output()
		if err != nil {
			t.Fatal(err)
		}
		activity, err := parseUserTraffic(output, time.Now())
		if err != nil {
			t.Fatalf("decode actual nft JSON: %v %s", err, output)
		}
		return activity
	}
	if len(read()) != 0 {
		t.Fatal("empty activity set marked a client online")
	}
	connection, err := net.Dial("udp4", "127.0.0.1:55333")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("client data")); err != nil {
		t.Fatal(err)
	}
	seen := read()["127.0.0.1"]
	if seen.IsZero() || time.Since(seen) > 2*time.Second {
		t.Fatalf("actual packet did not refresh activity: %v", seen)
	}
}
