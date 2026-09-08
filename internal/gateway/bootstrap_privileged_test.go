package gateway

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBootstrapPrivilegedDoubleApplyKeepsOneOwnedPolicyRule(t *testing.T) {
	if os.Getenv("HYDRAT_PRIVILEGED_NETWORK_TEST") != "1" {
		t.Skip("set HYDRAT_PRIVILEGED_NETWORK_TEST=1 inside an isolated privileged network namespace")
	}
	nftConfig := os.Getenv("HYDRAT_PRIVILEGED_NFT_CONFIG")
	if nftConfig == "" {
		t.Fatal("HYDRAT_PRIVILEGED_NFT_CONFIG is required")
	}

	ctx := context.Background()
	const interfaceName = "hydratdns0"
	runPrivilegedCommand(t, ctx, "ip", "link", "add", interfaceName, "type", "dummy")
	t.Cleanup(func() {
		_ = exec.CommandContext(ctx, "ip", "link", "delete", interfaceName).Run()
	})

	bootstrap := Bootstrap{
		Interface:       interfaceName,
		WireGuardConfig: "/unused/wg0.conf",
		NFTConfig:       nftConfig,
	}
	if err := bootstrap.Apply(ctx); err != nil {
		t.Fatalf("first Apply(): %v", err)
	}
	if err := bootstrap.Apply(ctx); err != nil {
		t.Fatalf("second Apply(): %v", err)
	}

	output := runPrivilegedCommand(t, ctx, "ip", "-4", "-o", "rule", "show")
	var owned []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, "fwmark 0x1 lookup 100") {
			owned = append(owned, strings.Join(strings.Fields(line), " "))
		}
	}
	want := []string{"10000: from all fwmark 0x1 lookup 100"}
	if strings.Join(owned, "\n") != strings.Join(want, "\n") {
		t.Fatalf("owned policy rules=%v, want exactly %v; all rules:\n%s", owned, want, output)
	}
}

func runPrivilegedCommand(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
