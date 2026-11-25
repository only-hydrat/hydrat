//go:build linux && !android

package device

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestLinuxRoutingRollsBackOnlyOwnedOperations(t *testing.T) {
	ctx := context.Background()
	var commands []string
	run := func(_ context.Context, name string, args ...string) error {
		command := strings.Join(append([]string{name}, args...), " ")
		commands = append(commands, command)
		if command == "ip -6 rule add priority 11893 not uidrange 61190-61190 table 28481" {
			return errors.New("another service owns this rule")
		}
		return nil
	}
	_, err := installLinuxRouting(ctx, 61190, run)
	if err == nil {
		t.Fatal("conflicting policy rule was accepted")
	}
	want := []string{
		"ip -4 rule del priority 11893 not uidrange 61190-61190 table 28481",
		"ip -6 route del table 28481 default dev hydrat-app",
		"ip -4 route del table 28481 default dev hydrat-app",
		"ip -6 route del unreachable default table 28481 metric 32760",
		"ip -4 route del unreachable default table 28481 metric 32760",
		"ip -6 address del fd24:6b91:e70d::2/126 dev hydrat-app",
		"ip -4 address del 10.231.90.2/30 dev hydrat-app",
	}
	if len(commands) < len(want) || !reflect.DeepEqual(commands[len(commands)-len(want):], want) {
		t.Fatalf("rollback commands %q, want suffix %q", commands, want)
	}
}

func TestLinuxRoutingKeepsPhysicalEgressForTheService(t *testing.T) {
	if os.Getenv("HYDRAT_ROUTE_TEST_NAMESPACE") != "1" {
		t.Skip("requires an isolated network namespace with both test UIDs mapped")
	}
	ctx := context.Background()
	for _, args := range [][]string{
		{"link", "add", "physical", "type", "dummy"},
		{"link", "set", "dev", "physical", "up"},
		{"address", "add", "192.0.2.2/24", "dev", "physical"},
		{"route", "add", "default", "dev", "physical"},
		{"tuntap", "add", "dev", linuxTunnel, "mode", "tun"},
		{"link", "set", "dev", linuxTunnel, "up"},
	} {
		if err := invokeRouting(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	close, err := installLinuxRouting(ctx, 61190, invokeRouting)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	assertRoute := func(uid, device string) {
		t.Helper()
		output, err := exec.Command("ip", "-4", "route", "get", "203.0.113.1", "uid", uid).CombinedOutput()
		if err != nil || !strings.Contains(string(output), "dev "+device+" ") {
			t.Fatalf("uid %s, want %s: %v %s", uid, device, err, output)
		}
	}
	assertRoute("61190", "physical")
	assertRoute("1000", linuxTunnel)
	if err := invokeRouting(ctx, "ip", "-4", "route", "del", "table", linuxRouteTable, "default", "dev", linuxTunnel); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("ip", "-4", "route", "get", "203.0.113.1", "uid", "1000").CombinedOutput(); err == nil {
		t.Fatalf("ordinary traffic escaped the tunnel after the TUN route disappeared: %s", output)
	}
	assertRoute("61190", "physical")
	if err := invokeRouting(ctx, "ip", "-4", "route", "add", "table", linuxRouteTable, "default", "dev", linuxTunnel); err != nil {
		t.Fatal(err)
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
	assertRoute("1000", "physical")
}
