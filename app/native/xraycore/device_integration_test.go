//go:build linux && !android

package xraycore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func TestEmbeddedDeviceStartsWithRealTUN(t *testing.T) {
	if os.Getenv("HYDRAT_EMBEDDED_TUN_TEST") == "" {
		t.Skip("set HYDRAT_EMBEDDED_TUN_TEST=1 to test an isolated kernel TUN")
	}
	if os.Getenv("HYDRAT_EMBEDDED_TUN_NAMESPACE") == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-Urn", "sh", "-c",
			`ip link set lo up && exec "$1" -test.run '^TestEmbeddedDeviceStartsWithRealTUN$' -test.v`, "sh", os.Args[0])
		cmd.Env = append(os.Environ(), "HYDRAT_EMBEDDED_TUN_NAMESPACE=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("TUN namespace: %v\n%s", err, output)
		}
		return
	}
	directory, err := os.MkdirTemp("", "hydrat-app-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "flows.sock")
	t.Setenv(xrayflow.SocketEnvironment, socket)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	for range 2 {
		backend, err := device.StartProcesses(ctx, device.ProcessOptions{
			Embedded: Host{}, FlowSocket: socket, Tor: "/bin/true", Lyrebird: "/bin/true", RuntimeDirectory: directory,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = backend.Close() })
		if _, err := net.InterfaceByName("hydrat-app"); err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:28180", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte{5, 1, 0})
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		var response [2]byte
		_, err = io.ReadFull(conn, response[:])
		_ = conn.Close()
		if err != nil || response != [2]byte{5, 0xff} {
			t.Fatalf("anonymous connection: response %v, error %v", response, err)
		}
		for _, check := range []func(context.Context) error{
			backend.Health,
			func(ctx context.Context) error {
				_, err := backend.ProbeRuntimeHealth(ctx)
				return err
			},
			func(ctx context.Context) error {
				_, err := backend.ActiveProbeRuntimeHealth(ctx)
				return err
			},
		} {
			if err := check(ctx); err != nil {
				t.Fatal(err)
			}
		}
		testEmbeddedVLESSEgress(t, ctx, directory, backend)
		if err := backend.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := net.InterfaceByName("hydrat-app"); err == nil {
			t.Fatal("TUN stayed open on disconnect")
		}
	}
}

func testEmbeddedVLESSEgress(t *testing.T, ctx context.Context, directory string, backend *device.ProcessBackend) {
	t.Helper()
	const user = "36b1e281-656f-4d13-b3b4-935642836c43"
	const target = "192.0.2.21"
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("from-vless-exit"))
	}))
	defer fixture.Close()
	fixtureAddress := strings.TrimPrefix(fixture.URL, "http://")
	echo, err := net.ListenPacket("udp4", fixtureAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			count, peer, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:count], peer)
		}
	}()
	primary, closePrimary := startEmbeddedTestExit(t, ctx, directory, user, fixtureAddress, "primary")
	reserve, _ := startEmbeddedTestExit(t, ctx, directory, user, fixtureAddress, "reserve")
	for _, args := range [][]string{
		{"addr", "add", device.TunnelCIDR, "dev", "hydrat-app"},
		{"route", "add", target + "/32", "dev", "hydrat-app"},
	} {
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	route := dataplane.ClientRoute{ClientID: "local-device", SourceCIDR: device.TunnelCIDR, BlockTCP: true, BlockUDP: true}
	plan := dataplane.DesiredPlan{
		Generation: 1, FailClosed: true, Clients: []dataplane.ClientRoute{route},
		DirectSuffixes: []string{".ru"},
	}
	if err := backend.ApplyWithRecovery(ctx, plan, nil); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	if response, err := client.Get("http://" + target); err == nil {
		_ = response.Body.Close()
		t.Fatal("protected request succeeded without an assigned outbound")
	}
	plan.Generation++
	route.BlockTCP, route.TCPOutbound = false, primary.ID
	route.BlockUDP, route.UDPOutbound = false, primary.ID
	route.TCPReserveOutbound, route.UDPReserveOutbound = reserve.ID, reserve.ID
	plan.Clients[0] = route
	plan.Outbounds = []dataplane.Outbound{primary, reserve}
	if err := backend.ApplyWithRecovery(ctx, plan, nil); err != nil {
		t.Fatal(err)
	}
	checkEmbeddedTraffic(t, ctx, client, target)

	if err := closePrimary(); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get("http://" + target); err == nil {
		_ = response.Body.Close()
		t.Fatal("protected request succeeded after the primary exit stopped")
	}
	plan.Generation++
	route.TCPOutbound, route.UDPOutbound = reserve.ID, reserve.ID
	route.TCPReserveOutbound, route.UDPReserveOutbound = "", ""
	plan.Clients[0] = route
	plan.Outbounds = []dataplane.Outbound{reserve}
	if err := backend.ApplyWithRecovery(ctx, plan, nil); err != nil {
		t.Fatal(err)
	}
	checkEmbeddedTraffic(t, ctx, client, target)
	if backend.LastTraffic().IsZero() {
		t.Fatal("TUN traffic was not counted")
	}
}

func startEmbeddedTestExit(t *testing.T, ctx context.Context, directory, user, destination, id string) (dataplane.Outbound, func() error) {
	t.Helper()
	portListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	_ = portListener.Close()
	path := filepath.Join(directory, id+".json")
	config := fmt.Sprintf(`{
		"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless",
			"settings":{"clients":[{"id":%q}],"decryption":"none"}}],
		"outbounds":[{"protocol":"freedom","settings":{"redirect":%q,
			"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]
	}`, port, user, destination)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	exit, err := (Host{}).Start(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = exit.Close() })
	outbound, err := xrayconfig.VLESSOutbound(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none", user, port), id)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(outbound)
	if err != nil {
		t.Fatal(err)
	}
	return dataplane.Outbound{ID: id, Protocol: dataplane.ProtocolVLESS, Config: body}, exit.Close
}

func checkEmbeddedTraffic(t *testing.T, ctx context.Context, client *http.Client, target string) {
	t.Helper()
	response, err := client.Get("http://" + target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "from-vless-exit" {
		t.Fatalf("TUN response: %s, %v", data, err)
	}
	udp, err := (&net.Dialer{}).DialContext(ctx, "udp4", target+":9000")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(time.Second))
	if _, err := udp.Write([]byte("udp-through-vless")); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 64)
	n, err := udp.Read(packet)
	if err != nil || string(packet[:n]) != "udp-through-vless" {
		t.Fatalf("TUN UDP response: %s, %v", packet[:n], err)
	}
}
