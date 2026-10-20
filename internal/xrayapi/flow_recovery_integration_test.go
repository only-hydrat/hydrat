//go:build xrayintegration

package xrayapi

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func TestPinnedXrayRecoversOnlyFailedClientPreexistingTCP(t *testing.T) {
	for _, network := range []string{"tcp", "xhttp"} {
		for _, reconciler := range []bool{false, true} {
			name := network + "/private_control"
			if reconciler {
				name = network + "/gateway_reconciler"
			}
			t.Run(name, func(t *testing.T) { testPinnedFlowRecovery(t, reconciler, network) })
		}
	}
}

func testPinnedFlowRecovery(t *testing.T, useReconciler bool, network string) {
	binary := os.Getenv("HYDRAT_XRAY_BINARY")
	if binary == "" {
		t.Fatal("HYDRAT_XRAY_BINARY required")
	}
	var blackhole atomic.Bool
	a, b := flowEchoFixture(t, 'A', &blackhole), flowEchoFixture(t, 'B', nil)
	const uuid = "00000000-0000-4000-8000-000000000001"
	stream := map[string]any{"network": network, "security": "none"}
	if network == "xhttp" {
		stream["xhttpSettings"] = map[string]any{"path": "/flow-recovery"}
	}
	inbound := func(tag string, port int) any {
		return map[string]any{
			"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": uuid}}, "decryption": "none"},
			"streamSettings": stream,
		}
	}
	serverConfig := map[string]any{
		"log":      map[string]any{"access": "none", "loglevel": "warning"},
		"inbounds": []any{inbound("a", 22401), inbound("b", 22402)},
		"outbounds": []any{
			map[string]any{"tag": "a", "protocol": "freedom", "settings": map[string]any{"redirect": a, "finalRules": []any{map[string]any{"action": "allow"}}}},
			map[string]any{"tag": "b", "protocol": "freedom", "settings": map[string]any{"redirect": b, "finalRules": []any{map[string]any{"action": "allow"}}}},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"a"}, "outboundTag": "a"},
			map[string]any{"type": "field", "inboundTag": []string{"b"}, "outboundTag": "b"},
		}},
	}
	server := startXray(t, binary, serverConfig, "127.0.0.1:22401")
	defer server.stop(t)
	vless := func(tag string, port int) any {
		return map[string]any{
			"tag": tag, "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": uuid, "encryption": "none"}},
			}}},
			"streamSettings": stream,
		}
	}
	routes := func(tag string) map[string]any {
		return map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			map[string]any{"type": "field", "source": []string{"127.0.0.2/32"}, "inboundTag": []string{"tcp-in"}, "outboundTag": tag},
			map[string]any{"type": "field", "inboundTag": []string{"tcp-in"}, "outboundTag": "a"},
		}}
	}
	config := map[string]any{
		"log":       map[string]any{"access": "none", "loglevel": "warning"},
		"api":       map[string]any{"tag": "api", "listen": "127.0.0.1:22386", "services": []string{"RoutingService", "HandlerService"}},
		"inbounds":  []any{map[string]any{"tag": "tcp-in", "listen": "127.0.0.1", "port": 22354, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": 80, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"tag": "api", "protocol": "blackhole"}, vless("a", 22401), vless("b", 22402)}, "routing": routes("a"),
	}
	if useReconciler {
		config["outbounds"] = []any{map[string]any{"tag": "api", "protocol": "blackhole"},
			map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "direct", "protocol": "freedom"}}
		config["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}}
	}
	dir, err := os.MkdirTemp("", "flow-integration-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "control.sock")
	gateway := startXray(t, binary, config, "127.0.0.1:22386", xrayflow.SocketEnvironment+"="+socket)
	defer gateway.stop(t)
	control := xrayflow.NewClient(socket)
	var reconciler *dataplane.Reconciler
	var plan dataplane.DesiredPlan
	if useReconciler {
		adapter := NewAdapter(binary, "127.0.0.1:22386", "1.1.1.1", nil)
		adapter.ConfigureFlowControl(socket)
		plan = dataplane.DesiredPlan{Generation: 1, FailClosed: true, DirectSuffixes: []string{".ru"},
			Clients: []dataplane.ClientRoute{
				{ClientID: "alice", SourceCIDR: "127.0.0.2/32", TCPOutbound: "a", BlockUDP: true},
				{ClientID: "bob", SourceCIDR: "127.0.0.3/32", TCPOutbound: "a", BlockUDP: true},
			}}
		for _, target := range []struct {
			tag  string
			port int
		}{{"a", 22401}, {"b", 22402}} {
			encoded, _ := json.Marshal(vless(target.tag, target.port))
			plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{ID: target.tag, Protocol: dataplane.ProtocolVLESS, Config: encoded})
		}
		reconciler, err = dataplane.NewReconciler(adapter, filepath.Join(dir, "applied.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := reconciler.Apply(t.Context(), plan); err != nil {
			t.Fatal(err)
		}
	}
	dial := func(source string) net.Conn {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: time.Second}
		c, err := d.Dial("tcp", "127.0.0.1:22354")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	old, other := dial("127.0.0.2"), dial("127.0.0.3")
	requireFlowEcho(t, old, 2, 'A')
	requireFlowEcho(t, other, 3, 'A')
	snapshot, err := control.Snapshot(t.Context())
	if err != nil {
		t.Fatalf("flow control unavailable: %v", err)
	}
	if snapshot.Active < 2 {
		t.Fatalf("TCP dispatches not registered: %+v", snapshot)
	}
	if useReconciler {
		blackhole.Store(true)
		_ = old.SetDeadline(time.Now().Add(150 * time.Millisecond))
		_, _ = old.Write([]byte{2})
		var buffer [1]byte
		if _, err := old.Read(buffer[:]); err == nil {
			t.Fatal("old TCP not blackholed")
		}
		plan.Generation++
		plan.Clients = append([]dataplane.ClientRoute(nil), plan.Clients...)
		plan.Clients[0].TCPOutbound = "b"
		scopes := []dataplane.FlowRecovery{{ClientID: "alice", SourceCIDR: "127.0.0.2/32", FailedOutbound: "a", ReplacementOutbound: "b"}}
		if err := reconciler.ApplyWithRecovery(t.Context(), plan, scopes); err != nil {
			t.Fatal(err)
		}
		_ = old.SetReadDeadline(time.Now().Add(time.Second))
		_, err := old.Read(buffer[:])
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("gateway did not terminate hung flow: %v", err)
		}
		fresh := dial("127.0.0.2")
		requireFlowEcho(t, fresh, 2, 'B')
		if err := reconciler.ApplyWithRecovery(t.Context(), plan, scopes); err != nil {
			t.Fatal(err)
		}
		requireFlowEcho(t, other, 3, 'A')
		requireFlowEcho(t, fresh, 2, 'B')
		t.Log("GATEWAY recovery applied replacement, closed hung old TCP, preserved healthy same-outbound client and new TCP on replay")
		return
	}
	switchRoute := func(tag string) {
		if out, err := replaceRules(t.Context(), binary, "127.0.0.1:22386", routes(tag)); err != nil {
			t.Fatalf("rules: %v %s", err, out)
		}
	}
	switchRoute("b")
	fresh := dial("127.0.0.2")
	requireFlowEcho(t, fresh, 2, 'B')
	// Same client and old tag, but accepted after the snapshot: a delayed reset
	// must not touch this session if the route is later reused after recovery.
	switchRoute("a")
	freshSameTag := dial("127.0.0.2")
	requireFlowEcho(t, freshSameTag, 3, 'A')
	switchRoute("b")
	blackhole.Store(true)
	_ = old.SetDeadline(time.Now().Add(150 * time.Millisecond))
	_, _ = old.Write([]byte{2})
	var buffer [1]byte
	if _, err := old.Read(buffer[:]); err == nil {
		t.Fatal("fixture did not blackhole old TCP")
	}
	q := xrayflow.ResetRequest{Snapshot: snapshot, Outbound: "a", Source: "127.0.0.2"}
	for want := 1; want >= 0; want-- {
		if n, err := control.Reset(t.Context(), q); err != nil || n != want {
			t.Fatalf("reset closed=%d want%d err=%v", n, want, err)
		}
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	_, err = old.Read(buffer[:])
	var timeout net.Error
	if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("old TCP still hung after reset: %v", err)
	}
	requireFlowEcho(t, other, 3, 'A')
	requireFlowEcho(t, fresh, 2, 'B')
	requireFlowEcho(t, freshSameTag, 3, 'A')
	t.Log("RECOVERY old failed TCP terminated; other client, replacement and post-snapshot same-tag TCP survived replay")
}

func flowEchoFixture(t *testing.T, mark byte, blackhole *atomic.Bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var b [1]byte
				for {
					if _, err := io.ReadFull(c, b[:]); err != nil {
						return
					}
					if blackhole != nil && blackhole.Load() && b[0] == 2 {
						continue
					}
					if _, err := c.Write([]byte{mark}); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

func requireFlowEcho(t *testing.T, c net.Conn, payload, mark byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte{payload}); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != mark {
		t.Fatalf("echo=%q want%q err=%v", b, mark, err)
	}
}
