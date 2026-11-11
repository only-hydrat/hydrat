package xrayapi

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/i2p"
	"github.com/only-hydrat/hydrat/internal/onion"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Extends the isolated WireGuard/Tor regression lab with the real DNS, Xray and
// I2P bridge path. The final SOCKS backend is local; public i2pd is tested by the
// separate opt-in TestPublicI2PWeb, so this test needs no public network.
func testI2PBridgeVPN(t *testing.T, ctx context.Context, root string, a *Adapter, r *dataplane.Reconciler, plan *dataplane.DesiredPlan, check func(string, string, string, bool), stream func(string, string, string) <-chan error, unrelated ...<-chan error) {
	t.Helper()
	cfg := filepath.Join(root, "i2p-socks.json")
	os.WriteFile(cfg, []byte(`{"log":{"loglevel":"warning","access":"none"},"inbounds":[{"listen":"127.0.0.1","port":4447,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom","settings":{"redirect":"10.66.0.1:4747"}}]}`), 0600)
	core := exec.CommandContext(ctx, "xray", "run", "-config", cfg)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { core.Process.Kill(); core.Wait() }()
	socket := filepath.Join(root, "i2p-supervisor.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var readyAt atomic.Int64
	control := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/status":
			state := "warm"
			if time.Now().UnixNano() < readyAt.Load() {
				state = "starting"
			}
			json.NewEncoder(w).Encode(i2p.Status{State: state})
		case "/lease":
			readyAt.CompareAndSwap(0, time.Now().Add(65*time.Second).UnixNano())
			json.NewEncoder(w).Encode(map[string]string{"id": "lab"})
		default:
			w.WriteHeader(204)
		}
	})}
	go control.Serve(l)
	defer control.Close()
	book, err := i2p.OpenBook(filepath.Join(root, "i2p-book.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	host := "lab.i2p"
	dest := strings.Repeat("a", 52) + ".b32.i2p"
	if err := book.Put(host, dest, "manual", false); err != nil {
		t.Fatal(err)
	}
	access := &i2p.Access{Policy: r.OnionPolicy, Available: true, Control: i2p.ControlClient{Socket: socket}}
	bridge := &i2p.Bridge{Book: book, Control: i2p.ControlClient{Socket: socket}, Proxy: "127.0.0.1:4447", Grants: access.Grants}
	bridgeListener, err := net.Listen("tcp4", "127.0.0.1:19447")
	if err != nil {
		t.Fatal(err)
	}
	go bridge.ServeListener(ctx, bridgeListener)
	dns := i2p.DNS{Book: book, Allowed: bridge.Allowed, Wake: func(context.Context) error { return nil }}
	listener, err := onion.Listen(ctx, "10.66.0.1:53", onion.DNS{I2P: dns.Handle})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := strings.Repeat("x", 32)
	tag := "i2p-client-alice"
	raw, _ := json.Marshal(map[string]any{"tag": tag, "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 19447, "users": []any{map[string]any{"user": "alice", "pass": token, "level": dataplane.I2PPolicyLevel}}}}}})
	plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{ID: tag, Protocol: dataplane.ProtocolI2P, Config: raw})
	plan.Clients[0].I2PEnabled = true
	plan.Clients[0].I2POutbound = tag
	plan.Clients[0].I2PToken = token
	plan.Generation++
	a.ConfigureI2P(true)
	if err := r.Apply(ctx, *plan); err != nil {
		t.Fatal(err)
	}
	check("I2P HTTP through WireGuard/DNS/Xray/bridge", "alice", "http://lab.i2p/", false)
	ip, _, err := book.Resolve(host)
	if err != nil {
		t.Fatal(err)
	}
	cached := "http://" + ip.String() + "/"
	check("I2P denied for other client", "bob", "http://lab.i2p/", true)
	check("I2P cached IP denied for other client", "bob", cached, true)
	active := stream("alice", cached+"stream", "i2p-stream")
	plan.Generation++
	plan.Clients[0].I2PEnabled = false
	plan.Clients[0].I2POutbound = ""
	plan.Clients[0].I2PToken = ""
	if err := r.Apply(ctx, *plan); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-active:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked I2P stream remains open")
	}
	for _, c := range unrelated {
		select {
		case err := <-c:
			t.Fatal("I2P revoke closed unrelated stream", err)
		default:
		}
	}
	check("revoked I2P cached IP denied", "alice", cached, true)
	check("ordinary HTTP after I2P revoke", "alice", "http://10.66.0.1:4747/", false)
	t.Log("I2P permission revocation preserved ordinary streams")
}
