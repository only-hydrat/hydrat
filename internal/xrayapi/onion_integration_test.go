package xrayapi

// This opt-in test runs only inside scripts/test-onion-integration.sh's isolated
// privileged container. It uses kernel WireGuard, the shipped Xray and a local
// Tor test network, never production peers or the public Tor network.
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/onion"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
	"golang.org/x/net/dns/dnsmessage"
)

func TestOnionVPNClient(t *testing.T) {
	if os.Getenv("HYDRAT_ONION_CLIENT") == "" {
		t.Skip("integration child")
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "10.66.0.1:53")
	}}
	d := &net.Dialer{Resolver: resolver, Timeout: 3 * time.Second}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		// Go's resolver intentionally rejects .onion even with a custom DNS dialer.
		// Send an explicit DNS query, as a browser with onion DNS enabled does.
		if strings.HasSuffix(host, ".onion") || strings.HasSuffix(host, ".i2p") {
			name, err := dnsmessage.NewName(host + ".")
			if err != nil {
				return nil, err
			}
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
			packet, _ := q.Pack()
			c, err := d.DialContext(ctx, "udp", "10.66.0.1:53")
			if err != nil {
				return nil, err
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(packet); err != nil {
				return nil, err
			}
			b := make([]byte, 4096)
			n, err := c.Read(b)
			if err != nil {
				return nil, err
			}
			var reply dnsmessage.Message
			if err := reply.Unpack(b[:n]); err != nil {
				return nil, err
			}
			host = ""
			for _, rr := range reply.Answers {
				if a, ok := rr.Body.(*dnsmessage.AResource); ok {
					host = net.IP(a.A[:]).String()
					break
				}
			}
			if host == "" {
				return nil, fmt.Errorf("onion DNS rejected: %v", reply.RCode)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true}, Timeout: 15 * time.Second}
	target := os.Getenv("HYDRAT_ONION_URL")
	if strings.Contains(target, ".i2p/") {
		client.Timeout = 90 * time.Second
	}
	if strings.HasPrefix(target, "ssh:") {
		c, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(target, "ssh:"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 128)
		n, err := c.Read(b)
		if err != nil || !strings.HasPrefix(string(b[:n]), "SSH-2.0-") {
			t.Fatal("SSH greeting missing", err)
		}
		return
	}
	if os.Getenv("HYDRAT_ONION_STREAM") != "" {
		client.Timeout = 0
	}
	req, err := http.NewRequestWithContext(t.Context(), "GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host := os.Getenv("HYDRAT_ONION_HOST"); host != "" {
		req.Host = host
	}
	response, err := client.Do(req)
	if os.Getenv("HYDRAT_ONION_DENY") == "1" {
		if err == nil {
			response.Body.Close()
			t.Fatal("denied traffic reached server")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if marker := os.Getenv("HYDRAT_ONION_STREAM"); marker != "" {
		b := make([]byte, len("stream-open\n"))
		if _, err := io.ReadFull(response.Body, b); err != nil {
			t.Fatal(err)
		}
		if string(b) != "stream-open\n" {
			t.Fatal("stream not opened")
		}
		if err := os.WriteFile(marker, []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		return
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil || string(b) != "hydrat-onion-lab" {
		t.Fatalf("unexpected response %q: %v", b, err)
	}
}

func TestOnionVPNIntegration(t *testing.T) {
	if os.Getenv("HYDRAT_ONION_LAB") != "1" {
		t.Skip("use scripts/test-onion-integration.sh")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		c := exec.CommandContext(ctx, name, args...)
		b, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", "alice").Run()
		exec.Command("ip", "netns", "del", "bob").Run()
		exec.Command("ip", "link", "del", "wg-lab").Run()
		exec.Command("nft", "delete", "table", "ip", "onionlab").Run()
	})
	root := t.TempDir()
	os.Chmod(root, 0700)
	keys := func(name string) (string, string) {
		priv := run("wg", "genkey")
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(priv+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("wg", "pubkey")
		c.Stdin = strings.NewReader(priv)
		pub, err := c.Output()
		if err != nil {
			t.Fatal(err)
		}
		return p, strings.TrimSpace(string(pub))
	}
	serverKey, serverPub := keys("gateway.key")
	run("ip", "link", "add", "wg-lab", "type", "wireguard")
	run("ip", "addr", "add", "10.66.0.1/24", "dev", "wg-lab")
	run("wg", "set", "wg-lab", "private-key", serverKey, "listen-port", "51830")
	run("ip", "link", "set", "wg-lab", "up")
	for i, name := range []string{"alice", "bob"} {
		key, pub := keys(name + ".key")
		address := fmt.Sprintf("10.66.0.%d/32", i+2)
		run("ip", "netns", "add", name)
		run("ip", "link", "add", name, "type", "wireguard")
		run("ip", "link", "set", name, "netns", name)
		run("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")
		run("ip", "netns", "exec", name, "ip", "addr", "add", address, "dev", name)
		run("wg", "set", "wg-lab", "peer", pub, "allowed-ips", address)
		run("ip", "netns", "exec", name, "wg", "set", name, "private-key", key, "peer", serverPub, "endpoint", "127.0.0.1:51830", "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "5")
		run("ip", "netns", "exec", name, "ip", "link", "set", name, "up")
		run("ip", "netns", "exec", name, "ip", "route", "add", "default", "dev", name)
	}
	nft := filepath.Join(root, "nft.conf")
	os.WriteFile(nft, []byte("table ip onionlab { chain prerouting { type nat hook prerouting priority dstnat; policy accept; iifname \"wg-lab\" tcp dport != 53 redirect to :12345; }\n}\n"), 0600)
	run("nft", "-f", nft)
	web := &http.Server{Addr: "0.0.0.0:4747", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			fmt.Fprint(w, "stream-open\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "hydrat-onion-lab")
	})}
	go web.ListenAndServe()
	defer web.Close()
	ssh, err := net.Listen("tcp", "0.0.0.0:18022")
	if err != nil {
		t.Fatal(err)
	}
	defer ssh.Close()
	go func() {
		for {
			c, e := ssh.Accept()
			if e != nil {
				return
			}
			io.WriteString(c, "SSH-2.0-hydrat-lab\r\n")
			c.Close()
		}
	}()
	// A local VLESS server exercises the ordinary proxy path independently of Tor.
	normalCfg := filepath.Join(root, "normal.json")
	os.WriteFile(normalCfg, []byte(`{"log":{"loglevel":"warning","access":"none"},"inbounds":[{"listen":"127.0.0.1","port":18090,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"12345678-1234-1234-1234-123456789abc"}]}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp","ip":["10.66.0.1/32"],"port":"4747,18022"}]}}]}`), 0600)
	normalCore := exec.CommandContext(ctx, "xray", "run", "-config", normalCfg)

	if err := normalCore.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { normalCore.Process.Kill(); normalCore.Wait() }()
	flow := filepath.Join(root, "flow.sock")
	config := `{"policy":{"levels":{"19819":{"handshake":300}}},"log":{"loglevel":"warning","access":"none"},"api":{"tag":"api","listen":"127.0.0.1:10085","services":["HandlerService","RoutingService"]},"inbounds":[{"tag":"vpn","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":true},"streamSettings":{"sockopt":{"tproxy":"redirect"}}}],"outbounds":[{"tag":"block","protocol":"blackhole"},{"tag":"api","protocol":"blackhole"},{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}`
	cfg := filepath.Join(root, "xray.json")
	os.WriteFile(cfg, []byte(config), 0600)
	defer func() {
		if t.Failed() {
			for _, args := range [][]string{{"wg", "show", "all", "latest-handshakes"}, {"wg", "show", "all", "transfer"}, {"ip", "netns", "exec", "alice", "wg", "show"}} {
				b, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
				t.Logf("diagnostic: %s", b)
			}
			b, _ := os.ReadFile(filepath.Join(root, "xray.log"))
			t.Logf("Xray: %s", b)
		}
	}()
	logFile, _ := os.Create(filepath.Join(root, "xray.log"))
	defer logFile.Close()
	xray := exec.CommandContext(ctx, "xray", "run", "-config", cfg)
	xray.Env = append(os.Environ(), "HYDRAT_XRAY_FLOW_SOCKET="+flow)
	xray.Stdout = logFile
	xray.Stderr = logFile
	if err := xray.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { xray.Process.Kill(); xray.Wait() }()
	a := NewAdapter("xray", "127.0.0.1:10085", "1.1.1.1", nil)
	a.ConfigureFlowControl(flow)
	wait := func(label string, f func() error) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			if err = f(); err == nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(200 * time.Millisecond):
			}
		}
		t.Fatalf("%s: %v", label, err)
	}
	wait("Xray control", func() error { _, err := a.FlowSnapshot(ctx); return err })
	r, err := dataplane.NewReconciler(a, filepath.Join(root, "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	profiles := []torpool.Profile{{Slot: 0, Role: "warm", CandidateID: "a", SocksAddr: "127.0.0.1:19050", DataDir: "/chutney/net/nodes/006c"}, {Slot: 1, Role: "warm", CandidateID: "b", SocksAddr: "127.0.0.1:19051", DataDir: "/chutney/net/nodes/007h"}}
	runtime, err := onion.NewRuntime(filepath.Join(root, "onion.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { runtime.Close() }()
	runtime.Policy = r.OnionPolicy
	runtime.Profiles = func() []torpool.Profile { return profiles }
	for _, p := range profiles {
		wait("Tor readiness", func() error { return runtime.Prepare(ctx, p) })
	}
	var forwarded atomic.Int64
	// Match production: frontend -> dnsmasq -> UDP-only upstream. This
	// catches accidental conversion of all ordinary DNS traffic to TCP.
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	answerOrdinary := func(packet []byte) ([]byte, error) {
		forwarded.Add(1)
		var q dnsmessage.Message
		if err := q.Unpack(packet); err != nil {
			return nil, err
		}
		q.Response = true
		q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{10, 66, 0, 1}}}}
		return q.Pack()
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := upstream.ReadFrom(buffer)
			if err != nil {
				return
			}
			if reply, err := answerOrdinary(buffer[:n]); err == nil {
				upstream.WriteTo(reply, peer)
			}
		}
	}()
	_, upstreamPort, _ := net.SplitHostPort(upstream.LocalAddr().String())
	resolver := exec.CommandContext(ctx, "/usr/sbin/dnsmasq", "--keep-in-foreground", "--no-resolv", "--no-hosts", "--listen-address=127.0.0.1", "--port=1053", "--bind-interfaces", "--server=127.0.0.1#"+upstreamPort, "--pid-file=", "--conf-file=")
	if err := resolver.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { resolver.Process.Kill(); resolver.Wait() }()
	wait("dnsmasq listener", func() error {
		c, err := net.DialTimeout("tcp4", "127.0.0.1:1053", time.Second)
		if err == nil {
			c.Close()
		}
		return err
	})
	forward := onion.Forward("127.0.0.1:1053")
	listener := func() *onion.Listener {
		l, e := onion.Listen(ctx, "10.66.0.1:53", onion.DNS{Resolve: runtime.Resolve, Allowed: runtime.Allowed, Install: runtime.Install, Forward: forward})
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	dns := listener()
	defer func() { dns.Close() }()
	plan := dataplane.DesiredPlan{Generation: 1, FailClosed: true, DirectSuffixes: []string{".ru"}, Outbounds: []dataplane.Outbound{{ID: "normal", Protocol: dataplane.ProtocolVLESS, Config: json.RawMessage(`{"tag":"normal","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":18090,"users":[{"id":"12345678-1234-1234-1234-123456789abc","encryption":"none"}]}]}}`)}}, Clients: []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.66.0.2/32", TCPOutbound: "normal", BlockUDP: true, OnionEnabled: true, OnionOutbound: "onion-a", OnionReserveOutbound: "onion-b"}, {ClientID: "bob", SourceCIDR: "10.66.0.3/32", TCPOutbound: "normal", BlockUDP: true}}}
	for i, p := range profiles {
		tag := []string{"onion-a", "onion-b"}[i]
		v := xrayconfig.TorOutbound(p.SocksAddr, tag, "onion-alice", []byte("lab-only-secret"))
		b, _ := json.Marshal(v)
		plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{ID: tag, Protocol: dataplane.ProtocolTor, Config: b})
	}
	apply := func() {
		t.Helper()
		if err := r.Apply(ctx, plan); err != nil {
			t.Fatal(err)
		}
		plan.Clients = append([]dataplane.ClientRoute(nil), plan.Clients...)
	}
	apply()
	hostname, err := os.ReadFile("/chutney/net/nodes/007h/hidden_service/hostname")
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSpace(string(hostname))
	url := "http://" + host + ":5858/"
	hostHeader := ""
	request := func(who, url string, denied bool) error {
		c := exec.CommandContext(ctx, "ip", "netns", "exec", who, "/onion-test", "-test.run=^TestOnionVPNClient$", "-test.v")
		c.Env = append(os.Environ(), "HYDRAT_ONION_CLIENT=1", "HYDRAT_ONION_URL="+url)
		if hostHeader != "" {
			c.Env = append(c.Env, "HYDRAT_ONION_HOST="+hostHeader)
		}
		if denied {
			c.Env = append(c.Env, "HYDRAT_ONION_DENY=1")
		}
		b, e := c.CombinedOutput()
		if e != nil {
			return fmt.Errorf("%s: %w: %s", who, e, b)
		}
		return nil
	}
	check := func(label, who, url string, denied bool) {
		t.Helper()
		if err := request(who, url, denied); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		t.Log(label)
	}
	check("ordinary HTTP over WireGuard", "alice", "http://10.66.0.1:4747/", false)
	check("ordinary SSH over WireGuard", "alice", "ssh:10.66.0.1:18022", false)
	wait("onion service publication", func() error { return request("alice", url, false) })
	t.Log("onion HTTP over WireGuard, DNS, Xray and Tor passed")
	check("other client denied", "bob", url, true)
	ip, err := runtime.Mappings.Resolve(host)
	if err != nil {
		t.Fatal(err)
	}
	cached := "http://" + ip.String() + ":5858/"
	check("other client cached address denied", "bob", cached, true)
	hostHeader = "example.ru"
	check("synthetic IP cannot bypass permission with a direct Host header", "bob", cached, true)
	check("direct Host header cannot divert an authorized onion stream", "alice", cached, false)
	hostHeader = ""
	if forwarded.Load() != 0 {
		t.Fatal("onion DNS leaked", forwarded.Load())
	}
	check("ordinary DNS still works", "alice", "http://ordinary.test:4747/", false)
	if forwarded.Load() == 0 {
		t.Fatal("ordinary DNS was not forwarded")
	}
	// Keep real Xray flows open while changing only the onion route.
	stream := func(who, url, label string) <-chan error {
		marker := filepath.Join(root, label)
		c := exec.CommandContext(ctx, "ip", "netns", "exec", who, "/onion-test", "-test.run=^TestOnionVPNClient$")
		c.Env = append(os.Environ(), "HYDRAT_ONION_CLIENT=1", "HYDRAT_ONION_URL="+url, "HYDRAT_ONION_STREAM="+marker)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		t.Cleanup(func() { c.Process.Kill() })
		wait("stream opened", func() error { _, err := os.Stat(marker); return err })
		return done
	}
	onionStream := stream("alice", url+"stream", "onion-open")
	normalStream := stream("alice", "http://10.66.0.1:4747/stream", "normal-open")
	otherStream := stream("bob", "http://10.66.0.1:4747/stream", "other-open")
	plan.Generation++
	plan.Clients[0].OnionOutbound = "onion-b"
	plan.Clients[0].OnionReserveOutbound = ""
	apply()
	select {
	case err := <-onionStream:
		if err != nil {
			t.Fatal("onion stream reset", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old onion stream not closed")
	}
	for _, done := range []<-chan error{normalStream, otherStream} {
		select {
		case err := <-done:
			t.Fatal("unrelated stream closed", err)
		default:
		}
	}
	t.Log("real Xray reset closed only the old onion stream")
	check("reserve profile serves cached virtual address", "alice", cached, false)
	// Stop the previously selected Tor process: the replacement must remain usable.
	run("sh", "-c", "kill $(cat /chutney/net/nodes/006c/pid)")
	check("failed old profile does not break replacement", "alice", cached, false)
	plan.Generation++
	plan.Clients[0].OnionEnabled = false
	plan.Clients[0].OnionOutbound = ""
	apply()
	check("revoked DNS denied", "alice", url, true)
	check("revoked cached address denied", "alice", cached, true)
	check("ordinary HTTP after revoke", "alice", "http://10.66.0.1:4747/", false)
	check("other client ordinary HTTP", "bob", "http://10.66.0.1:4747/", false)
	// Reopen persistent state and replay into the still-serving profile.
	dns.Close()
	runtime.Close()
	runtime, err = onion.NewRuntime(filepath.Join(root, "onion.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime.Policy = r.OnionPolicy
	profiles = profiles[1:]
	runtime.Profiles = func() []torpool.Profile { return profiles }
	if err := runtime.Prepare(ctx, profiles[0]); err != nil {
		t.Fatal(err)
	}
	dns = listener()
	plan.Generation++
	plan.Clients[0].OnionEnabled = true
	plan.Clients[0].OnionOutbound = "onion-b"
	apply()
	check("gateway address book restart preserves cached mapping", "alice", cached, false)
	run("sh", "-c", "kill $(cat /chutney/net/nodes/007h/pid)")
	check("Tor unavailable fails closed", "alice", cached, true)
	check("ordinary HTTP survives Tor outage", "alice", "http://10.66.0.1:4747/", false)
	dns.Close()
	testI2PBridgeVPN(t, ctx, root, a, r, &plan, check, stream, normalStream, otherStream)
}
