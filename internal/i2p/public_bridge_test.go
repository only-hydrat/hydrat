package i2p

import (
	"context"
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/socks5"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicI2PBridge(t *testing.T) {
	if os.Getenv("HYDRAT_I2P_BRIDGE_TEST") != "1" {
		t.Skip("isolated live supervisor required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	control := ControlClient{Socket: "/run/hydrat-i2p/control.sock"}
	if _, err := control.Do(ctx, "POST", "/stop", nil); err != nil {
		t.Fatal(err)
	}
	defer control.Do(context.Background(), "POST", "/stop", nil)
	book, err := OpenBook(t.TempDir() + "/book.json")
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	dest := "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p"
	ip, _, err := book.Resolve(dest)
	if err != nil {
		t.Fatal(err)
	}
	bridge := &Bridge{Book: book, Control: control, Proxy: "127.0.0.1:4447", Grants: func() []Grant { return []Grant{{User: "lab", Password: strings.Repeat("x", 32)}} }}
	listener, err := net.Listen("tcp4", "127.0.0.1:19447")
	if err != nil {
		t.Fatal(err)
	}
	bridgeDone := make(chan error, 1)
	go func() {
		stop := context.AfterFunc(ctx, func() { listener.Close() })
		defer stop()
		for {
			conn, err := listener.Accept()
			if err != nil {
				bridgeDone <- err
				return
			}
			started := time.Now()
			err = bridge.handle(ctx, conn)
			conn.Close()
			if err != nil {
				t.Logf("bridge connection ended after %s: %v", time.Since(started), err)
			}
		}
	}()
	defer func() { cancel(); <-bridgeDone }()
	proxy, user, password := "127.0.0.1:19447", "lab", strings.Repeat("x", 32)
	if binary := os.Getenv("HYDRAT_I2P_XRAY_BINARY"); binary != "" {
		cfg := map[string]any{
			"log":       map[string]any{"loglevel": "info", "access": "none"},
			"policy":    map[string]any{"levels": map[string]any{"19819": map[string]any{"handshake": 300}}},
			"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": 19448, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
			"outbounds": []any{map[string]any{"protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 19447, "users": []any{map[string]any{"user": user, "pass": password, "level": dataplane.I2PPolicyLevel}}}}}}},
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "xray.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		core := exec.CommandContext(ctx, binary, "run", "-config", path)
		core.Stdout = os.Stdout
		core.Stderr = os.Stderr
		if err := core.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { core.Process.Kill(); core.Wait() }()
		proxy, user, password = "127.0.0.1:19448", "", ""
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, err := net.DialTimeout("tcp", proxy, time.Second)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var responseTime []time.Duration
	for i := 0; i < 2; i++ {
		start := time.Now()
		tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (socks5.Dialer{ProxyAddress: proxy, Username: user, Password: password, HandshakeTimeout: 5 * time.Minute}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "80"))
		}}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Minute}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+dest+"/hosts.txt", nil)
		res, err := client.Do(req)
		if err != nil {
			tr.CloseIdleConnections()
			state, statusErr := control.Status(ctx)
			t.Logf("runtime at failure: %+v, status error: %v", state, statusErr)
			t.Fatal(err)
		}
		t.Logf("request %d: HTTP %d headers after %s", i+1, res.StatusCode, time.Since(start))
		_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		tr.CloseIdleConnections()
		if err != nil || res.StatusCode != 200 {
			t.Fatal(res.StatusCode, err)
		}
		responseTime = append(responseTime, time.Since(start))
	}
	status, err := control.Status(ctx)
	if err != nil || status.Transit != 0 {
		t.Fatal(status, err)
	}
	t.Logf("Xray=%t bridge + supervisor + i2pd: cold=%s warm=%s transit=%d", os.Getenv("HYDRAT_I2P_XRAY_BINARY") != "", responseTime[0], responseTime[1], status.Transit)
}
