package i2p

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/socks5"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRealI2PProcessIsClientOnlyAndStops(t *testing.T) {
	binary := os.Getenv("HYDRAT_I2PD_BINARY")
	if binary == "" {
		t.Skip("set HYDRAT_I2PD_BINARY inside isolated image")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	wrapper := filepath.Join(t.TempDir(), "i2pd-test")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+strconv.Quote(binary)+" \"$@\" --reseed.file=/nonexistent-isolated-test.su3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := &ExecRouter{Binary: wrapper, Directory: t.TempDir(), Output: os.Stdout}
	defer r.Stop(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, err := r.Inspect(ctx)
		if err == nil {
			if _, e := os.Stat(r.Directory + "/control.sock"); e == nil {
				if status.Transit != 0 {
					t.Fatal("foreign transit accepted")
				}
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("I2P control unavailable:", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.Remove(filepath.Join(r.Directory, "control.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Inspect(ctx); err == nil {
		t.Fatal("lost control socket accepted after verified startup")
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if r.cmd != nil {
		t.Fatal("process survived stop")
	}
}

func TestGeneratedConfigUsesDedicatedClientTunnels(t *testing.T) {
	r := &ExecRouter{Binary: "/bin/true", Directory: t.TempDir()}
	if err := r.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(context.Background())
	config, _ := os.ReadFile(filepath.Join(r.Directory, "i2pd.conf"))
	for _, value := range []string{"keys=shareddest", "notransit=true", "floodfill=false", "share=0", "tunconf=/dev/null", "tunnelsdir=" + filepath.Join(r.Directory, "empty-tunnels")} {
		if !strings.Contains(string(config), value) {
			t.Fatalf("missing fixed setting %s", value)
		}
	}
}

// Opt-in public network test: no transit, no published ports, fixed public site.
func TestPublicI2PWeb(t *testing.T) {
	if os.Getenv("HYDRAT_I2P_PUBLIC_TEST") != "1" {
		t.Skip("explicit isolated public I2P lab required")
	}
	r := &ExecRouter{Binary: "/usr/local/bin/i2pd", Directory: "/data/i2p", Output: os.Stdout}
	if err := r.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(context.Background())
	deadline := time.Now().Add(6 * time.Minute)
	started := time.Now()
	for {
		status, err := r.Inspect(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if status.Transit != 0 {
			t.Fatal("foreign transit", status.Transit)
		}
		if status.Ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("I2P did not become ready")
		}
		time.Sleep(time.Second)
	}
	t.Logf("router warm after %s", time.Since(started))
	for i := 0; i < 2; i++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (socks5.Dialer{HandshakeTimeout: 90 * time.Second, ProxyAddress: "127.0.0.1:4447"}).DialContext(ctx, network, address)
		}}
		client := &http.Client{Transport: tr, Timeout: 90 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt", nil)
		res, err := client.Do(req)

		if err != nil {
			cancel()
			tr.CloseIdleConnections()
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		cancel()
		tr.CloseIdleConnections()
		if err != nil || res.StatusCode != 200 {
			t.Fatal("site response", res.StatusCode, err)
		}
		t.Logf("public site attempt %d responded in %s", i+1, time.Since(start))
	}
	status, err := r.Inspect(t.Context())
	if err != nil || status.Transit != 0 {
		t.Fatal(status, err)
	}
}
func TestReadinessUsesTheSameDestinationAsSOCKS(t *testing.T) {
	r := &ExecRouter{Binary: "/bin/true", Directory: t.TempDir()}
	if err := r.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(context.Background())
	config, _ := os.ReadFile(filepath.Join(r.Directory, "i2pd.conf"))
	if !strings.Contains(string(config), "keys=shareddest") || !strings.Contains(string(config), "[shareddest]\ninbound.length=3\noutbound.length=3\ninbound.quantity=2\noutbound.quantity=2") {
		t.Fatal("control readiness and SOCKS use different tunnel pools")
	}
}
