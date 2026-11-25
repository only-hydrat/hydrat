package xraycore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestPrivateAPIStartsAndReleasesItsSocket(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "api")
	endpoint := "unix://" + socket
	config := filepath.Join(directory, "core.json")
	if err := os.WriteFile(config, []byte(`{
		"api":{"tag":"api","listen":"`+socket+`","services":["HandlerService","RoutingService","StatsService"]},
		"outbounds":[{"tag":"block","protocol":"blackhole"}],
		"routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":"block"}]},
		"stats":{}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := Host{}
	for range 2 {
		instance, err := host.Start(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = instance.Close() })
		if err := host.Run(ctx, `{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`,
			"", "api", "ado", "--server="+endpoint); err != nil {
			t.Fatal(err)
		}
		if err := host.Run(ctx, `{"routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":"direct"}]}}`,
			"", "api", "adrules", "--timeout=2", "--server="+endpoint); err != nil {
			t.Fatal(err)
		}
		if value, err := host.Uplink(ctx, endpoint, "not present"); err != nil || value != 0 {
			t.Fatalf("initial traffic counter = %d, %v", value, err)
		}
		if err := host.Run(ctx, "", "", "api", "rmo", "--server="+endpoint, "direct"); err != nil {
			t.Fatal(err)
		}
		if err := instance.Close(); err != nil {
			t.Fatal(err)
		}
		if conn, err := net.DialTimeout("unix", socket, time.Second); err == nil {
			conn.Close()
			t.Fatal("private API socket accepts connections after close")
		}
	}
}

func TestEmbeddedInstancesKeepTheirDNSSeparate(t *testing.T) {
	listeners := make([]net.Listener, 0, 2)
	for _, address := range []string{"127.0.0.1:0", "127.0.0.2:0"} {
		if len(listeners) > 0 {
			address = fmt.Sprintf("127.0.0.2:%d", listeners[0].Addr().(*net.TCPAddr).Port)
		}
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		listeners = append(listeners, listener)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var instances []*core.Instance
	for i, listener := range listeners {
		go func() {
			if conn, err := listener.Accept(); err == nil {
				defer conn.Close()
				_, _ = conn.Write([]byte{byte(i + 1)})
			}
		}()
		path := filepath.Join(dir, fmt.Sprintf("dns-%d.json", i))
		conf := fmt.Sprintf(`{
			"dns":{"hosts":{"isolated.example":%q}},
			"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":"ForceIPv4"}}}]
		}`, listener.Addr().(*net.TCPAddr).IP.String())
		if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
			t.Fatal(err)
		}
		instance, err := (Host{}).Start(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer instance.Close()
		instances = append(instances, instance.(*core.Instance))
	}
	port := xraynet.Port(listeners[0].Addr().(*net.TCPAddr).Port)
	for i, instance := range instances {
		connection, err := core.Dial(ctx, instance, xraynet.TCPDestination(xraynet.DomainAddress("isolated.example"), port))
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		var response [1]byte
		_, err = io.ReadFull(connection, response[:])
		_ = connection.Close()
		if err != nil || response[0] != byte(i+1) {
			t.Fatalf("instance %d reached %d: %v", i+1, response[0], err)
		}
	}
}

func TestPrivateAPIRejectsNonUnixEndpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := (Host{}).Run(ctx, "", "", "api", "rmo", "--server=127.0.0.1:1", "direct")
	if !errors.Is(err, errPrivateAPI) {
		t.Fatalf("TCP endpoint gave %v", err)
	}
}

func TestPrivateAPIAcceptsNativeAbsoluteSocketPath(t *testing.T) {
	endpoint := "unix://" + filepath.Join(t.TempDir(), "api.sock")
	conn, err := privateAPI(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
