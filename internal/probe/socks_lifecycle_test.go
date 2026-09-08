package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingSOCKSServer struct {
	address     string
	active      atomic.Int32
	listener    net.Listener
	wait        sync.WaitGroup
	closeOnce   sync.Once
	connections map[net.Conn]struct{}
	mu          sync.Mutex
}

func newCountingSOCKSServer(t *testing.T) *countingSOCKSServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &countingSOCKSServer{
		address:     listener.Addr().String(),
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
	}
	server.wait.Add(1)
	go func() {
		defer server.wait.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.wait.Add(1)
			go func() {
				defer server.wait.Done()
				server.serve(connection)
			}()
		}
	}()
	t.Cleanup(server.Close)
	return server
}

func (server *countingSOCKSServer) Address() string { return server.address }

func (server *countingSOCKSServer) Active() int32 { return server.active.Load() }

func (server *countingSOCKSServer) Close() {
	server.closeOnce.Do(func() {
		_ = server.listener.Close()
		server.mu.Lock()
		for connection := range server.connections {
			_ = connection.Close()
		}
		server.mu.Unlock()
		server.wait.Wait()
	})
}

func (server *countingSOCKSServer) WaitForZero(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if server.Active() == 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return server.Active() == 0
}

func (server *countingSOCKSServer) serve(client net.Conn) {
	server.mu.Lock()
	server.connections[client] = struct{}{}
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		delete(server.connections, client)
		server.mu.Unlock()
		_ = client.Close()
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var hello [2]byte
	if _, err := io.ReadFull(client, hello[:]); err != nil || hello[0] != 5 {
		return
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	host, err := readSOCKSTestHost(client, request[3])
	if err != nil {
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:]))))
	upstream, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	server.active.Add(1)
	defer server.active.Add(-1)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func readSOCKSTestHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		address := make([]byte, net.IPv4len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 4:
		address := make([]byte, net.IPv6len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", err
		}
		address := make([]byte, int(size[0]))
		_, err := io.ReadFull(reader, address)
		return string(address), err
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
}

func TestDisposableRouteClientsReturnSOCKSConnectionsToZero(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)
	proxy := newCountingSOCKSServer(t)
	for range 100 {
		client := (Liveness{}).client(context.Background(), proxy.Address())
		response, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		client.CloseIdleConnections()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent {
			t.Fatalf("status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
		}
	}
	if !proxy.WaitForZero(2*time.Second) || proxy.Active() != 0 {
		t.Fatalf("active SOCKS connections=%d", proxy.Active())
	}
}
