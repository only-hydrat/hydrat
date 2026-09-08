package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialerPacketConnRelaysUDPAndPreservesPeerAddress(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		var hello [3]byte
		_, _ = io.ReadFull(server, hello[:])
		_, _ = server.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(server, request[:])
		if request[0] != 5 || request[1] != 3 {
			return
		}
		address := relay.LocalAddr().(*net.UDPAddr)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(address.Port))
		response := append([]byte{5, 0, 0, 1}, address.IP.To4()...)
		response = append(response, port...)
		_, _ = server.Write(response)
		_, _ = io.Copy(io.Discard, server)
	}()

	dialer := Dialer{
		ProxyAddress: "127.0.0.1:1080",
		Dial:         func(context.Context, string, string) (net.Conn, error) { return client, nil },
	}
	packet, err := dialer.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	target := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 443}
	if _, err := packet.WriteTo([]byte("ping"), target); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 64)
	_ = relay.SetReadDeadline(time.Now().Add(time.Second))
	count, source, err := relay.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest := []byte{0, 0, 0, 1, 198, 51, 100, 7, 1, 187, 'p', 'i', 'n', 'g'}
	if !bytes.Equal(buffer[:count], wantRequest) {
		t.Fatalf("relay request=%v want=%v", buffer[:count], wantRequest)
	}
	wantPeer := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 8443}
	response := []byte{0, 0, 0, 1, 203, 0, 113, 9, 32, 251, 'p', 'o', 'n', 'g'}
	if _, err := relay.WriteToUDP(response, source); err != nil {
		t.Fatal(err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(time.Second))
	count, peer, err := packet.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "pong" || peer.String() != wantPeer.String() {
		t.Fatalf("response=%q peer=%s want pong/%s", buffer[:count], peer, wantPeer)
	}
}

func TestDialerNegotiatesAuthenticatedDomainConnect(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	requested := make(chan string, 1)
	go func() {
		defer close(requested)
		header := make([]byte, 4)
		_, _ = io.ReadFull(server, header[:2])
		methods := make([]byte, int(header[1]))
		_, _ = io.ReadFull(server, methods)
		_, _ = server.Write([]byte{5, 2})
		_, _ = io.ReadFull(server, header[:2])
		username := make([]byte, int(header[1]))
		_, _ = io.ReadFull(server, username)
		_, _ = io.ReadFull(server, header[:1])
		password := make([]byte, int(header[0]))
		_, _ = io.ReadFull(server, password)
		if string(username) != "user" || string(password) != "pass" {
			requested <- "bad auth"
			return
		}
		_, _ = server.Write([]byte{1, 0})
		_, _ = io.ReadFull(server, header)
		var host string
		if header[3] == 3 {
			_, _ = io.ReadFull(server, header[:1])
			name := make([]byte, int(header[0]))
			_, _ = io.ReadFull(server, name)
			host = string(name)
		}
		_, _ = io.ReadFull(server, header[:2])
		port := binary.BigEndian.Uint16(header[:2])
		requested <- net.JoinHostPort(host, "443")
		if port != 443 {
			return
		}
		_, _ = server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	}()
	dialer := Dialer{
		ProxyAddress: "127.0.0.1:1080", Username: "user", Password: "pass",
		Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", "api.openai.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if got := <-requested; got != "api.openai.com:443" {
		t.Fatalf("target=%s", got)
	}
}
