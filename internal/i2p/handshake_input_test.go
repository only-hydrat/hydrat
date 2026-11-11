package i2p

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandshakeInputPreservesEarlyAndLaterData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader, finish, cleanup := handshakeInput(ctx, server, cancel)
	defer cleanup()
	written := make(chan struct{})
	go func() { client.Write([]byte("early")); close(written) }()
	<-written
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	go client.Write([]byte("later"))
	server.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 10)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "earlylater" {
		t.Fatal(string(data))
	}
}
func TestHandshakeInputBoundsEarlyData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, _, cleanup := handshakeInput(ctx, server, cancel)
	defer cleanup()
	go client.Write([]byte(strings.Repeat("x", 64<<10)))
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("unbounded early data")
	}
}
