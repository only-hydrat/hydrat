package i2p

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeRejectsAnonymousAndInvalidCredentials(t *testing.T) {
	for _, anon := range []bool{true, false} {
		t.Run(map[bool]string{true: "anonymous", false: "bad-password"}[anon], func(t *testing.T) {
			b := &Bridge{Grants: func() []Grant { return []Grant{{User: "alice", Password: "correct"}} }}
			server, client := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { defer server.Close(); done <- b.handle(context.Background(), server) }()
			if anon {
				client.Write([]byte{5, 1, 0})
				var r [2]byte
				io.ReadFull(client, r[:])
				if r[1] != 255 {
					t.Fatal(r)
				}
			} else {
				client.Write([]byte{5, 1, 2})
				var r [2]byte
				io.ReadFull(client, r[:])
				client.Write(append([]byte{1, 5}, []byte("alice")...))
				client.Write(append([]byte{3}, []byte("bad")...))
				io.ReadFull(client, r[:])
				if r[1] == 0 {
					t.Fatal("unauthorized")
				}
			}
			if err := <-done; err == nil {
				t.Fatal("admitted unauthorized user")
			}
		})
	}
}
func TestRelayTerminatesWhenClientDisconnects(t *testing.T) {
	a, client := net.Pipe()
	b, upstream := net.Pipe()
	defer upstream.Close()
	done := make(chan struct{})
	go func() { relayInput(a, b, a); close(done) }()
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client disconnect pinned stream")
	}
}
