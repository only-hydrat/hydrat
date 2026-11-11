package onion

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestDNSListenerUDPAndTCPAndShutdown(t *testing.T) {
	handler := DNS{Forward: func(_ context.Context, b []byte) ([]byte, error) {
		var m dnsmessage.Message
		m.Unpack(b)
		m.Response = true
		return m.Pack()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Listen(ctx, "127.0.0.1:0", handler)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 123}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, _ := msg.Pack()
	for _, network := range []string{"udp", "tcp"} {
		c, err := net.DialTimeout(network, server.Addr(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		var reply []byte
		if network == "tcp" {
			prefix := []byte{byte(len(packet) >> 8), byte(len(packet))}
			c.Write(append(prefix, packet...))
			if _, err := io.ReadFull(c, prefix); err != nil {
				t.Fatal(err)
			}
			reply = make([]byte, binary.BigEndian.Uint16(prefix))
			_, err = io.ReadFull(c, reply)
		} else {
			c.Write(packet)
			reply = make([]byte, 2048)
			var n int
			n, err = c.Read(reply)
			reply = reply[:n]
		}
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		var decoded dnsmessage.Message
		if err := decoded.Unpack(reply); err != nil || !decoded.Response || decoded.ID != 123 {
			t.Fatalf("bad %s reply", network)
		}
	}
	cancel()
	server.Close()
	if c, err := net.DialTimeout("tcp", server.Addr(), 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener still open")
	}
}

func TestUDPTruncatesOversizedOrdinaryResponse(t *testing.T) {
	var q dnsmessage.Message
	q.Header.ID = 1
	q.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("ordinary.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
	query, _ := q.Pack()
	q.Response = true
	for i := 0; i < 100; i++ {
		q.Answers = append(q.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
	}
	response, _ := q.Pack()
	bounded := udpReply(query, response)
	if len(bounded) > 512 {
		t.Fatal("oversized UDP reply", len(bounded))
	}
	var parsed dnsmessage.Message
	if err := parsed.Unpack(bounded); err != nil || !parsed.Truncated {
		t.Fatal("TCP retry not signaled", err)
	}
}

func TestOnionConcurrencyCannotConsumeOrdinaryDNSBudget(t *testing.T) {
	book, err := OpenMappings(filepath.Join(t.TempDir(), "book"), "198.18.0.0/15", 16)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	handler := DNS{Resolve: func(_ netip.Addr, name string) (netip.Addr, error) { return book.Resolve(name) }, Allowed: func(netip.Addr) bool { return true }, Install: func(ctx context.Context, ip, host string) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, Forward: func(ctx context.Context, b []byte) ([]byte, error) {
		var m dnsmessage.Message
		m.Unpack(b)
		m.Response = true
		return m.Pack()
	}}
	s, err := Listen(t.Context(), "127.0.0.1:0", handler)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer close(release)
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(testHost(1) + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, _ := q.Pack()
	for i := 0; i < 8; i++ {
		c, e := net.Dial("udp", s.Addr())
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.Write(packet)
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("onion budget did not fill")
		}
	}
	c, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	q.Questions[0].Name = dnsmessage.MustNewName("ordinary.test.")
	packet, _ = q.Pack()
	c.Write(packet)
	b := make([]byte, 512)
	if _, err := c.Read(b); err != nil {
		t.Fatal("ordinary DNS blocked behind onion", err)
	}
}
