package onion

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestDNSIsolatesPermissionsAndNeverForwardsOnion(t *testing.T) {
	mappings, err := OpenMappings(filepath.Join(t.TempDir(), "map.json"), "198.18.0.0/15", 10)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	installed := 0
	handler := DNS{Resolve: func(_ netip.Addr, name string) (netip.Addr, error) { return mappings.Resolve(name) }, Allowed: func(ip netip.Addr) bool { return ip.String() == "10.44.0.2" },
		Install: func(context.Context, string, string) error { installed++; return nil },
		Forward: func(_ context.Context, packet []byte) ([]byte, error) { forwarded++; return packet, nil }}
	query := func(name string, kind dnsmessage.Type, source string) dnsmessage.Message {
		t.Helper()
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: kind, Class: dnsmessage.ClassINET}}}
		raw, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		response, err := handler.Handle(context.Background(), netip.MustParseAddr(source), raw)
		if err != nil {
			t.Fatal(err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(response); err != nil {
			t.Fatal(err)
		}
		return msg
	}
	if r := query(testHost(1), dnsmessage.TypeA, "10.44.0.3"); r.RCode != dnsmessage.RCodeRefused {
		t.Fatal(r)
	}
	if len(mappings.Snapshot()) != 0 {
		t.Fatal("unauthorized query allocated mapping")
	}
	if r := query(testHost(1), dnsmessage.TypeA, "10.44.0.2"); len(r.Answers) != 1 || !r.Response || r.ID != 7 {
		t.Fatal(r)
	}
	if r := query(testHost(1), dnsmessage.TypeAAAA, "10.44.0.2"); len(r.Answers) != 0 || r.RCode != dnsmessage.RCodeSuccess {
		t.Fatal(r)
	}
	if r := query("bad.onion", dnsmessage.TypeA, "10.44.0.2"); r.RCode != dnsmessage.RCodeNameError {
		t.Fatal(r)
	}
	if forwarded != 0 || installed != 1 {
		t.Fatalf("forwarded=%d installed=%d", forwarded, installed)
	}
	query("example.com", dnsmessage.TypeA, "10.44.0.2")
	if forwarded != 1 {
		t.Fatal("ordinary DNS was not forwarded")
	}
}

func TestI2PQueriesNeverFallBackToExternalDNS(t *testing.T) {
	forwarded := false
	h := DNS{Forward: func(context.Context, []byte) ([]byte, error) { forwarded = true; return nil, nil }}
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.i2p."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, _ := q.Pack()
	b, err := h.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), packet)
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if forwarded || reply.Unpack(b) != nil || reply.RCode != dnsmessage.RCodeRefused {
		t.Fatal("I2P leaked or was not refused")
	}
}

func TestDNSRechecksPermissionAfterSlowMappingInstall(t *testing.T) {
	m, _ := OpenMappings(filepath.Join(t.TempDir(), "book"), "198.18.0.0/15", 8)
	allowed := true
	h := DNS{Resolve: func(_ netip.Addr, name string) (netip.Addr, error) { return m.Resolve(name) }, Allowed: func(netip.Addr) bool { return allowed }, Install: func(context.Context, string, string) error { allowed = false; return nil }}
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(testHost(1) + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := q.Pack()
	reply, err := h.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), raw)
	if err != nil {
		t.Fatal(err)
	}
	var got dnsmessage.Message
	if got.Unpack(reply) != nil || got.RCode != dnsmessage.RCodeRefused || len(got.Answers) != 0 {
		t.Fatal("revocation ignored during mapping install")
	}
}

func TestDNSMissingAdmissionResolverFailsClosed(t *testing.T) {
	m, _ := OpenMappings(filepath.Join(t.TempDir(), "book"), "198.18.0.0/15", 8)
	h := DNS{Allowed: func(netip.Addr) bool { return true }, Install: func(context.Context, string, string) error { return nil }}
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(testHost(1) + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := q.Pack()
	reply, err := h.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), raw)
	if err != nil {
		t.Fatal(err)
	}
	var got dnsmessage.Message
	if got.Unpack(reply) != nil || got.RCode != dnsmessage.RCodeServerFailure || len(m.Snapshot()) != 0 {
		t.Fatal("missing admission resolver bypassed through raw allocator")
	}
}
