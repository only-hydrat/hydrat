package i2p

import (
	"context"
	"encoding/base32"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strings"
	"testing"
)

func TestDNSPermissionAndNonAQueriesNeverWakeOrAllocate(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	allowed := false
	wakes := 0
	d := DNS{Book: b, Allowed: func(netip.Addr) bool { return allowed }, Wake: func(context.Context) error { wakes++; return nil }}
	host := strings.Repeat("a", 52) + ".b32.i2p."
	query := func(kind dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(host), Type: kind, Class: dnsmessage.ClassINET}}}
		raw, _ := q.Pack()
		reply, err := d.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), raw)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(reply); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := query(dnsmessage.TypeA); m.RCode != dnsmessage.RCodeRefused {
		t.Fatal(m)
	}
	if wakes != 0 || len(b.state.Mappings) != 0 {
		t.Fatal("unauthorized allocation")
	}
	allowed = true
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, 64, 65} {
		if m := query(typ); len(m.Answers) != 0 || m.RCode != dnsmessage.RCodeSuccess {
			t.Fatal(m)
		}
	}
	if wakes != 0 {
		t.Fatal("non-A woke router")
	}
	if m := query(dnsmessage.TypeA); len(m.Answers) != 1 || !Pool.Contains(netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)) {
		t.Fatal(m)
	}
	allowed = false
	if m := query(dnsmessage.TypeA); m.RCode != dnsmessage.RCodeRefused {
		t.Fatal(m)
	}
	if wakes != 1 {
		t.Fatal("revoked client woke router")
	}
}

func TestDNSNewAddressBudgetPreservesExistingAndOtherClients(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	d := DNS{Book: b, Allowed: func(netip.Addr) bool { return true }, Wake: func(context.Context) error { return nil }}
	ask := func(source string, index byte) dnsmessage.RCode {
		rawDest := make([]byte, 32)
		rawDest[0] = index
		host := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawDest)) + ".b32.i2p."
		q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(host), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		raw, _ := q.Pack()
		reply, err := d.Handle(t.Context(), netip.MustParseAddr(source), raw)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(reply); err != nil {
			t.Fatal(err)
		}
		return m.RCode
	}
	for i := byte(0); i < 8; i++ {
		if code := ask("10.44.0.2", i); code != dnsmessage.RCodeSuccess {
			t.Fatal(code)
		}
	}
	if code := ask("10.44.0.2", 8); code != dnsmessage.RCodeServerFailure {
		t.Fatalf("unbounded new mappings: %v", code)
	}
	if code := ask("10.44.0.2", 0); code != dnsmessage.RCodeSuccess {
		t.Fatal("existing mapping blocked", code)
	}
	if code := ask("10.44.0.3", 8); code != dnsmessage.RCodeSuccess {
		t.Fatal("other client blocked", code)
	}
}
func TestDNSPersistenceFailureIsNotNXDOMAIN(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book")
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	d := DNS{Book: b, Allowed: func(netip.Addr) bool { return true }, Wake: func(context.Context) error { t.Fatal("failed book woke router"); return nil }}
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.i2p."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := q.Pack()
	reply, err := d.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), raw)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	m.Unpack(reply)
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("storage failure reported as %v", m.RCode)
	}
}

func TestDNSRechecksPermissionAfterWake(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book.json")
	if err != nil {
		t.Fatal(err)
	}
	allowed := true
	d := DNS{Book: b, Allowed: func(netip.Addr) bool { return allowed }, Wake: func(context.Context) error { allowed = false; return nil }}
	name := dnsmessage.MustNewName(strings.Repeat("a", 52) + ".b32.i2p.")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, _ := query.Pack()
	raw, err := d.Handle(t.Context(), netip.MustParseAddr("10.44.0.2"), packet)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if answer.RCode != dnsmessage.RCodeRefused || len(answer.Answers) > 0 {
		t.Fatal("revoked DNS grant returned address", answer)
	}
}
