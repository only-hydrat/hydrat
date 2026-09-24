package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestLookupQUICProbeIPUsesSOCKSUDPAndResolvedAddress(t *testing.T) {
	packet := &quicDNSPacketConn{}
	ip, err := lookupQUICProbeIP(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("resolved IP=%s", ip)
	}
	if packet.destination != "1.1.1.1:53" || !bytes.Contains(packet.query, []byte("youtube")) {
		t.Fatalf("DNS destination=%s query=%x", packet.destination, packet.query)
	}
	if !packet.deadline.IsZero() {
		t.Fatalf("DNS deadline leaked into QUIC: %s", packet.deadline)
	}
}

func TestCheckQUICResolvesThroughClientDNSBeforeCandidateSOCKS(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	querySeen := make(chan bool, 1)
	go func() {
		response := make([]byte, 1500)
		_ = dns.SetReadDeadline(time.Now().Add(time.Second))
		n, source, readErr := dns.ReadFrom(response)
		if readErr != nil {
			querySeen <- false
			return
		}
		querySeen <- bytes.Contains(response[:n], []byte("youtube"))
		response = append(response[:n], 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9)
		response[2] |= 0x80
		binary.BigEndian.PutUint16(response[6:8], 1)
		_, _ = dns.WriteTo(response, source)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if CheckQUICWithDNS(ctx, "127.0.0.1:1", dns.LocalAddr().String()) {
		t.Fatal("unavailable candidate SOCKS passed QUIC")
	}
	if !<-querySeen {
		t.Fatal("client DNS did not receive YouTube lookup")
	}
}

type quicDNSPacketConn struct {
	destination string
	query       []byte
	response    []byte
	deadline    time.Time
}

func (packet *quicDNSPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	// A proxy may return a valid reply with a rewritten source address.
	return copy(payload, packet.response), &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 53}, nil
}

func (packet *quicDNSPacketConn) WriteTo(payload []byte, target net.Addr) (int, error) {
	packet.destination = target.String()
	packet.query = append([]byte(nil), payload...)
	packet.response = append([]byte(nil), payload...)
	packet.response[2] |= 0x80
	binary.BigEndian.PutUint16(packet.response[6:8], 1)
	packet.response = append(packet.response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9)
	return len(payload), nil
}

func (*quicDNSPacketConn) Close() error        { return nil }
func (*quicDNSPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (packet *quicDNSPacketConn) SetDeadline(value time.Time) error {
	packet.deadline = value
	return nil
}
func (*quicDNSPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*quicDNSPacketConn) SetWriteDeadline(time.Time) error { return nil }
