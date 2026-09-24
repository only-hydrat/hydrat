package probe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/only-hydrat/hydrat/internal/socks5"
)

const (
	quicProbeHost    = "www.youtube.com"
	quicProbeTimeout = 5 * time.Second
)

// CheckQUIC verifies the UDP behavior clients actually need for HTTP/3. Both
// DNS resolution and QUIC traffic use the same SOCKS UDP association.
func CheckQUIC(ctx context.Context, socksAddress string) bool {
	ctx, cancel := context.WithTimeout(ctx, quicProbeTimeout)
	defer cancel()
	packet, err := (socks5.Dialer{ProxyAddress: socksAddress}).ListenPacket(ctx)
	if err != nil {
		return false
	}
	defer packet.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stopClose()
	targetIP, err := lookupQUICProbeIP(ctx, packet)
	if err != nil {
		return false
	}
	transport := &quic.Transport{Conn: packet}
	defer transport.Close()
	target := &net.UDPAddr{IP: targetIP, Port: 443}
	tlsConfig := &tls.Config{ServerName: quicProbeHost, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	quicConfig := &quic.Config{HandshakeIdleTimeout: quicProbeTimeout, MaxIdleTimeout: quicProbeTimeout}
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := transport.Dial(ctx, target, tlsConfig, quicConfig)
		if err != nil {
			return false
		}
		_ = connection.CloseWithError(0, "probe complete")
	}
	return true
}

func lookupQUICProbeIP(ctx context.Context, packet net.PacketConn) (net.IP, error) {
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x4859, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(quicProbeHost + "."),
			Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	query, err := message.Pack()
	if err != nil {
		return nil, err
	}
	response := make([]byte, 1500)
	for _, resolver := range []string{"1.1.1.1", "9.9.9.9"} {
		deadline := time.Now().Add(time.Second)
		if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
			deadline = parentDeadline
		}
		if err := packet.SetDeadline(deadline); err != nil {
			return nil, err
		}
		if _, err := packet.WriteTo(query, &net.UDPAddr{IP: net.ParseIP(resolver), Port: 53}); err != nil {
			continue
		}
		n, _, err := packet.ReadFrom(response)
		if err != nil {
			continue
		}
		if ip := parseQUICProbeDNSAnswer(response[:n]); ip != nil {
			if err := packet.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			return ip, nil
		}
	}
	return nil, net.ErrClosed
}

func parseQUICProbeDNSAnswer(message []byte) net.IP {
	var response dnsmessage.Message
	if response.Unpack(message) != nil || response.ID != 0x4859 ||
		!response.Response || response.RCode != dnsmessage.RCodeSuccess ||
		len(response.Questions) != 1 ||
		response.Questions[0].Name.String() != quicProbeHost+"." ||
		response.Questions[0].Type != dnsmessage.TypeA {
		return nil
	}
	for _, answer := range response.Answers {
		if a, ok := answer.Body.(*dnsmessage.AResource); ok && answer.Header.Class == dnsmessage.ClassINET {
			return net.IP(a.A[:])
		}
	}
	return nil
}
