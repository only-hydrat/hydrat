package probe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/only-hydrat/hydrat/internal/socks5"
)

const (
	quicProbeHost    = "www.youtube.com"
	quicProbeTimeout = 3 * time.Second
)

// CheckQUIC verifies the UDP behavior clients actually need for HTTP/3. A DNS
// datagram alone is insufficient: some VLESS endpoints relay small UDP packets
// while blackholing the stateful QUIC exchange used by YouTube and browsers.
func CheckQUIC(ctx context.Context, socksAddress string) bool {
	ctx, cancel := context.WithTimeout(ctx, quicProbeTimeout)
	defer cancel()
	var targetIP net.IP
	if addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", quicProbeHost); err == nil && len(addresses) > 0 {
		targetIP = net.IP(addresses[0].AsSlice())
	} else {
		targetIP = net.ParseIP("142.250.180.206")
	}
	packet, err := (socks5.Dialer{ProxyAddress: socksAddress}).ListenPacket(ctx)
	if err != nil {
		return false
	}
	defer packet.Close()
	transport := &quic.Transport{Conn: packet}
	defer transport.Close()
	target := &net.UDPAddr{IP: targetIP, Port: 443}
	tlsConfig := &tls.Config{
		ServerName: quicProbeHost, NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: quicProbeTimeout,
		MaxIdleTimeout:       quicProbeTimeout,
	}
	// Two fresh handshakes reject endpoints that pass a lucky single datagram
	// while remaining too lossy for an HTTP/3 video session.
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := transport.Dial(ctx, target, tlsConfig, quicConfig)
		if err != nil {
			return false
		}
		_ = connection.CloseWithError(0, "probe complete")
	}
	return true
}
