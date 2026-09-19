package probe

import (
	"context"
	"net"
	"time"

	"github.com/only-hydrat/hydrat/internal/socks5"
)

const udpDNSProbeTimeout = 3 * time.Second

// CheckUDPDNS verifies general UDP relay without relying on UDP/443, which the
// standard xtls-rprx-vision flow intentionally rejects to force TCP fallback.
func CheckUDPDNS(ctx context.Context, socksAddress string) bool {
	ctx, cancel := context.WithTimeout(ctx, udpDNSProbeTimeout)
	defer cancel()
	packet, err := (socks5.Dialer{ProxyAddress: socksAddress}).ListenPacket(ctx)
	if err != nil {
		return false
	}
	defer packet.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stopClose()
	query := []byte{
		0x48, 0x59, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w',
		0x07, 'y', 'o', 'u', 't', 'u', 'b', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	response := make([]byte, 512)
	for _, resolver := range []string{"1.1.1.1", "9.9.9.9"} {
		deadline := time.Now().Add(udpDNSProbeTimeout / 2)
		if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
			deadline = parentDeadline
		}
		if packet.SetDeadline(deadline) != nil {
			return false
		}
		if _, err := packet.WriteTo(query, &net.UDPAddr{IP: net.ParseIP(resolver), Port: 53}); err != nil {
			continue
		}
		count, _, err := packet.ReadFrom(response)
		if err == nil && count >= 12 && response[0] == query[0] && response[1] == query[1] && response[2]&0x80 != 0 {
			return true
		}
	}
	return false
}
