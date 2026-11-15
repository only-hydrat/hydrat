package onion

import (
	"context"
	"errors"
	"net/netip"
)

// Control uses only the private Unix control socket of a serving Tor profile.
// Errors deliberately omit cookies, hostnames, and server-provided text.
type Control struct{ Socket, CookieFile string }

func (control Control) Map(ctx context.Context, address, host string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || !netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
		return errors.New("invalid virtual address")
	}
	host, err = Normalize(host)
	if err != nil {
		return err
	}
	return control.commands(ctx, [][2]string{{"MAPADDRESS " + ip.String() + "=" + host, "250 " + ip.String() + "=" + host}})
}

// Ready requires a bootstrapped circuit, independently of ordinary profile health.
func (control Control) Ready(ctx context.Context) error {
	// A persisted dormant profile waits for user traffic, while admission
	// waits for a circuit. Wake it explicitly to break that startup cycle.
	return control.commands(ctx, [][2]string{{"SIGNAL ACTIVE", "250 OK"}, {"GETINFO status/circuit-established", "250-status/circuit-established=1\r\n250 OK"}})
}
