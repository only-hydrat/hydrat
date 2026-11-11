package onion

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
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

func (control Control) commands(ctx context.Context, commands [][2]string) error {
	file, err := os.Open(control.CookieFile)
	if err != nil {
		return errors.New("Tor authentication cookie unavailable")
	}
	cookie, readErr := io.ReadAll(io.LimitReader(file, 33))
	file.Close()
	if readErr != nil || len(cookie) != 32 {
		return errors.New("invalid Tor authentication cookie")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", control.Socket)
	if err != nil {
		return errors.New("Tor control socket unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	reader := bufio.NewReaderSize(conn, 4096)
	exchange := func(command, expected string) error {
		if _, err := io.WriteString(conn, command+"\r\n"); err != nil {
			return errors.New("Tor control write failed")
		}
		for _, want := range strings.Split(expected, "\r\n") {
			line, err := reader.ReadSlice('\n')
			if err != nil || strings.TrimSuffix(string(line), "\r\n") != want {
				return errors.New("Tor control acknowledgement rejected")
			}
		}
		return nil
	}
	if err := exchange("AUTHENTICATE "+hex.EncodeToString(cookie), "250 OK"); err != nil {
		return err
	}
	for _, command := range commands {
		if err := exchange(command[0], command[1]); err != nil {
			return err
		}
	}
	return nil
}
