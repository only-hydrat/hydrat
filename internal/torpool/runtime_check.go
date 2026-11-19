package torpool

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CheckRuntime exercises the same Tor launcher as production, against local
// endpoints. Run it in a separate network namespace with no external network.
func CheckRuntime(ctx context.Context, tor, lyrebird string) error {
	for _, transport := range []string{"obfs4", "webtunnel"} {
		if err := checkTransport(ctx, tor, lyrebird, transport); err != nil {
			return fmt.Errorf("%s runtime check: %w", transport, err)
		}
	}
	return nil
}

func checkTransport(parent context.Context, tor, lyrebird, transport string) error {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()

	bridge, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer bridge.Close()
	stop := context.AfterFunc(ctx, func() { _ = bridge.Close() })
	defer stop()
	address := bridge.Addr().String()

	socks, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := socks.Addr().(*net.TCPAddr).Port
	if err := socks.Close(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "hydrat-tor-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	options := "url=https://" + address + "/test"
	if transport == "obfs4" {
		var certificate [52]byte
		if _, err := rand.Read(certificate[:]); err != nil {
			return err
		}
		options = "cert=" + base64.RawStdEncoding.EncodeToString(certificate[:]) + " iat-mode=0"
	}
	manager, err := NewManager(Config{
		Binary: tor, LyrebirdBinary: lyrebird, DataDir: dir,
		SocksPortBase: port, ExplorerProfiles: 1,
		PrepareOnion: func(context.Context, Profile) error { return nil },
	}, nil)
	if err != nil {
		return err
	}
	defer manager.Close()
	profile, err := manager.ProbeCandidate(ctx, Candidate{
		ID:     transport,
		Bridge: fmt.Sprintf("%s %s 0123456789ABCDEF0123456789ABCDEF01234567 %s", transport, address, options),
	})
	if err != nil {
		return err
	}

	// A bridge connection with bytes on the wire proves Tor registered and
	// used the configured pluggable transport. The peer is a local fixture.
	conn, err := bridge.Accept()
	if err != nil {
		return errors.Join(errors.New("no connection from the bridge transport"), ctx.Err(), err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	var packet [1]byte
	if _, err := conn.Read(packet[:]); err != nil {
		return fmt.Errorf("bridge transport did not start its handshake: %w", err)
	}
	dialer := net.Dialer{}
	for _, endpoint := range []struct{ network, address string }{
		{"tcp4", profile.SocksAddr},
		{"unix", filepath.Join(profile.DataDir, "control.sock")},
	} {
		conn, err := dialer.DialContext(ctx, endpoint.network, endpoint.address)
		if err != nil {
			return err
		}
		_ = conn.Close()
	}
	return nil
}
