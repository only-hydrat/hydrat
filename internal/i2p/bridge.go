package i2p

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/only-hydrat/hydrat/internal/socks5"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type Grant struct {
	User, Password string
	Source         netip.Addr
}
type Bridge struct {
	Book    *Book
	Control ControlClient
	Proxy   string
	Grants  func() []Grant
}

func (b *Bridge) authenticate(user, password string) bool {
	if b.Grants == nil {
		return false
	}
	for _, g := range b.Grants() {
		if g.User == user && subtle.ConstantTimeCompare([]byte(g.Password), []byte(password)) == 1 {
			return true
		}
	}
	return false
}
func (b *Bridge) Allowed(ip netip.Addr) bool {
	if b.Grants == nil {
		return false
	}
	for _, g := range b.Grants() {
		if g.Source == ip {
			return true
		}
	}
	return false
}

// ServeListener owns the listener and closes it during shutdown.
func (b *Bridge) ServeListener(ctx context.Context, l net.Listener) error {
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	slots := make(chan struct{}, 64)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		workers.Add(1)
		go func() { defer workers.Done(); defer func() { <-slots }(); defer c.Close(); _ = b.handle(ctx, c) }()
	}
}
func (b *Bridge) handle(parent context.Context, c net.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] == 0 {
		return errors.New("SOCKS5 required")
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	auth := false
	for _, m := range methods {
		if m == 2 {
			auth = true
		}
	}
	if !auth {
		c.Write([]byte{5, 255})
		return errors.New("authentication required")
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 1 || h[1] == 0 {
		return errors.New("invalid auth")
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return err
	}
	p := make([]byte, h[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	user, password := string(u), string(p)
	if !b.authenticate(user, password) {
		c.Write([]byte{1, 1})
		return errors.New("permission denied")
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return err
	}
	var req [10]byte
	if _, err := io.ReadFull(c, req[:4]); err != nil {
		return err
	}
	if req[0] != 5 || req[1] != 1 || req[2] != 0 || req[3] != 1 {
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return errors.New("only mapped IPv4 TCP supported")
	}
	if _, err := io.ReadFull(c, req[4:]); err != nil {
		return err
	}
	ip := netip.AddrFrom4([4]byte(req[4:8]))
	destination, err := b.Book.Reverse(ip)
	if err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(req[8:])
	if port == 0 {
		return errors.New("invalid port")
	}
	// Watch peer closure before acquiring a lease or waiting for startup.
	c.SetWriteDeadline(time.Now().Add(275 * time.Second))
	input, finishInput, cleanupInput := handshakeInput(ctx, c, cancel)
	defer cleanupInput()
	payload, err := b.Control.Do(ctx, "POST", "/lease", nil)
	if err != nil {
		return err
	}
	var lease struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(payload, &lease) != nil || lease.ID == "" {
		return errors.New("lease unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b.Control.Do(cleanup, "DELETE", "/lease/"+lease.ID, nil)
	}()
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		count := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				d, err := b.Book.Reverse(ip)
				if err != nil || d != destination || !b.authenticate(user, password) {
					cancel()
					return
				}
				count++
				if count%10 == 0 {
					if _, err = b.Control.Do(ctx, "PUT", "/lease/"+lease.ID, nil); err != nil {
						cancel()
						return
					}
				}
			}
		}
	}()
	// Admission remains installed during sleep, so cached DNS addresses can wake
	// the backend without waiting for a new controller plan.
	readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer readyCancel()
	for {
		status, err := b.Control.Status(readyCtx)
		if err != nil || status.State == "error" {
			return errors.New("I2P unavailable")
		}
		if status.State == "warm" || status.State == "active" {
			break
		}
		select {
		case <-readyCtx.Done():
			return readyCtx.Err()
		case <-time.After(time.Second):
		}
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 90*time.Second)
	defer dialCancel()
	remote, err := (socks5.Dialer{HandshakeTimeout: 90 * time.Second, ProxyAddress: b.Proxy}).DialContext(dialCtx, "tcp", net.JoinHostPort(destination, strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	if err := finishInput(); err != nil {
		return err
	}
	if _, err = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	c.SetDeadline(time.Time{})
	relayInput(c, remote, input)
	return nil
}

func relayInput(client, remote net.Conn, input io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, input); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
	client.Close()
	remote.Close()
	<-done
}
