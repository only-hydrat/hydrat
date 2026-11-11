package i2p

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// During slow I2P startup no relay reads from the client yet. Buffer a bounded
// amount of pipelined data while watching EOF; a read deadline hands the same
// reader to the relay without losing those bytes. SOCKS clients normally wait
// for CONNECT success before sending data.
func handshakeInput(ctx context.Context, c net.Conn, cancel context.CancelFunc) (*bufio.Reader, func() error, func()) {
	const maxEarlyData = 64 << 10
	reader := bufio.NewReaderSize(c, maxEarlyData)
	done := make(chan struct{})
	var handingOff atomic.Bool
	c.SetReadDeadline(time.Time{})
	go func() {
		defer close(done)
		_, err := reader.Peek(maxEarlyData)
		var timeout net.Error
		if !handingOff.Load() || !errors.As(err, &timeout) || !timeout.Timeout() {
			cancel()
		}
	}()
	finish := func() error {
		handingOff.Store(true)
		c.SetReadDeadline(time.Now())
		<-done
		c.SetReadDeadline(time.Time{})
		return ctx.Err()
	}
	cleanup := func() { cancel(); c.Close(); <-done }
	return reader, finish, cleanup
}
