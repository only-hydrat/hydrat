package i2p

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func subscriptionSOCKSServer(t *testing.T, body string) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var hello [3]byte
				if _, err := io.ReadFull(c, hello[:]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				var h [5]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				if h[3] != 3 {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(h[4])+2); err != nil {
					return
				}
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				r, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				r.Body.Close()
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	return l.Addr().String()
}

type retryStopControl struct {
	runtime  *Runtime
	failStop bool
}

func (c *retryStopControl) Do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	switch path {
	case "/wake":
		return nil, c.runtime.Wake(ctx, time.Now())
	case "/stop":
		if c.failStop {
			c.failStop = false
			return nil, errors.New("temporary socket unavailable")
		}
		return nil, c.runtime.Stop(ctx)
	}
	return nil, nil
}
func TestDeferredStopMustNotKillNewClients(t *testing.T) {
	router := &testRouter{ready: true}
	runtime := NewRuntime(router, time.Hour)
	control := &retryStopControl{runtime: runtime, failStop: true}
	clients := []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", I2PEnabled: true, I2POutbound: "i2p-alice", I2PToken: "token"}}
	a := &Access{Available: true, Control: control, Policy: func() []dataplane.ClientRoute { return clients }}
	now := time.Now()
	a.sync(t.Context(), now)
	clients = nil
	a.sync(t.Context(), now.Add(time.Second))
	clients = []dataplane.ClientRoute{{ClientID: "bob", SourceCIDR: "10.44.0.3/32", I2PEnabled: true, I2POutbound: "i2p-bob", I2PToken: "token"}}
	a.sync(t.Context(), now.Add(2*time.Second))
	release, err := runtime.Acquire(t.Context(), now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer release(time.Now())
	a.sync(t.Context(), now.Add(62*time.Second))
	if router.stops != 0 {
		t.Fatalf("deferred stop killed router serving a newly authorized client: stops=%d starts=%d streams=%d", router.stops, router.starts, runtime.Status().Streams)
	}
}

func TestDeferredStopRetriesWithoutNewClients(t *testing.T) {
	router := &testRouter{ready: true}
	runtime := NewRuntime(router, time.Hour)
	control := &retryStopControl{runtime: runtime, failStop: true}
	clients := []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", I2PEnabled: true, I2POutbound: "i2p-alice", I2PToken: "token"}}
	access := &Access{Available: true, Control: control, Policy: func() []dataplane.ClientRoute { return clients }}
	now := time.Now()
	access.sync(t.Context(), now)
	clients = nil
	access.sync(t.Context(), now.Add(time.Second))
	if !access.pendingStop {
		t.Fatal("lost pending stop")
	}
	access.sync(t.Context(), now.Add(62*time.Second))
	if router.stops != 1 || access.pendingStop {
		t.Fatalf("stop not retried: stops=%d pending=%v", router.stops, access.pendingStop)
	}
}
