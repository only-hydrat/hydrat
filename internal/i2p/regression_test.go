package i2p

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
func TestFeedConflictBudgetKeepsStateAndAPIUsable(t *testing.T) {
	book, err := OpenBook(filepath.Join(t.TempDir(), "book"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	raw := make([]byte, 387)
	old := base64.StdEncoding.EncodeToString(raw)
	raw[0] = 1
	next := base64.StdEncoding.EncodeToString(raw)
	var original, changes strings.Builder
	for i := 0; i < 1024; i++ {
		fmt.Fprintf(&original, "site-%04d.i2p=%s\n", i, old)
		fmt.Fprintf(&changes, "site-%04d.i2p=%s\n", i, next)
	}
	if err := book.ApplyImport(book.Preview(original.String()), "manual", false); err != nil {
		t.Fatal(err)
	}
	proxy := subscriptionSOCKSServer(t, changes.String())
	path := filepath.Join(t.TempDir(), "settings")
	admin, err := NewAdmin(book, ControlClient{}, path, proxy, true)
	if err != nil {
		t.Fatal(err)
	}
	dest, _ := Destination(old)
	for i := 0; i < 4; i++ {
		id := fmt.Sprint(i)
		admin.config.Subscriptions = append(admin.config.Subscriptions, Subscription{ID: id, URL: "http://" + dest + "/hosts" + id, Enabled: true})
		err := admin.Refresh(t.Context(), id, time.Now())
		sub := admin.config.Subscriptions[i]
		if i == 0 {
			if err != nil || len(sub.Conflicts) != 1024 || sub.LastSuccess.IsZero() {
				t.Fatalf("first feed not accepted: conflicts=%d err=%v", len(sub.Conflicts), err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "conflict capacity") || !sub.LastSuccess.IsZero() || sub.Error == "" || len(sub.Conflicts) != 0 {
			t.Fatalf("overflow must reject refresh without reporting success: %+v err=%v", sub, err)
		}
	}
	if len(admin.config.Subscriptions[0].Conflicts) != 1024 {
		t.Fatal("overflow discarded previously accepted conflicts")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	response := w.Body.Bytes()
	t.Logf("each feed=%d bytes; saved settings=%d bytes; API response=%d bytes; complete JSON=%t; capped API JSON=%t", changes.Len(), len(data), len(response), json.Valid(response), json.Valid(response[:min(len(response), 2<<20)]))
	if len(data) > 2<<20 || len(response) > 2<<20 {
		t.Errorf("unbounded state/API: %d / %d", len(data), len(response))
	}
	if _, err := NewAdmin(book, ControlClient{}, path, proxy, true); err != nil {
		t.Fatalf("normal accepted feeds made settings unreadable after restart: %v", err)
	}
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
func TestDisconnectedColdClientMustReleaseLease(t *testing.T) {
	book, err := OpenBook(filepath.Join(t.TempDir(), "book"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	ip, _, err := book.Resolve(strings.Repeat("a", 52) + ".b32.i2p")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "control")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	leased := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lease":
			leased <- struct{}{}
			io.WriteString(w, `{"id":"lease"}`)
		case "/status":
			io.WriteString(w, `{"state":"starting"}`)
		default:
			w.WriteHeader(204)
		}
	})}
	go server.Serve(l)
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bridge := &Bridge{Book: book, Control: ControlClient{Socket: socket}, Grants: func() []Grant { return []Grant{{User: "a", Password: "p"}} }}
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	client, err := net.Dial("tcp4", tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := tcpListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { defer gateway.Close(); done <- bridge.handle(ctx, gateway) }()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write([]byte{5, 1, 2})
	var reply [2]byte
	io.ReadFull(client, reply[:])
	client.Write([]byte{1, 1, 'a', 1, 'p'})
	io.ReadFull(client, reply[:])
	request := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	v := ip.As4()
	copy(request[4:8], v[:])
	binary.BigEndian.PutUint16(request[8:], 80)
	client.Write(request)
	<-leased
	client.Close()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("closed SOCKS client still occupies startup slot and renews runtime lease")
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
