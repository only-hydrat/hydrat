package i2p

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminBookConflictRequiresExplicitReplacement(t *testing.T) {
	b, _ := OpenBook(filepath.Join(t.TempDir(), "book.json"))
	a, err := NewAdmin(b, ControlClient{}, filepath.Join(t.TempDir(), "settings.json"), "127.0.0.1:4447", true)
	if err != nil {
		t.Fatal(err)
	}
	put := func(dest string, replace bool) int {
		body, _ := json.Marshal(map[string]any{"name": "test.i2p", "destination": dest, "replace": replace})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("PUT", "/entries", strings.NewReader(string(body))))
		return w.Code
	}
	d := strings.Repeat("a", 52) + ".b32.i2p"
	e := strings.Repeat("b", 51) + "a.b32.i2p"
	if c := put(d, false); c != http.StatusNoContent {
		t.Fatal(c)
	}
	ip, _, _ := b.Resolve("test.i2p")
	if c := put(e, false); c != 409 {
		t.Fatal(c)
	}
	if c := put(e, true); c != 204 {
		t.Fatal(c)
	}
	if _, err := b.Reverse(ip); err == nil {
		t.Fatal("old IP retained")
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/export", nil))
	if !strings.Contains(w.Body.String(), "test.i2p=") {
		t.Fatal(w.Body.String())
	}
}
func TestSubscriptionRejectsPrivateAndClearnetHTTP(t *testing.T) {
	for _, u := range []string{"http://example.org/hosts.txt", "https://127.0.0.1/x", "https://[::1]/x", "https://example.org:123/x", "https://user:pass@example.org/"} {
		if validateSubscriptionURL(u) == nil {
			t.Fatal(u)
		}
	}
}
func TestManualRefreshQueuesColdStartInsteadOfHoldingHTTPRequest(t *testing.T) {
	b, _ := OpenBook(filepath.Join(t.TempDir(), "book"))
	a, _ := NewAdmin(b, ControlClient{}, filepath.Join(t.TempDir(), "settings"), "127.0.0.1:4447", true)
	a.config.Subscriptions = []Subscription{{ID: "test", URL: "https://example.org/hosts.txt", Enabled: true}}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("POST", "/subscriptions/test/refresh", nil))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestSubscriptionRefreshThroughI2PRequiresConflictReview(t *testing.T) {
	b, err := OpenBook(filepath.Join(t.TempDir(), "book"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	old := strings.Repeat("a", 52) + ".b32.i2p"
	replacement := strings.Repeat("b", 51) + "a.b32.i2p"
	if err := b.Put("known.i2p", old, "manual", false); err != nil {
		t.Fatal(err)
	}
	oldIP, _, err := b.Resolve("known.i2p")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		var hello [3]byte
		if _, err = io.ReadFull(c, hello[:]); err != nil {
			served <- err
			return
		}
		c.Write([]byte{5, 0})
		var header [5]byte
		if _, err = io.ReadFull(c, header[:]); err != nil {
			served <- err
			return
		}
		if header[3] != 3 {
			served <- fmt.Errorf("expected canonical domain destination")
			return
		}
		address := make([]byte, int(header[4])+2)
		if _, err = io.ReadFull(c, address); err != nil {
			served <- err
			return
		}
		if string(address[:len(address)-2]) != old {
			served <- fmt.Errorf("unexpected SOCKS target")
			return
		}
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			served <- err
			return
		}
		req.Body.Close()
		body := "known.i2p=" + replacement + "\nnew.i2p=" + old + "\n"
		_, err = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		served <- err
	}()
	path := filepath.Join(t.TempDir(), "settings")
	a, err := NewAdmin(b, ControlClient{}, path, listener.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	a.config.Subscriptions = []Subscription{{ID: "feed", URL: "http://" + old + "/hosts.txt", Enabled: true}}
	now := time.Now()
	if err := a.Refresh(t.Context(), "feed", now); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if len(a.config.Subscriptions[0].Conflicts) != 1 || !a.config.Subscriptions[0].LastSuccess.Equal(now) {
		t.Fatal(a.config)
	}
	if ip, _, err := b.Resolve("known.i2p"); err != nil || ip != oldIP {
		t.Fatal("feed replaced a manual record", err)
	}
	if _, _, err := b.Resolve("new.i2p"); err != nil {
		t.Fatal("new name not imported", err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("POST", "/subscriptions/feed/conflicts", strings.NewReader(`{"name":"known.i2p","accept":true}`)))
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := b.Reverse(oldIP); err == nil {
		t.Fatal("old destination remains accessible after confirmation")
	}
	restored, err := NewAdmin(b, ControlClient{}, path, listener.Addr().String(), true)
	if err != nil || len(restored.config.Subscriptions[0].Conflicts) != 0 {
		t.Fatal("conflict result not persisted", err)
	}
}
