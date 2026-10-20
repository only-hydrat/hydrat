package xrayflow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrivateUnixControlAndSafeRetry(t *testing.T) {
	r := NewRegistry()
	path := privateSocketPath(t)
	server, err := Listen(path, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	var old, other atomic.Int32
	_, done := r.Track(t.Context(), "old", "10.44.0.2", "tcp", func() { old.Add(1) })
	defer done()
	_, otherDone := r.Track(t.Context(), "old", "10.44.0.3", "tcp", func() { other.Add(1) })
	defer otherDone()
	c := NewClient(path)
	snapshot, err := c.Snapshot(t.Context())
	if err != nil || snapshot.Active != 2 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	q := ResetRequest{Snapshot: snapshot, Outbound: "old", Source: "10.44.0.2"}
	for n := 1; n >= 0; n-- {
		if closed, err := c.Reset(t.Context(), q); err != nil || closed != n {
			t.Fatalf("closed=%d err=%v", closed, err)
		}
	}
	if old.Load() != 1 || other.Load() != 0 {
		t.Fatal("reset isolation failed")
	}
	q.Snapshot = NewRegistry().Snapshot()
	if _, err := c.Reset(t.Context(), q); !errors.Is(err, ErrStaleInstance) {
		t.Fatalf("stale instance=%v", err)
	}
	if _, err := Listen(path, NewRegistry()); err == nil {
		t.Fatal("second listener replaced active socket")
	}
	if _, err := c.Snapshot(t.Context()); err != nil {
		t.Fatal("original socket was damaged")
	}
}

func TestUnixControlRejectsMalformedOrBroadRequests(t *testing.T) {
	r := NewRegistry()
	path := privateSocketPath(t)
	s, err := Listen(path, r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := NewClient(path)
	for _, input := range []struct{ method, path, body string }{
		{"GET", "/v1/reset", ""},
		{"POST", "/v1/reset", `{"source":"0.0.0.0/0","outbound":"*"}`},
		{"POST", "/v1/reset", `{"password":"must-not-be-echoed"}`},
		{"POST", "/v1/reset", strings.Repeat("x", 8192)},
		{"POST", "/unknown", "{}"},
	} {
		req, _ := http.NewRequest(input.method, "http://unix"+input.path, strings.NewReader(input.body))
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 400 || strings.Contains(string(body), "must-not-be-echoed") {
			t.Fatalf("unsafe response=%d %s", resp.StatusCode, body)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestUnixControlDoesNotReplaceRegularFile(t *testing.T) {
	p := privateSocketPath(t)
	if err := os.WriteFile(p, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p, NewRegistry()); err == nil {
		t.Fatal("regular file accepted as control socket")
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "keep" {
		t.Fatal("existing file was modified")
	}
}

func TestClientBoundsConnectionTimeout(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "missing.sock"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Snapshot(ctx)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("unbounded missing socket request: %v", err)
	}
}

func privateSocketPath(t *testing.T) string {
	t.Helper()
	// Keep below Unix socket path limits even with long Go test TMPDIR/name.
	dir, err := os.MkdirTemp("", "hf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "flow.sock")
}
