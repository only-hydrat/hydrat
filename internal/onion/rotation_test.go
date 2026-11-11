package onion

import (
	"bufio"
	"context"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mappingProcess struct{ stopped atomic.Bool }

func (p *mappingProcess) Stop() error  { p.stopped.Store(true); return nil }
func (p *mappingProcess) Exited() bool { return p.stopped.Load() }

type mappingTorRunner struct {
	t    *testing.T
	mu   sync.Mutex
	maps map[string]map[string]string
}

func (r *mappingTorRunner) Start(_ context.Context, _ string, args ...string) (torpool.Process, error) {
	var dir string
	for i, a := range args {
		if a == "--DataDirectory" {
			dir = args[i+1]
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "control_auth_cookie"), make([]byte, 32), 0600); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", filepath.Join(dir, "control.sock"))
	if err != nil {
		return nil, err
	}
	r.t.Cleanup(func() { l.Close() })
	r.mu.Lock()
	r.maps[dir] = make(map[string]string)
	r.mu.Unlock()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				s := bufio.NewScanner(c)
				for s.Scan() {
					cmd := s.Text()
					switch {
					case strings.HasPrefix(cmd, "AUTHENTICATE "):
						c.Write([]byte("250 OK\r\n"))
					case cmd == "SIGNAL ACTIVE":
						c.Write([]byte("250 OK\r\n"))
					case cmd == "GETINFO status/circuit-established":
						c.Write([]byte("250-status/circuit-established=1\r\n250 OK\r\n"))
					case strings.HasPrefix(cmd, "MAPADDRESS "):
						mapping := strings.TrimPrefix(cmd, "MAPADDRESS ")
						ip, host, _ := strings.Cut(mapping, "=")
						r.mu.Lock()
						r.maps[dir][ip] = host
						r.mu.Unlock()
						c.Write([]byte("250 " + mapping + "\r\n"))
					}
				}
			}()
		}
	}()
	return &mappingProcess{}, nil
}
func TestExplorerPromotionMustReplayCurrentMappings(t *testing.T) {
	r, err := NewRuntime(filepath.Join(t.TempDir(), "book.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	runner := &mappingTorRunner{t: t, maps: make(map[string]map[string]string)}
	m, err := torpool.NewManager(torpool.Config{DataDir: filepath.Join(t.TempDir(), "profiles"), WarmProfiles: 1, ExplorerProfiles: 1, PrepareOnion: r.Prepare}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r.Profiles = m.Profiles
	candidates := []torpool.Candidate{{ID: "a", Score: 20, Qualified: true, Bridge: "192.0.2.1:443"}, {ID: "b", Score: 10, Qualified: true, Bridge: "192.0.2.2:443"}}
	if _, err := m.Reconcile(t.Context(), candidates); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		ready := 0
		for _, p := range m.Profiles() {
			if p.OnionReady {
				ready++
			}
		}
		if ready == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("setup profiles not ready")
		}
		time.Sleep(time.Millisecond)
	}
	host := testHost(3)
	ip, err := r.Resolve(netip.MustParseAddr("10.44.0.2"), host)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(t.Context(), ip.String(), host); err != nil {
		t.Fatal(err)
	}
	candidates[1].Score = 30
	if _, err := m.Reconcile(t.Context(), candidates); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, p := range m.Profiles() {
			if p.CandidateID == "b" && p.Role == "warm" && p.OnionReady {
				runner.mu.Lock()
				has := runner.maps[p.DataDir][ip.String()] == host
				runner.mu.Unlock()
				if !has {
					t.Fatalf("promoted profile advertises OnionReady=true without previously issued mapping %s", ip)
				}
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("promoted profile never became onion ready")
}
