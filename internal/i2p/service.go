package i2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type lease struct {
	release func(time.Time)
	expires time.Time
}

// ServeSupervisor keeps only a small control process alive while i2pd sleeps.
// Leases expire if a gateway dies, so crashed clients cannot pin warmup forever.
func ServeSupervisor(ctx context.Context, binary, dir, socket string) error {
	r := NewRuntime(&ExecRouter{Binary: binary, Directory: dir}, 2*time.Hour)
	defer r.Close(context.Background())
	lastState := r.Status().State
	mux, expire := supervisorHandler(r)
	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return err
	}
	// Refuse to replace an active socket owned by another supervisor.
	if c, err := net.DialTimeout("unix", socket, time.Second); err == nil {
		c.Close()
		return errors.New("I2P supervisor already running")
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(socket)
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	if err = os.Chown(socket, -1, 10001); err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case now := <-tick.C:
				expire(now)
				bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
				err := r.Tick(bounded, now)
				state := r.Status().State
				if state != lastState {
					log.Printf("I2P state=%s transit=%d verification_failed=%t", state, r.Status().Transit, err != nil)
					lastState = state
				}
				cancel()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// ControlClient talks only to the private supervisor socket. User input never
// chooses a socket, host or executable.
type ControlClient struct{ Socket string }

func (c ControlClient) Do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://i2p"+path, body)
	if err != nil {
		return nil, err
	}
	res, err := (&http.Client{Transport: tr, Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, errors.New("I2P supervisor unavailable")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, errors.New("I2P operation rejected")
	}
	return b, nil
}
func (c ControlClient) Status(ctx context.Context) (Status, error) {
	b, err := c.Do(ctx, "GET", "/status", nil)
	if err != nil {
		return Status{}, err
	}
	var s Status
	err = json.Unmarshal(b, &s)
	return s, err
}

// supervisorHandler is shared by the private Unix server and lifecycle tests.
func supervisorHandler(r *Runtime) (http.Handler, func(time.Time)) {
	var mu sync.Mutex
	leases := map[string]lease{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, q *http.Request) { json.NewEncoder(w).Encode(r.Status()) })
	mux.HandleFunc("POST /wake", func(w http.ResponseWriter, q *http.Request) {
		if err := r.Wake(q.Context(), time.Now()); err != nil {
			http.Error(w, "I2P unavailable", 503)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /stop", func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		for id, l := range leases {
			l.release(time.Now())
			delete(leases, id)
		}
		if err := r.Stop(q.Context()); err != nil {
			http.Error(w, "I2P stop failed", 503)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("PUT /idle", func(w http.ResponseWriter, q *http.Request) {
		var b struct {
			Seconds int `json:"seconds"`
		}
		if json.NewDecoder(io.LimitReader(q.Body, 1024)).Decode(&b) != nil || r.SetIdle(time.Duration(b.Seconds)*time.Second) != nil {
			http.Error(w, "invalid warmup timeout", 400)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /lease", func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		release, err := r.Acquire(q.Context(), time.Now())
		if err != nil {
			http.Error(w, "I2P unavailable", 503)
			return
		}
		var id [24]byte
		if _, err := rand.Read(id[:]); err != nil {
			release(time.Now())
			http.Error(w, "lease unavailable", 503)
			return
		}
		key := hex.EncodeToString(id[:])
		leases[key] = lease{release, time.Now().Add(45 * time.Second)}
		json.NewEncoder(w).Encode(map[string]string{"id": key})
	})
	mux.HandleFunc("PUT /lease/{id}", func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		l, ok := leases[q.PathValue("id")]
		if !ok {
			http.NotFound(w, q)
			return
		}
		l.expires = time.Now().Add(45 * time.Second)
		leases[q.PathValue("id")] = l
		w.WriteHeader(204)
	})
	mux.HandleFunc("DELETE /lease/{id}", func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if l, ok := leases[q.PathValue("id")]; ok {
			l.release(time.Now())
			delete(leases, q.PathValue("id"))
		}
		w.WriteHeader(204)
	})

	return mux, func(now time.Time) {
		mu.Lock()
		defer mu.Unlock()
		for id, l := range leases {
			if !now.Before(l.expires) {
				l.release(now)
				delete(leases, id)
			}
		}
	}
}
