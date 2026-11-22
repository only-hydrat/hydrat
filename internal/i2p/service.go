package i2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

type lease struct {
	release func(time.Time)
	expires time.Time
}

// ControlClient talks only to the private supervisor socket. User input never
// chooses a socket, host or executable.
type ControlClient struct{ Socket string }

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
