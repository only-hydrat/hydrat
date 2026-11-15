//go:build unix

package xrayflow

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Listen never exposes a TCP port. A private parent also prevents a transient
// permissive socket umask from admitting another user before chmod0600.
func Listen(path string, r *Registry) (*http.Server, error) {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("flow control requires a private parent directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("flow control path is not a socket")
		}
		connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("flow control socket already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, errors.New("flow control socket cannot be verified")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("flow control stale socket cannot be removed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("flow control socket cannot be inspected")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.Snapshot())
	})
	mux.HandleFunc("POST /v1/reset", func(w http.ResponseWriter, req *http.Request) {
		var q ResetRequest
		if err := decodeJSON(http.MaxBytesReader(w, req.Body, 4096), &q); err != nil {
			http.Error(w, "invalid flow recovery request", http.StatusBadRequest)
			return
		}
		n, err := r.Reset(req.Context(), q)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrStaleInstance) {
				status = http.StatusConflict
			}
			http.Error(w, "flow recovery request rejected", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ResetResponse{Closed: n})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print("flow control listener stopped")
		}
	}()
	return server, nil
}
