package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Status struct {
	Enabled    bool             `json:"enabled"`
	Installed  Versions         `json:"installed"`
	Available  map[string]Offer `json:"available"`
	CheckedAt  time.Time        `json:"checked_at,omitempty"`
	Checking   bool             `json:"checking,omitempty"`
	CheckError bool             `json:"check_error,omitempty"`
	Result     Result           `json:"result"`
}

type Result struct {
	State     string `json:"state,omitempty"`
	Component string `json:"component,omitempty"`
	Version   string `json:"version,omitempty"`
}

type Selection struct {
	Component string `json:"component"`
	Version   string `json:"version"`
}

type service struct {
	mu             sync.Mutex
	ctx            context.Context
	status         Status
	check          func(context.Context) (Versions, map[string]Offer, error)
	install        func(context.Context, string, Offer) error
	finishRollback func(context.Context) (bool, error)
}

var (
	errRolledBack      = errors.New("previous release restored")
	errRollbackFailed  = errors.New("rollback must be completed")
	errRollbackWaiting = errors.New("restored release is waiting for routing readiness")
)

func (s *service) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		reply(w, http.StatusOK, s.status)
	})
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		s.refresh()
		reply(w, http.StatusAccepted, nil)
	})
	mux.HandleFunc("POST /v1/install", s.start)
	return mux
}

func (s *service) refresh() {
	s.mu.Lock()
	if s.check == nil || s.status.Checking || s.status.Result.State == "installing" ||
		time.Since(s.status.CheckedAt) < 20*time.Second {
		s.mu.Unlock()
		return
	}
	s.status.Checking = true
	waiting := s.status.Result.State == "rollback_waiting"
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		defer cancel()
		finished := false
		if waiting {
			var err error
			finished, err = s.finishRollback(ctx)
			if err != nil {
				log.Printf("check restored routes: %v", err)
			}
			if !finished {
				s.mu.Lock()
				s.status.Checking = false
				s.status.CheckedAt = time.Now()
				s.mu.Unlock()
				return
			}
		}
		current, offers, err := s.check(ctx)
		if err != nil {
			log.Printf("update check: %v", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.status.Checking = false
		if finished {
			s.status.Result.State = "rolled_back"
		}
		s.status.Installed = current
		s.status.Available = offers
		s.status.CheckedAt = time.Now()
		s.status.CheckError = err != nil
	}()
}

func (s *service) refreshWhileRestoring() {
	s.mu.Lock()
	waiting := s.status.Result.State == "rollback_waiting"
	s.mu.Unlock()
	if waiting {
		s.refresh()
	}
}

func (s *service) start(w http.ResponseWriter, r *http.Request) {
	selection, valid := decodeSelection(w, r)
	if !valid {
		reply(w, http.StatusBadRequest, nil)
		return
	}
	s.mu.Lock()
	offer := s.status.Available[selection.Component]
	if s.status.Checking || s.status.Result.State == "installing" || s.status.Result.State == "rollback_failed" || s.status.Result.State == "rollback_waiting" ||
		offer.Manual || offer.Version != selection.Version || !newer(offer.Version, s.status.Installed.Hydrat) {
		s.mu.Unlock()
		reply(w, http.StatusConflict, nil)
		return
	}
	s.status.Result = Result{State: "installing", Component: selection.Component, Version: offer.Version}
	s.mu.Unlock()
	go func() {
		err := s.install(s.ctx, selection.Component, offer)
		state := "installed"
		switch {
		case errors.Is(err, errRollbackWaiting):
			state = "rollback_waiting"
		case errors.Is(err, errRollbackFailed):
			state = "rollback_failed"
		case errors.Is(err, errRolledBack):
			state = "rolled_back"
		case err != nil:
			state = "failed"
		}
		if err != nil {
			log.Printf("update %s %s: %v", selection.Component, offer.Version, err)
		} else {
			log.Printf("update %s %s installed", selection.Component, offer.Version)
		}
		s.mu.Lock()
		s.status.Result.State = state
		s.status.Available = nil
		s.status.CheckedAt = time.Time{}
		s.mu.Unlock()
		s.refresh()
	}()
	reply(w, http.StatusAccepted, nil)
}

func decodeSelection(w http.ResponseWriter, r *http.Request) (Selection, bool) {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	var selection Selection
	valid := d.Decode(&selection) == nil && d.Decode(new(any)) == io.EOF &&
		validVersion(selection.Version) && selection.Component == "hydrat"
	return selection, valid
}

func reply(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// Proxy forwards only the three fixed updater operations over the local socket.
func Proxy(socket string) http.Handler {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := r.PathValue("operation")
		if !(r.Method == http.MethodGet && operation == "status") &&
			!(r.Method == http.MethodPost && (operation == "check" || operation == "install")) {
			http.NotFound(w, r)
			return
		}
		var body io.Reader
		if operation == "install" {
			selection, valid := decodeSelection(w, r)
			if !valid {
				reply(w, http.StatusBadRequest, nil)
				return
			}
			encoded, _ := json.Marshal(selection)
			body = bytes.NewReader(encoded)
		}
		if socket == "" {
			if operation == "status" {
				reply(w, http.StatusOK, Status{})
				return
			}
			reply(w, http.StatusServiceUnavailable, nil)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://updater/v1/"+operation, body)
		if err != nil {
			reply(w, http.StatusBadRequest, nil)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if operation == "status" {
				reply(w, http.StatusOK, Status{})
				return
			}
			reply(w, http.StatusServiceUnavailable, nil)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 32<<10))
	})
}

// Maintenance prevents client/admin changes during replacement and rollback of the database.
func Maintenance(socket string, next http.Handler) http.Handler {
	if socket == "" {
		return next
	}
	marker := filepath.Join(filepath.Dir(socket), "maintenance")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			clean != "/api/admin/session" && !strings.HasPrefix(clean, "/api/admin/updates/") {
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				reply(w, http.StatusServiceUnavailable, map[string]string{"error": "Устанавливается обновление Hydrat"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
