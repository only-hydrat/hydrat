package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

type Applier interface {
	Apply(context.Context, dataplane.DesiredPlan) error
}

type Server struct {
	applier                   Applier
	activity                  ActivityProvider
	peers                     PeerManager
	profiles                  ProfileManager
	geo                       GeoManager
	probeRuntime              probeRuntimeHealth
	activeProbeRuntime        probeRuntimeHealth
	readiness                 func(context.Context) error
	probeRunner               ProbeRunner
	criticalActiveProbeRunner ProbeRunner
	probeLimits               probeLimits
	probeDeadlines            probeDeadlines
	maxPlanSize               int64
	mux                       *http.ServeMux
}
type GeoAssetStatus struct {
	Enabled         bool      `json:"enabled"`
	AutoUpdate      bool      `json:"auto_update"`
	GeoIPURL        string    `json:"geoip_url"`
	GeoSiteURL      string    `json:"geosite_url"`
	UpdateInterval  string    `json:"update_interval"`
	LastUpdate      time.Time `json:"last_update,omitempty"`
	GeoIPExists     bool      `json:"geoip_exists"`
	GeoIPSize       int64     `json:"geoip_size"`
	GeoIPModified   time.Time `json:"geoip_modified,omitempty"`
	GeoSiteExists   bool      `json:"geosite_exists"`
	GeoSiteSize     int64     `json:"geosite_size"`
	GeoSiteModified time.Time `json:"geosite_modified,omitempty"`
}

type GeoManager interface {
	Status() GeoAssetStatus
	UpdateConfig(enabled, autoUpdate bool, geoIPURL, geoSiteURL string, updateInterval time.Duration) error
	ForceUpdate(context.Context) error
}

type ActivityProvider interface {
	Snapshot(context.Context) ([]wireguard.PeerActivity, error)
}

type PeerManager interface {
	Create(context.Context, string, string) (wireguard.Peer, string, error)
	SetPaused(context.Context, wireguard.Peer, bool) error
}

type ProfileManager interface {
	Reconcile(context.Context, []torpool.Candidate) ([]torpool.Profile, error)
	Profiles() []torpool.Profile
	ExploreNext(context.Context) ([]torpool.Profile, error)
}

type probeRuntimeHealth interface {
	Snapshot() proberuntime.Snapshot
}

type Option func(*Server)

func WithActivityProvider(provider ActivityProvider) Option {
	return func(server *Server) { server.activity = provider }
}

func WithPeerManager(manager PeerManager) Option {
	return func(server *Server) { server.peers = manager }
}

func WithProfileManager(manager ProfileManager) Option {
	return func(server *Server) { server.profiles = manager }
}

func WithProbeRuntime(runtime probeRuntimeHealth) Option {
	return func(server *Server) { server.probeRuntime = runtime }
}

func WithActiveProbeRuntime(runtime probeRuntimeHealth) Option {
	return func(server *Server) { server.activeProbeRuntime = runtime }
}

func WithReadiness(check func(context.Context) error) Option {
	return func(server *Server) { server.readiness = check }
}

func WithGeoManager(manager GeoManager) Option {
	return func(server *Server) { server.geo = manager }
}

func WithProbeRunner(runner ProbeRunner) Option {
	return func(server *Server) { server.probeRunner = runner }
}

func WithCriticalActiveProbeRunner(runner ProbeRunner, workers int) Option {
	return func(server *Server) {
		server.criticalActiveProbeRunner = runner
		if workers <= 0 {
			workers = 48
		}
		server.probeLimits.activeCritical = make(chan struct{}, workers)
	}
}

func WithProbeWorkers(fast, full, active int) Option {
	return func(server *Server) {
		limits := newProbeLimits(fast, full, active)
		server.probeLimits.fast = limits.fast
		server.probeLimits.full = limits.full
		server.probeLimits.active = limits.active
	}
}

func WithQoEProbeWorkers(workers int) Option {
	return func(server *Server) {
		if workers > 0 {
			if workers > qoe.MaxProbeWorkers {
				workers = qoe.MaxProbeWorkers
			}
			server.probeLimits.qoe = make(chan struct{}, workers)
		}
	}
}

func WithProbeDeadlines(fast, full, active time.Duration) Option {
	return func(server *Server) {
		if fast > 0 {
			server.probeDeadlines.fast = fast
		}
		if full > 0 {
			server.probeDeadlines.full = full
		}
		if active > 0 {
			server.probeDeadlines.active = active
		}
	}
}

func WithQoEProbeDeadline(deadline time.Duration) Option {
	return func(server *Server) {
		if deadline > 0 {
			server.probeDeadlines.qoe = deadline
		}
	}
}

func WithTorProbeDeadlines(fast, full time.Duration) Option {
	return func(server *Server) {
		if fast > 0 {
			server.probeDeadlines.torFast = fast
		}
		if full > 0 {
			server.probeDeadlines.torFull = full
		}
	}
}

func NewServer(applier Applier, maxPlanSize int64, options ...Option) http.Handler {
	if maxPlanSize <= 0 {
		maxPlanSize = 4 * 1024 * 1024
	}
	server := &Server{
		applier: applier, maxPlanSize: maxPlanSize, mux: http.NewServeMux(),
		probeLimits: newProbeLimits(8, 4, 16), probeDeadlines: defaultProbeDeadlines(),
	}
	for _, option := range options {
		option(server)
	}
	server.mux.HandleFunc("GET /v1/health", server.health)
	server.mux.HandleFunc("GET /v1/activity", server.activitySnapshot)
	server.mux.HandleFunc("POST /v1/peers", server.createPeer)
	server.mux.HandleFunc("POST /v1/peer-state", server.setPeerState)
	server.mux.HandleFunc("GET /v1/profiles", server.listProfiles)
	server.mux.HandleFunc("POST /v1/profiles/reconcile", server.reconcileProfiles)
	server.mux.HandleFunc("POST /v1/profiles/explore", server.exploreProfile)
	server.mux.HandleFunc("POST /v1/probes/fast", func(response http.ResponseWriter, request *http.Request) {
		server.probe(response, request, ProbeModeFast)
	})
	server.mux.HandleFunc("POST /v1/probes/full", func(response http.ResponseWriter, request *http.Request) {
		server.probe(response, request, ProbeModeFull)
	})
	server.mux.HandleFunc("POST /v1/probes/active", func(response http.ResponseWriter, request *http.Request) {
		server.probe(response, request, ProbeModeActive)
	})
	server.mux.HandleFunc("POST /v1/probes/active-critical", func(response http.ResponseWriter, request *http.Request) {
		server.probe(response, request, ProbeModeActiveCritical)
	})
	server.mux.HandleFunc("POST /v1/probes/qoe", func(response http.ResponseWriter, request *http.Request) {
		server.probe(response, request, ProbeModeQoE)
	})
	server.mux.HandleFunc("POST /v1/plan", server.applyPlan)
	server.mux.HandleFunc("GET /v1/geo", server.geoStatus)
	server.mux.HandleFunc("POST /v1/geo/update", server.updateGeo)
	return server
}

func (server *Server) geoStatus(response http.ResponseWriter, _ *http.Request) {
	if server.geo == nil {
		writeJSON(response, http.StatusOK, map[string]any{"enabled": false, "available": false})
		return
	}
	writeJSON(response, http.StatusOK, server.geo.Status())
}

func (server *Server) updateGeo(response http.ResponseWriter, request *http.Request) {
	if server.geo == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "geo manager is unavailable"})
		return
	}
	var body struct {
		Enabled        *bool   `json:"enabled"`
		AutoUpdate     *bool   `json:"auto_update"`
		GeoIPURL       *string `json:"geoip_url"`
		GeoSiteURL     *string `json:"geosite_url"`
		UpdateInterval *string `json:"update_interval"`
		Force          bool    `json:"force"`
	}
	if request.Body != nil && request.ContentLength > 0 {
		if !server.decodeJSON(response, request, &body) {
			return
		}
	}
	var interval time.Duration
	if body.UpdateInterval != nil && *body.UpdateInterval != "" {
		parsed, err := time.ParseDuration(*body.UpdateInterval)
		if err != nil {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid update_interval: " + err.Error()})
			return
		}
		interval = parsed
	}
	var enabled, autoUpdate bool
	var geoIPURL, geoSiteURL string
	current := server.geo.Status()
	enabled = current.Enabled
	autoUpdate = current.AutoUpdate
	geoIPURL = current.GeoIPURL
	geoSiteURL = current.GeoSiteURL
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if body.AutoUpdate != nil {
		autoUpdate = *body.AutoUpdate
	}
	if body.GeoIPURL != nil {
		geoIPURL = *body.GeoIPURL
	}
	if body.GeoSiteURL != nil {
		geoSiteURL = *body.GeoSiteURL
	}
	_ = server.geo.UpdateConfig(enabled, autoUpdate, geoIPURL, geoSiteURL, interval)
	if body.Force {
		if err := server.geo.ForceUpdate(request.Context()); err != nil {
			writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "geo update failed: " + err.Error()})
			return
		}
	}
	writeJSON(response, http.StatusOK, server.geo.Status())
}

func (server *Server) listProfiles(response http.ResponseWriter, _ *http.Request) {
	if server.profiles == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "profile manager is unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"profiles": server.profiles.Profiles()})
}

func (server *Server) reconcileProfiles(response http.ResponseWriter, request *http.Request) {
	if server.profiles == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "profile manager is unavailable"})
		return
	}
	var body struct {
		Candidates []torpool.Candidate `json:"candidates"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	profiles, err := server.profiles.Reconcile(request.Context(), body.Candidates)
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"profiles": profiles})
}

func (server *Server) exploreProfile(response http.ResponseWriter, request *http.Request) {
	if server.profiles == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "profile manager is unavailable"})
		return
	}
	profiles, err := server.profiles.ExploreNext(request.Context())
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"profiles": profiles})
}

func (server *Server) createPeer(response http.ResponseWriter, request *http.Request) {
	if server.peers == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "peer manager is unavailable"})
		return
	}
	var body struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	peer, config, err := server.peers.Create(request.Context(), body.Name, body.Address)
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{"peer": peer, "config": config})
}

func (server *Server) setPeerState(response http.ResponseWriter, request *http.Request) {
	if server.peers == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "peer manager is unavailable"})
		return
	}
	var body struct {
		Peer   wireguard.Peer `json:"peer"`
		Paused bool           `json:"paused"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	if err := server.peers.SetPaused(request.Context(), body.Peer, body.Paused); err != nil {
		writeJSON(response, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) decodeJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(response, request.Body, server.maxPlanSize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON value"})
		return false
	}
	return true
}

func (server *Server) activitySnapshot(response http.ResponseWriter, request *http.Request) {
	if server.activity == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "activity provider is unavailable"})
		return
	}
	peers, err := server.activity.Snapshot(request.Context())
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "WireGuard activity unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"peers": peers})
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	server.mux.ServeHTTP(response, request)
}

func (server *Server) health(response http.ResponseWriter, request *http.Request) {
	payload := struct {
		Status             string                 `json:"status"`
		APIVersion         string                 `json:"api_version"`
		ProbeRuntime       *proberuntime.Snapshot `json:"probe_runtime,omitempty"`
		ActiveProbeRuntime *proberuntime.Snapshot `json:"active_probe_runtime,omitempty"`
	}{
		Status:     "ok",
		APIVersion: "v1",
	}
	if server.probeRuntime != nil {
		snapshot := server.probeRuntime.Snapshot()
		payload.ProbeRuntime = &snapshot
	}
	if server.activeProbeRuntime != nil {
		snapshot := server.activeProbeRuntime.Snapshot()
		payload.ActiveProbeRuntime = &snapshot
	}
	if server.readiness != nil {
		if err := server.readiness(request.Context()); err != nil {
			payload.Status = "starting"
			writeJSON(response, http.StatusServiceUnavailable, payload)
			return
		}
	}
	writeJSON(response, http.StatusOK, payload)
}

func (server *Server) applyPlan(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, server.maxPlanSize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var plan dataplane.DesiredPlan
	if err := decoder.Decode(&plan); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid desired plan"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "request must contain one desired plan"})
		return
	}
	if err := server.applier.Apply(request.Context(), plan); err != nil {
		status := http.StatusConflict
		message := err.Error()
		retryable := false
		if errors.Is(err, dataplane.ErrRuntimeRecovering) {
			status = http.StatusServiceUnavailable
			message = dataplane.ErrRuntimeRecovering.Error()
			retryable = true
		} else {
			var temporary dataplane.TemporaryError
			if errors.As(err, &temporary) && temporary.Temporary() {
				status = http.StatusServiceUnavailable
				retryable = true
			}
		}
		writeJSON(response, status, struct {
			Error     string `json:"error"`
			Retryable bool   `json:"retryable,omitempty"`
		}{Error: message, Retryable: retryable})
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
