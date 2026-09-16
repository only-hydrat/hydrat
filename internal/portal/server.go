package portal

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

const (
	defaultMaxBodyBytes    int64 = 1024 * 1024
	defaultRetirementGrace       = 15 * time.Minute
)

type ServerConfig struct {
	Store               *store.Store
	Health              HealthChecker
	ControllerReadiness HealthChecker
	AdminPassword       string
	MaxBodyBytes        int64
	RetirementGrace     time.Duration
	InternalToken       string
	Reassigner          Reassigner
	Provisioner         PeerProvisioner
	Refresher           SourceRefresher
	Profiles            ProfileManager
	ProbeRuntime        ProbeRuntimeHealthProvider
	SourceChanges       chan<- struct{}
	ClientChanges       chan<- struct{}
	Routing             RoutingProvider
	WireGuardEndpoint   string
}

type RoutingState struct {
	DirectSuffixes   []string                `json:"direct_suffixes"`
	DirectDomains    []string                `json:"direct_domains"`
	DisallowRUEgress bool                    `json:"disallow_ru_egress"`
	GeoRules         GeoRulesView            `json:"geo_rules"`
	GeoStatus        agentapi.GeoAssetStatus `json:"geo_status"`
}
type GeoRulesView struct {
	Enabled        bool   `json:"enabled"`
	AutoUpdate     bool   `json:"auto_update"`
	GeoIPURL       string `json:"geoip_url"`
	GeoSiteURL     string `json:"geosite_url"`
	UpdateInterval string `json:"update_interval"`
}

type GeoRulesInput struct {
	Enabled        bool   `json:"enabled"`
	AutoUpdate     bool   `json:"auto_update"`
	GeoIPURL       string `json:"geoip_url"`
	GeoSiteURL     string `json:"geosite_url"`
	UpdateInterval string `json:"update_interval"`
}

type UpdateRoutingInput struct {
	DirectSuffixes   []string       `json:"direct_suffixes"`
	DirectDomains    []string       `json:"direct_domains"`
	DisallowRUEgress *bool          `json:"disallow_ru_egress,omitempty"`
	GeoRules         *GeoRulesInput `json:"geo_rules,omitempty"`
}
type RoutingProvider interface {
	GetRouting(context.Context) (RoutingState, error)
	UpdateRouting(context.Context, UpdateRoutingInput) (RoutingState, error)
	TriggerGeoUpdate(context.Context) (agentapi.GeoAssetStatus, error)
}

type Reassigner interface {
	Reassign(context.Context, string) error
}

type HealthChecker interface {
	Health(context.Context) error
}

type PeerProvisioner interface {
	Create(context.Context, string) (store.ClientRecord, string, error)
	SetPaused(context.Context, store.ClientRecord, bool) error
	Delete(context.Context, store.ClientRecord) error
}

type SourceRefresher interface {
	Source(context.Context, string) error
}

type ProfileManager interface {
	Profiles() []torpool.Profile
	ExploreNext(context.Context) ([]torpool.Profile, error)
}

type ProbeRuntimeHealthProvider interface {
	ProbeRuntimeHealth(context.Context) (proberuntime.Snapshot, error)
}

type ActiveProbeRuntimeHealthProvider interface {
	ActiveProbeRuntimeHealth(context.Context) (proberuntime.Snapshot, error)
}

type Server struct {
	store               *store.Store
	healthChecker       HealthChecker
	controllerReadiness HealthChecker
	auth                *adminAuth
	internalToken       string
	maxBodyBytes        int64
	retirementGrace     time.Duration
	reassigner          Reassigner
	provisioner         PeerProvisioner
	refresher           SourceRefresher
	profiles            ProfileManager
	probeRuntime        ProbeRuntimeHealthProvider
	sourceChanges       chan<- struct{}
	clientChanges       chan<- struct{}
	routing             RoutingProvider
	wireguardEndpoint   string
	mux                 *http.ServeMux
}

func New(config ServerConfig) http.Handler {
	maxBodyBytes := config.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	retirementGrace := config.RetirementGrace
	if retirementGrace < time.Second {
		retirementGrace = defaultRetirementGrace
	}
	server := &Server{
		store: config.Store, auth: newAdminAuth(config.AdminPassword), internalToken: config.InternalToken,
		healthChecker: config.Health, controllerReadiness: config.ControllerReadiness,
		maxBodyBytes: maxBodyBytes, reassigner: config.Reassigner, provisioner: config.Provisioner,
		retirementGrace: retirementGrace,
		refresher:       config.Refresher, profiles: config.Profiles, probeRuntime: config.ProbeRuntime,
		sourceChanges: config.SourceChanges, clientChanges: config.ClientChanges,
		routing:           config.Routing,
		wireguardEndpoint: strings.TrimSpace(config.WireGuardEndpoint),
		mux:               http.NewServeMux(),
	}
	server.mux.HandleFunc("GET /{$}", server.dashboard)
	server.mux.HandleFunc("GET /assets/{name}", server.asset)
	server.mux.HandleFunc("GET /api/health", server.health)
	server.mux.HandleFunc("GET /api/ready", server.ready)
	server.mux.HandleFunc("GET /api/me", server.me)
	server.mux.HandleFunc("POST /api/me/reassign", server.reassign)
	server.mux.HandleFunc("POST /api/admin/session", server.createAdminSession)
	server.mux.HandleFunc("DELETE /api/admin/session", server.deleteAdminSession)
	server.mux.HandleFunc("GET /api/admin/clients", server.admin(server.listClients))
	server.mux.HandleFunc("POST /api/admin/clients", server.admin(server.createClient))
	server.mux.HandleFunc("GET /api/admin/clients/{id}", server.admin(server.getClient))
	server.mux.HandleFunc("PATCH /api/admin/clients/{id}", server.admin(server.updateClient))
	server.mux.HandleFunc("DELETE /api/admin/clients/{id}", server.admin(server.deleteClient))
	server.mux.HandleFunc("GET /api/admin/clients/{id}/config", server.admin(server.clientConfig))
	server.mux.HandleFunc("GET /api/admin/clients/{id}/qr", server.admin(server.clientQR))
	server.mux.HandleFunc("GET /api/admin/clients/{id}/config.json", server.admin(server.clientConfigJSON))
	server.mux.HandleFunc("GET /api/admin/clients/{id}/qr.png", server.admin(server.clientQR))
	server.mux.HandleFunc("POST /api/admin/clients/{id}/pause", server.admin(server.pauseClient))
	server.mux.HandleFunc("POST /api/admin/clients/{id}/resume", server.admin(server.resumeClient))
	server.mux.HandleFunc("POST /api/admin/clients/{id}/rename", server.admin(server.renameClient))
	server.mux.HandleFunc("POST /api/admin/clients/{id}/reassign", server.admin(server.adminReassignClient))
	server.mux.HandleFunc("POST /api/admin/sources/preview", server.admin(server.previewSources))
	server.mux.HandleFunc("POST /api/admin/sources/import", server.admin(server.importSources))
	server.mux.HandleFunc("GET /api/admin/sources", server.admin(server.listSources))
	server.mux.HandleFunc("PATCH /api/admin/sources/{id}", server.admin(server.updateSource))
	server.mux.HandleFunc("DELETE /api/admin/sources/{id}", server.admin(server.deleteSource))
	server.mux.HandleFunc("POST /api/admin/sources/{id}/refresh", server.admin(server.refreshSource))
	server.mux.HandleFunc("GET /api/admin/profiles", server.admin(server.listProfiles))
	server.mux.HandleFunc("POST /api/admin/profiles/explore", server.admin(server.exploreProfile))
	server.mux.HandleFunc("GET /api/admin/candidates", server.admin(server.listCandidates))
	server.mux.HandleFunc("GET /api/admin/system", server.admin(server.systemSummary))
	server.mux.HandleFunc("GET /api/admin/routing", server.admin(server.getRouting))
	server.mux.HandleFunc("PUT /api/admin/routing", server.admin(server.updateRouting))
	server.mux.HandleFunc("POST /api/admin/routing/geo/update", server.admin(server.triggerGeoUpdate))
	return server
}

func (server *Server) me(response http.ResponseWriter, request *http.Request) {
	client, assignment, ok := server.clientForRequest(response, request)
	if !ok {
		return
	}
	result := map[string]any{
		"id": client.ID, "name": client.Name, "address": client.Address, "paused": client.Paused,
		"assignment": assignment.TCPOutbound, "tcp_assignment": assignment.TCPOutbound,
		"udp_assignment": assignment.UDPOutbound, "last_traffic_at": client.LastTrafficAt,
	}
	var referenced []string
	if assignment.TCPOutbound != "" {
		referenced = append(referenced, assignment.TCPOutbound)
	}
	if assignment.UDPOutbound != "" && assignment.UDPOutbound != assignment.TCPOutbound {
		referenced = append(referenced, assignment.UDPOutbound)
	}
	if len(referenced) > 0 {
		summaries, err := server.store.CandidateSummaries(request.Context(), referenced)
		if err == nil {
			if s, ok := summaries[assignment.TCPOutbound]; ok {
				result["tcp_kind"] = string(s.Kind)
				result["tcp_label"] = s.Label
			}
			if s, ok := summaries[assignment.UDPOutbound]; ok {
				result["udp_kind"] = string(s.Kind)
				result["udp_label"] = s.Label
			}
		}
	}
	writeJSON(response, http.StatusOK, result)
}

func (server *Server) reassign(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("X-Hydrat-Action") != "reassign" {
		writeError(response, http.StatusBadRequest, "X-Hydrat-Action: reassign is required")
		return
	}
	client, _, ok := server.clientForRequest(response, request)
	if !ok {
		return
	}
	if server.reassigner == nil {
		writeError(response, http.StatusServiceUnavailable, "reassignment is unavailable")
		return
	}
	if err := server.reassigner.Reassign(request.Context(), client.ID); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "scheduled"})
}

func (server *Server) clientForRequest(response http.ResponseWriter, request *http.Request) (store.ClientRecord, store.AssignmentRecord, bool) {
	host := server.requestSource(request)
	clients, err := server.store.ListClients(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "client lookup failed")
		return store.ClientRecord{}, store.AssignmentRecord{}, false
	}
	var found store.ClientRecord
	for _, client := range clients {
		address := strings.SplitN(client.Address, "/", 2)[0]
		if address == host {
			found = client
			break
		}
	}
	if found.ID == "" {
		writeError(response, http.StatusNotFound, "WireGuard client not found")
		return store.ClientRecord{}, store.AssignmentRecord{}, false
	}
	assignments, err := server.store.ListAssignments(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "assignment lookup failed")
		return store.ClientRecord{}, store.AssignmentRecord{}, false
	}
	for _, assignment := range assignments {
		if assignment.ClientID == found.ID {
			return found, assignment, true
		}
	}
	return found, store.AssignmentRecord{ClientID: found.ID}, true
}

func (server *Server) listClients(response http.ResponseWriter, request *http.Request) {
	clients, err := server.store.ListClients(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "client list failed")
		return
	}
	assignments, err := server.store.ListAssignments(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "assignment list failed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"clients": clients, "assignments": assignments})
}

func (server *Server) createClient(response http.ResponseWriter, request *http.Request) {
	if server.provisioner == nil {
		writeError(response, http.StatusServiceUnavailable, "client provisioning is unavailable")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeError(response, http.StatusBadRequest, "name is required")
		return
	}
	client, config, err := server.provisioner.Create(request.Context(), body.Name)
	if err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	if err := server.store.PutClient(request.Context(), client, config); err != nil {
		_ = server.provisioner.Delete(request.Context(), client)
		writeError(response, http.StatusConflict, "client state could not be saved")
		return
	}
	server.notifyClientChange()
	writeJSON(response, http.StatusCreated, client)
}

func (server *Server) getClient(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, client)
}

func (server *Server) updateClient(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	var body struct {
		Name   string `json:"name"`
		Paused *bool  `json:"paused"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	if strings.TrimSpace(body.Name) != "" {
		client.Name = strings.TrimSpace(body.Name)
	}
	pausedChanged := body.Paused != nil && *body.Paused != client.Paused
	if body.Paused != nil {
		if server.provisioner != nil && *body.Paused != client.Paused {
			if err := server.provisioner.SetPaused(request.Context(), client, *body.Paused); err != nil {
				writeError(response, http.StatusConflict, err.Error())
				return
			}
		}
		client.Paused = *body.Paused
	}
	if err := server.store.UpdateClient(request.Context(), client.ID, client.Name, client.Paused); err != nil {
		writeError(response, http.StatusInternalServerError, "client update failed")
		return
	}
	if pausedChanged {
		server.notifyClientChange()
	}
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) deleteClient(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	if server.provisioner != nil {
		if err := server.provisioner.Delete(request.Context(), client); err != nil {
			writeError(response, http.StatusConflict, err.Error())
			return
		}
	}
	if err := server.store.DeleteClient(request.Context(), client.ID); err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	server.notifyClientChange()
	response.WriteHeader(http.StatusNoContent)
}
func (server *Server) formatClientConfig(config string) string {
	if server.wireguardEndpoint != "" {
		return wireguard.ReplaceEndpoint(config, server.wireguardEndpoint)
	}
	return config
}

func (server *Server) clientConfig(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	config, err := server.store.ClientConfig(request.Context(), client.ID)
	if err != nil {
		writeError(response, http.StatusNotFound, "client not found")
		return
	}
	config = server.formatClientConfig(config)
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="wireguard.conf"`)
	_, _ = io.WriteString(response, config)
}

func (server *Server) clientQR(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	config, err := server.store.ClientConfig(request.Context(), client.ID)
	if err != nil {
		writeError(response, http.StatusNotFound, "client not found")
		return
	}
	config = server.formatClientConfig(config)
	png, err := qrcode.Encode(config, qrcode.Medium, 384)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "QR generation failed")
		return
	}
	response.Header().Set("Content-Type", "image/png")
	_, _ = response.Write(png)
}

func (server *Server) clientConfigJSON(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	config, err := server.store.ClientConfig(request.Context(), client.ID)
	if err != nil {
		writeError(response, http.StatusNotFound, "client not found")
		return
	}
	config = server.formatClientConfig(config)
	writeJSON(response, http.StatusOK, map[string]any{
		"name": client.Name, "address": client.Address, "public_key": client.PublicKey, "config": config,
	})
}

func (server *Server) pauseClient(response http.ResponseWriter, request *http.Request) {
	server.setPaused(response, request, true)
}

func (server *Server) resumeClient(response http.ResponseWriter, request *http.Request) {
	server.setPaused(response, request, false)
}

func (server *Server) setPaused(response http.ResponseWriter, request *http.Request, paused bool) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	if server.provisioner != nil {
		if err := server.provisioner.SetPaused(request.Context(), client, paused); err != nil {
			writeError(response, http.StatusConflict, err.Error())
			return
		}
	}
	if err := server.store.UpdateClient(request.Context(), client.ID, client.Name, paused); err != nil {
		writeError(response, http.StatusInternalServerError, "client state update failed")
		return
	}
	if paused != client.Paused {
		server.notifyClientChange()
	}
	action := "resumed"
	if paused {
		action = "paused"
	}
	writeJSON(response, http.StatusOK, map[string]string{action: client.Name, "address": client.Address})
}

func (server *Server) notifyClientChange() {
	if server.clientChanges == nil {
		return
	}
	select {
	case server.clientChanges <- struct{}{}:
	default:
	}
}

func (server *Server) renameClient(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeError(response, http.StatusBadRequest, "name is required")
		return
	}
	if err := server.store.UpdateClient(request.Context(), client.ID, body.Name, client.Paused); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{
		"renamed": client.Name, "name": body.Name, "address": client.Address, "public_key": client.PublicKey,
	})
}

func (server *Server) adminReassignClient(response http.ResponseWriter, request *http.Request) {
	client, ok := server.findClient(response, request, request.PathValue("id"))
	if !ok {
		return
	}
	if server.reassigner == nil {
		writeError(response, http.StatusServiceUnavailable, "reassignment is unavailable")
		return
	}
	if err := server.reassigner.Reassign(request.Context(), client.ID); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "scheduled"})
}

func (server *Server) findClient(response http.ResponseWriter, request *http.Request, id string) (store.ClientRecord, bool) {
	clients, err := server.store.ListClients(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "client lookup failed")
		return store.ClientRecord{}, false
	}
	for _, client := range clients {
		if client.ID == id || client.Name == id {
			return client, true
		}
	}
	writeError(response, http.StatusNotFound, "client not found")
	return store.ClientRecord{}, false
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' blob: data:; frame-ancestors 'none'")
	server.mux.ServeHTTP(response, request)
}

func (server *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if _, present := request.Header["Authorization"]; present {
			authorization := request.Header.Get("Authorization")
			token, ok := strings.CutPrefix(authorization, "Bearer ")
			if !ok || !server.auth.authenticateBearer(token) {
				writeError(response, http.StatusUnauthorized, "admin authentication required")
				return
			}
			next(response, request)
			return
		}
		if authenticated, retry := server.auth.authenticatePassword(server.requestSource(request), request.Header.Get("X-Hydrat-Admin-Password")); !authenticated {
			if retry > 0 {
				response.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
				writeError(response, http.StatusTooManyRequests, "admin authentication required")
				return
			}
			writeError(response, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next(response, request)
	}
}

func (server *Server) createAdminSession(response http.ResponseWriter, request *http.Request) {
	authenticated, retry := server.auth.authenticatePassword(server.requestSource(request), request.Header.Get("X-Hydrat-Admin-Password"))
	if !authenticated {
		if retry > 0 {
			response.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
			writeError(response, http.StatusTooManyRequests, "admin authentication required")
			return
		}
		writeError(response, http.StatusUnauthorized, "admin authentication required")
		return
	}
	token, idle, absolute, err := server.auth.createSession()
	if err != nil {
		if errors.Is(err, errSessionCapacity) {
			writeError(response, http.StatusServiceUnavailable, "admin sessions unavailable")
			return
		}
		writeError(response, http.StatusInternalServerError, "admin session creation failed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"token": token, "expires_in": int(idle.Seconds()), "absolute_expires_in": int(absolute.Seconds()),
	})
}

func (server *Server) deleteAdminSession(response http.ResponseWriter, request *http.Request) {
	token, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok || !server.auth.authenticateBearer(token) {
		writeError(response, http.StatusUnauthorized, "admin authentication required")
		return
	}
	server.auth.revoke(token)
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) requestSource(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	if server.internalTokenValid(request.Header.Get("X-Hydrat-Internal-Token")) {
		if ip := net.ParseIP(strings.TrimSpace(request.Header.Get("X-Hydrat-Client-IP"))); ip != nil {
			return ip.String()
		}
	}
	return host
}

func (server *Server) internalTokenValid(token string) bool {
	return server.internalToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(server.internalToken)) == 1
}

func (server *Server) health(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if status := server.livenessStatus(ctx); status != "" {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"status": status})
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) ready(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if status := server.livenessStatus(ctx); status != "" {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"status": status})
		return
	}
	if server.controllerReadiness != nil {
		if err := server.controllerReadiness.Health(ctx); err != nil {
			writeJSON(response, http.StatusServiceUnavailable, map[string]string{
				"status": "controller unavailable: " + err.Error(),
			})
			return
		}
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) livenessStatus(ctx context.Context) string {
	if server.store == nil {
		return "unavailable"
	}
	if _, _, err := server.store.PlanGenerations(ctx); err != nil {
		return "database unavailable"
	}
	if server.healthChecker != nil {
		if err := server.healthChecker.Health(ctx); err != nil {
			return "gateway agent unavailable"
		}
	}
	return ""
}

func (server *Server) previewSources(response http.ResponseWriter, request *http.Request) {
	input, ok := server.decodeInput(response, request)
	if !ok {
		return
	}
	preview := sources.PreviewInput(input)
	for index := range preview.Items {
		preview.Items[index] = preview.Items[index].Safe()
	}
	writeJSON(response, http.StatusOK, preview)
}

func (server *Server) importSources(response http.ResponseWriter, request *http.Request) {
	input, ok := server.decodeInput(response, request)
	if !ok {
		return
	}
	preview := sources.PreviewInput(input)
	result, err := server.store.ImportSources(request.Context(), preview.Items)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "source import failed")
		return
	}
	server.signalSourceChange()
	writeJSON(response, http.StatusCreated, map[string]any{
		"result": result, "valid_count": preview.ValidCount,
		"duplicate_count": preview.DuplicateCount, "error_count": preview.ErrorCount,
	})
}

func (server *Server) listSources(response http.ResponseWriter, request *http.Request) {
	listed, err := server.store.ListSources(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "source list failed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"sources": listed})
}

func (server *Server) updateSource(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Label   string `json:"label"`
		Enabled *bool  `json:"enabled"`
	}
	if !server.decodeJSON(response, request, &body) {
		return
	}
	if body.Enabled == nil {
		writeError(response, http.StatusBadRequest, "enabled is required")
		return
	}
	if err := server.store.UpdateSource(request.Context(), request.PathValue("id"), strings.TrimSpace(body.Label), *body.Enabled); err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	server.signalSourceChange()
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) deleteSource(response http.ResponseWriter, request *http.Request) {
	if err := server.store.DeleteSource(
		request.Context(),
		request.PathValue("id"),
		server.retirementGrace,
	); err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	server.signalSourceChange()
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) refreshSource(response http.ResponseWriter, request *http.Request) {
	if server.refresher == nil {
		writeError(response, http.StatusServiceUnavailable, "source refresh is unavailable")
		return
	}
	if err := server.refresher.Source(request.Context(), request.PathValue("id")); err != nil {
		writeError(response, http.StatusBadGateway, err.Error())
		return
	}
	server.signalSourceChange()
	writeJSON(response, http.StatusOK, map[string]string{"refreshed": request.PathValue("id")})
}

func (server *Server) signalSourceChange() {
	if server.sourceChanges == nil {
		return
	}
	select {
	case server.sourceChanges <- struct{}{}:
	default:
	}
}

func (server *Server) listProfiles(response http.ResponseWriter, _ *http.Request) {
	profiles := []torpool.Profile{}
	if server.profiles != nil {
		profiles = server.profiles.Profiles()
	}
	writeJSON(response, http.StatusOK, map[string]any{"profiles": profiles})
}

func (server *Server) exploreProfile(response http.ResponseWriter, request *http.Request) {
	if server.profiles == nil {
		writeError(response, http.StatusServiceUnavailable, "Tor profiles are unavailable")
		return
	}
	profiles, err := server.profiles.ExploreNext(request.Context())
	if err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"profiles": profiles})
}

func (server *Server) decodeInput(response http.ResponseWriter, request *http.Request) (string, bool) {
	var body struct {
		Input string `json:"input"`
	}
	if !server.decodeJSON(response, request, &body) {
		return "", false
	}
	if strings.TrimSpace(body.Input) == "" {
		writeError(response, http.StatusBadRequest, "input is required")
		return "", false
	}
	return body.Input, true
}

func (server *Server) decodeJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(response, request.Body, server.maxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(response, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(response, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "request must contain one JSON value")
		return false
	}
	return true
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}

func (server *Server) getRouting(response http.ResponseWriter, request *http.Request) {
	if server.routing == nil {
		writeJSON(response, http.StatusOK, RoutingState{
			DirectSuffixes:   []string{".ru", ".su", ".xn--p1ai"},
			DirectDomains:    []string{"thecode.media", "habr.com"},
			DisallowRUEgress: true,
			GeoRules: GeoRulesView{
				Enabled:        true,
				AutoUpdate:     true,
				GeoIPURL:       "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/geoip.dat",
				GeoSiteURL:     "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/geosite.dat",
				UpdateInterval: "24h",
			},
		})
		return
	}
	state, err := server.routing.GetRouting(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "failed to get routing state: "+err.Error())
		return
	}
	writeJSON(response, http.StatusOK, state)
}
func (server *Server) updateRouting(response http.ResponseWriter, request *http.Request) {
	if server.routing == nil {
		writeError(response, http.StatusServiceUnavailable, "routing manager is unavailable")
		return
	}
	var input UpdateRoutingInput
	if !server.decodeJSON(response, request, &input) {
		return
	}
	if len(input.DirectSuffixes) == 0 {
		writeError(response, http.StatusBadRequest, "direct_suffixes must contain at least one suffix")
		return
	}
	for _, suffix := range input.DirectSuffixes {
		s := strings.TrimSpace(suffix)
		if s == "" || !strings.HasPrefix(s, ".") || len(s) < 2 {
			writeError(response, http.StatusBadRequest, fmt.Sprintf("invalid direct suffix %q: must start with '.' and be >= 2 chars", suffix))
			return
		}
	}
	for _, domain := range input.DirectDomains {
		d := strings.TrimSpace(domain)
		if d == "" {
			writeError(response, http.StatusBadRequest, "direct domain must not be empty")
			return
		}
		if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			writeError(response, http.StatusBadRequest, fmt.Sprintf("invalid direct domain %q: must be clean domain without scheme, port, or path", domain))
			return
		}
	}
	if input.GeoRules != nil && input.GeoRules.Enabled {
		if input.GeoRules.AutoUpdate {
			if strings.TrimSpace(input.GeoRules.GeoIPURL) == "" {
				writeError(response, http.StatusBadRequest, "geoip_url must not be empty when auto_update is enabled")
				return
			}
			u, err := url.Parse(input.GeoRules.GeoIPURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				writeError(response, http.StatusBadRequest, "geoip_url must be a valid http or https URL")
				return
			}
			if strings.TrimSpace(input.GeoRules.GeoSiteURL) == "" {
				writeError(response, http.StatusBadRequest, "geosite_url must not be empty when auto_update is enabled")
				return
			}
			u, err = url.Parse(input.GeoRules.GeoSiteURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				writeError(response, http.StatusBadRequest, "geosite_url must be a valid http or https URL")
				return
			}
			if strings.TrimSpace(input.GeoRules.UpdateInterval) != "" {
				dur, err := time.ParseDuration(input.GeoRules.UpdateInterval)
				if err != nil || dur <= 0 {
					writeError(response, http.StatusBadRequest, "update_interval must be a valid positive duration like '24h'")
					return
				}
			}
		}
	}

	state, err := server.routing.UpdateRouting(request.Context(), input)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "failed to update routing: "+err.Error())
		return
	}
	writeJSON(response, http.StatusOK, state)
}

func (server *Server) triggerGeoUpdate(response http.ResponseWriter, request *http.Request) {
	if server.routing == nil {
		writeError(response, http.StatusServiceUnavailable, "routing manager is unavailable")
		return
	}
	status, err := server.routing.TriggerGeoUpdate(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "failed to trigger geo update: "+err.Error())
		return
	}
	writeJSON(response, http.StatusOK, status)
}
