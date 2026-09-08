package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probetimeout"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

type Client struct {
	http                *http.Client
	probeHTTP           *http.Client
	probeDeadlines      probeDeadlines
	activeResponseSlack time.Duration
	mu                  sync.RWMutex
	profiles            []torpool.Profile
}

type ClientOption func(*Client)

func ProbeRequestTimeout(serverDeadline time.Duration) time.Duration {
	return probetimeout.RequestTimeout(serverDeadline)
}

func WithClientProbeDeadlines(fast, full, active, torFast, torFull time.Duration) ClientOption {
	return func(client *Client) {
		if fast > 0 {
			client.probeDeadlines.fast = fast
		}
		if full > 0 {
			client.probeDeadlines.full = full
		}
		if active > 0 {
			client.probeDeadlines.active = active
		}
		if torFast > 0 {
			client.probeDeadlines.torFast = torFast
		}
		if torFull > 0 {
			client.probeDeadlines.torFull = torFull
		}
	}
}

func WithClientQoEProbeDeadline(deadline time.Duration) ClientOption {
	return func(client *Client) {
		if deadline > 0 {
			client.probeDeadlines.qoe = deadline
		}
	}
}

func WithClientActiveResponseSlack(slack time.Duration) ClientOption {
	return func(client *Client) {
		if slack > 0 {
			client.activeResponseSlack = slack
		}
	}
}

func NewClient(socketPath string, options ...ClientOption) *Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       4,
		IdleConnTimeout:    90 * time.Second,
	}
	return newClientWithHTTP(&http.Client{Transport: transport, Timeout: 25 * time.Second}, options...)
}

func newClientWithHTTP(httpClient *http.Client, options ...ClientOption) *Client {
	probeHTTP := *httpClient
	probeHTTP.Timeout = 0
	client := &Client{
		http: httpClient, probeHTTP: &probeHTTP, probeDeadlines: defaultProbeDeadlines(),
		activeResponseSlack: 75 * time.Millisecond,
	}
	for _, option := range options {
		option(client)
	}
	return client
}

func (client *Client) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/health", nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("agent health returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *Client) ProbeRuntimeHealth(ctx context.Context) (proberuntime.Snapshot, error) {
	return client.probeRuntimeHealth(ctx, "probe_runtime")
}

func (client *Client) ActiveProbeRuntimeHealth(ctx context.Context) (proberuntime.Snapshot, error) {
	return client.probeRuntimeHealth(ctx, "active_probe_runtime")
}

func (client *Client) probeRuntimeHealth(
	ctx context.Context,
	field string,
) (proberuntime.Snapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/health", nil)
	if err != nil {
		return proberuntime.Snapshot{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return proberuntime.Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK &&
		response.StatusCode != http.StatusServiceUnavailable {
		return proberuntime.Snapshot{}, fmt.Errorf(
			"agent health returned HTTP %d",
			response.StatusCode,
		)
	}
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&payload); err != nil {
		return proberuntime.Snapshot{}, err
	}
	raw, exists := payload[field]
	if !exists {
		if field == "probe_runtime" {
			return proberuntime.Snapshot{}, nil
		}
		return proberuntime.Snapshot{}, fmt.Errorf("agent health omitted %s", field)
	}
	var snapshot proberuntime.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return proberuntime.Snapshot{}, err
	}
	return snapshot, nil
}

func (client *Client) Apply(ctx context.Context, plan dataplane.DesiredPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/plan", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return dataplane.MarkTemporary(fmt.Errorf("agent apply transport: %w", err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		message, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		if readErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return dataplane.MarkTemporary(fmt.Errorf(
				"read agent apply response: %w", readErr,
			))
		}
		if response.StatusCode == http.StatusServiceUnavailable {
			var payload struct {
				Error     string `json:"error"`
				Retryable bool   `json:"retryable"`
			}
			if json.Unmarshal(message, &payload) == nil {
				if payload.Error == dataplane.ErrRuntimeRecovering.Error() {
					return fmt.Errorf("agent apply: %w", dataplane.ErrRuntimeRecovering)
				}
				if payload.Retryable {
					return dataplane.MarkTemporary(fmt.Errorf("agent apply: %s", payload.Error))
				}
			}
		}
		return fmt.Errorf("agent apply returned HTTP %d: %s", response.StatusCode, bytes.TrimSpace(message))
	}
	return nil
}

func (client *Client) Activity(ctx context.Context) ([]wireguard.PeerActivity, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/activity", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent activity returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Peers []wireguard.PeerActivity `json:"peers"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Peers, nil
}

func (client *Client) CreatePeer(ctx context.Context, name, address string) (wireguard.Peer, string, error) {
	body, err := json.Marshal(map[string]string{"name": name, "address": address})
	if err != nil {
		return wireguard.Peer{}, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/peers", bytes.NewReader(body))
	if err != nil {
		return wireguard.Peer{}, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return wireguard.Peer{}, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return wireguard.Peer{}, "", fmt.Errorf("agent peer create returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Peer   wireguard.Peer `json:"peer"`
		Config string         `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&payload); err != nil {
		return wireguard.Peer{}, "", err
	}
	return payload.Peer, payload.Config, nil
}

func (client *Client) SetPeerPaused(ctx context.Context, peer wireguard.Peer, paused bool) error {
	body, err := json.Marshal(map[string]any{"peer": peer, "paused": paused})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/peer-state", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent peer state returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *Client) ProbeFast(ctx context.Context, request ProbeRequest) (ProbeResponse, error) {
	return client.probe(ctx, ProbeModeFast, request)
}

func (client *Client) ProbeFull(ctx context.Context, request ProbeRequest) (ProbeResponse, error) {
	return client.probe(ctx, ProbeModeFull, request)
}

func (client *Client) ProbeActive(ctx context.Context, request ProbeRequest) (ProbeResponse, error) {
	return client.probe(ctx, ProbeModeActive, request)
}

func (client *Client) ProbeActiveCritical(
	ctx context.Context,
	request ProbeRequest,
) (ProbeResponse, error) {
	return client.probe(ctx, ProbeModeActiveCritical, request)
}

func (client *Client) ProbeQoE(ctx context.Context, request ProbeRequest) (ProbeResponse, error) {
	return client.probe(ctx, ProbeModeQoE, request)
}

func (client *Client) probe(ctx context.Context, mode ProbeMode, payload ProbeRequest) (ProbeResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return ProbeResponse{}, err
	}
	requestTimeout := ProbeRequestTimeout(
		client.probeDeadlines.forRequest(mode, payload.Kind),
	)
	if mode == ProbeModeActive || mode == ProbeModeActiveCritical {
		requestTimeout = client.probeDeadlines.active + client.activeResponseSlack
	}
	probeCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodPost, "http://unix/v1/probes/"+string(mode), bytes.NewReader(body))
	if err != nil {
		return ProbeResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.probeHTTP.Do(request)
	if err != nil {
		return ProbeResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return ProbeResponse{}, fmt.Errorf("agent %s probe returned HTTP %d: %s", mode, response.StatusCode, bytes.TrimSpace(message))
	}
	var result ProbeResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&result); err != nil {
		return ProbeResponse{}, err
	}
	return result, nil
}

func (client *Client) ReconcileProfiles(ctx context.Context, candidates []torpool.Candidate) ([]torpool.Profile, error) {
	body, err := json.Marshal(map[string]any{"candidates": candidates})
	if err != nil {
		return nil, err
	}
	profiles, err := client.profileRequest(
		ctx, http.MethodPost, "/v1/profiles/reconcile", body, true,
	)
	if err == nil {
		client.cacheProfiles(profiles)
	}
	return profiles, err
}

func (client *Client) FetchProfiles(ctx context.Context) ([]torpool.Profile, error) {
	profiles, err := client.profileRequest(
		ctx, http.MethodGet, "/v1/profiles", nil, false,
	)
	if err == nil {
		client.cacheProfiles(profiles)
	}
	return profiles, err
}

func (client *Client) Profiles() []torpool.Profile {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return append([]torpool.Profile(nil), client.profiles...)
}

func (client *Client) ExploreNext(ctx context.Context) ([]torpool.Profile, error) {
	profiles, err := client.profileRequest(
		ctx, http.MethodPost, "/v1/profiles/explore", nil, true,
	)
	if err == nil {
		client.cacheProfiles(profiles)
	}
	return profiles, err
}

func (client *Client) cacheProfiles(profiles []torpool.Profile) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.profiles = append(client.profiles[:0], profiles...)
}

type ambiguousProfileMutationError struct{ cause error }

func (err ambiguousProfileMutationError) Error() string       { return err.cause.Error() }
func (err ambiguousProfileMutationError) Unwrap() error       { return err.cause }
func (ambiguousProfileMutationError) AmbiguousMutation() bool { return true }

type unsentProfileMutationError struct{ cause error }

func (err unsentProfileMutationError) Error() string               { return err.cause.Error() }
func (err unsentProfileMutationError) Unwrap() error               { return err.cause }
func (unsentProfileMutationError) MutationDefinitelyNotSent() bool { return true }

func (client *Client) profileRequest(
	ctx context.Context,
	method, path string,
	body []byte,
	mutation bool,
) ([]torpool.Profile, error) {
	if err := ctx.Err(); err != nil {
		if mutation {
			return nil, unsentProfileMutationError{cause: err}
		}
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		if mutation {
			return nil, ambiguousProfileMutationError{cause: err}
		}
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		var payload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(message, &payload) == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf(
				"agent profiles returned HTTP %d: %s",
				response.StatusCode,
				strings.TrimSpace(payload.Error),
			)
		}
		return nil, fmt.Errorf("agent profiles returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Profiles []torpool.Profile `json:"profiles"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&payload); err != nil {
		if mutation {
			return nil, ambiguousProfileMutationError{cause: err}
		}
		return nil, err
	}
	return payload.Profiles, nil
}

func (client *Client) GeoStatus(ctx context.Context) (GeoAssetStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/geo", nil)
	if err != nil {
		return GeoAssetStatus{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return GeoAssetStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return GeoAssetStatus{}, fmt.Errorf("agent geo returned HTTP %d", response.StatusCode)
	}
	var status GeoAssetStatus
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&status); err != nil {
		return GeoAssetStatus{}, err
	}
	return status, nil
}

type GeoUpdateRequest struct {
	Force          bool           `json:"force"`
	Enabled        *bool          `json:"enabled,omitempty"`
	AutoUpdate     *bool          `json:"auto_update,omitempty"`
	GeoIPURL       *string        `json:"geoip_url,omitempty"`
	GeoSiteURL     *string        `json:"geosite_url,omitempty"`
	UpdateInterval *time.Duration `json:"-"`
}

func (client *Client) UpdateGeo(ctx context.Context, req GeoUpdateRequest) (GeoAssetStatus, error) {
	payload := map[string]any{
		"force": req.Force,
	}
	if req.Enabled != nil {
		payload["enabled"] = *req.Enabled
	}
	if req.AutoUpdate != nil {
		payload["auto_update"] = *req.AutoUpdate
	}
	if req.GeoIPURL != nil && *req.GeoIPURL != "" {
		payload["geoip_url"] = *req.GeoIPURL
	}
	if req.GeoSiteURL != nil && *req.GeoSiteURL != "" {
		payload["geosite_url"] = *req.GeoSiteURL
	}
	if req.UpdateInterval != nil && *req.UpdateInterval > 0 {
		payload["update_interval"] = req.UpdateInterval.String()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return GeoAssetStatus{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/geo/update", bytes.NewReader(body))
	if err != nil {
		return GeoAssetStatus{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return GeoAssetStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return GeoAssetStatus{}, fmt.Errorf("agent geo update returned HTTP %d: %s", response.StatusCode, string(message))
	}
	var status GeoAssetStatus
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&status); err != nil {
		return GeoAssetStatus{}, err
	}
	return status, nil
}
