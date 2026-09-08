package refresh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

type Refresher struct {
	store           *store.Store
	client          *http.Client
	maxBody         int64
	inventoryLimit  int
	retirementGrace time.Duration
	hwid            string
	userAgent       string
}

const defaultUserAgent = "linuxmint_22.3"

// WithUserAgent configures a custom User-Agent for subscription requests.
func (refresher *Refresher) WithUserAgent(userAgent string) *Refresher {
	trimmed := strings.TrimSpace(userAgent)
	if trimmed != "" {
		refresher.userAgent = trimmed
	}
	return refresher
}

// UserAgent returns the configured or default User-Agent for subscription requests.
func (refresher *Refresher) UserAgent() string {
	if refresher.userAgent != "" {
		return refresher.userAgent
	}
	return defaultUserAgent
}

func New(database *store.Store, client *http.Client, maxBody int64, inventoryLimit ...int) *Refresher {
	if client == nil {
		client = http.DefaultClient
	}
	if maxBody <= 0 {
		maxBody = 4 * 1024 * 1024
	}
	maxCandidates := 200
	if len(inventoryLimit) > 0 && inventoryLimit[0] > 0 {
		maxCandidates = inventoryLimit[0]
	} else {
		maxCandidates = 10_000
	}
	return &Refresher{
		store: database, client: client, maxBody: maxBody,
		inventoryLimit: maxCandidates, retirementGrace: 15 * time.Minute,
	}
}

func (refresher *Refresher) WithRetirementGrace(grace time.Duration) *Refresher {
	if grace > 0 {
		refresher.retirementGrace = grace
	}
	return refresher
}

func (refresher *Refresher) Source(ctx context.Context, sourceID string) error {
	payload, err := refresher.store.SourcePayload(ctx, sourceID)
	if err != nil {
		return err
	}
	listed, err := refresher.store.ListSources(ctx)
	if err != nil {
		return err
	}
	var kind sources.Kind
	for _, item := range listed {
		if item.ID == sourceID {
			kind = item.Kind
			break
		}
	}
	if kind == "" {
		return errors.New("source not found")
	}

	input, err := refresher.resolve(ctx, kind, payload)
	if err == nil {
		parsed := sources.PreviewInput(input)
		candidates := make([]store.CandidateInput, 0, parsed.ValidCount)
		for _, item := range parsed.Items {
			if item.Error != "" || item.Duplicate || (item.Kind != sources.KindVLESS && item.Kind != sources.KindTorBridge) {
				continue
			}
			if isDummyUnsupportedCandidate(item) {
				continue
			}
			candidate := store.CandidateInput{
				Kind: item.Kind, Label: item.Display, Fingerprint: item.Fingerprint, Payload: item.Payload,
			}
			if item.Kind == sources.KindVLESS {
				identity, identityErr := xrayconfig.VLESSIdentity(item.Payload)
				if identityErr != nil {
					if kind == sources.KindRemoteAuto {
						continue
					}
					err = identityErr
					break
				}
				candidate.RouteKey = identity.RouteKey
				candidate.FailureDomain = identity.FailureDomain
			}
			candidates = append(candidates, candidate)
		}
		if err == nil {
			if len(candidates) == 0 {
				err = errors.New("subscription contains no valid VLESS or Tor candidates")
			} else {
				err = refresher.validateInventoryLimit(ctx, sourceID, candidates)
				if err == nil {
					err = refresher.store.ReplaceCandidates(
						ctx, sourceID, candidates, refresher.retirementGrace,
					)
				}
			}
		}
	}
	if err != nil {
		safeError := safeRefreshError(err)
		_ = refresher.store.RecordRefreshFailure(ctx, sourceID, safeError.Error())
		return safeError
	}
	return nil
}

func safeRefreshError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "x-hwid-not-supported"):
		return errors.New("subscription device/application not supported (x-hwid-not-supported)")
	case strings.Contains(message, "x-hwid-max-devices-reached"):
		return errors.New("subscription device limit reached (x-hwid-max-devices-reached)")
	case strings.Contains(message, "inventory limit"):
		return err
	case strings.Contains(message, "HTTP "):
		index := strings.LastIndex(message, "HTTP ")
		return errors.New(message[index:])
	case strings.Contains(message, "subscription exceeds size limit"):
		return errors.New("subscription exceeds size limit")
	case strings.Contains(message, "no valid VLESS or Tor candidates"):
		return errors.New("subscription contains no valid VLESS or Tor candidates")
	case strings.Contains(message, "fetch subscription"):
		return errors.New("fetch subscription failed")
	case strings.Contains(message, "read subscription"):
		return errors.New("read subscription failed")
	default:
		return errors.New("source refresh failed")
	}
}

func (refresher *Refresher) validateInventoryLimit(ctx context.Context, sourceID string, incoming []store.CandidateInput) error {
	existing, err := refresher.store.ListCandidates(ctx, "")
	if err != nil {
		return err
	}
	fingerprints := make(map[string]bool, len(existing)+len(incoming))
	for _, candidate := range existing {
		if candidate.SourceID != sourceID {
			fingerprints[candidate.Fingerprint] = true
		}
	}
	for _, candidate := range incoming {
		fingerprints[candidate.Fingerprint] = true
	}
	if len(fingerprints) > refresher.inventoryLimit {
		return fmt.Errorf("inventory limit exceeded: %d candidates (limit %d)", len(fingerprints), refresher.inventoryLimit)
	}
	return nil
}

func (refresher *Refresher) resolve(ctx context.Context, kind sources.Kind, payload string) (string, error) {
	switch kind {
	case sources.KindVLESS, sources.KindTorBridge:
		return payload, nil
	case sources.KindVLESSSubscription, sources.KindTorSubscription, sources.KindRemoteAuto:
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, payload, nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("User-Agent", refresher.UserAgent())
		if hwid := refresher.HWID(); hwid != "" {
			request.Header.Set("x-hwid", hwid)
			request.Header.Set("x-device-os", runtimeOS())
		}
		response, err := refresher.client.Do(request)
		if err != nil {
			return "", fmt.Errorf("fetch subscription: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return "", fmt.Errorf("fetch subscription: HTTP %d", response.StatusCode)
		}
		if strings.EqualFold(response.Header.Get("x-hwid-not-supported"), "true") {
			return "", errors.New("subscription server reported device/application not supported (x-hwid-not-supported)")
		}
		if strings.EqualFold(response.Header.Get("x-hwid-max-devices-reached"), "true") {
			return "", errors.New("subscription device limit reached (x-hwid-max-devices-reached)")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, refresher.maxBody+1))
		if err != nil {
			return "", fmt.Errorf("read subscription: %w", err)
		}
		if int64(len(body)) > refresher.maxBody {
			return "", errors.New("subscription exceeds size limit")
		}
		return decodeSubscription(string(body)), nil
	default:
		return "", fmt.Errorf("unsupported source kind %q", kind)
	}
}

func decodeSubscription(input string) string {
	normalizedInput := normalizeSubscriptionPayload(input)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(normalizedInput)
		if err == nil && len(decoded) > 0 {
			normalizedDecoded := normalizeSubscriptionPayload(string(decoded))
			if normalizedDecoded == "" {
				continue
			}
			if clashPayload := decodeClashSubscription(normalizedDecoded); clashPayload != "" {
				return clashPayload
			}
			return normalizedDecoded
		}
	}
	if clashPayload := decodeClashSubscription(normalizedInput); clashPayload != "" {
		return clashPayload
	}
	return normalizedInput
}

func isDummyUnsupportedCandidate(item sources.PreviewItem) bool {
	lower := strings.ToLower(item.Display)
	return strings.Contains(lower, "приложение не поддерживается") ||
		strings.Contains(lower, "устройство не поддерживается") ||
		strings.Contains(lower, "application is not supported") ||
		strings.Contains(lower, "client is not supported") ||
		strings.Contains(lower, "device is not supported")
}

func decodeClashSubscription(input string) string {
	var config struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		return ""
	}
	if len(config.Proxies) == 0 {
		return ""
	}

	var lines []string
	for _, proxy := range config.Proxies {
		line := decodeClashVLESSProxy(proxy)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

func decodeClashVLESSProxy(proxy map[string]any) string {
	if strings.ToLower(strings.TrimSpace(asString(proxy["type"]))) != "vless" {
		return ""
	}

	transport := mapClashTransport(asString(proxy["network"]))
	if transport == "" {
		return ""
	}

	server := strings.TrimSpace(asString(proxy["server"]))
	port := asInt(proxy["port"])
	if server == "" || port < 1 || port > 65535 {
		return ""
	}

	userID := asString(proxy["uuid"])
	if userID == "" {
		userID = asString(proxy["id"])
	}
	if userID == "" {
		return ""
	}

	query := url.Values{}
	query.Set("type", transport)

	security, hasUnsupportedSecurity := normalizeClashSecurity(proxy)
	if hasUnsupportedSecurity {
		return ""
	}
	query.Set("security", security)

	if security == "reality" {
		if realityOpts, hasReality := asMap(proxy["reality-opts"]); hasReality {
			pbk := asString(realityOpts["public-key"])
			if pbk == "" {
				return ""
			}
			query.Set("pbk", pbk)
			if sid := asString(realityOpts["short-id"]); sid != "" {
				query.Set("sid", sid)
			}
		}
	}

	if sni := firstString(asString(proxy["serverName"]), asString(proxy["servername"]), asString(proxy["sni"])); sni != "" {
		query.Set("sni", sni)
	}
	if flow := asString(proxy["flow"]); flow != "" {
		query.Set("flow", flow)
	}

	if transport == "ws" || transport == "grpc" || transport == "xhttp" {
		if host := firstString(asString(proxy["host"]), asNestedString(proxy, "ws-opts", "host"), asNestedString(proxy, "xhttp-opts", "host")); host != "" {
			query.Set("host", host)
		}
		if headers, hasHeaders := asMapFromPath(proxy, "ws-opts", "headers"); hasHeaders {
			if host := firstString(asString(headers["Host"]), asString(headers["host"])); host != "" {
				query.Set("host", host)
			}
		}
		if path := firstString(asString(proxy["path"]), asNestedString(proxy, "ws-opts", "path")); path != "" {
			query.Set("path", path)
		}
	}

	fragment := strings.TrimSpace(asString(proxy["name"]))
	if fragment == "" {
		fragment = server
	}
	payload := &url.URL{
		Scheme:   "vless",
		User:     url.User(userID),
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: query.Encode(),
		Fragment: fragment,
	}
	return payload.String()
}

func mapClashTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "tcp":
		return "tcp"
	case "raw":
		return "raw"
	case "ws":
		return "ws"
	case "grpc":
		return "grpc"
	case "xhttp":
		return "xhttp"
	default:
		return ""
	}
}

func normalizeClashSecurity(proxy map[string]any) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(asString(proxy["security"]))) {
	case "":
		if asBool(proxy["tls"]) {
			if hasReality := hasClashRealitySecurity(proxy); hasReality {
				return "reality", false
			}
			return "tls", false
		}
		return "none", false
	case "none":
		return "none", false
	case "tls":
		return "tls", false
	case "reality":
		if hasReality := hasClashRealitySecurity(proxy); hasReality {
			return "reality", false
		}
		return "", true
	default:
		return "", true
	}
}

func hasClashRealitySecurity(proxy map[string]any) bool {
	realityOpts, hasReality := asMap(proxy["reality-opts"])
	if !hasReality {
		return false
	}
	return asString(realityOpts["public-key"]) != ""
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func asString(value any) string {
	switch decoded := value.(type) {
	case string:
		return strings.TrimSpace(decoded)
	case []byte:
		return strings.TrimSpace(string(decoded))
	default:
		return ""
	}
}

func asInt(value any) int {
	switch decoded := value.(type) {
	case int:
		return decoded
	case int64:
		return int(decoded)
	case uint64:
		return int(decoded)
	case float64:
		return int(decoded)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(decoded))
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

func asBool(value any) bool {
	switch decoded := value.(type) {
	case bool:
		return decoded
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(decoded))
		return parsed
	case int:
		return decoded != 0
	case uint64:
		return decoded != 0
	case float64:
		return decoded != 0
	default:
		return false
	}
}

func asMap(value any) (map[string]any, bool) {
	switch decoded := value.(type) {
	case map[string]any:
		return decoded, true
	case map[any]any:
		converted := make(map[string]any, len(decoded))
		for rawKey, rawValue := range decoded {
			key := asString(rawKey)
			if key == "" {
				continue
			}
			converted[key] = rawValue
		}
		return converted, len(converted) > 0
	default:
		return nil, false
	}
}

func asMapFromPath(current any, path ...string) (map[string]any, bool) {
	next, ok := asMap(current)
	if !ok || len(path) == 0 {
		return nil, false
	}
	for _, key := range path {
		raw, exists := next[key]
		if !exists {
			return nil, false
		}
		nested, nestedOK := asMap(raw)
		if !nestedOK {
			return nil, false
		}
		next = nested
	}
	return next, len(next) > 0
}

func asNestedString(current any, path ...string) string {
	next, ok := asMap(current)
	if !ok || len(path) == 0 {
		return ""
	}
	for index, key := range path {
		raw, exists := next[key]
		if !exists {
			return ""
		}
		if index == len(path)-1 {
			return asString(raw)
		}
		nested, nestedOK := asMap(raw)
		if !nestedOK {
			return ""
		}
		next = nested
	}
	return ""
}

func normalizeSubscriptionPayload(input string) string {
	normalized := strings.ToValidUTF8(strings.TrimSpace(input), "")
	normalized = strings.Map(func(r rune) rune {
		if r == '\ufeff' || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return -1
		}
		return r
	}, normalized)
	normalized = strings.TrimSpace(normalized)

	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "base64,") {
		return strings.TrimSpace(normalized[len("base64,"):])
	}
	if strings.HasPrefix(lower, "base64:") {
		return strings.TrimSpace(normalized[len("base64:"):])
	}
	return normalized
}
