package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Protocol string

const (
	ProtocolVLESS Protocol = "vless"
	ProtocolTor   Protocol = "tor"
	ProtocolDNS   Protocol = "dns"
)

var ErrRuntimeRecovering = errors.New("dataplane runtime is recovering")

type Outbound struct {
	ID       string          `json:"id"`
	Protocol Protocol        `json:"protocol"`
	Config   json.RawMessage `json:"config,omitempty"`
}

type ClientRoute struct {
	ClientID           string `json:"client_id"`
	SourceCIDR         string `json:"source_cidr,omitempty"`
	TCPOutbound        string `json:"tcp_outbound"`
	UDPOutbound        string `json:"udp_outbound"`
	DNSOutbound        string `json:"dns_outbound,omitempty"`
	TCPReserveOutbound string `json:"tcp_reserve_outbound,omitempty"`
	UDPReserveOutbound string `json:"udp_reserve_outbound,omitempty"`
	BlockTCP           bool   `json:"block_tcp,omitempty"`
	BlockUDP           bool   `json:"block_udp,omitempty"`
}

type DesiredPlan struct {
	Generation     int64         `json:"generation"`
	Outbounds      []Outbound    `json:"outbounds"`
	Clients        []ClientRoute `json:"clients"`
	DirectSuffixes []string      `json:"direct_suffixes"`
	DirectDomains  []string      `json:"direct_domains,omitempty"`
	FailClosed     bool          `json:"fail_closed"`
}

type AppliedPlan struct {
	DesiredPlan
	Digest string `json:"digest"`
}

type Adapter interface {
	AddOutbound(context.Context, Outbound) error
	RouteClient(context.Context, ClientRoute) error
	DrainOutbound(context.Context, string) error
	RemoveOutbound(context.Context, string) error
}

type RouteBatcher interface {
	ReplaceRoutes(context.Context, []ClientRoute) error
}

type StagedRouteBatcher interface {
	ReplaceRoutesStaged(context.Context, []ClientRoute, []ClientRoute, []ClientRoute) error
}

// RecoveryOutboundNormalizer may rewrite runtime-only outbound details that
// are owned by current process configuration. Persisted desired bytes and
// their digest remain unchanged.
type RecoveryOutboundNormalizer interface {
	NormalizeOutboundForRecovery(context.Context, Outbound) (Outbound, error)
}

type Reconciler struct {
	mu               sync.Mutex
	adapter          Adapter
	statePath        string
	applied          AppliedPlan
	runtimeOutbounds map[string]Outbound
	pendingAdds      map[string]Outbound
	pendingRemoves   map[string]Outbound
	runtimeReady     bool
	recoveryRequired atomic.Bool
}

func NewReconciler(adapter Adapter, statePath string) (*Reconciler, error) {
	if adapter == nil {
		return nil, errors.New("dataplane adapter is required")
	}
	reconciler := &Reconciler{
		adapter:          adapter,
		statePath:        statePath,
		runtimeOutbounds: make(map[string]Outbound),
		pendingAdds:      make(map[string]Outbound),
		pendingRemoves:   make(map[string]Outbound),
	}
	data, err := os.ReadFile(statePath)
	if err == nil {
		if err := json.Unmarshal(data, &reconciler.applied); err != nil {
			return nil, fmt.Errorf("decode applied plan: %w", err)
		}
		if reconciler.applied.Generation > 0 {
			reconciler.recoveryRequired.Store(true)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read applied plan: %w", err)
	}
	return reconciler, nil
}

func (reconciler *Reconciler) Apply(ctx context.Context, desired DesiredPlan) error {
	recoveringAtAdmission := reconciler.recoveryRequired.Load()
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	if recoveringAtAdmission || reconciler.recoveryRequired.Load() {
		return ErrRuntimeRecovering
	}
	return reconciler.applyLocked(ctx, desired, false)
}

// InvalidateRuntime marks all dynamic Xray state as lost. It is serialized with
// Apply and Rehydrate so a plan for the same generation cannot falsely no-op
// after a supervised Xray process restart.
func (reconciler *Reconciler) InvalidateRuntime() {
	reconciler.recoveryRequired.Store(true)
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	reconciler.runtimeOutbounds = make(map[string]Outbound)
	reconciler.pendingAdds = make(map[string]Outbound)
	reconciler.pendingRemoves = make(map[string]Outbound)
	reconciler.runtimeReady = false
}

func (reconciler *Reconciler) applyLocked(
	ctx context.Context,
	desired DesiredPlan,
	recovering bool,
) error {
	if err := desired.Validate(); err != nil {
		return err
	}
	digest, err := desired.digest()
	if err != nil {
		return err
	}
	if desired.Generation < reconciler.applied.Generation {
		return fmt.Errorf("stale plan generation %d", desired.Generation)
	}
	if desired.Generation == reconciler.applied.Generation {
		if reconciler.applied.Digest == digest && reconciler.runtimeReady {
			return nil
		}
		if reconciler.applied.Digest != digest {
			return errors.New("plan generation was reused with different contents")
		}
	}

	runtimeDesired := desired.Outbounds
	if recovering {
		runtimeDesired, err = reconciler.normalizeRecoveryOutbounds(ctx, desired.Outbounds)
		if err != nil {
			return err
		}
		runtimePlan := desired
		runtimePlan.Outbounds = runtimeDesired
		if err := runtimePlan.Validate(); err != nil {
			return fmt.Errorf("validate normalized recovery plan: %w", err)
		}
	}
	next := outboundsByID(runtimeDesired)
	if err := validateImmutableOutboundIDs(reconciler.runtimeOutbounds, next); err != nil {
		return err
	}
	runtimeWasReady := reconciler.runtimeReady
	// Any call below can succeed in Xray while its response is canceled or
	// lost. Until the complete graph is reasserted and persisted, the runtime
	// must be treated as an unknown partial state rather than compared with the
	// last acknowledged route snapshot.
	reconciler.runtimeReady = false
	if err := reconciler.normalizePendingOutboundOperations(ctx, next); err != nil {
		return err
	}
	current := cloneOutbounds(reconciler.runtimeOutbounds)
	for _, outbound := range sortedOutboundsForAdd(runtimeDesired) {
		previous, exists := current[outbound.ID]
		if !exists || !equalOutbound(previous, outbound) {
			if err := reconciler.adapter.AddOutbound(ctx, outbound); err != nil {
				reconciler.pendingAdds[outbound.ID] = outbound
				return fmt.Errorf("add outbound %s: %w", outbound.ID, err)
			}
			delete(reconciler.pendingAdds, outbound.ID)
			reconciler.runtimeOutbounds[outbound.ID] = outbound
		}
	}
	routes := sortedRoutes(desired.Clients)
	if batcher, ok := reconciler.adapter.(StagedRouteBatcher); ok {
		previousRoutes := sortedRoutes(reconciler.applied.Clients)
		if !runtimeWasReady {
			previousRoutes = nil
		}
		affected := affectedRoutes(previousRoutes, routes, current, next)
		if err := batcher.ReplaceRoutesStaged(ctx, previousRoutes, routes, affected); err != nil {
			return fmt.Errorf("replace client routes: %w", err)
		}
	} else if batcher, ok := reconciler.adapter.(RouteBatcher); ok {
		if err := batcher.ReplaceRoutes(ctx, routes); err != nil {
			return fmt.Errorf("replace client routes: %w", err)
		}
	} else {
		for _, route := range routes {
			if err := reconciler.adapter.RouteClient(ctx, route); err != nil {
				return fmt.Errorf("route client %s: %w", route.ClientID, err)
			}
		}
	}
	removed := make([]Outbound, 0)
	for id, old := range current {
		replacement, exists := next[id]
		if !exists || !equalOutbound(old, replacement) {
			removed = append(removed, old)
		}
	}
	sortOutboundsForRemoval(removed)
	for _, outbound := range removed {
		if err := reconciler.adapter.DrainOutbound(ctx, outbound.ID); err != nil {
			return fmt.Errorf("drain outbound %s: %w", outbound.ID, err)
		}
		if err := reconciler.adapter.RemoveOutbound(ctx, outbound.ID); err != nil {
			reconciler.pendingRemoves[outbound.ID] = outbound
			return fmt.Errorf("remove outbound %s: %w", outbound.ID, err)
		}
		delete(reconciler.pendingRemoves, outbound.ID)
		delete(reconciler.runtimeOutbounds, outbound.ID)
	}

	applied := AppliedPlan{DesiredPlan: desired, Digest: digest}
	if err := writeAppliedPlan(reconciler.statePath, applied); err != nil {
		return err
	}
	reconciler.applied = applied
	if !recovering {
		reconciler.runtimeReady = true
	}
	return nil
}

func (reconciler *Reconciler) normalizeRecoveryOutbounds(
	ctx context.Context,
	outbounds []Outbound,
) ([]Outbound, error) {
	normalizer, ok := reconciler.adapter.(RecoveryOutboundNormalizer)
	if !ok {
		return outbounds, nil
	}
	normalized := make([]Outbound, len(outbounds))
	for index, outbound := range outbounds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item, err := normalizer.NormalizeOutboundForRecovery(ctx, outbound)
		if err != nil {
			return nil, fmt.Errorf("normalize recovery outbound %s: %w", outbound.ID, err)
		}
		if item.ID != outbound.ID || item.Protocol != outbound.Protocol {
			return nil, fmt.Errorf("recovery normalizer changed outbound identity %q", outbound.ID)
		}
		normalized[index] = item
	}
	return normalized, nil
}

func (reconciler *Reconciler) normalizePendingOutboundOperations(
	ctx context.Context,
	desired map[string]Outbound,
) error {
	desiredPendingAdds := make([]Outbound, 0, len(reconciler.pendingAdds))
	obsoletePendingAdds := make([]Outbound, 0, len(reconciler.pendingAdds))
	for id, pending := range reconciler.pendingAdds {
		if replacement, exists := desired[id]; exists {
			desiredPendingAdds = append(desiredPendingAdds, replacement)
		} else {
			obsoletePendingAdds = append(obsoletePendingAdds, pending)
		}
	}
	for _, outbound := range sortedOutboundsForAdd(desiredPendingAdds) {
		// A previous Add may have reached Xray even when its response was lost.
		// This tag has never reached the route phase, so removing it before a
		// retry cannot interrupt an admitted client route.
		_ = reconciler.adapter.RemoveOutbound(ctx, outbound.ID)
		if err := reconciler.adapter.AddOutbound(ctx, outbound); err != nil {
			reconciler.pendingAdds[outbound.ID] = outbound
			return fmt.Errorf("normalize pending add %s: %w", outbound.ID, err)
		}
		delete(reconciler.pendingAdds, outbound.ID)
		reconciler.runtimeOutbounds[outbound.ID] = outbound
	}

	sortOutboundsForRemoval(obsoletePendingAdds)
	for _, outbound := range obsoletePendingAdds {
		// Restore-then-remove makes both the pre-effect and post-effect error
		// states converge even for adapters that reject removal of a missing ID.
		_ = reconciler.adapter.AddOutbound(ctx, outbound)
		if err := reconciler.adapter.RemoveOutbound(ctx, outbound.ID); err != nil {
			return fmt.Errorf("discard pending add %s: %w", outbound.ID, err)
		}
		delete(reconciler.pendingAdds, outbound.ID)
		delete(reconciler.runtimeOutbounds, outbound.ID)
	}

	pendingRemoves := make([]Outbound, 0, len(reconciler.pendingRemoves))
	for _, outbound := range reconciler.pendingRemoves {
		pendingRemoves = append(pendingRemoves, outbound)
	}
	sortOutboundsForRemoval(pendingRemoves)
	for _, outbound := range pendingRemoves {
		// Routes were already replaced before Remove was attempted. Restoring
		// this obsolete handler temporarily is therefore unreachable by new
		// client flows and normalizes a lost Remove response.
		_ = reconciler.adapter.AddOutbound(ctx, outbound)
		if err := reconciler.adapter.RemoveOutbound(ctx, outbound.ID); err != nil {
			return fmt.Errorf("normalize pending remove %s: %w", outbound.ID, err)
		}
		delete(reconciler.pendingRemoves, outbound.ID)
		delete(reconciler.runtimeOutbounds, outbound.ID)
	}
	return nil
}

func (reconciler *Reconciler) Rehydrate(ctx context.Context) error {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	if !reconciler.recoveryRequired.Load() {
		reconciler.runtimeOutbounds = make(map[string]Outbound)
		reconciler.pendingAdds = make(map[string]Outbound)
		reconciler.pendingRemoves = make(map[string]Outbound)
		reconciler.runtimeReady = false
		reconciler.recoveryRequired.Store(true)
	}
	if reconciler.applied.Generation == 0 {
		reconciler.runtimeReady = true
		reconciler.recoveryRequired.Store(false)
		return nil
	}
	if err := reconciler.applyLocked(ctx, reconciler.applied.DesiredPlan, true); err != nil {
		return err
	}
	reconciler.runtimeReady = true
	reconciler.recoveryRequired.Store(false)
	return nil
}

func (plan DesiredPlan) Validate() error {
	if plan.Generation <= 0 {
		return errors.New("plan generation must be positive")
	}
	if !plan.FailClosed {
		return errors.New("fail-open plans are forbidden")
	}
	if len(plan.DirectSuffixes) == 0 {
		return errors.New("direct suffixes must contain at least one suffix")
	}
	for _, suffix := range plan.DirectSuffixes {
		s := strings.TrimSpace(suffix)
		if s == "" || !strings.HasPrefix(s, ".") || len(s) < 2 {
			return fmt.Errorf("direct suffix %q must start with '.' and be at least 2 characters", suffix)
		}
	}
	for _, domain := range plan.DirectDomains {
		d := strings.TrimSpace(domain)
		if d == "" {
			return errors.New("direct domain must not be empty")
		}
		if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return fmt.Errorf("direct domain %q must be a clean domain name without scheme, port, or path", domain)
		}
	}
	outbounds := make(map[string]Outbound, len(plan.Outbounds))
	dnsProxies := make(map[string]string)
	for _, outbound := range plan.Outbounds {
		if outbound.ID == "" || (outbound.Protocol != ProtocolVLESS &&
			outbound.Protocol != ProtocolTor && outbound.Protocol != ProtocolDNS) {
			return fmt.Errorf("invalid outbound %q", outbound.ID)
		}
		if _, exists := outbounds[outbound.ID]; exists {
			return fmt.Errorf("duplicate outbound %q", outbound.ID)
		}
		outbounds[outbound.ID] = outbound
	}
	for _, outbound := range plan.Outbounds {
		if outbound.Protocol != ProtocolDNS {
			continue
		}
		proxy, err := validateDNSOutboundConfig(outbound.Config)
		if err != nil {
			return fmt.Errorf("invalid DNS outbound %q: %w", outbound.ID, err)
		}
		if proxy == outbound.ID {
			return fmt.Errorf("invalid DNS outbound %q: self reference", outbound.ID)
		}
		target, exists := outbounds[proxy]
		if !exists {
			return fmt.Errorf("invalid DNS outbound %q: unknown proxy", outbound.ID)
		}
		if target.Protocol != ProtocolVLESS && target.Protocol != ProtocolTor {
			return fmt.Errorf("invalid DNS outbound %q: proxy is not TCP capable", outbound.ID)
		}
		dnsProxies[outbound.ID] = proxy
	}
	clients := make(map[string]struct{}, len(plan.Clients))
	for _, route := range plan.Clients {
		if route.ClientID == "" {
			return errors.New("client ID must not be empty")
		}
		if _, exists := clients[route.ClientID]; exists {
			return fmt.Errorf("duplicate client %q", route.ClientID)
		}
		clients[route.ClientID] = struct{}{}
		if (route.TCPOutbound == "") == !route.BlockTCP {
			return fmt.Errorf("client %s must select or explicitly block TCP", route.ClientID)
		}
		if (route.UDPOutbound == "") == !route.BlockUDP {
			return fmt.Errorf("client %s must select or explicitly block UDP", route.ClientID)
		}
		if !route.BlockTCP {
			tcp, exists := outbounds[route.TCPOutbound]
			if !exists {
				return fmt.Errorf("client %s references unknown TCP outbound", route.ClientID)
			}
			if tcp.Protocol != ProtocolVLESS && tcp.Protocol != ProtocolTor {
				return fmt.Errorf("client %s has invalid TCP outbound", route.ClientID)
			}
		}
		if !route.BlockUDP {
			udp, exists := outbounds[route.UDPOutbound]
			if !exists {
				return fmt.Errorf("client %s references unknown UDP outbound", route.ClientID)
			}
			if udp.Protocol != ProtocolVLESS {
				return fmt.Errorf("client %s UDP outbound must be VLESS", route.ClientID)
			}
		}
		if route.DNSOutbound != "" {
			dns, exists := outbounds[route.DNSOutbound]
			if !exists {
				return fmt.Errorf("client %s references unknown DNS outbound", route.ClientID)
			}
			if dns.Protocol != ProtocolDNS {
				return fmt.Errorf("client %s has invalid DNS outbound", route.ClientID)
			}
			if dnsProxies[route.DNSOutbound] != route.TCPOutbound {
				return fmt.Errorf("client %s DNS outbound does not follow its TCP route", route.ClientID)
			}
		}
		if route.TCPReserveOutbound != "" {
			if route.BlockTCP || route.TCPOutbound == "" {
				return fmt.Errorf("client %s has TCP reserve without primary", route.ClientID)
			}
			if route.TCPReserveOutbound == route.TCPOutbound {
				return fmt.Errorf("client %s TCP reserve equals primary", route.ClientID)
			}
			reserve, exists := outbounds[route.TCPReserveOutbound]
			if !exists {
				return fmt.Errorf("client %s references unknown TCP reserve", route.ClientID)
			}
			if reserve.Protocol != ProtocolVLESS && reserve.Protocol != ProtocolTor {
				return fmt.Errorf("client %s has invalid TCP reserve", route.ClientID)
			}
		}
		if route.UDPReserveOutbound != "" {
			if route.BlockUDP || route.UDPOutbound == "" {
				return fmt.Errorf("client %s has UDP reserve without primary", route.ClientID)
			}
			if route.UDPReserveOutbound == route.UDPOutbound {
				return fmt.Errorf("client %s UDP reserve equals primary", route.ClientID)
			}
			reserve, exists := outbounds[route.UDPReserveOutbound]
			if !exists {
				return fmt.Errorf("client %s references unknown UDP reserve", route.ClientID)
			}
			if reserve.Protocol != ProtocolVLESS {
				return fmt.Errorf("client %s UDP reserve must be VLESS", route.ClientID)
			}
		}
	}
	return nil
}

func validateDNSOutboundConfig(encoded json.RawMessage) (string, error) {
	type dnsSettings struct {
		RewriteNetwork string `json:"rewriteNetwork"`
		RewriteAddress string `json:"rewriteAddress"`
		RewritePort    int    `json:"rewritePort"`
	}
	type proxySettings struct {
		Tag string `json:"tag"`
	}
	type socketSettings struct {
		DialerProxy string `json:"dialerProxy"`
	}
	type streamSettings struct {
		Sockopt *socketSettings `json:"sockopt"`
	}
	type dnsConfig struct {
		Protocol       string          `json:"protocol"`
		Settings       *dnsSettings    `json:"settings"`
		StreamSettings *streamSettings `json:"streamSettings"`
		ProxySettings  *proxySettings  `json:"proxySettings"`
	}
	if len(bytes.TrimSpace(encoded)) == 0 {
		return "", errors.New("config is required")
	}
	var config *dnsConfig
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || config == nil {
		return "", errors.New("config is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("config has trailing data")
	}
	if config.Protocol != string(ProtocolDNS) {
		return "", errors.New("protocol must be dns")
	}
	if config.Settings == nil || config.Settings.RewriteNetwork != "tcp" ||
		config.Settings.RewritePort != 53 {
		return "", errors.New("TCP rewrite settings are required")
	}
	if err := ValidatePublicDNSResolver(config.Settings.RewriteAddress); err != nil {
		return "", errors.New("rewrite address must be a canonical public IPv4 literal")
	}
	dialerProxy := ""
	if config.StreamSettings != nil && config.StreamSettings.Sockopt != nil {
		dialerProxy = config.StreamSettings.Sockopt.DialerProxy
	}
	if config.ProxySettings != nil {
		if dialerProxy != "" {
			return "", errors.New("DNS outbound has both dialerProxy and legacy proxySettings")
		}
		dialerProxy = config.ProxySettings.Tag
	}
	if dialerProxy == "" {
		return "", errors.New("DNS outbound dialerProxy is required")
	}
	return dialerProxy, nil
}

var nonPublicDNSPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ValidatePublicDNSResolver accepts only canonical IPv4 literals that are not
// reserved for private, documentation, benchmarking, multicast, or other
// special-purpose use.
func ValidatePublicDNSResolver(value string) error {
	resolver, err := netip.ParseAddr(value)
	if err != nil || !resolver.Is4() || resolver.Is4In6() ||
		resolver.String() != value || !resolver.IsGlobalUnicast() ||
		resolver.IsPrivate() || resolver.IsLoopback() || resolver.IsUnspecified() ||
		resolver.IsLinkLocalUnicast() || resolver.IsMulticast() {
		return errors.New("address must be a canonical public IPv4 literal")
	}
	for _, prefix := range nonPublicDNSPrefixes {
		if prefix.Contains(resolver) {
			return errors.New("address must be a canonical public IPv4 literal")
		}
	}
	return nil
}

// ValidateDNSResolverPool rejects empty, duplicate, or non-public resolver
// pools before they can be rendered into runtime routing state.
func ValidateDNSResolverPool(resolvers []string) error {
	if len(resolvers) == 0 {
		return errors.New("at least one DNS resolver is required")
	}
	seen := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		if err := ValidatePublicDNSResolver(resolver); err != nil {
			return fmt.Errorf("DNS resolver %q: %w", resolver, err)
		}
		if _, exists := seen[resolver]; exists {
			return fmt.Errorf("duplicate DNS resolver %q", resolver)
		}
		seen[resolver] = struct{}{}
	}
	return nil
}

// SelectDNSResolver deterministically spreads candidates across independent
// upstreams. A route migration therefore also changes the upstream for most
// candidates without introducing per-cycle randomness or connection churn.
func SelectDNSResolver(candidateID string, resolvers []string) (string, error) {
	if candidateID == "" {
		return "", errors.New("candidate ID is required")
	}
	if err := ValidateDNSResolverPool(resolvers); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(candidateID))
	index := binary.BigEndian.Uint64(digest[:8]) % uint64(len(resolvers))
	return resolvers[index], nil
}

// BuildDNSOutbound creates a client-scoped DNS handler pinned to a specific
// TCP-capable target. The full digest keeps active and preloaded reserve
// handlers distinct even when their human-readable candidate IDs are similar.
func BuildDNSOutbound(clientID string, target Outbound, resolver string) (Outbound, error) {
	if clientID == "" {
		return Outbound{}, errors.New("client ID is required")
	}
	if target.ID == "" {
		return Outbound{}, errors.New("target outbound ID is required")
	}
	if target.Protocol != ProtocolVLESS && target.Protocol != ProtocolTor {
		return Outbound{}, errors.New("DNS target must be TCP capable")
	}
	if err := ValidatePublicDNSResolver(resolver); err != nil {
		return Outbound{}, errors.New("DNS resolver must be a canonical public IPv4 literal")
	}
	canonicalConfig, err := canonicalOutboundJSON(target.Config)
	if err != nil {
		return Outbound{}, fmt.Errorf("canonicalize DNS target %q: %w", target.ID, err)
	}

	targetHash := sha256.New()
	writeDigestField(targetHash, []byte(target.ID))
	writeDigestField(targetHash, []byte(target.Protocol))
	writeDigestField(targetHash, canonicalConfig)
	targetDigest := targetHash.Sum(nil)

	tagHash := sha256.New()
	writeDigestField(tagHash, []byte("streamSettings.sockopt.dialerProxy/v1"))
	writeDigestField(tagHash, []byte(clientID))
	writeDigestField(tagHash, targetDigest)
	writeDigestField(tagHash, []byte(resolver))
	tag := "hydrat-dns-" + hex.EncodeToString(tagHash.Sum(nil))

	type dnsSettings struct {
		RewriteNetwork string `json:"rewriteNetwork"`
		RewriteAddress string `json:"rewriteAddress"`
		RewritePort    int    `json:"rewritePort"`
	}
	type socketSettings struct {
		DialerProxy string `json:"dialerProxy"`
	}
	type streamSettings struct {
		Sockopt socketSettings `json:"sockopt"`
	}
	type dnsConfig struct {
		Protocol       string         `json:"protocol"`
		Settings       dnsSettings    `json:"settings"`
		StreamSettings streamSettings `json:"streamSettings"`
	}
	config, err := json.Marshal(dnsConfig{
		Protocol: string(ProtocolDNS),
		Settings: dnsSettings{
			RewriteNetwork: "tcp",
			RewriteAddress: resolver,
			RewritePort:    53,
		},
		StreamSettings: streamSettings{Sockopt: socketSettings{DialerProxy: target.ID}},
	})
	if err != nil {
		return Outbound{}, fmt.Errorf("encode DNS outbound: %w", err)
	}
	return Outbound{ID: tag, Protocol: ProtocolDNS, Config: config}, nil
}

func writeDigestField(destination io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}

func (plan DesiredPlan) SemanticDigest() (string, error) {
	normalized := plan
	normalized.Generation = 0
	normalized.Outbounds = make([]Outbound, len(plan.Outbounds))
	normalized.Clients = append([]ClientRoute(nil), plan.Clients...)
	normalized.DirectSuffixes = append([]string(nil), plan.DirectSuffixes...)
	normalized.DirectDomains = append([]string(nil), plan.DirectDomains...)
	for index, outbound := range plan.Outbounds {
		normalized.Outbounds[index] = outbound
		canonical, err := canonicalOutboundJSON(outbound.Config)
		if err != nil {
			return "", fmt.Errorf("canonicalize outbound %q: %w", outbound.ID, err)
		}
		normalized.Outbounds[index].Config = canonical
	}
	sort.Slice(normalized.Outbounds, func(leftIndex, rightIndex int) bool {
		left, right := normalized.Outbounds[leftIndex], normalized.Outbounds[rightIndex]
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		return bytes.Compare(left.Config, right.Config) < 0
	})
	sort.Slice(normalized.Clients, func(leftIndex, rightIndex int) bool {
		left, right := normalized.Clients[leftIndex], normalized.Clients[rightIndex]
		switch {
		case left.ClientID != right.ClientID:
			return left.ClientID < right.ClientID
		case left.SourceCIDR != right.SourceCIDR:
			return left.SourceCIDR < right.SourceCIDR
		case left.TCPOutbound != right.TCPOutbound:
			return left.TCPOutbound < right.TCPOutbound
		case left.UDPOutbound != right.UDPOutbound:
			return left.UDPOutbound < right.UDPOutbound
		case left.DNSOutbound != right.DNSOutbound:
			return left.DNSOutbound < right.DNSOutbound
		case left.TCPReserveOutbound != right.TCPReserveOutbound:
			return left.TCPReserveOutbound < right.TCPReserveOutbound
		case left.UDPReserveOutbound != right.UDPReserveOutbound:
			return left.UDPReserveOutbound < right.UDPReserveOutbound
		case left.BlockTCP != right.BlockTCP:
			return !left.BlockTCP
		default:
			return !left.BlockUDP && right.BlockUDP
		}
	})
	sort.Strings(normalized.DirectSuffixes)
	sort.Strings(normalized.DirectDomains)
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalOutboundJSON(encoded json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(encoded)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid trailing JSON")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("invalid JSON value")
	}
	return canonical, nil
}

func (plan DesiredPlan) digest() (string, error) {
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func writeAppliedPlan(path string, plan AppliedPlan) error {
	return writeAppliedPlanWithSync(path, plan, syncDirectory)
}

func writeAppliedPlanWithSync(
	path string,
	plan AppliedPlan,
	syncParent func(string) error,
) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".applied-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	if err := encoder.Encode(plan); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func outboundsByID(items []Outbound) map[string]Outbound {
	result := make(map[string]Outbound, len(items))
	for _, item := range items {
		result[item.ID] = item
	}
	return result
}

func cloneOutbounds(items map[string]Outbound) map[string]Outbound {
	result := make(map[string]Outbound, len(items))
	for id, item := range items {
		result[id] = item
	}
	return result
}

func validateImmutableOutboundIDs(current, desired map[string]Outbound) error {
	for id, currentOutbound := range current {
		desiredOutbound, exists := desired[id]
		if !exists {
			continue
		}
		equal, err := semanticallyEqualOutbound(currentOutbound, desiredOutbound)
		if err != nil {
			return fmt.Errorf("validate immutable outbound ID %q: %w", id, err)
		}
		if !equal {
			return fmt.Errorf("outbound ID %q is immutable and cannot change protocol or config", id)
		}
	}
	return nil
}

func semanticallyEqualOutbound(left, right Outbound) (bool, error) {
	if left.ID != right.ID || left.Protocol != right.Protocol {
		return false, nil
	}
	if len(left.Config) == 0 || len(right.Config) == 0 {
		return len(left.Config) == 0 && len(right.Config) == 0, nil
	}
	var leftConfig any
	if err := json.Unmarshal(left.Config, &leftConfig); err != nil {
		return false, errors.New("existing outbound config is invalid JSON")
	}
	var rightConfig any
	if err := json.Unmarshal(right.Config, &rightConfig); err != nil {
		return false, errors.New("desired outbound config is invalid JSON")
	}
	return reflect.DeepEqual(leftConfig, rightConfig), nil
}

func affectedRoutes(
	currentRoutes []ClientRoute,
	desiredRoutes []ClientRoute,
	currentOutbounds map[string]Outbound,
	desiredOutbounds map[string]Outbound,
) []ClientRoute {
	changedOutbounds := make(map[string]struct{})
	for id, current := range currentOutbounds {
		desired, exists := desiredOutbounds[id]
		if !exists || !equalOutbound(current, desired) {
			changedOutbounds[id] = struct{}{}
		}
	}
	for id, desired := range desiredOutbounds {
		current, exists := currentOutbounds[id]
		if !exists || !equalOutbound(current, desired) {
			changedOutbounds[id] = struct{}{}
		}
	}

	currentByClient := make(map[string]ClientRoute, len(currentRoutes))
	desiredByClient := make(map[string]ClientRoute, len(desiredRoutes))
	for _, route := range currentRoutes {
		currentByClient[route.ClientID] = route
	}
	for _, route := range desiredRoutes {
		desiredByClient[route.ClientID] = route
	}
	affectedClients := make(map[string]struct{})
	for id, current := range currentByClient {
		desired, exists := desiredByClient[id]
		if !exists || current != desired || routeUsesChangedOutbound(current, changedOutbounds) {
			affectedClients[id] = struct{}{}
		}
	}
	for id, desired := range desiredByClient {
		current, exists := currentByClient[id]
		if !exists || current != desired || routeUsesChangedOutbound(desired, changedOutbounds) {
			affectedClients[id] = struct{}{}
		}
	}

	result := make([]ClientRoute, 0, len(affectedClients)*2)
	seen := make(map[string]struct{})
	appendAffected := func(route ClientRoute) {
		if _, affected := affectedClients[route.ClientID]; !affected {
			return
		}
		key := route.ClientID + "\x00" + route.SourceCIDR
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	for _, route := range currentRoutes {
		appendAffected(route)
	}
	for _, route := range desiredRoutes {
		appendAffected(route)
	}
	return sortedRoutes(result)
}

func routeUsesChangedOutbound(route ClientRoute, changed map[string]struct{}) bool {
	for _, id := range []string{
		route.TCPOutbound,
		route.UDPOutbound,
		route.DNSOutbound,
		route.TCPReserveOutbound,
		route.UDPReserveOutbound,
	} {
		if _, exists := changed[id]; exists {
			return true
		}
	}
	return false
}

func equalOutbound(left, right Outbound) bool {
	equal, err := semanticallyEqualOutbound(left, right)
	return err == nil && equal
}

func sortedOutboundsForAdd(items []Outbound) []Outbound {
	result := append([]Outbound(nil), items...)
	sort.Slice(result, func(i, j int) bool {
		leftLayer, rightLayer := addLayer(result[i]), addLayer(result[j])
		if leftLayer != rightLayer {
			return leftLayer < rightLayer
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func sortOutboundsForRemoval(items []Outbound) {
	sort.Slice(items, func(i, j int) bool {
		leftLayer, rightLayer := removalLayer(items[i]), removalLayer(items[j])
		if leftLayer != rightLayer {
			return leftLayer < rightLayer
		}
		return items[i].ID < items[j].ID
	})
}

func addLayer(outbound Outbound) int {
	if outbound.Protocol == ProtocolDNS {
		return 1
	}
	return 0
}

func removalLayer(outbound Outbound) int {
	if outbound.Protocol == ProtocolDNS {
		return 0
	}
	return 1
}

func sortedRoutes(items []ClientRoute) []ClientRoute {
	result := append([]ClientRoute(nil), items...)
	sort.Slice(result, func(i, j int) bool { return result[i].ClientID < result[j].ClientID })
	return result
}
