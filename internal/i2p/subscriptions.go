package i2p

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Preview struct {
	Entries   []Entry  `json:"entries"`
	Valid     int      `json:"valid"`
	Errors    []string `json:"errors"`
	Conflicts []Entry  `json:"conflicts"`
}

func (b *Book) Preview(text string) Preview {
	p := Preview{Entries: []Entry{}, Errors: []string{}, Conflicts: []Entry{}}
	if len(text) > 1<<20 {
		p.Errors = append(p.Errors, "file exceeds 1 MiB")
		return p
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := bufio.NewScanner(strings.NewReader(text))
	seen := map[string]bool{}
	line := 0
	for s.Scan() {
		line++
		v := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if v == "" {
			continue
		}
		n, d, ok := strings.Cut(v, "=")
		name, nerr := Name(strings.TrimSpace(n))
		dest, derr := Destination(d)
		if !ok || nerr != nil || derr != nil || seen[name] || strings.HasSuffix(name, ".b32.i2p") && name != dest {
			p.Errors = append(p.Errors, fmt.Sprintf("invalid or duplicate record at line %d", line))
			continue
		}
		seen[name] = true
		e := Entry{Name: name, Destination: dest}
		if !strings.HasSuffix(strings.TrimSpace(d), ".b32.i2p") {
			e.PublicDestination = strings.TrimSpace(d)
		}
		p.Entries = append(p.Entries, e)
		p.Valid++
		if old, ok := b.state.Entries[name]; ok && old.Destination != dest {
			p.Conflicts = append(p.Conflicts, e)
		}
	}
	if s.Err() != nil {
		p.Errors = append(p.Errors, "record too long")
	}
	return p
}
func (b *Book) ApplyImport(p Preview, source string, replace bool) error {
	if len(p.Errors) > 0 {
		return errors.New("import contains invalid records")
	}
	// Revalidate untrusted preview payload, then commit the batch once.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return errors.New("I2P persistence unavailable")
	}
	entries := make(map[string]Entry, len(b.state.Entries))
	for k, v := range b.state.Entries {
		entries[k] = v
	}
	changed := map[string]bool{}
	for _, e := range p.Entries {
		n, err := Name(e.Name)
		if err != nil || n != e.Name {
			return errors.New("invalid import name")
		}
		d, err := Destination(e.Destination)
		if err != nil {
			return err
		}
		if strings.HasSuffix(n, ".b32.i2p") && n != d {
			return errors.New("b32 names cannot be retargeted")
		}
		if e.PublicDestination != "" {
			v, err := Destination(e.PublicDestination)
			if err != nil || v != d {
				return errors.New("invalid public Destination")
			}
		}
		if old, ok := entries[n]; ok && old.Source == "manual" && source != "manual" && old.Destination == d {
			continue
		}
		if old, ok := entries[n]; ok && old.Destination != d {
			if !replace || old.Source == "manual" && source != "manual" {
				return errors.New("destination conflict requires confirmation")
			}
			changed[n] = true
		}
		entries[n] = Entry{Name: n, Destination: d, Source: source, PublicDestination: e.PublicDestination}
	}
	if len(entries) > MaxEntries {
		return errors.New("address book full")
	}
	b.state.Entries = entries
	for ip, m := range b.state.Mappings {
		if changed[m.Name] {
			m.Retired = true
			b.state.Mappings[ip] = m
		}
	}
	return b.save()
}
func (b *Book) Export() string {
	entries := b.List()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	var s strings.Builder
	for _, e := range entries {
		dest := e.Destination
		if e.PublicDestination != "" {
			dest = e.PublicDestination
		}
		fmt.Fprintf(&s, "%s=%s\n", e.Name, dest)
	}
	return s.String()
}

// PublicHTTPSClient prevents private-network fetches and DNS rebinding. Each
// request dials one of the already validated IPs, retaining TLS hostname checks.
func PublicHTTPSClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" {
			return nil, errors.New("HTTPS port 443 required")
		}
		name := strings.TrimSuffix(strings.ToLower(host), ".")
		if strings.HasSuffix(name, ".i2p") || name == "i2p" || strings.HasSuffix(name, ".onion") || name == "onion" {
			return nil, errors.New("private namespace cannot use public DNS")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("subscription DNS unavailable")
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, errors.New("private subscription destination denied")
			}
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || validateSubscriptionURL(r.URL.String()) != nil || strings.HasSuffix(strings.TrimSuffix(strings.ToLower(r.URL.Hostname()), "."), ".i2p") {
			return errors.New("subscription redirect denied")
		}
		return nil
	}}
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48", "192.88.99.0/24"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func FetchSubscription(ctx context.Context, address string, inside *http.Client) (string, error) {
	if err := validateSubscriptionURL(address); err != nil {
		return "", err
	}
	u, err := url.Parse(address)
	if err != nil || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return "", errors.New("invalid subscription URL")
	}
	client := PublicHTTPSClient()
	defer client.CloseIdleConnections()
	if strings.HasSuffix(strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), ".i2p") {
		if _, err := Name(u.Hostname()); err != nil {
			return "", err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", errors.New("invalid I2P subscription scheme")
		}
		if inside == nil {
			return "", errors.New("I2P is sleeping")
		}
		client = inside
	} else if u.Scheme != "https" {
		return "", errors.New("public subscriptions require HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", errors.New("invalid subscription request")
	}
	r, err := client.Do(req)
	if err != nil {
		return "", errors.New("subscription fetch failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("subscription returned HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return "", errors.New("subscription response too large or incomplete")
	}
	return string(b), nil
}
