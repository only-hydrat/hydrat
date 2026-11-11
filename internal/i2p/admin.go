package i2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/only-hydrat/hydrat/internal/socks5"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Subscription struct {
	Refreshing  bool      `json:"refreshing,omitempty"`
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	Error       string    `json:"error,omitempty"`
	Conflicts   []Entry   `json:"conflicts"`
}
type settings struct {
	WarmSeconds   int            `json:"warm_seconds"`
	Subscriptions []Subscription `json:"subscriptions"`
}
type Admin struct {
	manual      chan string
	pending     map[string]bool
	book        *Book
	control     ControlClient
	path, proxy string
	available   bool
	mu          sync.Mutex
	config      settings
	failed      bool
	updating    bool
	mux         *http.ServeMux
}

func NewAdmin(book *Book, control ControlClient, path, proxy string, available bool) (*Admin, error) {
	a := &Admin{manual: make(chan string, 10), pending: map[string]bool{}, book: book, control: control, path: path, proxy: proxy, available: available, mux: http.NewServeMux(), config: settings{WarmSeconds: 7200, Subscriptions: []Subscription{}}}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxSettingsBytes {
			return nil, errors.New("unsafe I2P settings")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal(data, &a.config) != nil || a.config.WarmSeconds < 900 || a.config.WarmSeconds > 86400 || len(a.config.Subscriptions) > 10 {
			return nil, errors.New("invalid I2P settings")
		}
		ids := map[string]bool{}
		for _, s := range a.config.Subscriptions {
			if s.ID == "" || ids[s.ID] || validateSubscriptionURL(s.URL) != nil || len(s.Conflicts) > MaxEntries {
				return nil, errors.New("invalid I2P subscription")
			}
			ids[s.ID] = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	a.mux.HandleFunc("GET /{$}", a.status)
	a.mux.HandleFunc("POST /wake", a.wake)
	a.mux.HandleFunc("PUT /settings", a.setSettings)
	a.mux.HandleFunc("PUT /entries", a.put)
	a.mux.HandleFunc("DELETE /entries/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.book.Delete(r.PathValue("name")); err != nil {
			adminError(w, "I2P book unavailable", 503)
			return
		}
		w.WriteHeader(204)
	})
	a.mux.HandleFunc("GET /export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="hosts.txt"`)
		io.WriteString(w, a.book.Export())
	})
	a.mux.HandleFunc("POST /import/preview", a.preview)
	a.mux.HandleFunc("POST /import", a.importBook)
	a.mux.HandleFunc("POST /subscriptions", a.addSubscription)
	a.mux.HandleFunc("DELETE /subscriptions/{id}", a.deleteSubscription)
	a.mux.HandleFunc("PATCH /subscriptions/{id}", a.updateSubscription)
	a.mux.HandleFunc("POST /subscriptions/{id}/refresh", a.refresh)
	a.mux.HandleFunc("POST /subscriptions/{id}/conflicts", a.conflict)
	a.mux.HandleFunc("GET /subscriptions/{id}/conflicts", a.conflictPage)
	return a, nil
}
func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.book == nil {
		adminError(w, "I2P address book unavailable", 503)
		return
	}
	a.mux.ServeHTTP(w, r)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, (1<<20)+4096))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		adminError(w, "invalid I2P request", 400)
		return false
	}
	return true
}
func (a *Admin) save() error {
	b, e := json.Marshal(a.config)
	if e == nil && len(b) > maxSettingsBytes {
		return errors.New("I2P settings capacity exceeded")
	}
	if e == nil {
		e = atomicFile(a.path, b)
	}
	if e != nil {
		a.failed = true
	}
	return e
}
func (a *Admin) status(w http.ResponseWriter, r *http.Request) {
	offset, err := pageOffset(r)
	if err != nil {
		adminError(w, err.Error(), 400)
		return
	}
	state, err := a.control.Status(r.Context())
	if err != nil {
		state.State = "unavailable"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	type feedView struct {
		Subscription
		ConflictTotal      int  `json:"conflict_total"`
		NextConflictOffset *int `json:"next_conflict_offset"`
	}
	feeds := make([]feedView, 0, len(a.config.Subscriptions))
	for _, s := range a.config.Subscriptions {
		page := pageEntries(s.Conflicts, 0, conflictPageSize)
		s.Conflicts = page.Entries
		s.Refreshing = a.pending[s.ID]
		feeds = append(feeds, feedView{s, page.Total, page.Next})
	}
	page := pageEntries(filterEntries(a.book.List(), r.URL.Query().Get("q")), offset, addressPageSize)
	json.NewEncoder(w).Encode(map[string]any{"runtime": state, "available": a.available && !a.failed, "no_transit": true, "warm_seconds": a.config.WarmSeconds, "entries": page.Entries, "total": page.Total, "next_offset": page.Next, "subscriptions": feeds})
}
func (a *Admin) wake(w http.ResponseWriter, r *http.Request) {
	if !a.available {
		adminError(w, "I2P namespace unavailable", 409)
		return
	}
	if _, err := a.control.Do(r.Context(), "POST", "/wake", nil); err != nil {
		adminError(w, "I2P supervisor unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
func (a *Admin) setSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		WarmSeconds int `json:"warm_seconds"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.WarmSeconds < 900 || b.WarmSeconds > 86400 {
		adminError(w, "warm timeout must be 900..86400 seconds", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	a.config.WarmSeconds = b.WarmSeconds
	if a.save() != nil {
		adminError(w, "settings unavailable", 503)
		return
	}
	payload, _ := json.Marshal(map[string]int{"seconds": b.WarmSeconds})
	if _, err := a.control.Do(r.Context(), "PUT", "/idle", strings.NewReader(string(payload))); err != nil {
		adminError(w, "settings saved; supervisor unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
func (a *Admin) put(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
		Replace     bool   `json:"replace"`
	}
	if !decode(w, r, &b) {
		return
	}
	if _, err := Name(b.Name); err != nil {
		adminError(w, "invalid I2P name", 400)
		return
	}
	if _, err := Destination(b.Destination); err != nil {
		adminError(w, "invalid public Destination", 400)
		return
	}
	if err := a.book.Put(b.Name, b.Destination, "manual", b.Replace); err != nil {
		adminError(w, err.Error(), 409)
		return
	}
	w.WriteHeader(204)
}
func (a *Admin) preview(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
	}
	if !decode(w, r, &b) {
		return
	}
	json.NewEncoder(w).Encode(a.book.Preview(b.Text))
}
func (a *Admin) importBook(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text    string `json:"text"`
		Replace bool   `json:"replace"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := a.book.ApplyImport(a.book.Preview(b.Text), "manual", b.Replace); err != nil {
		adminError(w, err.Error(), 409)
		return
	}
	w.WriteHeader(204)
}
func validateSubscriptionURL(address string) error {
	if len(address) > 2048 {
		return errors.New("subscription URL exceeds 2048 bytes")
	}
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid subscription URL")
	}
	if strings.HasSuffix(strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), ".i2p") {
		if _, err := Name(u.Hostname()); err != nil {
			return err
		}
		if (u.Scheme == "http" && (u.Port() == "" || u.Port() == "80")) || (u.Scheme == "https" && (u.Port() == "" || u.Port() == "443")) {
			return nil
		}
		return errors.New("I2P subscriptions require HTTP(S) default ports")
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("public subscriptions require HTTPS port 443")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicIP(ip) {
		return errors.New("private subscription address denied")
	}
	return nil
}
func (a *Admin) addSubscription(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := validateSubscriptionURL(b.URL); err != nil {
		adminError(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	if len(a.config.Subscriptions) >= 10 {
		adminError(w, "subscription limit reached", 409)
		return
	}
	for _, s := range a.config.Subscriptions {
		if s.URL == b.URL {
			adminError(w, "subscription already exists", 409)
			return
		}
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		adminError(w, "ID unavailable", 503)
		return
	}
	s := Subscription{ID: hex.EncodeToString(key[:]), URL: b.URL, Enabled: b.Enabled, Conflicts: []Entry{}}
	a.config.Subscriptions = append(a.config.Subscriptions, s)
	if a.save() != nil {
		adminError(w, "settings unavailable", 503)
		return
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(s)
}
func (a *Admin) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	for i, s := range a.config.Subscriptions {
		if s.ID == r.PathValue("id") {
			a.config.Subscriptions = append(a.config.Subscriptions[:i], a.config.Subscriptions[i+1:]...)
			if a.save() != nil {
				adminError(w, "settings unavailable", 503)
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	http.NotFound(w, r)
}
func (a *Admin) insideClient() *http.Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if port != "80" && port != "443" {
			return nil, errors.New("invalid I2P feed port")
		}
		// Resolve locally, then send only a canonical public Destination to i2pd.
		_, dest, err := a.book.Resolve(host)
		if err != nil {
			return nil, err
		}
		return (socks5.Dialer{HandshakeTimeout: 90 * time.Second, ProxyAddress: a.proxy}).DialContext(ctx, "tcp", net.JoinHostPort(dest, port))
	}}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !strings.HasSuffix(strings.TrimSuffix(strings.ToLower(r.URL.Hostname()), "."), ".i2p") || validateSubscriptionURL(r.URL.String()) != nil {
			return errors.New("I2P redirect denied")
		}
		return nil
	}}
}
func (a *Admin) refresh(w http.ResponseWriter, r *http.Request) {
	if !a.available {
		adminError(w, "I2P namespace unavailable", 409)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	id := r.PathValue("id")
	found := false
	for _, s := range a.config.Subscriptions {
		if s.ID == id {
			found = true
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	if !a.pending[id] {
		select {
		case a.manual <- id:
			a.pending[id] = true
		default:
			adminError(w, "refresh queue full", 429)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}
func (a *Admin) manualRefresh(parent context.Context, id string) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	_, err := a.control.Do(ctx, "POST", "/wake", nil)
	for err == nil {
		var s Status
		s, err = a.control.Status(ctx)
		if err != nil || s.State == "error" {
			err = errors.New("I2P unavailable")
			break
		}
		if s.State == "warm" || s.State == "active" {
			err = a.Refresh(ctx, id, time.Now())
			break
		}
		select {
		case <-ctx.Done():
			err = errors.New("I2P warmup timed out")
		case <-time.After(time.Second):
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pending, id)
	if err != nil && !a.failed {
		for i := range a.config.Subscriptions {
			if a.config.Subscriptions[i].ID == id {
				a.config.Subscriptions[i].Error = "I2P refresh failed; retry after warmup"
				a.config.Subscriptions[i].LastAttempt = time.Now()
			}
		}
		_ = a.save()
	}
}
func (a *Admin) Refresh(ctx context.Context, id string, now time.Time) error {
	a.mu.Lock()
	if a.failed || a.updating {
		a.mu.Unlock()
		return errors.New("subscription update unavailable")
	}
	var selected Subscription
	for _, s := range a.config.Subscriptions {
		if s.ID == id {
			selected = s
		}
	}
	if selected.ID == "" {
		a.mu.Unlock()
		return errors.New("subscription not found")
	}
	a.updating = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.updating = false; a.mu.Unlock() }()
	client := a.insideClient()
	defer client.CloseIdleConnections()
	text, fetchErr := FetchSubscription(ctx, selected.URL, client)
	preview := Preview{}
	if fetchErr == nil {
		preview = a.book.Preview(text)
		if len(preview.Errors) > 0 {
			fetchErr = errors.New("subscription contains invalid records")
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.config.Subscriptions {
		s := &a.config.Subscriptions[i]
		if s.ID != id {
			continue
		}
		if selected.Enabled && !s.Enabled {
			return errors.New("subscription disabled during refresh")
		}
		s.LastAttempt = now
		if fetchErr != nil {
			s.Error = fetchErr.Error()
			return errors.Join(fetchErr, a.save())
		}
		// Recompute conflicts against the latest book, then import new entries only.
		preview = a.book.Preview(text)
		conflicting := map[string]bool{}
		for _, c := range preview.Conflicts {
			conflicting[c.Name] = true
		}
		accepted := Preview{}
		for _, e := range preview.Entries {
			if !conflicting[e.Name] {
				accepted.Entries = append(accepted.Entries, e)
			}
		}
		if !a.conflictsFit(id, preview.Conflicts) {
			s.Error = "conflict capacity exceeded; resolve existing conflicts then refresh"
			return errors.Join(errors.New(s.Error), a.save())
		}
		if err := a.book.ApplyImport(accepted, id, false); err != nil {
			s.Error = "address book changed or unavailable"
			return errors.Join(errors.New(s.Error), a.save())
		}
		s.Conflicts = preview.Conflicts
		s.LastSuccess = now
		s.Error = ""
		return a.save()
	}
	return errors.New("subscription removed during refresh")
}
func (a *Admin) conflict(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name   string `json:"name"`
		Accept bool   `json:"accept"`
	}
	if !decode(w, r, &b) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	for i := range a.config.Subscriptions {
		s := &a.config.Subscriptions[i]
		if s.ID != r.PathValue("id") {
			continue
		}
		for j, e := range s.Conflicts {
			if e.Name != b.Name {
				continue
			}
			if b.Accept {
				if err := a.book.Put(e.Name, func() string {
					if e.PublicDestination != "" {
						return e.PublicDestination
					}
					return e.Destination
				}(), "manual", true); err != nil {
					adminError(w, "address book unavailable", 409)
					return
				}
			}
			s.Conflicts = append(s.Conflicts[:j], s.Conflicts[j+1:]...)
			if a.save() != nil {
				adminError(w, "settings unavailable", 503)
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	http.NotFound(w, r)
}

// Run never wakes the router. Updates happen only while an existing warm/active
// runtime is available, once per source per six hours, including failed attempts.
func (a *Admin) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-a.manual:
			a.manualRefresh(ctx, id)
		case now := <-tick.C:
			status, err := a.control.Status(ctx)
			if err != nil {
				continue
			}
			a.mu.Lock()
			seconds := a.config.WarmSeconds
			var due []string
			for _, s := range a.config.Subscriptions {
				if s.Enabled && now.Sub(s.LastAttempt) >= 6*time.Hour {
					due = append(due, s.ID)
				}
			}
			failed := a.failed
			a.mu.Unlock()
			if failed || !a.available {
				continue
			}
			payload, _ := json.Marshal(map[string]int{"seconds": seconds})
			a.control.Do(ctx, "PUT", "/idle", strings.NewReader(string(payload)))
			if status.State != "warm" && status.State != "active" {
				continue
			}
			for _, id := range due {
				bounded, cancel := context.WithTimeout(ctx, 35*time.Second)
				_ = a.Refresh(bounded, id, now)
				cancel()
			}
		}
	}
}

func adminError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func (a *Admin) updateSubscription(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &b) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		adminError(w, "settings unavailable", 503)
		return
	}
	for i := range a.config.Subscriptions {
		if a.config.Subscriptions[i].ID == r.PathValue("id") {
			a.config.Subscriptions[i].Enabled = b.Enabled
			if a.save() != nil {
				adminError(w, "settings unavailable", 503)
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	http.NotFound(w, r)
}
