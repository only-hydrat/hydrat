package i2p

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MaxEntries = 1024

var errUnknownName = errors.New("name not in I2P address book")

var Pool = netip.MustParsePrefix("198.19.0.0/16")

type Entry struct {
	PublicDestination string `json:"public_destination,omitempty"`
	Name              string `json:"name"`
	Destination       string `json:"destination"`
	Source            string `json:"source"`
}
type Mapping struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Retired     bool   `json:"retired"`
}
type bookState struct {
	DefaultHostsSeeded bool               `json:"default_hosts_seeded,omitempty"`
	Version            int                `json:"version"`
	Entries            map[string]Entry   `json:"entries"`
	Mappings           map[string]Mapping `json:"mappings"`
	Next               uint32             `json:"next"`
}
type Book struct {
	lock             *os.File
	mu               sync.Mutex
	path             string
	state            bookState
	failed           bool
	allocations      map[netip.Addr]allocationBudget
	globalAllocation allocationBudget
}

func Name(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) > 253 || !strings.HasSuffix(s, ".i2p") {
		return "", errors.New("I2P name required")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid I2P label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid I2P name")
			}
		}
	}
	return s, nil
}
func Destination(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".b32.i2p") {
		name, err := Name(s)
		if err != nil {
			return "", err
		}
		id := strings.TrimSuffix(name, ".b32.i2p")
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(id))
		if err != nil || len(id) != 52 || len(raw) != 32 || strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)) != id {
			return "", errors.New("standard public b32 address required")
		}
		return name, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.NewReplacer("-", "+", "~", "/").Replace(s))
	if err != nil || len(raw) < 387 || len(raw) > 4096 {
		return "", errors.New("invalid public Destination")
	}
	// A Destination contains 384 key bytes and a typed certificate with a
	// two-byte length. Reject truncated or appended data before deriving b32.
	length := int(raw[385])<<8 | int(raw[386])
	if len(raw) != 387+length {
		return "", errors.New("invalid Destination certificate")
	}
	sum := sha256.Sum256(raw)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])) + ".b32.i2p", nil
}
func OpenBook(path string) (result *Book, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			lock.Close()
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("I2P book already owned")
	}

	b := &Book{lock: lock, path: path, state: bookState{Version: 1, Entries: map[string]Entry{}, Mappings: map[string]Mapping{}, Next: 1}}
	info, err := os.Lstat(path)
	var data []byte
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
			return nil, errors.New("unsafe I2P address book")
		}
		data, err = os.ReadFile(path)
	}
	if os.IsNotExist(err) {
		if _, e := os.Stat(path + ".initialized"); e == nil {
			return nil, errors.New("I2P book lost; restore backup")
		}
		if err = b.save(); err != nil {
			return nil, err
		}
		if err = atomicFile(path+".initialized", []byte("1\n")); err != nil {
			return nil, err
		}
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(data) > 8<<20 {
		return nil, errors.New("unsafe I2P address book")
	}
	if err = json.Unmarshal(data, &b.state); err != nil {
		return nil, err
	}
	if b.state.Version != 1 || b.state.Entries == nil || b.state.Mappings == nil || len(b.state.Entries) > MaxEntries || b.state.Next < 1 || b.state.Next > 65535 {
		return nil, errors.New("invalid I2P address book")
	}
	for n, e := range b.state.Entries {
		valid, err := Name(n)
		d, derr := Destination(e.Destination)
		if err != nil || derr != nil || valid != n || e.Name != n || d != e.Destination || strings.HasSuffix(n, ".b32.i2p") && n != d {
			return nil, errors.New("corrupt I2P entry")
		}
	}
	for _, e := range b.state.Entries {
		if e.PublicDestination != "" {
			d, err := Destination(e.PublicDestination)
			if err != nil || d != e.Destination {
				return nil, errors.New("corrupt public Destination")
			}
		}
	}
	for ip, m := range b.state.Mappings {
		p, err := netip.ParseAddr(ip)
		_, derr := Destination(m.Destination)
		_, nerr := Name(m.Name)
		if err != nil || !Pool.Contains(p) || p == Pool.Addr() || derr != nil || nerr != nil {
			return nil, errors.New("corrupt I2P mapping")
		}
	}
	for ip := range b.state.Mappings {
		p := netip.MustParseAddr(ip).As4()
		if uint32(p[2])<<8|uint32(p[3]) >= b.state.Next {
			return nil, errors.New("I2P allocator would reuse an address")
		}
	}
	if err := atomicFile(path+".initialized", []byte("1\n")); err != nil {
		return nil, err
	}
	return b, nil
}
func atomicFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".i2p-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (b *Book) save() error {
	data, err := json.Marshal(b.state)
	if err != nil {
		return err
	}
	if err = atomicFile(b.path, data); err != nil {
		b.failed = true
	}
	return err
}
func (b *Book) List() []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Entry, 0, len(b.state.Entries))
	for _, e := range b.state.Entries {
		out = append(out, e)
	}
	return out
}
func (b *Book) Put(name, destination, source string, replace bool) error {
	n, err := Name(name)
	if err != nil {
		return err
	}
	d, err := Destination(destination)
	if err != nil {
		return err
	}
	if strings.HasSuffix(n, ".b32.i2p") && n != d {
		return errors.New("b32 names cannot be retargeted")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return errors.New("I2P persistence unavailable")
	}
	if e, ok := b.state.Entries[n]; ok && e.Source == "manual" && source != "manual" && e.Destination == d {
		return nil
	}
	if e, ok := b.state.Entries[n]; ok && e.Destination != d {
		if !replace || e.Source == "manual" && source != "manual" {
			return errors.New("destination conflict requires confirmation")
		}
		for ip, m := range b.state.Mappings {
			if m.Name == n {
				m.Retired = true
				b.state.Mappings[ip] = m
			}
		}
	}
	if _, ok := b.state.Entries[n]; !ok && len(b.state.Entries) >= MaxEntries {
		return errors.New("address book full")
	}
	raw := ""
	if !strings.HasSuffix(strings.TrimSpace(destination), ".b32.i2p") {
		raw = strings.TrimSpace(destination)
	}
	b.state.Entries[n] = Entry{Name: n, Destination: d, Source: source, PublicDestination: raw}
	return b.save()
}
func (b *Book) Delete(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return errors.New("I2P persistence unavailable")
	}
	delete(b.state.Entries, name)
	for ip, m := range b.state.Mappings {
		if m.Name == name {
			m.Retired = true
			b.state.Mappings[ip] = m
		}
	}
	return b.save()
}
func (b *Book) Resolve(name string) (netip.Addr, string, error) {
	return b.resolve(name, netip.Addr{})
}

// resolve charges only new client mappings; cached addresses and admin imports
// remain usable during a burst. The quota map contains IPs, not browsing names.
func (b *Book) resolve(name string, source netip.Addr) (netip.Addr, string, error) {
	n, err := Name(name)
	if err != nil {
		return netip.Addr{}, "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return netip.Addr{}, "", errors.New("I2P persistence unavailable")
	}
	d, err := Destination(n)
	if err != nil {
		e, ok := b.state.Entries[n]
		if !ok {
			return netip.Addr{}, "", errUnknownName
		}
		d = e.Destination
	}
	for ip, m := range b.state.Mappings {
		if m.Name == n && m.Destination == d && !m.Retired {
			p, _ := netip.ParseAddr(ip)
			return p, d, nil
		}
	}
	if b.state.Next >= 65535 || len(b.state.Mappings) >= 4096 {
		return netip.Addr{}, "", errors.New("I2P mapping capacity exhausted")
	}
	if source.IsValid() && !b.allowAllocation(source, time.Now()) {
		return netip.Addr{}, "", errors.New("I2P allocation rate limited")
	}
	id := b.state.Next
	b.state.Next++
	ip := netip.AddrFrom4([4]byte{198, 19, byte(id >> 8), byte(id)})
	b.state.Mappings[ip.String()] = Mapping{Name: n, Destination: d}
	if err := b.save(); err != nil {
		return netip.Addr{}, "", err
	}
	return ip, d, nil
}
func (b *Book) Reverse(ip netip.Addr) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.state.Mappings[ip.String()]
	if b.failed || !ok || m.Retired {
		return "", errors.New("unknown I2P mapping")
	}
	return m.Destination, nil
}

func (b *Book) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed = true
	if b.lock == nil {
		return nil
	}
	err := b.lock.Close()
	b.lock = nil
	return err
}

type allocationBudget struct {
	tokens float64
	at     time.Time
}

func (b *allocationBudget) take(now time.Time, burst, perSecond float64) bool {
	if b.at.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*perSecond)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Called with the book mutex held, atomically with allocation.
func (b *Book) allowAllocation(source netip.Addr, now time.Time) bool {
	if b.allocations == nil {
		b.allocations = make(map[netip.Addr]allocationBudget)
	}
	budget, exists := b.allocations[source]
	if !exists && len(b.allocations) >= 1024 {
		for ip, item := range b.allocations {
			if now.Sub(item.at) > time.Hour {
				delete(b.allocations, ip)
			}
		}
		if len(b.allocations) >= 1024 {
			return false
		}
	}
	allowed := budget.take(now, 8, 1.0/6)
	b.allocations[source] = budget
	return allowed && b.globalAllocation.take(now, 16, 1)
}
