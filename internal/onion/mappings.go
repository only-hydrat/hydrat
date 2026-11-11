// Package onion implements the isolated address book for onion access.
package onion

import (
	"crypto/sha3"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Normalize accepts public v3 service names, including application subdomains.
func Normalize(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 || labels[len(labels)-1] != "onion" {
		return "", errors.New("invalid onion name")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid onion label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("invalid onion character")
			}
		}
	}
	id := labels[len(labels)-2]
	raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(id))
	if err != nil || len(id) != 56 || len(raw) != 35 || raw[34] != 3 {
		return "", errors.New("onion v3 required")
	}
	input := append([]byte(".onion checksum"), raw[:32]...)
	input = append(input, 3)
	checksum := sha3.Sum256(input)
	if raw[32] != checksum[0] || raw[33] != checksum[1] {
		return "", errors.New("invalid onion checksum")
	}
	return name, nil
}

type mappingState struct {
	Version int               `json:"version"`
	Pool    string            `json:"pool"`
	Hosts   map[string]string `json:"hosts"`
}

type Mappings struct {
	mu     sync.Mutex
	path   string
	pool   netip.Prefix
	limit  int
	state  mappingState
	failed error
}

// OpenMappings never recycles an issued address. Exhaustion fails closed.
// The owning gateway must keep this file with its persistent WireGuard data.
func OpenMappings(path, pool string, limit int) (*Mappings, error) {
	prefix, err := netip.ParsePrefix(pool)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 24 || prefix.Bits() < 15 || !netip.MustParsePrefix("198.18.0.0/15").Contains(prefix.Addr()) || limit < 1 || limit > 16384 {
		return nil, errors.New("invalid onion mapping configuration")
	}
	m := &Mappings{path: path, pool: prefix, limit: limit, state: mappingState{Version: 1, Pool: pool, Hosts: make(map[string]string)}}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe onion mapping file")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m.state); err != nil {
		return nil, errors.New("corrupt onion mappings")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing onion mapping data")
	}
	if m.state.Version != 1 || m.state.Pool != pool || m.state.Hosts == nil || len(m.state.Hosts) > limit {
		return nil, errors.New("incompatible onion mappings")
	}
	seen := make(map[netip.Addr]bool)
	for host, value := range m.state.Hosts {
		normalized, err := Normalize(host)
		if err != nil || normalized != host {
			return nil, errors.New("invalid stored onion name")
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !prefix.Contains(ip) || ip == prefix.Addr() || seen[ip] {
			return nil, errors.New("invalid stored onion address")
		}
		seen[ip] = true
	}
	return m, nil
}

func (m *Mappings) Resolve(host string) (netip.Addr, error) {
	host, err := Normalize(host)
	if err != nil {
		return netip.Addr{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return netip.Addr{}, m.failed
	}
	if value, ok := m.state.Hosts[host]; ok {
		return netip.ParseAddr(value)
	}
	if len(m.state.Hosts) >= m.limit {
		return netip.Addr{}, errors.New("onion mapping capacity exhausted")
	}
	used := make(map[string]bool, len(m.state.Hosts))
	for _, value := range m.state.Hosts {
		used[value] = true
	}
	ip := m.pool.Addr().Next()
	for m.pool.Contains(ip) && used[ip.String()] {
		ip = ip.Next()
	}
	if !m.pool.Contains(ip) {
		return netip.Addr{}, errors.New("onion address pool exhausted")
	}
	m.state.Hosts[host] = ip.String()
	if err := m.save(); err != nil {
		// A failed directory sync may still have published the new address. Never
		// roll the allocator back or issue any more addresses in this process.
		m.failed = fmt.Errorf("persist onion mappings: %w", err)
		return netip.Addr{}, m.failed
	}
	return ip, nil
}

func (m *Mappings) Snapshot() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]string, len(m.state.Hosts))
	for host, ip := range m.state.Hosts {
		result[host] = ip
	}
	return result
}

func (m *Mappings) save() error {
	data, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(m.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".onion-mappings-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), m.path); err != nil {
		return err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func (m *Mappings) lookup(host string) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return netip.Addr{}, false
	}
	value, ok := m.state.Hosts[host]
	if !ok {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(value)
	return ip, err == nil
}
