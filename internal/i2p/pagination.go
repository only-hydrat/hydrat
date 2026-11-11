package i2p

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const maxSettingsBytes = 2 << 20
const maxConflictBytes = 1 << 20
const addressPageSize = 50
const conflictPageSize = 10

type entryPage struct {
	Entries []Entry `json:"entries"`
	Total   int     `json:"total"`
	Next    *int    `json:"next_offset"`
}

func pageEntries(entries []Entry, offset, size int) entryPage {
	// Sort a copy: stored conflict slices may be read by another request.
	entries = append([]Entry{}, entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	total := len(entries)
	offset = min(offset, total)
	end := min(offset+size, total)
	page := entryPage{Entries: entries[offset:end], Total: total}
	if end < total {
		page.Next = &end
	}
	return page
}
func pageOffset(r *http.Request) (int, error) {
	value := r.URL.Query().Get("offset")
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > MaxEntries {
		return 0, errors.New("invalid page offset")
	}
	return n, nil
}
func (a *Admin) conflictPage(w http.ResponseWriter, r *http.Request) {
	offset, err := pageOffset(r)
	if err != nil {
		adminError(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.config.Subscriptions {
		if s.ID == r.PathValue("id") {
			json.NewEncoder(w).Encode(pageEntries(s.Conflicts, offset, conflictPageSize))
			return
		}
	}
	adminError(w, "subscription not found", 404)
}
func (a *Admin) conflictsFit(id string, next []Entry) bool {
	total := 0
	for _, s := range a.config.Subscriptions {
		entries := s.Conflicts
		if s.ID == id {
			entries = next
		}
		raw, err := json.Marshal(entries)
		if err != nil {
			return false
		}
		total += len(raw)
	}
	return total <= maxConflictBytes
}
func filterEntries(entries []Entry, query string) []Entry {
	query = strings.ToLower(query)
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(e.Name, query) {
			out = append(out, e)
		}
	}
	return out
}
