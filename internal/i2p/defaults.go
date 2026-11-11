package i2p

import (
	_ "embed"
	"errors"
	"sort"
)

//go:embed defaults/hosts.txt
var defaultHosts string

// SeedDefaultHosts adds the bundled upstream book once, preserving all existing
// ownership and mappings. The marker shares the atomic book write, so deletions
// remain deleted after restart. A full user book is left intact.
func (b *Book) SeedDefaultHosts() error {
	preview := b.Preview(defaultHosts)
	if len(preview.Errors) > 0 {
		return errors.New("invalid bundled I2P hosts")
	}
	sort.Slice(preview.Entries, func(i, j int) bool { return preview.Entries[i].Name < preview.Entries[j].Name })
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return errors.New("I2P persistence unavailable")
	}
	if b.state.DefaultHostsSeeded {
		return nil
	}
	for _, entry := range preview.Entries {
		if _, exists := b.state.Entries[entry.Name]; exists {
			continue
		}
		if len(b.state.Entries) >= MaxEntries {
			break
		}
		entry.Source = "builtin:i2p"
		b.state.Entries[entry.Name] = entry
	}
	b.state.DefaultHostsSeeded = true
	return b.save()
}
