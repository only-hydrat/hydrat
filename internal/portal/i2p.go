package portal

import (
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

func i2pStatus(c store.ClientRecord, routes map[string]dataplane.ClientRoute) string {
	r := routes[c.ID]
	if !c.I2PEnabled || c.Paused {
		if r.I2POutbound != "" {
			return "disabling"
		}
		return "disabled"
	}
	if !r.I2PEnabled {
		return "pending"
	}
	if r.I2POutbound == "" {
		return "unavailable"
	}
	return "enabled"
}
