package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/store"
)

// I2P is an optional local service, never a candidate for ordinary egress.
func (e *Engine) attachI2P(route *dataplane.ClientRoute, client store.ClientRecord, out map[string]dataplane.Outbound) {
	route.I2PEnabled = client.I2PEnabled && !client.Paused
	route.I2POutbound, route.I2PToken = "", ""
	if !route.I2PEnabled {
		return
	}
	mac := hmac.New(sha256.New, e.torSecret)
	mac.Write([]byte("hydrat-i2p-v1\x00" + client.ID))
	route.I2PToken = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	route.I2POutbound = "i2p-client-" + client.ID
	config, _ := json.Marshal(map[string]any{"tag": route.I2POutbound, "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 19447, "users": []any{map[string]any{"user": client.ID, "pass": route.I2PToken, "level": dataplane.I2PPolicyLevel}}}}}})
	out[route.I2POutbound] = dataplane.Outbound{ID: route.I2POutbound, Protocol: dataplane.ProtocolI2P, Config: config}
}
