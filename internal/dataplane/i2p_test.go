package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestI2PHandlerCannotDialExternalSOCKSOrBorrowCredentials(t *testing.T) {
	token := strings.Repeat("x", 32)
	plan := DesiredPlan{Generation: 1, FailClosed: true, DirectSuffixes: []string{".ru"}, Clients: []ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", BlockTCP: true, BlockUDP: true, I2PEnabled: true, I2POutbound: "i2p-client-alice", I2PToken: token}}}
	for _, tc := range []struct {
		host, user string
		port       int
		valid      bool
	}{{"127.0.0.1", "alice", 19447, true}, {"192.0.2.1", "alice", 19447, false}, {"127.0.0.1", "bob", 19447, false}, {"127.0.0.1", "alice", 9050, false}} {
		raw, _ := json.Marshal(map[string]any{"tag": "i2p-client-alice", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": tc.host, "port": tc.port, "users": []any{map[string]any{"user": tc.user, "pass": token, "level": I2PPolicyLevel}}}}}})
		plan.Outbounds = []Outbound{{ID: "i2p-client-alice", Protocol: ProtocolI2P, Config: raw}}
		if err := plan.Validate(); (err == nil) != tc.valid {
			t.Fatalf("host=%s user=%s port=%d err=%v", tc.host, tc.user, tc.port, err)
		}
	}
}
