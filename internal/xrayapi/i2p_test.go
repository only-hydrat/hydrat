package xrayapi

import (
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"os"
	"strconv"
	"testing"
)

func TestI2PRulesSeparateOnionAndFailClosed(t *testing.T) {
	a := NewAdapter("xray", "localhost:1", "1.1.1.1", nil)
	routes := []dataplane.ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", TCPOutbound: "normal", UDPOutbound: "normal", I2PEnabled: true, I2POutbound: "i2p-a", OnionEnabled: true, OnionOutbound: "onion-a"}}
	a.ConfigureI2P(true)
	raw, err := a.routeDocument(routes)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routing struct {
			Rules []struct {
				Tag    string   `json:"ruleTag"`
				IP     []string `json:"ip"`
				Source []string `json:"source"`
				Out    string   `json:"outboundTag"`
			}
		}
	}
	if err = json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	allow, block := -1, -1
	for i, r := range doc.Routing.Rules {
		switch r.Tag {
		case "hydrat-client-a-i2p":
			allow = i
			if len(r.IP) != 1 || r.IP[0] != "198.19.0.0/16" || len(r.Source) != 1 || r.Source[0] != "10.44.0.2/32" || r.Out != "i2p-a" {
				t.Fatal(r)
			}
		case "hydrat-client-a-onion":
			if len(r.IP) != 1 || r.IP[0] != "198.18.0.0/16" {
				t.Fatal("onion overlaps I2P", r)
			}
		case "hydrat-onion-block":
			block = i
		}
	}
	if allow < 0 || block <= allow {
		t.Fatal("missing I2P allow-before-block")
	}
	a.ConfigureI2P(false)
	raw, _ = a.routeDocument(routes)
	if json.Unmarshal([]byte(raw), &doc) != nil {
		t.Fatal("decode")
	}
	for _, r := range doc.Routing.Rules {
		if r.Out == "i2p-a" {
			t.Fatal("legacy collision granted I2P")
		}
	}
}

func TestI2PHandshakePolicyDoesNotChangeDefaultLevel(t *testing.T) {
	raw, err := os.ReadFile("../../config/xray/main.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policy struct {
			Levels map[string]struct{ Handshake int }
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Policy.Levels[strconv.Itoa(dataplane.I2PPolicyLevel)].Handshake < 275 {
		t.Fatal("cold I2P startup cut short")
	}
	if _, ok := doc.Policy.Levels["0"]; ok {
		t.Fatal("ordinary policy changed")
	}
}
