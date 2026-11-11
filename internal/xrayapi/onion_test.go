package xrayapi

import (
	"encoding/json"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"testing"
)

func TestOnionRulesPrecedeDirectAndAreClientScoped(t *testing.T) {
	a := NewAdapter("xray", "localhost:1", "1.1.1.1", nil)
	raw, err := a.routeDocument([]dataplane.ClientRoute{{ClientID: "a", SourceCIDR: "10.44.0.2/32", TCPOutbound: "normal", UDPOutbound: "normal", OnionEnabled: true, OnionOutbound: "onion-a"}, {ClientID: "b", SourceCIDR: "10.44.0.3/32", TCPOutbound: "normal", UDPOutbound: "normal"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routing struct {
			Rules []struct {
				RuleTag  string   `json:"ruleTag"`
				Outbound string   `json:"outboundTag"`
				Source   []string `json:"source"`
			}
		}
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	allow, block, direct := -1, -1, -1
	for i, r := range doc.Routing.Rules {
		switch r.RuleTag {
		case "hydrat-client-a-onion":
			allow = i
			if r.Outbound != "onion-a" || len(r.Source) != 1 || r.Source[0] != "10.44.0.2/32" {
				t.Fatal(r)
			}
		case "hydrat-onion-block":
			block = i
		case "hydrat-direct-ru":
			direct = i
		}
	}
	if allow < 0 || block <= allow || direct <= block {
		t.Fatalf("onion precedence %d %d %d", allow, block, direct)
	}
}
