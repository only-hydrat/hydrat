package xrayconfig

import (
	"encoding/json"
	"testing"
)

func TestVLESSOutboundSupportsRealityAndXHTTP(t *testing.T) {
	link := "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?type=xhttp&security=reality&encryption=mlkem768x25519plus.native.0rtt.token&pbk=public-key&pqv=verify-key&sni=cdn.example.net&sid=abcd&fp=chrome&path=%2Fapi&mode=auto&x_padding_bytes=100-1000#fast"
	config, err := VLESSOutbound(link, "candidate-a")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(config)
	text := string(data)
	for _, expected := range []string{
		`"tag":"candidate-a"`, `"protocol":"vless"`, `"network":"xhttp"`,
		`"password":"public-key"`, `"serverName":"cdn.example.net"`,
		`"path":"/api"`, `"xPaddingBytes":"100-1000"`,
		`"encryption":"mlkem768x25519plus.native.0rtt.token"`,
		`"mldsa65Verify":"verify-key"`,
	} {
		if !contains(text, expected) {
			t.Fatalf("missing %s in %s", expected, text)
		}
	}

	extraLink := "vless://550e8400-e29b-41d4-a716-446655440000@example.net:443?type=xhttp&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D"
	extraConfig, err := VLESSOutbound(extraLink, "candidate-extra")
	if err != nil {
		t.Fatal(err)
	}
	extraData, _ := json.Marshal(extraConfig)
	if !contains(string(extraData), `"mode":"auto"`) ||
		!contains(string(extraData), `"xPaddingBytes":"100-1000"`) ||
		!contains(string(extraData), `"extra":{"mode":"auto","xPaddingBytes":"100-1000"}`) {
		t.Fatalf("xhttp extra was not preserved: %s", extraData)
	}
}

func TestVLESSOutboundSupportsRawTransport(t *testing.T) {
	link := "vless://id@example.net:443?type=raw&security=reality&pbk=public-key&sni=example.com"
	config, err := VLESSOutbound(link, "candidate-raw")
	if err != nil {
		t.Fatalf("build raw outbound: %v", err)
	}

	stream := config["streamSettings"].(map[string]any)
	if got := stream["network"]; got != "raw" {
		t.Fatalf("network = %v, want raw", got)
	}
	if _, ok := stream["rawSettings"]; !ok {
		t.Fatalf("rawSettings missing from %#v", stream)
	}
}

func TestVLESSOutboundRejectsMissingRealityKeyAndUnsupportedTransport(t *testing.T) {
	if _, err := VLESSOutbound("vless://id@example.net:443?security=reality", "tag"); err == nil {
		t.Fatal("Reality without public key must fail")
	}
	if _, err := VLESSOutbound("vless://id@example.net:443?type=kcp", "tag"); err == nil {
		t.Fatal("unsupported transport must fail")
	}
}

func TestTorOutboundUsesPerClientSOCKSCredentials(t *testing.T) {
	first := TorOutbound("127.0.0.1:19050", "tor-a", "alice", []byte("master-secret"))
	second := TorOutbound("127.0.0.1:19050", "tor-b", "bob", []byte("master-secret"))
	one, _ := json.Marshal(first)
	two, _ := json.Marshal(second)
	if string(one) == string(two) || !contains(string(one), `"user":"hydrat-alice"`) || !contains(string(two), `"user":"hydrat-bob"`) {
		t.Fatalf("Tor circuit credentials not isolated: %s %s", one, two)
	}
}

func contains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
