package sources

import "testing"

func TestStandardVisionHandlerIdentityAndLegacyDecode(t *testing.T) {
	const candidate = "cand_10f2c5080e9a741a"
	link := "vless://id@example.org:443?flow=xtls-rprx-vision"
	if got := VLESSHandlerID(candidate, link); got != candidate+"-vision-standard-v2" {
		t.Fatalf("standard Vision handler=%q", got)
	}
	for _, handler := range []string{candidate, candidate + "-vision-udp443-v1", candidate + "-vision-standard-v2"} {
		if got := CandidateIDFromVLESSHandler(handler); got != candidate {
			t.Errorf("handler %q decodes as %q", handler, got)
		}
	}
	if got := VLESSHandlerID(candidate, "vless://id@example.org:443?flow=xtls-rprx-vision-udp443"); got != candidate {
		t.Fatalf("explicit UDP/443 handler=%q", got)
	}
}
