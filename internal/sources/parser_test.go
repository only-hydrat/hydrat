package sources

import (
	"strings"
	"testing"
)

func TestPreviewMixedInputClassifiesAndDeduplicates(t *testing.T) {
	vless := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#fast"
	input := strings.Join([]string{
		vless,
		strings.Replace(vless, "#fast", "#renamed", 1),
		"https://subscriptions.example/list",
		"Bridge 203.0.113.10:443 0123456789ABCDEF0123456789ABCDEF01234567",
		"tor-source https://bridges.example/list.txt",
		"not-a-source",
	}, "\n")

	preview := PreviewInput(input)

	if preview.ValidCount != 4 {
		t.Fatalf("valid count = %d, want 4", preview.ValidCount)
	}
	if preview.DuplicateCount != 1 {
		t.Fatalf("duplicate count = %d, want 1", preview.DuplicateCount)
	}
	if preview.ErrorCount != 1 {
		t.Fatalf("error count = %d, want 1", preview.ErrorCount)
	}
	wantKinds := []Kind{KindVLESS, KindVLESS, KindRemoteAuto, KindTorBridge, KindTorSubscription, KindInvalid}
	for i, want := range wantKinds {
		if preview.Items[i].Kind != want {
			t.Errorf("item %d kind = %q, want %q", i, preview.Items[i].Kind, want)
		}
	}
	if !preview.Items[1].Duplicate {
		t.Fatal("second VLESS link should be a duplicate when only fragment differs")
	}
	if preview.Items[0].Fingerprint == "" || preview.Items[0].Fingerprint != preview.Items[1].Fingerprint {
		t.Fatal("canonical VLESS fingerprints should be stable and equal")
	}
	if preview.Items[0].Display != "fast" {
		t.Fatalf("VLESS display = %q, want fragment label", preview.Items[0].Display)
	}
}

func TestPreviewInputAcceptsExplicitSourcePrefixes(t *testing.T) {
	preview := PreviewInput(strings.Join([]string{
		"proxy-source https://subscriptions.example/vless",
		"tor-bridge 203.0.113.11:9001 89ABCDEF0123456789ABCDEF0123456789ABCDEF",
	}, "\n"))

	if preview.ErrorCount != 0 || preview.ValidCount != 2 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if preview.Items[0].Kind != KindVLESSSubscription {
		t.Fatalf("first kind = %q", preview.Items[0].Kind)
	}
	if preview.Items[1].Kind != KindTorBridge {
		t.Fatalf("second kind = %q", preview.Items[1].Kind)
	}
}

func TestPreviewAcceptsBareSupportedTransportBridges(t *testing.T) {
	input := strings.Join([]string{
		"obfs4 5.199.162.203:4433 5502458248AA2F6A93E614E5DCD92212F60189BA cert=redacted iat-mode=0",
		"webtunnel [2001:db8:289b:84cd:4be3:77f1:1cdd:9cb1]:443 D71C8E9C2180D2F35DEBF4A39BFCA6972F076D1C url=https://example.com/ ver=0.0.1",
	}, "\n")

	preview := PreviewInput(input)

	if preview.ValidCount != 2 || preview.ErrorCount != 0 {
		t.Fatalf("preview=%+v", preview)
	}
	for _, item := range preview.Items {
		if item.Kind != KindTorBridge || !strings.HasPrefix(item.Payload, "Bridge ") {
			t.Fatalf("item=%+v", item)
		}
	}
}

func TestPreviewRejectsUnsupportedOrMalformedTransportBridges(t *testing.T) {
	input := strings.Join([]string{
		"snowflake 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567",
		"obfs4 missing-port 0123456789ABCDEF0123456789ABCDEF01234567 cert=x iat-mode=0",
		"webtunnel 192.0.2.10:443 NOTA40HEXFINGERPRINT url=https://example.com/",
	}, "\n")

	preview := PreviewInput(input)

	if preview.ValidCount != 0 || preview.ErrorCount != 3 {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestPreviewNeverIncludesSecretsInSafeItem(t *testing.T) {
	secret := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality"
	item := PreviewInput(secret).Items[0]

	safe := item.Safe()
	if strings.Contains(safe.Payload, "11111111") || strings.Contains(safe.Payload, "vless://") {
		t.Fatalf("safe payload leaked secret: %q", safe.Payload)
	}
	if safe.Fingerprint == "" || safe.Kind != KindVLESS {
		t.Fatalf("safe item lost identity: %+v", safe)
	}
}
