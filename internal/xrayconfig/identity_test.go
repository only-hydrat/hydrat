package xrayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestVLESSIdentityUsesExactRedactedCanonicalForms(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@EXAMPLE.COM.:0443" +
		"?type=ws&security=reality&sni=CDN.EXAMPLE.&host=FRONT.EXAMPLE." +
		"&path=%2Fsecret-one&pbk=public-key-one&sid=secret-short-id#private-label"

	got, err := VLESSIdentity(link)
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{
		RouteKey:      identityDigest("route-v1-", "v1|example.com|443|ws|reality|cdn.example|front.example"),
		FailureDomain: identityDigest("domain-v1-", "v1|example.com|443"),
	}
	if got != want {
		t.Fatalf("identity = %+v, want %+v", got, want)
	}

	digestPattern := regexp.MustCompile(`^(route|domain)-v1-[0-9a-f]{64}$`)
	for _, value := range []string{got.RouteKey, got.FailureDomain} {
		if !digestPattern.MatchString(value) {
			t.Fatalf("identity is not a prefixed lowercase SHA-256 digest: %q", value)
		}
		for _, secret := range []string{
			"example", "11111111", "secret-one", "public-key-one",
			"secret-short-id", "private-label",
		} {
			if strings.Contains(strings.ToLower(value), strings.ToLower(secret)) {
				t.Fatalf("identity %q disclosed %q", value, secret)
			}
		}
	}
}

func TestVLESSIdentityIgnoresCredentialsPathsKeysAndLabels(t *testing.T) {
	first := mustVLESSIdentity(t,
		"vless://11111111-1111-1111-1111-111111111111@example.com:443"+
			"?type=xhttp&security=reality&sni=cdn.example&host=front.example"+
			"&path=%2Fone&pbk=key-one&sid=short-one&token=query-one#label-one",
	)
	second := mustVLESSIdentity(t,
		"vless://22222222-2222-2222-2222-222222222222@example.com:443"+
			"?type=xhttp&security=reality&sni=cdn.example&host=front.example"+
			"&path=%2Ftwo&pbk=key-two&sid=short-two&token=query-two#label-two",
	)
	if first != second {
		t.Fatalf("secret-only changes altered identity: first=%+v second=%+v", first, second)
	}
}

func TestVLESSIdentitySeparatesRoutesWithinFailureDomain(t *testing.T) {
	tcp := mustVLESSIdentity(t, "vless://id@example.net:443?type=tcp&security=tls&sni=one.example")
	raw := mustVLESSIdentity(t, "vless://id@example.net:443?type=raw&security=tls&sni=one.example")
	otherSNI := mustVLESSIdentity(t, "vless://id@example.net:443?type=tcp&security=tls&sni=two.example")
	otherFront := mustVLESSIdentity(t, "vless://id@example.net:443?type=ws&security=tls&sni=one.example&host=front.example")

	for _, other := range []Identity{raw, otherSNI, otherFront} {
		if tcp.RouteKey == other.RouteKey {
			t.Fatalf("materially different routes shared route key: tcp=%+v other=%+v", tcp, other)
		}
		if tcp.FailureDomain != other.FailureDomain {
			t.Fatalf("same dial endpoint split failure domains: tcp=%+v other=%+v", tcp, other)
		}
	}

	otherHost := mustVLESSIdentity(t, "vless://id@other.example.net:443?type=tcp&security=tls&sni=one.example")
	otherPort := mustVLESSIdentity(t, "vless://id@example.net:8443?type=tcp&security=tls&sni=one.example")
	if tcp.FailureDomain == otherHost.FailureDomain || tcp.FailureDomain == otherPort.FailureDomain {
		t.Fatalf("different dial endpoints shared failure domain: base=%+v host=%+v port=%+v", tcp, otherHost, otherPort)
	}
}

func TestVLESSIdentityNormalizesDefaultsDNSAndIPAddresses(t *testing.T) {
	defaults := mustVLESSIdentity(t, "vless://id@EXAMPLE.NET.:443")
	explicit := mustVLESSIdentity(t, "vless://other@example.net:0443?type=tcp&security=none&sni=ignored.example&host=ignored.example")
	if defaults != explicit {
		t.Fatalf("equivalent default route identities differ: defaults=%+v explicit=%+v", defaults, explicit)
	}

	expandedIPv6 := mustVLESSIdentity(t, "vless://id@[2001:0db8:0:0:0:0:0:1]:443?security=tls")
	compressedIPv6 := mustVLESSIdentity(t, "vless://id@[2001:db8::1]:0443?security=tls&sni=2001%3Adb8%3A%3A1")
	if expandedIPv6 != compressedIPv6 {
		t.Fatalf("equivalent IPv6 routes differ: expanded=%+v compressed=%+v", expandedIPv6, compressedIPv6)
	}

	mappedIPv4 := mustVLESSIdentity(t, "vless://id@[::ffff:192.0.2.1]:443")
	ipv4 := mustVLESSIdentity(t, "vless://id@192.0.2.1:443")
	if mappedIPv4 != ipv4 {
		t.Fatalf("IPv4-mapped endpoint was not canonicalized: mapped=%+v ipv4=%+v", mappedIPv4, ipv4)
	}
}

func TestVLESSIdentityCanonicalizesBracketedIPv6FrontingHostsForWSAndXHTTP(t *testing.T) {
	for _, transport := range []string{"ws", "xhttp"} {
		t.Run(transport, func(t *testing.T) {
			link := func(frontingHost string) string {
				return "vless://id@example.net:443?type=" + transport +
					"&security=tls&host=" + url.QueryEscape(frontingHost)
			}

			expanded := mustVLESSIdentity(t, link("[2001:0db8:0:0:0:0:0:1]"))
			compressed := mustVLESSIdentity(t, link("[2001:db8::1]"))
			wantNoPort := Identity{
				RouteKey: identityDigest(
					"route-v1-",
					"v1|example.net|443|"+transport+"|tls|example.net|[2001:db8::1]",
				),
				FailureDomain: identityDigest("domain-v1-", "v1|example.net|443"),
			}
			if expanded != compressed || compressed != wantNoPort {
				t.Fatalf("no-port IPv6 identity: expanded=%+v compressed=%+v want=%+v",
					expanded, compressed, wantNoPort)
			}

			leadingZeroPort := mustVLESSIdentity(t, link("[2001:0db8::1]:0443"))
			canonicalPort := mustVLESSIdentity(t, link("[2001:db8::1]:443"))
			wantPort := Identity{
				RouteKey: identityDigest(
					"route-v1-",
					"v1|example.net|443|"+transport+"|tls|example.net|[2001:db8::1]:443",
				),
				FailureDomain: wantNoPort.FailureDomain,
			}
			if leadingZeroPort != canonicalPort || canonicalPort != wantPort {
				t.Fatalf("ported IPv6 identity: leading=%+v canonical=%+v want=%+v",
					leadingZeroPort, canonicalPort, wantPort)
			}

			otherPort := mustVLESSIdentity(t, link("[2001:db8::1]:8443"))
			if otherPort.RouteKey == canonicalPort.RouteKey {
				t.Fatalf("different fronting ports shared route key: first=%+v other=%+v",
					canonicalPort, otherPort)
			}
			if otherPort.FailureDomain != canonicalPort.FailureDomain {
				t.Fatalf("fronting port changed dial failure domain: first=%+v other=%+v",
					canonicalPort, otherPort)
			}
		})
	}

	mapped := mustVLESSIdentity(t,
		"vless://id@example.net:443?type=ws&host="+url.QueryEscape("[::ffff:192.0.2.1]:0443"),
	)
	ipv4 := mustVLESSIdentity(t,
		"vless://id@example.net:443?type=ws&host="+url.QueryEscape("192.0.2.1:443"),
	)
	if mapped != ipv4 {
		t.Fatalf("mapped IPv4 fronting host was not unmapped: mapped=%+v ipv4=%+v", mapped, ipv4)
	}
}

func TestVLESSIdentityRejectsMalformedIPv6FrontingHostsWithoutDisclosure(t *testing.T) {
	values := []string{
		"[]",
		"[2001:db8::1",
		"[2001:db8::1]trailing",
		"[2001:db8::1]:0",
		"[2001:db8::1]:70000",
		"[2001:db8::1]:+443",
		"[2001:db8::1]:443:trailing",
		"[fe80::1%secret-zone]",
		"2001:db8::1:443",
	}
	for _, transport := range []string{"ws", "xhttp"} {
		for _, value := range values {
			t.Run(transport+"/"+value, func(t *testing.T) {
				link := "vless://secret-id@secret-host.example:443?type=" + transport +
					"&host=" + url.QueryEscape(value) +
					"&path=%2Fsecret-path&key=secret-key#secret-label"
				got, err := VLESSIdentity(link)
				if err == nil {
					t.Fatalf("VLESSIdentity returned %+v for malformed fronting host", got)
				}
				if got != (Identity{}) {
					t.Fatalf("failed identity returned partial values: %+v", got)
				}
				message := strings.ToLower(err.Error())
				for _, secret := range []string{
					"secret-id", "secret-host", "secret-path", "secret-key",
					"secret-label", "secret-zone", strings.ToLower(value),
				} {
					if secret != "" && strings.Contains(message, secret) {
						t.Fatalf("error %q disclosed %q", err, secret)
					}
				}
			})
		}
	}
}

func TestVLESSIdentityRejectsMalformedUnsupportedAndAmbiguousLinksWithoutDisclosure(t *testing.T) {
	tests := []struct {
		name string
		link string
	}{
		{name: "malformed", link: "not-a-vless-link"},
		{name: "missing host", link: "vless://secret-id@:443"},
		{name: "missing port", link: "vless://secret-id@secret-host.example"},
		{name: "invalid port", link: "vless://secret-id@secret-host.example:70000"},
		{name: "malformed ipv4", link: "vless://secret-id@192.0.2.999:443"},
		{name: "unsupported transport", link: "vless://secret-id@secret-host.example:443?type=secret-transport&path=%2Fsecret-path#secret-label"},
		{name: "unsupported security", link: "vless://secret-id@secret-host.example:443?security=secret-security&key=secret-key#secret-label"},
		{name: "ambiguous transport", link: "vless://secret-id@secret-host.example:443?type=tcp&type=raw"},
		{name: "ambiguous sni", link: "vless://secret-id@secret-host.example:443?security=tls&sni=one.example&sni=two.example"},
		{name: "ambiguous fronting host", link: "vless://secret-id@secret-host.example:443?type=ws&host=one.example&host=two.example"},
		{name: "missing reality key", link: "vless://secret-id@secret-host.example:443?security=reality"},
		{name: "canonical delimiter", link: "vless://secret-id@secret-host.example:443?security=tls&sni=secret%7Csni"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := VLESSIdentity(test.link)
			if err == nil {
				t.Fatalf("VLESSIdentity(%q) = %+v, want error", test.name, got)
			}
			if got != (Identity{}) {
				t.Fatalf("failed identity returned partial values: %+v", got)
			}
			message := strings.ToLower(err.Error())
			for _, secret := range []string{
				"secret-id", "secret-host", "secret-path", "secret-key",
				"secret-label", "secret-transport", "secret-security", "secret|sni",
			} {
				if strings.Contains(message, secret) {
					t.Fatalf("error %q disclosed %q", err, secret)
				}
			}
		})
	}
}

func mustVLESSIdentity(t *testing.T, link string) Identity {
	t.Helper()
	identity, err := VLESSIdentity(link)
	if err != nil {
		t.Fatalf("VLESSIdentity: %v", err)
	}
	return identity
}

func identityDigest(prefix, canonical string) string {
	digest := sha256.Sum256([]byte(canonical))
	return prefix + hex.EncodeToString(digest[:])
}
