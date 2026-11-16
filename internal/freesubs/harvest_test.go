package freesubs

import (
	"encoding/base64"
	"strings"
	"testing"
)

const realityLink = "vless://11111111-1111-1111-1111-111111111111@reality.example:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF&sid=ab12&sni=www.microsoft.com&fp=chrome&type=tcp&flow=xtls-rprx-vision#reality"

const tlsLink = "vless://22222222-2222-2222-2222-222222222222@plain.example:8443?security=tls&type=ws&path=%2Fws#tls"

func TestDecodeBodyHandlesPlainAndBase64(t *testing.T) {
	list := realityLink + "\n" + tlsLink + "\n"

	plain, encoded := decodeBody([]byte(list))
	if encoded || plain != strings.TrimSpace(list) {
		t.Fatalf("plain body encoded=%v text=%q", encoded, plain)
	}

	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		wrapped, wasEncoded := decodeBody([]byte(encoding.EncodeToString([]byte(list))))
		if !strings.Contains(wrapped, "vless://11111111") {
			t.Fatalf("base64 body was not unwrapped: %q", wrapped)
		}
		if !wasEncoded {
			t.Fatal("base64 body was not reported as encoded")
		}
	}
}

func TestCountVLESSReportsReality(t *testing.T) {
	vless, reality := CountVLESS(realityLink + "\n" + tlsLink + "\n" + realityLink + "\n")
	if vless != 2 || reality != 1 {
		t.Fatalf("vless=%d reality=%d", vless, reality)
	}
}

func TestExtractVLESSDeduplicatesAndTrims(t *testing.T) {
	html := `<a href="` + tlsLink + `">x</a> (` + realityLink + `), "` + realityLink + `"`
	links := ExtractVLESS(html)
	if len(links) != 2 {
		t.Fatalf("links=%v", links)
	}
	for _, link := range links {
		if strings.HasSuffix(link, ",") || strings.HasSuffix(link, ")") {
			t.Fatalf("link was not trimmed: %q", link)
		}
	}
}

func TestIsFeedFile(t *testing.T) {
	for _, name := range []string{"vless", "mixed", "vlessbase64", "sub", "list.txt"} {
		if !IsFeedFile(name) {
			t.Fatalf("IsFeedFile(%q)=false", name)
		}
	}
	for _, name := range []string{"source_status.json", "README.md", "crawler.py", "nodes.md", "all"} {
		if IsFeedFile(name) {
			t.Fatalf("service file %q treated as a feed", name)
		}
	}
	if !IsVLESSOnlyFile("vless") || IsVLESSOnlyFile("mix") || IsVLESSOnlyFile("mixed") {
		t.Fatal("vless-only detection is wrong")
	}
}
