package freesubs

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
)

var (
	vlessPattern = regexp.MustCompile(`vless://[^\s"'<>\x60\\]+`)
	urlPattern   = regexp.MustCompile(`https?://[^\s"'<>\x60\\]+`)
)

// maxLinksPerFeed bounds how many links a single feed may contribute.
const maxLinksPerFeed = 20000

// decodeBody returns the subscription text, transparently unwrapping base64
// bodies produced by subscription panel generators.
func decodeBody(body []byte) (string, bool) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return "", false
	}
	if looksLikeSubscriptionText(raw) {
		return raw, false
	}
	compact := compactBase64(raw)
	if compact == "" {
		return raw, false
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(compact)
		if err != nil || len(decoded) == 0 {
			continue
		}
		text := strings.TrimSpace(string(decoded))
		if looksLikeSubscriptionText(text) {
			return text, true
		}
	}
	return raw, false
}

func looksLikeSubscriptionText(text string) bool {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "vless://") {
		return true
	}
	return strings.Contains(lower, "proxies:") && strings.Contains(lower, "vless")
}

func compactBase64(text string) string {
	var builder strings.Builder
	for _, char := range text {
		switch {
		case char == '\n' || char == '\r' || char == ' ' || char == '\t':
			continue
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z',
			char >= '0' && char <= '9', char == '+', char == '/', char == '=', char == '-', char == '_':
			builder.WriteRune(char)
		default:
			return ""
		}
	}
	return builder.String()
}

// ExtractVLESS returns the unique VLESS URIs found in a subscription body.
func ExtractVLESS(text string) []string {
	text = html.UnescapeString(strings.ReplaceAll(text, "\\/", "/"))
	seen := make(map[string]struct{})
	links := make([]string, 0, 64)
	for _, match := range vlessPattern.FindAllString(text, maxLinksPerFeed) {
		link := cleanLink(match)
		if !strings.HasPrefix(link, "vless://") || !strings.Contains(link, "@") {
			continue
		}
		if _, exists := seen[link]; exists {
			continue
		}
		seen[link] = struct{}{}
		links = append(links, link)
	}
	return links
}

// CountVLESS returns the number of VLESS URIs and how many of them use REALITY.
func CountVLESS(text string) (vless, reality int) {
	links := ExtractVLESS(text)
	for _, link := range links {
		if strings.Contains(strings.ToLower(link), "security=reality") {
			reality++
		}
	}
	return len(links), reality
}

// ExtractSubscriptionLinks returns candidate subscription URLs published on an
// index page or inside another feed.
func ExtractSubscriptionLinks(text string) []string {
	text = html.UnescapeString(strings.ReplaceAll(text, "\\/", "/"))
	seen := make(map[string]struct{})
	links := make([]string, 0, 16)
	for _, match := range urlPattern.FindAllString(text, 5000) {
		link := cleanLink(match)
		parsed, err := url.Parse(link)
		if err != nil || parsed.Host == "" || !looksLikeSubscriptionURL(parsed) {
			continue
		}
		parsed.Fragment = ""
		normalized := parsed.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		links = append(links, normalized)
	}
	return links
}

func looksLikeSubscriptionURL(parsed *url.URL) bool {
	path := strings.ToLower(parsed.Path)
	switch {
	case strings.HasSuffix(path, ".txt"), strings.HasSuffix(path, ".yaml"),
		strings.HasSuffix(path, ".yml"), strings.HasSuffix(path, ".json"),
		strings.HasSuffix(path, ".conf"):
		return true
	}
	last := path
	if index := strings.LastIndex(path, "/"); index >= 0 {
		last = path[index+1:]
	}
	switch last {
	case "sub", "subs", "vless", "mix", "mixed", "all", "nodes", "list", "raw":
		return true
	}
	return false
}

func cleanLink(link string) string {
	link = strings.TrimSpace(link)
	link = strings.TrimRight(link, ".,;:)]}>\u00ab\u00bb")
	link = strings.ReplaceAll(link, "&amp;", "&")
	return link
}

// IsFeedFile reports whether a repository file name looks like a subscription
// feed worth checking (VLESS lists, mixed lists, published subscriptions).
func IsFeedFile(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".md"), strings.HasSuffix(lower, ".py"),
		strings.HasSuffix(lower, ".go"), strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".lock"):
		return false
	}
	for _, marker := range []string{"vless", "reality", "mix", "sub", "list", "nodes"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// IsVLESSOnlyFile reports whether a feed file publishes VLESS links only.
func IsVLESSOnlyFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "vless") && !strings.Contains(lower, "mix")
}
