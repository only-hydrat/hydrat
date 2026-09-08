package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Kind string

const (
	KindInvalid           Kind = "invalid"
	KindVLESS             Kind = "vless"
	KindVLESSSubscription Kind = "vless_subscription"
	KindTorBridge         Kind = "tor_bridge"
	KindTorSubscription   Kind = "tor_subscription"
	KindRemoteAuto        Kind = "remote_auto"
)

var supportedTorTransports = map[string]bool{
	"obfs4":     true,
	"webtunnel": true,
}

type PreviewItem struct {
	Line        int    `json:"line"`
	Kind        Kind   `json:"kind"`
	Display     string `json:"display,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Duplicate   bool   `json:"duplicate,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (item PreviewItem) Safe() PreviewItem {
	item.Payload = ""
	return item
}

type Preview struct {
	Items          []PreviewItem `json:"items"`
	ValidCount     int           `json:"valid_count"`
	DuplicateCount int           `json:"duplicate_count"`
	ErrorCount     int           `json:"error_count"`
}

func PreviewInput(input string) Preview {
	preview := Preview{}
	seen := make(map[string]struct{})
	for index, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item := parseLine(index+1, line)
		if item.Error != "" {
			preview.ErrorCount++
		} else if _, exists := seen[item.Fingerprint]; exists {
			item.Duplicate = true
			preview.DuplicateCount++
		} else {
			seen[item.Fingerprint] = struct{}{}
			preview.ValidCount++
		}
		preview.Items = append(preview.Items, item)
	}
	return preview
}

func parseLine(lineNumber int, line string) PreviewItem {
	if strings.HasPrefix(line, "proxy-source ") {
		return parseRemote(lineNumber, KindVLESSSubscription, strings.TrimSpace(strings.TrimPrefix(line, "proxy-source ")))
	}
	if strings.HasPrefix(line, "tor-source ") {
		return parseRemote(lineNumber, KindTorSubscription, strings.TrimSpace(strings.TrimPrefix(line, "tor-source ")))
	}
	if strings.HasPrefix(line, "tor-bridge ") {
		line = "Bridge " + strings.TrimSpace(strings.TrimPrefix(line, "tor-bridge "))
	}
	if strings.HasPrefix(line, "Bridge ") ||
		looksLikeVanillaBridge(line) ||
		looksLikeSupportedTransportBridge(line) {
		return parseTorBridge(lineNumber, line)
	}
	if strings.HasPrefix(line, "vless://") {
		return parseVLESS(lineNumber, line)
	}
	if parsed, err := url.Parse(line); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		return parseRemote(lineNumber, KindRemoteAuto, line)
	}
	return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "unsupported source format"}
}

func parseVLESS(lineNumber int, raw string) PreviewItem {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil || parsed.User.Username() == "" || parsed.Hostname() == "" {
		return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "invalid VLESS URI"}
	}
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonicalQuery := url.Values{}
	for _, key := range keys {
		values := append([]string(nil), query[key]...)
		sort.Strings(values)
		for _, value := range values {
			canonicalQuery.Add(key, value)
		}
	}
	canonical := fmt.Sprintf("vless://%s@%s", parsed.User.Username(), strings.ToLower(parsed.Host))
	if encoded := canonicalQuery.Encode(); encoded != "" {
		canonical += "?" + encoded
	}
	display, _ := url.PathUnescape(parsed.Fragment)
	if strings.TrimSpace(display) == "" {
		display = parsed.Host
	}
	return PreviewItem{
		Line:        lineNumber,
		Kind:        KindVLESS,
		Display:     display,
		Fingerprint: fingerprint(canonical),
		Payload:     raw,
	}
}

func parseRemote(lineNumber int, kind Kind, raw string) PreviewItem {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "invalid subscription URL"}
	}
	parsed.Fragment = ""
	return PreviewItem{
		Line:        lineNumber,
		Kind:        kind,
		Display:     parsed.Host,
		Fingerprint: fingerprint(kindString(kind) + ":" + parsed.String()),
		Payload:     raw,
	}
}

func parseTorBridge(lineNumber int, raw string) PreviewItem {
	parts := strings.Fields(raw)
	if len(parts) > 0 && parts[0] == "Bridge" {
		parts = parts[1:]
	}
	if len(parts) < 2 {
		return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "invalid Tor bridge line"}
	}
	fingerprintIndex := 1
	if !strings.Contains(parts[0], ":") {
		if !supportedTorTransports[parts[0]] {
			return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "unsupported Tor bridge transport"}
		}
		fingerprintIndex = 2
	}
	if len(parts) <= fingerprintIndex ||
		!validBridgeAddress(parts[fingerprintIndex-1]) ||
		!validHexFingerprint(parts[fingerprintIndex]) {
		return PreviewItem{Line: lineNumber, Kind: KindInvalid, Error: "invalid Tor bridge line"}
	}
	canonical := "Bridge " + strings.Join(parts, " ")
	return PreviewItem{
		Line:        lineNumber,
		Kind:        KindTorBridge,
		Display:     "Tor bridge " + shortFingerprint(parts[fingerprintIndex]),
		Fingerprint: fingerprint(canonical),
		Payload:     canonical,
	}
}

func looksLikeVanillaBridge(line string) bool {
	parts := strings.Fields(line)
	return len(parts) == 2 && strings.Contains(parts[0], ":") && validHexFingerprint(parts[1])
}

func looksLikeSupportedTransportBridge(line string) bool {
	parts := strings.Fields(line)
	return len(parts) >= 3 && supportedTorTransports[parts[0]]
}

func validBridgeAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func validHexFingerprint(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func shortFingerprint(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func fingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func kindString(kind Kind) string { return string(kind) }
