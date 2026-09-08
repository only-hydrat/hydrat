package xrayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Identity struct {
	RouteKey      string
	FailureDomain string
}

func VLESSIdentity(link string) (Identity, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil ||
		parsed.Scheme != "vless" ||
		parsed.User == nil ||
		parsed.User.Username() == "" ||
		parsed.Hostname() == "" ||
		parsed.Port() == "" {
		return Identity{}, errors.New("invalid VLESS link")
	}

	host, err := normalizeIdentityHost(parsed.Hostname())
	if err != nil {
		return Identity{}, errors.New("invalid VLESS host")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return Identity{}, errors.New("invalid VLESS port")
	}
	portText := strconv.Itoa(port)

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return Identity{}, errors.New("invalid VLESS query")
	}
	transport, err := unambiguousIdentityValue(query, "type", "tcp")
	if err != nil {
		return Identity{}, err
	}
	if transport == "websocket" {
		transport = "ws"
	}
	switch transport {
	case "tcp", "raw", "xhttp", "ws", "grpc":
	default:
		return Identity{}, errors.New("unsupported VLESS transport")
	}

	security, err := unambiguousIdentityValue(query, "security", "none")
	if err != nil {
		return Identity{}, err
	}
	switch security {
	case "", "none":
		security = "none"
	case "reality":
		publicKey, valueErr := unambiguousIdentityValue(query, "pbk", "")
		if valueErr != nil {
			return Identity{}, valueErr
		}
		if publicKey == "" {
			return Identity{}, errors.New("Reality public key is required")
		}
	case "tls":
	default:
		return Identity{}, errors.New("unsupported VLESS security")
	}

	serverName := ""
	if security == "tls" || security == "reality" {
		serverName, err = unambiguousIdentityValue(query, "sni", host)
		if err != nil {
			return Identity{}, err
		}
		serverName, err = normalizeIdentityHost(serverName)
		if err != nil {
			return Identity{}, errors.New("invalid VLESS server name")
		}
	}

	frontingHost := ""
	if transport == "ws" || transport == "xhttp" {
		frontingHost, err = unambiguousIdentityValue(query, "host", "")
		if err != nil {
			return Identity{}, err
		}
		if frontingHost != "" {
			frontingHost, err = normalizeIdentityFrontingHost(frontingHost)
			if err != nil {
				return Identity{}, errors.New("invalid VLESS fronting host")
			}
		}
	}

	failureCanonical := strings.Join([]string{"v1", host, portText}, "|")
	routeCanonical := strings.Join([]string{
		"v1", host, portText, transport, security, serverName, frontingHost,
	}, "|")
	return Identity{
		RouteKey:      prefixedIdentityDigest("route-v1-", routeCanonical),
		FailureDomain: prefixedIdentityDigest("domain-v1-", failureCanonical),
	}, nil
}

func unambiguousIdentityValue(query url.Values, key, fallback string) (string, error) {
	values, present := query[key]
	if !present {
		return fallback, nil
	}
	if len(values) != 1 {
		return "", errors.New("ambiguous VLESS query")
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func normalizeIdentityFrontingHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty fronting host")
	}
	if strings.HasPrefix(value, "[") {
		return normalizeBracketedIdentityFrontingHost(value)
	}
	switch strings.Count(value, ":") {
	case 0:
		return normalizeIdentityHost(value)
	case 1:
		host, portText, err := net.SplitHostPort(value)
		if err != nil {
			return "", err
		}
		normalizedHost, err := normalizeIdentityHost(host)
		if err != nil {
			return "", err
		}
		port, err := normalizeIdentityPort(portText)
		if err != nil {
			return "", err
		}
		return normalizedHost + ":" + port, nil
	default:
		return "", errors.New("ambiguous IPv6 fronting host")
	}
}

func normalizeBracketedIdentityFrontingHost(value string) (string, error) {
	closingBracket := strings.IndexByte(value, ']')
	if closingBracket < 0 {
		return "", errors.New("unclosed IPv6 fronting host")
	}
	address, err := netip.ParseAddr(value[1:closingBracket])
	if err != nil || !address.Is6() || address.Zone() != "" {
		return "", errors.New("invalid IPv6 fronting host")
	}
	address = address.Unmap()
	host := address.String()
	if address.Is6() {
		host = "[" + host + "]"
	}

	suffix := value[closingBracket+1:]
	if suffix == "" {
		return host, nil
	}
	if !strings.HasPrefix(suffix, ":") {
		return "", errors.New("invalid IPv6 fronting host suffix")
	}
	port, err := normalizeIdentityPort(strings.TrimPrefix(suffix, ":"))
	if err != nil {
		return "", err
	}
	return host + ":" + port, nil
}

func normalizeIdentityPort(value string) (string, error) {
	if value == "" {
		return "", errors.New("invalid fronting host port")
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return "", errors.New("invalid fronting host port")
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid fronting host port")
	}
	return strconv.Itoa(port), nil
}

func normalizeIdentityHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || strings.Contains(value, "|") || containsIdentityControl(value) {
		return "", errors.New("invalid host")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String(), nil
	}
	if strings.Contains(value, ":") || len(value) > 253 {
		return "", errors.New("invalid host")
	}

	labels := strings.Split(value, ".")
	numericLabels := len(labels) == 4
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid host")
		}
		numericLabel := true
		for _, character := range []byte(label) {
			if !isIdentityHostnameCharacter(character) {
				return "", errors.New("invalid host")
			}
			if character < '0' || character > '9' {
				numericLabel = false
			}
		}
		numericLabels = numericLabels && numericLabel
	}
	if numericLabels {
		return "", errors.New("invalid IPv4 address")
	}
	return strings.ToLower(value), nil
}

func isIdentityHostnameCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '-'
}

func containsIdentityControl(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func prefixedIdentityDigest(prefix, canonical string) string {
	digest := sha256.Sum256([]byte(canonical))
	return prefix + hex.EncodeToString(digest[:])
}
