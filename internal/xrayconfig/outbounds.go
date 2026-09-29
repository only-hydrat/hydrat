package xrayconfig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func VLESSOutbound(link, tag string) (map[string]any, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil || parsed.User.Username() == "" || parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, errors.New("invalid VLESS link")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid VLESS port")
	}
	query := parsed.Query()
	transport := first(query, "type", "tcp")
	if transport == "websocket" {
		transport = "ws"
	}
	if transport != "tcp" && transport != "raw" && transport != "xhttp" && transport != "ws" && transport != "grpc" {
		return nil, fmt.Errorf("unsupported VLESS transport %q", transport)
	}
	security := first(query, "security", "")
	if security != "" && security != "none" && security != "reality" && security != "tls" {
		return nil, fmt.Errorf("unsupported VLESS security %q", security)
	}
	user := map[string]any{"id": parsed.User.Username(), "encryption": first(query, "encryption", "none")}
	if flow := first(query, "flow", ""); flow != "" {
		user["flow"] = flow
	}
	stream := map[string]any{"network": transport}
	switch transport {
	case "tcp":
		stream["tcpSettings"] = map[string]any{}
	case "raw":
		stream["rawSettings"] = map[string]any{}
	case "xhttp":
		extraMode, extraPadding, extra := xhttpExtra(query.Get("extra"))
		settings := map[string]any{"path": first(query, "path", "/")}
		optional(settings, "mode", first(query, "mode", extraMode))
		optional(settings, "host", first(query, "host", ""))
		padding := first(query, "x_padding_bytes", first(query, "xPaddingBytes", extraPadding))
		optional(settings, "xPaddingBytes", padding)
		if len(extra) > 0 {
			settings["extra"] = extra
		}
		stream["xhttpSettings"] = settings
	case "ws":
		settings := map[string]any{"path": first(query, "path", "/")}
		if host := first(query, "host", ""); host != "" {
			settings["headers"] = map[string]string{"Host": host}
		}
		stream["wsSettings"] = settings
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": first(query, "serviceName", first(query, "path", ""))}
	}
	serverName := first(query, "sni", parsed.Hostname())
	switch security {
	case "reality":
		publicKey := first(query, "pbk", "")
		if publicKey == "" {
			return nil, errors.New("Reality public key is required")
		}
		settings := map[string]any{
			"serverName": serverName, "fingerprint": first(query, "fp", "chrome"), "password": publicKey,
		}
		optional(settings, "shortId", first(query, "sid", ""))
		optional(settings, "spiderX", first(query, "spx", ""))
		optional(settings, "mldsa65Verify", first(query, "pqv", ""))
		stream["security"] = "reality"
		stream["realitySettings"] = settings
	case "tls":
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"serverName": serverName, "fingerprint": first(query, "fp", "chrome"),
		}
	}
	return map[string]any{
		"tag": tag, "protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": parsed.Hostname(), "port": port, "users": []any{user},
		}}},
		"streamSettings": stream,
	}, nil
}

func xhttpExtra(value string) (mode, padding string, raw json.RawMessage) {
	value = strings.TrimSpace(value)
	if value == "" || value[0] != '{' {
		return "", "", nil
	}
	var extra struct {
		Mode          string `json:"mode"`
		XPaddingBytes string `json:"xPaddingBytes"`
	}
	if json.Unmarshal([]byte(value), &extra) != nil {
		return "", "", nil
	}
	return strings.TrimSpace(extra.Mode), strings.TrimSpace(extra.XPaddingBytes), json.RawMessage(value)
}

func TorOutbound(socksAddress, tag, clientID string, secret []byte) map[string]any {
	host, portText, err := net.SplitHostPort(socksAddress)
	if err != nil {
		host, portText = "127.0.0.1", "9050"
	}
	port, _ := strconv.Atoi(portText)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(clientID))
	password := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
	return map[string]any{
		"tag": tag, "protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": host, "port": port,
			"users": []any{map[string]any{"user": "hydrat-" + clientID, "pass": password}},
		}}},
	}
}

func first(query url.Values, key, fallback string) string {
	value := strings.TrimSpace(query.Get(key))
	if value == "" {
		return fallback
	}
	return value
}

func optional(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}
