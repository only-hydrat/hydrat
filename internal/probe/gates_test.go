package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPServiceGatesRequireChatGPTOpenAI401AndTelegramWeb(t *testing.T) {
	client := gateClient(map[string]int{
		"chatgpt.com":      http.StatusOK,
		"api.openai.com":   http.StatusUnauthorized,
		"web.telegram.org": http.StatusOK,
	})
	result := CheckHTTPGates(context.Background(), client)
	if !result.ChatGPTWeb || !result.OpenAI401 || !result.TelegramWeb || !result.YouTubeWeb || !result.InstagramWeb {
		t.Fatalf("gates=%+v", result)
	}
}

func TestHTTPServiceGatesRejectRouteThatCannotReachYouTube(t *testing.T) {
	result := CheckHTTPGates(context.Background(), gateClient(map[string]int{
		"chatgpt.com":      http.StatusOK,
		"api.openai.com":   http.StatusUnauthorized,
		"web.telegram.org": http.StatusOK,
		"www.youtube.com":  http.StatusServiceUnavailable,
	}))
	if result.YouTubeWeb {
		t.Fatalf("YouTube gate unexpectedly passed: %+v", result)
	}
}

func TestHTTPServiceGatesRejectRouteThatCannotReachInstagram(t *testing.T) {
	result := CheckHTTPGates(context.Background(), gateClient(map[string]int{
		"chatgpt.com":       http.StatusOK,
		"api.openai.com":    http.StatusUnauthorized,
		"web.telegram.org":  http.StatusOK,
		"www.instagram.com": http.StatusServiceUnavailable,
	}))
	if result.InstagramWeb {
		t.Fatalf("Instagram gate unexpectedly passed: %+v", result)
	}
}

func TestHTTPServiceGatesAcceptAuthenticChatGPTChallengeStatuses(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := gateClient(map[string]int{
				"chatgpt.com":      status,
				"api.openai.com":   http.StatusUnauthorized,
				"web.telegram.org": http.StatusOK,
			})
			result := CheckHTTPGates(context.Background(), client)
			if !result.ChatGPTWeb || !result.OpenAI401 || !result.TelegramWeb {
				t.Fatalf("gates=%+v", result)
			}
		})
	}
}

func TestHTTPServiceGatesRejectRestrictedOrUnexpectedStatuses(t *testing.T) {
	tests := []struct {
		name     string
		statuses map[string]int
	}{
		{"chatgpt 451", map[string]int{"chatgpt.com": http.StatusUnavailableForLegalReasons, "api.openai.com": http.StatusUnauthorized, "web.telegram.org": http.StatusOK}},
		{"openai regional 403", map[string]int{"chatgpt.com": http.StatusOK, "api.openai.com": http.StatusForbidden, "web.telegram.org": http.StatusOK}},
		{"telegram 403", map[string]int{"chatgpt.com": http.StatusOK, "api.openai.com": http.StatusUnauthorized, "web.telegram.org": http.StatusForbidden}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := CheckHTTPGates(context.Background(), gateClient(test.statuses))
			if result.ChatGPTWeb && result.OpenAI401 && result.TelegramWeb {
				t.Fatalf("unexpected success: %+v", result)
			}
		})
	}
}

func TestHTTPServiceReachabilityAcceptsNonServerResponsesAsControlProof(t *testing.T) {
	result := CheckHTTPReachability(context.Background(), gateClient(map[string]int{
		"chatgpt.com":      http.StatusForbidden,
		"api.openai.com":   http.StatusForbidden,
		"web.telegram.org": http.StatusUnavailableForLegalReasons,
	}))
	if !result.ChatGPTWeb || !result.OpenAI401 || !result.TelegramWeb {
		t.Fatalf("reachability=%+v", result)
	}
}

func TestHTTPServiceReachabilityRejectsServerFailures(t *testing.T) {
	result := CheckHTTPReachability(context.Background(), gateClient(map[string]int{
		"chatgpt.com":      http.StatusServiceUnavailable,
		"api.openai.com":   http.StatusBadGateway,
		"web.telegram.org": http.StatusGatewayTimeout,
	}))
	if result.ChatGPTWeb || result.OpenAI401 || result.TelegramWeb {
		t.Fatalf("reachability=%+v", result)
	}
}

func TestHTTPServiceGatesEvaluateOriginStatusWithoutFollowingRedirects(t *testing.T) {
	var redirectTargets atomic.Int32
	client := &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusOK
		header := make(http.Header)
		switch request.URL.Host {
		case "chatgpt.com":
			status = http.StatusFound
			header.Set("Location", "https://redirect.test/chatgpt")
		case "api.openai.com":
			status = http.StatusFound
			header.Set("Location", "https://redirect.test/openai")
		case "redirect.test":
			redirectTargets.Add(1)
			if request.URL.Path == "/openai" {
				status = http.StatusUnauthorized
			} else {
				status = http.StatusUnavailableForLegalReasons
			}
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     header,
		}, nil
	})}

	result := CheckHTTPGates(context.Background(), client)
	if !result.ChatGPTWeb || result.OpenAI401 || !result.TelegramWeb {
		t.Fatalf("origin gates=%+v", result)
	}
	if calls := redirectTargets.Load(); calls != 0 {
		t.Fatalf("followed %d redirect targets", calls)
	}
}

func gateClient(statuses map[string]int) *http.Client {
	return &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status, exists := statuses[request.URL.Host]
		if !exists && (request.URL.Host == "www.youtube.com" || request.URL.Host == "www.instagram.com") {
			status = http.StatusOK
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})}
}

func TestMTProtoGateUsesUnauthenticatedReqPQMulti(t *testing.T) {
	connection := &mtprotoConn{}
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) { return connection, nil })
	ok, err := CheckTelegramMTProto(context.Background(), dialer, []string{"149.154.167.50:443"})
	if err != nil || !ok {
		t.Fatalf("MTProto gate ok=%v err=%v", ok, err)
	}
	if len(connection.request) < 1+20+20 || connection.request[0] != 0xef {
		t.Fatalf("not abridged MTProto: %x", connection.request)
	}
	payload := connection.request[2:]
	if constructor := binary.LittleEndian.Uint32(payload[20:24]); constructor != reqPQMultiConstructor {
		t.Fatalf("constructor=%x", constructor)
	}
}

type gateRoundTripFunc func(*http.Request) (*http.Response, error)

func (function gateRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (function dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

type mtprotoConn struct {
	request  []byte
	response *bytes.Reader
}

func (connection *mtprotoConn) Write(data []byte) (int, error) {
	connection.request = append(connection.request, data...)
	if len(connection.request) >= 42 {
		requestPayload := connection.request[2:]
		responsePayload := make([]byte, 20+4+16)
		binary.LittleEndian.PutUint32(responsePayload[16:20], 20)
		binary.LittleEndian.PutUint32(responsePayload[20:24], resPQConstructor)
		copy(responsePayload[24:40], requestPayload[24:40])
		framed := append([]byte{byte(len(responsePayload) / 4)}, responsePayload...)
		connection.response = bytes.NewReader(framed)
	}
	return len(data), nil
}

func (connection *mtprotoConn) Read(data []byte) (int, error) {
	if connection.response == nil {
		return 0, io.EOF
	}
	return connection.response.Read(data)
}
func (*mtprotoConn) Close() error                     { return nil }
func (*mtprotoConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*mtprotoConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*mtprotoConn) SetDeadline(time.Time) error      { return nil }
func (*mtprotoConn) SetReadDeadline(time.Time) error  { return nil }
func (*mtprotoConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (address dummyAddr) Network() string { return "tcp" }
func (address dummyAddr) String() string  { return string(address) }

func TestConfigurableGateEndpointsAndCustomGates(t *testing.T) {
	client := &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusOK
		switch request.URL.Host {
		case "custom-yt.test":
			status = http.StatusNoContent
		case "custom-tg.test":
			status = http.StatusOK
		case "custom-api.test":
			status = http.StatusAccepted
		default:
			status = http.StatusNotFound
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})}

	cfg := HTTPGateConfig{
		YouTubeURL:  "https://custom-yt.test/generate_204",
		TelegramURL: "https://custom-tg.test/",
		CustomGates: []CustomGateCheck{
			{
				Name:       "my_custom_service",
				URL:        "https://custom-api.test/status",
				Acceptable: StatusesAcceptable([]int{http.StatusAccepted}),
			},
		},
	}

	result := CheckHTTPGatesWithConfig(context.Background(), client, cfg)
	if !result.YouTubeWeb {
		t.Fatal("custom youtube endpoint should pass")
	}
	if !result.TelegramWeb {
		t.Fatal("custom telegram endpoint should pass")
	}
	if result.ChatGPTWeb || result.OpenAI401 {
		t.Fatal("unconfigured default endpoints returning 404 should fail")
	}
	if !result.CustomGates["my_custom_service"] {
		t.Fatal("custom gate should pass")
	}
}
