package probe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
)

func TestMeasurerRequiresBothLivenessEndpointsAndAllServiceGates(t *testing.T) {
	client := &http.Client{Transport: gateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusNoContent
		switch request.URL.Host {
		case "api.openai.com":
			status = http.StatusUnauthorized
		case "web.telegram.org":
			status = http.StatusOK
		case "speed.cloudflare.com":
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(make([]byte, 1024))), Header: make(http.Header)}, nil
	})}
	measurer := Measurer{
		ClientFactory: func(string) *http.Client { return client },
		MTProtoCheck:  func(context.Context, string) bool { return true },
		UDPCheck:      func(context.Context, string) bool { return true },
		Now:           func() time.Time { return time.Unix(1, 0) },
	}
	metrics, err := measurer.Measure(context.Background(), "127.0.0.1:1080", health.ProtocolVLESS)
	if err != nil || metrics.SuccessRatio != 1 || !metrics.ChatGPTWeb || !metrics.OpenAI401 || !metrics.TelegramWeb || !metrics.TelegramMTProto || !metrics.YouTubeWeb || !metrics.UDP {
		t.Fatalf("metrics=%+v err=%v", metrics, err)
	}
}

func TestMeasurerUsesRealQUICForVLESSUDPQualification(t *testing.T) {
	called := 0
	measurer := Measurer{
		ClientFactory: func(string) *http.Client { return qoeSuccessClient() },
		MTProtoCheck:  func(context.Context, string) bool { return true },
		UDPCheck: func(_ context.Context, socksAddress string) bool {
			called++
			if socksAddress != "127.0.0.1:1080" {
				t.Fatalf("SOCKS address=%s", socksAddress)
			}
			return false
		},
	}
	metrics, err := measurer.Measure(context.Background(), "127.0.0.1:1080", health.ProtocolVLESS)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 || metrics.UDP {
		t.Fatalf("QUIC checks=%d UDP=%v", called, metrics.UDP)
	}
}

func TestMeasurerUsesGeneralUDPOnlyForStandardVision(t *testing.T) {
	for _, test := range []struct {
		name       string
		flow       string
		wantUDP    bool
		wantQUIC   int
		wantDNSUDP int
	}{
		{name: "standard vision", flow: "xtls-rprx-vision", wantUDP: true, wantDNSUDP: 1},
		{name: "vision udp443", flow: "xtls-rprx-vision-udp443", wantQUIC: 1},
		{name: "empty flow", wantQUIC: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			quicChecks := 0
			dnsUDPChecks := 0
			measurer := Measurer{
				ClientFactory: func(string) *http.Client { return qoeSuccessClient() },
				MTProtoCheck:  func(context.Context, string) bool { return true },
				UDPCheck: func(context.Context, string) bool {
					quicChecks++
					return false
				},
				VisionUDPCheck: func(context.Context, string) bool {
					dnsUDPChecks++
					return true
				},
			}
			metrics, err := measurer.MeasureVLESS(
				context.Background(), "127.0.0.1:1080", test.flow,
			)
			if err != nil {
				t.Fatal(err)
			}
			if metrics.UDP != test.wantUDP || quicChecks != test.wantQUIC || dnsUDPChecks != test.wantDNSUDP {
				t.Fatalf("UDP=%v QUIC checks=%d DNS UDP checks=%d", metrics.UDP, quicChecks, dnsUDPChecks)
			}
		})
	}
}

func TestMeasurerReturnsAtDeadlineWhenResponseBodyStalls(t *testing.T) {
	body := newBlockingBody()
	transport := &closeTrackingTransport{roundTrip: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	}}
	client := &http.Client{Transport: transport}
	measurer := Measurer{
		ClientFactory: func(string) *http.Client { return client },
		MTProtoCheck:  func(context.Context, string) bool { return true },
		UDPCheck:      func(context.Context, string) bool { return true },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := measurer.Measure(ctx, "127.0.0.1:1080", health.ProtocolVLESS)
	if err == nil {
		t.Fatal("expected deadline error")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("probe ignored deadline: %s", elapsed)
	}
	if !body.Closed() {
		t.Fatal("stalled response body was not closed")
	}
	if transport.closed.Load() != 1 {
		t.Fatalf("client closes=%d", transport.closed.Load())
	}
}

type blockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingBody() *blockingBody {
	return &blockingBody{closed: make(chan struct{})}
}

func (body *blockingBody) Read([]byte) (int, error) {
	<-body.closed
	return 0, io.EOF
}

func (body *blockingBody) Close() error {
	body.once.Do(func() { close(body.closed) })
	return nil
}

func (body *blockingBody) Closed() bool {
	select {
	case <-body.closed:
		return true
	default:
		return false
	}
}
