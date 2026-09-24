package probe

import (
	"context"
	"net/http"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/socks5"
)

type Measurer struct {
	GateConfig     HTTPGateConfig
	ClientFactory  func(string) *http.Client
	MTProtoCheck   func(context.Context, string) bool
	UDPCheck       func(context.Context, string) bool
	VisionUDPCheck func(context.Context, string) bool
	Now            func() time.Time
}

func (measurer Measurer) Measure(ctx context.Context, socksAddress string, protocol health.Protocol) (health.Metrics, error) {
	return measurer.measure(ctx, socksAddress, protocol, measurer.UDPCheck)
}

func (measurer Measurer) MeasureVLESS(ctx context.Context, socksAddress, flow string) (health.Metrics, error) {
	udpCheck := measurer.UDPCheck
	if flow == "xtls-rprx-vision" {
		udpCheck = measurer.VisionUDPCheck
		if udpCheck == nil {
			udpCheck = CheckUDPDNS
		}
	}
	return measurer.measure(ctx, socksAddress, health.ProtocolVLESS, udpCheck)
}

func (measurer Measurer) measure(
	ctx context.Context,
	socksAddress string,
	protocol health.Protocol,
	udpCheck func(context.Context, string) bool,
) (health.Metrics, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	now := measurer.Now
	if now == nil {
		now = time.Now
	}
	client := measurer.client(socksAddress)
	defer client.CloseIdleConnections()
	metrics := health.Metrics{}
	latencies := make([]time.Duration, 0, 2)
	for _, endpoint := range []string{"https://cp.cloudflare.com/generate_204", "https://www.gstatic.com/generate_204"} {
		started := now()
		if requestOK(ctx, client, endpoint) {
			latencies = append(latencies, now().Sub(started))
		}
	}
	metrics.SuccessRatio = float64(len(latencies)) / 2
	metrics.PacketDropRatio = 1 - metrics.SuccessRatio
	for _, latency := range latencies {
		metrics.Latency += latency
	}
	if len(latencies) > 0 {
		metrics.Latency /= time.Duration(len(latencies))
	}

	gates := CheckHTTPGatesWithConfig(ctx, client, measurer.GateConfig)
	metrics.ChatGPTWeb = gates.ChatGPTWeb
	metrics.OpenAI401 = gates.OpenAI401
	metrics.TelegramWeb = gates.TelegramWeb
	metrics.YouTubeWeb = gates.YouTubeWeb
	metrics.InstagramWeb = gates.InstagramWeb
	metrics.CustomGates = gates.CustomGates
	if err := ctx.Err(); err != nil {
		return metrics, err
	}
	if measurer.MTProtoCheck != nil {
		metrics.TelegramMTProto = measurer.MTProtoCheck(ctx, socksAddress)
	} else {
		dialer := socks5.Dialer{ProxyAddress: socksAddress}
		ok, _ := CheckTelegramMTProto(ctx, dialer, []string{
			"149.154.167.50:443", "149.154.167.51:443", "149.154.175.100:443",
		})
		metrics.TelegramMTProto = ok
	}
	if protocol == health.ProtocolVLESS {
		if udpCheck != nil {
			metrics.UDP = udpCheck(ctx, socksAddress)
		} else {
			metrics.UDP = CheckQUIC(ctx, socksAddress)
		}
	}
	if err := ctx.Err(); err != nil {
		return metrics, err
	}

	started := now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/__down?bytes=1048576", nil)
	if err == nil {
		response, requestErr := client.Do(request)
		if requestErr == nil {
			bytesRead, _ := discardBody(ctx, response.Body, 1024*1024)
			duration := now().Sub(started)
			if response.StatusCode >= 200 && response.StatusCode < 300 && duration > 0 {
				metrics.ThroughputMbps = float64(bytesRead*8) / duration.Seconds() / 1_000_000
			}
		}
	}
	return metrics, ctx.Err()
}

func (measurer Measurer) client(socksAddress string) *http.Client {
	if measurer.ClientFactory != nil {
		return withHTTPTimeout(measurer.ClientFactory(socksAddress), 20*time.Second)
	}
	dialer := socks5.Dialer{ProxyAddress: socksAddress}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

func requestOK(ctx context.Context, client *http.Client, endpoint string) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	if _, err := discardBody(ctx, response.Body, 4096); err != nil {
		return false
	}
	return response.StatusCode >= 200 && response.StatusCode < 400
}

func withHTTPTimeout(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	cloned := *client
	if cloned.Timeout <= 0 || cloned.Timeout > timeout {
		cloned.Timeout = timeout
	}
	return &cloned
}
