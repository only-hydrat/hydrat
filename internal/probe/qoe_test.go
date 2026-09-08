package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEMeasurerReturnsTTFBAndSustainedThroughput(t *testing.T) {
	clock := newStepClock(
		time.Unix(1_800_000_000, 0),
		time.Unix(1_800_000_000, 200_000_000),
		time.Unix(1_800_000_000, 300_000_000),
	)
	body := &trackingBody{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, 65536))}
	client := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Scheme != "https" ||
			request.URL.Host != "speed.cloudflare.com" || request.URL.Path != "/__down" {
			t.Fatalf("request=%s %s", request.Method, request.URL)
		}
		if request.Header.Get("Accept-Encoding") != "identity" ||
			!strings.Contains(request.Header.Get("Cache-Control"), "no-cache") ||
			request.Header.Get("Pragma") != "no-cache" ||
			request.URL.Query().Get("bytes") != "65536" ||
			request.URL.Query().Get("nonce") != "fixed-nonce" {
			t.Fatalf("request headers/query=%v %s", request.Header, request.URL.RawQuery)
		}
		trace := httptrace.ContextClientTrace(request.Context())
		if trace == nil || trace.GotFirstResponseByte == nil {
			t.Fatal("missing HTTP trace")
		}
		trace.GotFirstResponseByte()
		return qoeResponseBody(http.StatusOK, body), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return client },
		DirectClient:  client,
		SampleBytes:   65536,
		Now:           clock.Now,
		Nonce:         func() string { return "fixed-nonce" },
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	wantThroughput := float64(65536*8) / 0.1 / 1_000_000
	if !got.Success || got.Infrastructure || got.Bytes != 65536 ||
		got.At != time.Unix(1_800_000_000, 0) || got.TTFB != 200*time.Millisecond ||
		got.TransferDuration != 100*time.Millisecond || got.ThroughputMbps != wantThroughput {
		t.Fatalf("observation=%+v want throughput=%f", got, wantThroughput)
	}
	if !body.Closed() {
		t.Fatal("response body was not closed")
	}
}

func TestQoEMeasurerReportsVLESSQUICIndependentlyFromHealthyTCP(t *testing.T) {
	checks := 0
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return qoeSuccessClient() },
		DirectClient:  qoeSuccessClient(),
		SampleBytes:   65536,
		UDPCheck: func(_ context.Context, socksAddress string) bool {
			checks++
			if socksAddress != "127.0.0.1:1080" {
				t.Fatalf("SOCKS address=%s", socksAddress)
			}
			return false
		},
	})

	got := measurer.MeasureVLESS(context.Background(), "candidate", "127.0.0.1:1080")
	if !got.Success || got.Infrastructure || got.UDPReachable == nil || *got.UDPReachable || checks != 1 {
		t.Fatalf("observation=%+v checks=%d", got, checks)
	}
	plain := measurer.Measure(context.Background(), "tor", "127.0.0.1:1080")
	if plain.UDPReachable != nil || checks != 1 {
		t.Fatalf("plain observation=%+v checks=%d", plain, checks)
	}
}

func TestQoEMeasurerJoinsCanceledUDPCheckBeforeReturning(t *testing.T) {
	udpStarted := make(chan struct{})
	udpCanceled := make(chan struct{})
	releaseUDP := make(chan struct{})
	client := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return qoeResponse(http.StatusServiceUnavailable, nil), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return client },
		DirectClient:  client,
		SampleBytes:   65536,
		UDPCheck: func(ctx context.Context, _ string) bool {
			close(udpStarted)
			<-ctx.Done()
			close(udpCanceled)
			<-releaseUDP
			return false
		},
	})

	returned := make(chan qoe.Observation, 1)
	go func() {
		returned <- measurer.MeasureVLESS(
			context.Background(), "candidate", "127.0.0.1:1080",
		)
	}()

	select {
	case <-udpStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP check did not start")
	}
	select {
	case <-udpCanceled:
	case <-time.After(time.Second):
		t.Fatal("UDP check was not canceled after the TCP result completed")
	}
	select {
	case observation := <-returned:
		close(releaseUDP)
		t.Fatalf("measurement returned before UDP cleanup: %+v", observation)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseUDP)
	select {
	case observation := <-returned:
		if observation.Success || !observation.Infrastructure ||
			observation.ErrorCode != qoeEndpointHTTP {
			t.Fatalf("observation=%+v", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("measurement did not return after UDP cleanup")
	}
}

func TestQoEMeasurerAvailabilityUsesOnlyRoutedAndControlDNS(t *testing.T) {
	routeCalls, directCalls := 0, 0
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		DNSResolvers: []string{"1.1.1.1"},
		DNSRouteCheck: func(context.Context, string, string) error {
			routeCalls++
			return errors.New("routed DNS blocked")
		},
		DNSDirectCheck: func(context.Context, string) error {
			directCalls++
			return nil
		},
		ClientFactory: func(string) *http.Client {
			t.Fatal("availability probe started bulk HTTP measurement")
			return nil
		},
		UDPCheck: func(context.Context, string) bool {
			t.Fatal("availability probe started QUIC measurement")
			return false
		},
	})
	observation := measurer.MeasureAvailability(context.Background(), "candidate", "127.0.0.1:1080")
	if observation.Infrastructure || observation.Success || observation.ErrorCode != qoe.ReasonDNSRoute {
		t.Fatalf("observation=%+v", observation)
	}
	if routeCalls != 1 || directCalls != 1 {
		t.Fatalf("DNS calls route/direct=%d/%d", routeCalls, directCalls)
	}
}

func TestProbeBodyReadersJoinAfterCancellation(t *testing.T) {
	readers := map[string]func(context.Context, io.ReadCloser) (int64, error){
		"application gate": func(ctx context.Context, body io.ReadCloser) (int64, error) {
			return discardBody(ctx, body, 4096)
		},
		"qoe sample": func(ctx context.Context, body io.ReadCloser) (int64, error) {
			return readQoEBody(ctx, body, 4096)
		},
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			body := newCanceledBlockingBody()
			ctx, cancel := context.WithCancel(context.Background())
			returned := make(chan error, 1)
			go func() {
				_, err := read(ctx, body)
				returned <- err
			}()
			select {
			case <-body.started:
			case <-time.After(time.Second):
				t.Fatal("body read did not start")
			}
			cancel()
			select {
			case <-body.closed:
			case <-time.After(time.Second):
				t.Fatal("body was not closed after cancellation")
			}
			select {
			case err := <-returned:
				close(body.release)
				t.Fatalf("reader returned before its goroutine stopped: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(body.release)
			select {
			case err := <-returned:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error=%v want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("reader did not return after its goroutine stopped")
			}
		})
	}
}

func TestQoEMeasurerRejectsRouteWhenApplicationMajorityFailsButDirectControlPasses(t *testing.T) {
	routeClient := qoeSuccessClient()
	directClient := qoeSuccessClient()
	var routeChecks, directChecks int
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
			routeChecks++
			return HTTPGateResult{ChatGPTWeb: true}
		},
		ApplicationControl: func(_ context.Context, client *http.Client) HTTPGateResult {
			if client != directClient {
				t.Fatalf("control client=%p want %p", client, directClient)
			}
			directChecks++
			return HTTPGateResult{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, YouTubeWeb: true}
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || got.Infrastructure || got.ErrorCode != qoeApplicationGates {
		t.Fatalf("observation=%+v", got)
	}
	if routeChecks != 1 || directChecks != 1 {
		t.Fatalf("route checks=%d direct checks=%d", routeChecks, directChecks)
	}
}

func TestQoEMeasurerRejectsRouteWhenClientDNSFailsButDirectControlPasses(t *testing.T) {
	routeClient := qoeSuccessClient()
	dnsFailure := errors.New("route DNS timeout")
	var routeChecks, directChecks int
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		SampleBytes:   65536,
		DNSResolver:   "1.1.1.1",
		DNSRouteCheck: func(_ context.Context, socksAddress, resolver string) error {
			routeChecks++
			if socksAddress != "127.0.0.1:1080" || resolver != "1.1.1.1" {
				t.Fatalf("route DNS target=%s/%s", socksAddress, resolver)
			}
			return dnsFailure
		},
		DNSDirectCheck: func(_ context.Context, resolver string) error {
			directChecks++
			if resolver != "1.1.1.1" {
				t.Fatalf("direct DNS resolver=%s", resolver)
			}
			return nil
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || got.Infrastructure || got.ErrorCode != qoe.ReasonDNSRoute {
		t.Fatalf("observation=%+v", got)
	}
	if routeChecks != 1 || directChecks != 1 {
		t.Fatalf("route checks=%d direct checks=%d", routeChecks, directChecks)
	}
	if _, exists := measurer.recentFailures["candidate"]; exists {
		t.Fatal("DNS failure polluted bulk-endpoint circuit state")
	}
}

func TestQoEMeasurerTreatsSharedDNSFailureAsInfrastructure(t *testing.T) {
	routeClient := qoeSuccessClient()
	var directChecks atomic.Int32
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		SampleBytes:   65536,
		DNSResolvers:  []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		DNSRouteCheck: func(context.Context, string, string) error {
			return errors.New("route DNS timeout")
		},
		DNSDirectCheck: func(context.Context, string) error {
			directChecks.Add(1)
			return errors.New("resolver unavailable")
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || !got.Infrastructure || got.ErrorCode != qoeDNSUnavailable {
		t.Fatalf("observation=%+v", got)
	}
	if _, exists := measurer.recentFailures["candidate"]; exists {
		t.Fatal("shared DNS failure polluted candidate failure state")
	}
	if directChecks.Load() != 3 {
		t.Fatalf("direct DNS checks=%d want all configured resolvers", directChecks.Load())
	}
}

func TestQoEMeasurerRejectsRouteWhenSelectedResolverAndRouteFailButAlternateControlPasses(t *testing.T) {
	resolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	var selected string
	var directResolvers []string
	var directMu sync.Mutex
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return qoeSuccessClient() },
		SampleBytes:   65536,
		DNSResolvers:  resolvers,
		DNSRouteCheck: func(_ context.Context, _ string, resolver string) error {
			selected = resolver
			return errors.New("route DNS timeout")
		},
		DNSDirectCheck: func(_ context.Context, resolver string) error {
			directMu.Lock()
			directResolvers = append(directResolvers, resolver)
			directMu.Unlock()
			if resolver != selected {
				return nil
			}
			return errors.New("selected resolver unavailable")
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || got.Infrastructure || got.ErrorCode != qoe.ReasonDNSRoute {
		t.Fatalf("observation=%+v", got)
	}
	if selected == "" || len(directResolvers) != len(resolvers) {
		t.Fatalf("selected=%q direct checks=%v", selected, directResolvers)
	}
}

func TestQoEMeasurerChecksDNSBeforeBulkTransfer(t *testing.T) {
	var bulkRequests atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		bulkRequests.Add(1)
		return nil, errors.New("bulk transfer must not run after DNS failure")
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DNSResolvers:  []string{"1.1.1.1", "8.8.8.8"},
		DNSRouteCheck: func(context.Context, string, string) error {
			return errors.New("route DNS timeout")
		},
		DNSDirectCheck: func(context.Context, string) error { return nil },
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Infrastructure || got.ErrorCode != qoe.ReasonDNSRoute {
		t.Fatalf("observation=%+v", got)
	}
	if bulkRequests.Load() != 0 {
		t.Fatalf("bulk requests=%d want DNS gate first", bulkRequests.Load())
	}
}

func TestExchangeDNSOverTCPHandlesPartialWritesAndValidatesAnswer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		lengthBytes := make([]byte, 2)
		if _, err := io.ReadFull(server, lengthBytes); err != nil {
			serverResult <- err
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
		if _, err := io.ReadFull(server, query); err != nil {
			serverResult <- err
			return
		}
		if len(query) < 12 {
			serverResult <- errors.New("short DNS query")
			return
		}
		response := append([]byte(nil), query...)
		response[2], response[3] = 0x81, 0x80
		response[6], response[7] = 0, 1
		response = append(response,
			0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4,
		)
		framed := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
		copy(framed[2:], response)
		_, err := io.Copy(server, bytes.NewReader(framed))
		serverResult <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := exchangeDNSOverTCP(ctx, shortWriteConn{Conn: client, limit: 3}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

type shortWriteConn struct {
	net.Conn
	limit int
}

func (connection shortWriteConn) Write(payload []byte) (int, error) {
	if len(payload) > connection.limit {
		payload = payload[:connection.limit]
	}
	return connection.Conn.Write(payload)
}

func TestQoEMeasurerRejectsRouteWhenTelegramFailsEvenIfBothAIGatesPass(t *testing.T) {
	routeClient := qoeSuccessClient()
	directClient := qoeSuccessClient()
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{ChatGPTWeb: true, OpenAI401: true, YouTubeWeb: true}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, YouTubeWeb: true}
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || got.Infrastructure || got.ErrorCode != qoeApplicationGates {
		t.Fatalf("observation=%+v", got)
	}
}

func TestQoEMeasurerBoundsApplicationGateStallIndependently(t *testing.T) {
	routeClient := qoeSuccessClient()
	directClient := qoeSuccessClient()
	var gateBudget time.Duration
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Deadline:      10 * time.Second,
		ApplicationGates: func(ctx context.Context, _ *http.Client) HTTPGateResult {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("application gate context has no deadline")
			}
			gateBudget = time.Until(deadline)
			return HTTPGateResult{ChatGPTWeb: true, OpenAI401: true, YouTubeWeb: true}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, YouTubeWeb: true}
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || got.Infrastructure || got.ErrorCode != qoeApplicationGates {
		t.Fatalf("observation=%+v", got)
	}
	if gateBudget < 2500*time.Millisecond || gateBudget > 3100*time.Millisecond {
		t.Fatalf("application gate budget=%s want about 3s", gateBudget)
	}
}

func TestQoEMeasurerIgnoresApplicationFailureWhenDirectControlAlsoFails(t *testing.T) {
	routeClient := qoeSuccessClient()
	directClient := qoeSuccessClient()
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		ApplicationGates: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{ChatGPTWeb: true}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult {
			return HTTPGateResult{ChatGPTWeb: true}
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Success || !got.Infrastructure || got.ErrorCode != qoeApplicationGatesUnavailable {
		t.Fatalf("observation=%+v", got)
	}
}

func TestQoEMeasurerAcceptsRouteWhenApplicationMajorityPasses(t *testing.T) {
	routeClient := qoeSuccessClient()
	directChecks := 0
	directClient := qoeSuccessClient()
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		ApplicationGates: func(_ context.Context, client *http.Client) HTTPGateResult {
			if client == directClient {
				directChecks++
			}
			return HTTPGateResult{OpenAI401: true, TelegramWeb: true, YouTubeWeb: true}
		},
		ApplicationControl: func(context.Context, *http.Client) HTTPGateResult {
			directChecks++
			return HTTPGateResult{}
		},
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if !got.Success || got.Infrastructure || got.ErrorCode != "" {
		t.Fatalf("observation=%+v", got)
	}
	if directChecks != 0 {
		t.Fatalf("direct checks=%d want 0", directChecks)
	}
}

func qoeSuccessClient() *http.Client {
	return &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.GotFirstResponseByte != nil {
			trace.GotFirstResponseByte()
		}
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
}

func TestQoEMeasurerDefaultNonceIsURLSafeAndFresh(t *testing.T) {
	var nonces []string
	client := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		nonces = append(nonces, request.URL.Query().Get("nonce"))
		trace := httptrace.ContextClientTrace(request.Context())
		trace.GotFirstResponseByte()
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return client },
		DirectClient:  client,
		SampleBytes:   65536,
	})

	for range 2 {
		got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")
		if !got.Success {
			t.Fatalf("observation=%+v", got)
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("nonces=%q", nonces)
	}
	for _, nonce := range nonces {
		raw, err := base64.RawURLEncoding.DecodeString(nonce)
		if err != nil || len(raw) != 18 {
			t.Fatalf("nonce %q decoded length=%d err=%v", nonce, len(raw), err)
		}
	}
}

func TestRandomQoENonceEncodesFreshReaderBytes(t *testing.T) {
	reader := bytes.NewReader(append(
		bytes.Repeat([]byte{0x00}, 18),
		bytes.Repeat([]byte{0xff}, 18)...,
	))
	first := randomQoENonce(reader)
	second := randomQoENonce(reader)
	if first != "AAAAAAAAAAAAAAAAAAAAAAAA" || second != "________________________" {
		t.Fatalf("first=%q second=%q", first, second)
	}
}

func TestQoEMeasurerRequiresExactBoundedResponseSize(t *testing.T) {
	for _, test := range []struct {
		name      string
		size      int
		success   bool
		infra     bool
		errorCode string
		bytes     int64
	}{
		{name: "short", size: 65535, infra: true, errorCode: "qoe_endpoint_size", bytes: 65535},
		{name: "exact", size: 65536, success: true, bytes: 65536},
		{name: "long", size: 65537, infra: true, errorCode: "qoe_endpoint_size", bytes: 65537},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingBody{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, test.size))}
			client := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(request.Context())
				trace.GotFirstResponseByte()
				return qoeResponseBody(http.StatusOK, body), nil
			})}
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return client },
				DirectClient:  client,
				SampleBytes:   65536,
			})

			got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

			if got.Success != test.success || got.Infrastructure != test.infra ||
				got.ErrorCode != test.errorCode || got.Bytes != test.bytes {
				t.Fatalf("observation=%+v", got)
			}
			if !body.Closed() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestQoEMeasurerValidatesResponseContentLengthAndBodyFraming(t *testing.T) {
	for _, test := range []struct {
		name          string
		contentLength int64
		body          io.Reader
		errorCode     string
	}{
		{
			name:          "declared length mismatch",
			contentLength: 65535,
			body:          bytes.NewReader(bytes.Repeat([]byte{'x'}, 65536)),
			errorCode:     "qoe_endpoint_size",
		},
		{
			name:          "unexpected EOF",
			contentLength: 65536,
			body: io.MultiReader(
				bytes.NewReader(bytes.Repeat([]byte{'x'}, 1024)),
				errorReader{err: io.ErrUnexpectedEOF},
			),
			errorCode: "qoe_endpoint_size",
		},
		{
			name:          "chunked body too long",
			contentLength: -1,
			body:          bytes.NewReader(bytes.Repeat([]byte{'x'}, 65537)),
			errorCode:     "qoe_endpoint_size",
		},
		{
			name:          "malformed response length",
			contentLength: -2,
			body:          bytes.NewReader(bytes.Repeat([]byte{'x'}, 65536)),
			errorCode:     "qoe_endpoint_malformed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingBody{Reader: test.body}
			routeClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(request.Context())
				trace.GotFirstResponseByte()
				response := qoeResponseBody(http.StatusOK, body)
				response.ContentLength = test.contentLength
				return response, nil
			})}
			directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
			})}
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return routeClient },
				DirectClient:  directClient,
				SampleBytes:   65536,
			})

			got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

			if got.Success || !got.Infrastructure || got.ErrorCode != test.errorCode {
				t.Fatalf("observation=%+v", got)
			}
			if !body.Closed() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestQoEMeasurerAcceptsRealExplicitAndChunkedLengths(t *testing.T) {
	for _, test := range []struct {
		name              string
		writeResponse     func(http.ResponseWriter)
		wantContentLength int64
	}{
		{
			name: "explicit",
			writeResponse: func(response http.ResponseWriter) {
				response.Header().Set("Content-Length", "65536")
				_, _ = response.Write(bytes.Repeat([]byte{'x'}, 65536))
			},
			wantContentLength: 65536,
		},
		{
			name: "chunked",
			writeResponse: func(response http.ResponseWriter) {
				response.WriteHeader(http.StatusOK)
				response.(http.Flusher).Flush()
				_, _ = response.Write(bytes.Repeat([]byte{'x'}, 65536))
			},
			wantContentLength: -1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				test.writeResponse(response)
			}))
			defer server.Close()

			var contentLength int64
			baseTransport := server.Client().Transport
			client := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := baseTransport.RoundTrip(request)
				if response != nil {
					contentLength = response.ContentLength
				}
				return response, err
			})}
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return client },
				DirectClient:  client,
				Endpoint:      server.URL,
				SampleBytes:   65536,
			})

			got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

			if !got.Success || got.Infrastructure || got.Bytes != 65536 {
				t.Fatalf("observation=%+v", got)
			}
			if contentLength != test.wantContentLength {
				t.Fatalf("ContentLength=%d want=%d", contentLength, test.wantContentLength)
			}
		})
	}
}

func TestQoEMeasurerClassifiesEndpointResponsesAsInfrastructure(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusCode int
		body       []byte
		errorCode  string
	}{
		{name: "server error", statusCode: http.StatusServiceUnavailable, body: bytes.Repeat([]byte{'x'}, 65536), errorCode: "qoe_endpoint_http"},
		{name: "malformed length", statusCode: http.StatusOK, body: []byte("not the promised sample"), errorCode: "qoe_endpoint_size"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingBody{Reader: bytes.NewReader(test.body)}
			client := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(request.Context())
				trace.GotFirstResponseByte()
				return qoeResponseBody(test.statusCode, body), nil
			})}
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return client },
				DirectClient:  client,
				SampleBytes:   65536,
			})

			got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

			if got.Success || !got.Infrastructure || got.ErrorCode != test.errorCode {
				t.Fatalf("observation=%+v", got)
			}
			if !body.Closed() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestQoEMeasurerMapsRouteFailureAfterSuccessfulDirectControl(t *testing.T) {
	for _, test := range []struct {
		name      string
		routeErr  error
		errorCode string
	}{
		{name: "timeout", routeErr: context.DeadlineExceeded, errorCode: "qoe_route_timeout"},
		{name: "tls", routeErr: tls.RecordHeaderError{Msg: "secret tls detail"}, errorCode: "qoe_route_tls"},
		{name: "transport", routeErr: errors.New("secret route detail"), errorCode: "qoe_route_transport"},
	} {
		t.Run(test.name, func(t *testing.T) {
			routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, test.routeErr
			})}
			directBody := &trackingBody{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, 65536))}
			directClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return qoeResponseBody(http.StatusOK, directBody), nil
			})}
			measurer := NewQoEMeasurer(QoEMeasurerConfig{
				ClientFactory: func(string) *http.Client { return routeClient },
				DirectClient:  directClient,
				SampleBytes:   65536,
			})

			got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

			if got.Success || got.Infrastructure || got.ErrorCode != test.errorCode ||
				strings.Contains(got.ErrorCode, "secret") {
				t.Fatalf("observation=%+v", got)
			}
			if !directBody.Closed() {
				t.Fatal("direct response body was not closed")
			}
		})
	}
}

func TestQoEMeasurerFailedDirectControlOpensCircuitAfterThreeDistinctCandidates(t *testing.T) {
	var routeCalls atomic.Int32
	var directCalls atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		routeCalls.Add(1)
		return nil, errors.New("candidate detail")
	})}
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return nil, errors.New("secret endpoint detail")
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
	})

	for index, candidateID := range []string{
		"candidate-1",
		"candidate-2",
		"candidate-2", // A duplicate must not advance the distinct threshold.
		"candidate-3",
	} {
		got := measurer.Measure(context.Background(), candidateID, "127.0.0.1:1080")
		if got.Success || !got.Infrastructure || got.ErrorCode != "qoe_endpoint_unavailable" {
			t.Fatalf("failure %d observation=%+v", index+1, got)
		}
		if want := int32(index + 1); routeCalls.Load() != want {
			t.Fatalf("failure %d suppressed route: route calls=%d want=%d", index+1, routeCalls.Load(), want)
		}
	}

	skipped := measurer.Measure(context.Background(), "candidate-4", "127.0.0.1:1080")
	if skipped.Success || !skipped.Infrastructure || skipped.ErrorCode != "qoe_endpoint_unavailable" {
		t.Fatalf("open-circuit observation=%+v", skipped)
	}
	if routeCalls.Load() != 4 || directCalls.Load() != 4 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

func TestQoEMeasurerReservesTwoSecondsForDirectControl(t *testing.T) {
	var routeRemaining time.Duration
	var directRemaining time.Duration
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("route request has no deadline")
		}
		routeRemaining = time.Until(deadline)
		return nil, context.DeadlineExceeded
	})}
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("direct request has no deadline")
		}
		directRemaining = time.Until(deadline)
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Deadline:      6 * time.Second,
	})

	got := measurer.Measure(context.Background(), "candidate", "127.0.0.1:1080")

	if got.Infrastructure || got.ErrorCode != "qoe_route_timeout" {
		t.Fatalf("observation=%+v", got)
	}
	if routeRemaining < 3500*time.Millisecond || routeRemaining > 4100*time.Millisecond {
		t.Fatalf("route deadline remaining=%s", routeRemaining)
	}
	if directRemaining-routeRemaining < 1500*time.Millisecond {
		t.Fatalf("route=%s direct=%s; direct reserve missing", routeRemaining, directRemaining)
	}
}

func TestQoEMeasurerSingleFlightsDirectControlAcrossDistinctCandidates(t *testing.T) {
	var routeCalls atomic.Int32
	routesReady := make(chan struct{})
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if routeCalls.Add(1) == 3 {
			close(routesReady)
		}
		<-routesReady
		return nil, errors.New("route failed")
	})}
	var directCalls atomic.Int32
	directStarted := make(chan struct{})
	releaseDirect := make(chan struct{})
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if directCalls.Add(1) == 1 {
			close(directStarted)
		}
		<-releaseDirect
		return nil, errors.New("endpoint failed")
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
	})

	results := make(chan qoe.Observation, 3)
	for index := range 3 {
		go func() {
			got := measurer.Measure(context.Background(), "candidate-"+string(rune('a'+index)), "127.0.0.1:1080")
			results <- got
		}()
	}
	select {
	case <-directStarted:
	case <-time.After(time.Second):
		t.Fatal("direct control did not start")
	}
	time.Sleep(50 * time.Millisecond)
	if got := directCalls.Load(); got != 1 {
		close(releaseDirect)
		t.Fatalf("direct calls before release=%d", got)
	}
	close(releaseDirect)
	for range 3 {
		got := <-results
		if got.Success || !got.Infrastructure || got.ErrorCode != "qoe_endpoint_unavailable" {
			t.Fatalf("observation=%+v", got)
		}
	}
	skipped := measurer.Measure(context.Background(), "candidate-d", "127.0.0.1:1080")
	if skipped.Success || !skipped.Infrastructure || skipped.ErrorCode != "qoe_endpoint_unavailable" {
		t.Fatalf("open-circuit observation=%+v", skipped)
	}
	if routeCalls.Load() != 3 || directCalls.Load() != 1 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

func TestQoEMeasurerLeaderCancellationDoesNotPoisonSharedControl(t *testing.T) {
	var routeCalls atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		routeCalls.Add(1)
		return nil, errors.New("route failed")
	})}
	var directCalls atomic.Int32
	directStarted := make(chan struct{})
	releaseDirect := make(chan struct{})
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if directCalls.Add(1) == 1 {
			close(directStarted)
		}
		select {
		case <-releaseDirect:
			return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Deadline:      time.Second,
	})

	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan qoe.Observation, 1)
	go func() {
		leaderResult <- measurer.Measure(leaderContext, "candidate-a", "127.0.0.1:1080")
	}()
	select {
	case <-directStarted:
	case <-time.After(time.Second):
		t.Fatal("direct control did not start")
	}

	waiterResults := make(chan qoe.Observation, 2)
	for _, candidateID := range []string{"candidate-b", "candidate-c"} {
		go func() {
			waiterResults <- measurer.Measure(context.Background(), candidateID, "127.0.0.1:1080")
		}()
	}
	deadline := time.Now().Add(time.Second)
	for routeCalls.Load() != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if routeCalls.Load() != 3 {
		t.Fatalf("route calls before cancellation=%d", routeCalls.Load())
	}

	cancelLeader()
	select {
	case <-waiterResults:
		t.Fatal("healthy waiter returned before the isolated control completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseDirect)

	for range 2 {
		got := <-waiterResults
		if got.Success || got.Infrastructure || got.ErrorCode != "qoe_route_transport" {
			t.Fatalf("waiter observation=%+v", got)
		}
	}
	select {
	case <-leaderResult:
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}

	after := measurer.Measure(context.Background(), "candidate-d", "127.0.0.1:1080")
	if after.Success || after.Infrastructure || after.ErrorCode != "qoe_route_transport" {
		t.Fatalf("post-cancellation observation=%+v", after)
	}
	if routeCalls.Load() != 4 || directCalls.Load() != 1 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

func TestQoEMeasurerCanceledRouteDoesNotMutateEndpointHealth(t *testing.T) {
	var routeCalls atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		routeCalls.Add(1)
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		trace := httptrace.ContextClientTrace(request.Context())
		trace.GotFirstResponseByte()
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	var directCalls atomic.Int32
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return nil, errors.New("endpoint failed")
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
	})
	state := qoe.State{
		CandidateID:            "candidate-a",
		Status:                 qoe.StatusHealthy,
		BaselineTTFB:           time.Second,
		BaselineThroughputMbps: 20,
		BaselineSamples:        5,
		WindowValid:            2,
	}
	recent := []qoe.Sample{
		{At: time.Unix(1_800_000_000, 0), Valid: true, Success: true},
		{At: time.Unix(1_800_000_001, 0), Valid: true, Success: true},
	}

	for _, candidateID := range []string{"candidate-a", "candidate-b", "candidate-c"} {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		got := measurer.Measure(canceled, candidateID, "127.0.0.1:1080")
		if got.Success || !got.Infrastructure || got.ErrorCode != "qoe_measurement_canceled" {
			t.Fatalf("canceled observation=%+v", got)
		}
		decision := qoe.Apply(qoe.DefaultPolicy(), state, recent, nil, got)
		if decision.Sample != nil || decision.State != state || decision.Transition.Changed() {
			t.Fatalf("cancellation mutated QoE state: decision=%+v", decision)
		}
	}
	time.Sleep(20 * time.Millisecond)
	after := measurer.Measure(context.Background(), "candidate-d", "127.0.0.1:1080")
	if !after.Success || after.Infrastructure {
		t.Fatalf("post-cancellation observation=%+v", after)
	}
	if routeCalls.Load() != 4 || directCalls.Load() != 0 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

func TestQoEMeasurerReusesHealthyControlAcrossDistinctCandidateWindow(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	clock := newStepClock(
		base,
		base,
		base.Add(10*time.Second),
		base.Add(10*time.Second),
		base.Add(20*time.Second),
		base.Add(20*time.Second),
	)
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("route failed")
	})}
	var directCalls atomic.Int32
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Now:           clock.Now,
	})

	for index := range 3 {
		got := measurer.Measure(
			context.Background(),
			"candidate-"+string(rune('a'+index)),
			"127.0.0.1:1080",
		)
		if got.Success || got.Infrastructure || got.ErrorCode != "qoe_route_transport" {
			t.Fatalf("observation %d=%+v", index, got)
		}
	}
	if got := directCalls.Load(); got != 1 {
		t.Fatalf("direct calls=%d", got)
	}
}

func TestQoEMeasurerTimestampsOutOfOrderFailuresWhenProcessed(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	fastFailureAt := base.Add(20 * time.Second)
	slowFailureAt := base.Add(25 * time.Second)
	clock := newStepClock(
		base,
		base.Add(10*time.Second),
		fastFailureAt,
		slowFailureAt,
	)
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	slowClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		close(slowStarted)
		<-releaseSlow
		return nil, errors.New("slow route failed")
	})}
	fastClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fast route failed")
	})}
	var directCalls atomic.Int32
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(address string) *http.Client {
			if address == "slow" {
				return slowClient
			}
			return fastClient
		},
		DirectClient: directClient,
		SampleBytes:  65536,
		Now:          clock.Now,
	})

	slowResult := make(chan qoe.Observation, 1)
	go func() {
		slowResult <- measurer.Measure(context.Background(), "candidate-slow", "slow")
	}()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow route did not start")
	}
	fast := measurer.Measure(context.Background(), "candidate-fast", "fast")
	close(releaseSlow)
	slow := <-slowResult

	for name, got := range map[string]qoe.Observation{"fast": fast, "slow": slow} {
		if got.Success || got.Infrastructure || got.ErrorCode != "qoe_route_transport" {
			t.Fatalf("%s observation=%+v", name, got)
		}
	}
	if directCalls.Load() != 1 {
		t.Fatalf("direct calls=%d; negative freshness caused duplicate control", directCalls.Load())
	}
	measurer.mu.Lock()
	lastControlAttempt := measurer.lastControlAttempt
	fastRecordedAt := measurer.recentFailures["candidate-fast"]
	slowRecordedAt := measurer.recentFailures["candidate-slow"]
	measurer.mu.Unlock()
	if lastControlAttempt != fastFailureAt {
		t.Fatalf("lastControlAttempt=%s want=%s", lastControlAttempt, fastFailureAt)
	}
	if fastRecordedAt != fastFailureAt || slowRecordedAt != slowFailureAt {
		t.Fatalf("failure times fast=%s slow=%s", fastRecordedAt, slowRecordedAt)
	}
}

func TestQoEMeasurerRecoversOpenCircuitAtMostOncePerMinute(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	clock := newStepClock(
		base,
		base,
		base.Add(time.Second),
		base.Add(time.Second),
		base.Add(2*time.Second),
		base.Add(2*time.Second),
		base.Add(61*time.Second),
		base.Add(62*time.Second),
		base.Add(64*time.Second),
		base.Add(64*time.Second+200*time.Millisecond),
		base.Add(64*time.Second+300*time.Millisecond),
	)
	var routeCalls atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if routeCalls.Add(1) <= 3 {
			return nil, errors.New("route failed")
		}
		trace := httptrace.ContextClientTrace(request.Context())
		trace.GotFirstResponseByte()
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	var directCalls atomic.Int32
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if directCalls.Add(1) <= 3 {
			return nil, errors.New("endpoint failed")
		}
		return qoeResponse(http.StatusOK, bytes.Repeat([]byte{'x'}, 65536)), nil
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Now:           clock.Now,
	})

	first := measurer.Measure(context.Background(), "candidate-a", "127.0.0.1:1080")
	second := measurer.Measure(context.Background(), "candidate-b", "127.0.0.1:1081")
	opened := measurer.Measure(context.Background(), "candidate-c", "127.0.0.1:1082")
	skipped := measurer.Measure(context.Background(), "candidate-d", "127.0.0.1:1083")
	recovered := measurer.Measure(context.Background(), "candidate-e", "127.0.0.1:1084")

	for name, observation := range map[string]qoe.Observation{
		"first": first, "second": second, "opened": opened, "skipped": skipped,
	} {
		if !observation.Infrastructure || observation.ErrorCode != "qoe_endpoint_unavailable" {
			t.Fatalf("%s observation=%+v", name, observation)
		}
	}
	if !recovered.Success || recovered.Infrastructure || recovered.TTFB != 200*time.Millisecond ||
		recovered.TransferDuration != 100*time.Millisecond {
		t.Fatalf("recovered=%+v", recovered)
	}
	if routeCalls.Load() != 4 || directCalls.Load() != 4 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

func TestQoEMeasurerFailedRecoveryKeepsCircuitOpen(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	clock := newStepClock(
		base,
		base,
		base.Add(time.Second),
		base.Add(time.Second),
		base.Add(2*time.Second),
		base.Add(2*time.Second),
		base.Add(62*time.Second),
		base.Add(63*time.Second),
		base.Add(63*time.Second),
	)
	var routeCalls atomic.Int32
	routeClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		routeCalls.Add(1)
		return nil, errors.New("route failed")
	})}
	var directCalls atomic.Int32
	directClient := &http.Client{Transport: qoeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return nil, errors.New("endpoint failed")
	})}
	measurer := NewQoEMeasurer(QoEMeasurerConfig{
		ClientFactory: func(string) *http.Client { return routeClient },
		DirectClient:  directClient,
		SampleBytes:   65536,
		Now:           clock.Now,
	})

	for _, candidateID := range []string{"candidate-a", "candidate-b", "candidate-c"} {
		measurer.Measure(context.Background(), candidateID, "127.0.0.1:1080")
	}
	failedRecovery := measurer.Measure(context.Background(), "candidate-d", "127.0.0.1:1080")
	skipped := measurer.Measure(context.Background(), "candidate-e", "127.0.0.1:1080")

	for name, got := range map[string]qoe.Observation{"failed recovery": failedRecovery, "skipped": skipped} {
		if got.Success || !got.Infrastructure || got.ErrorCode != "qoe_endpoint_unavailable" {
			t.Fatalf("%s observation=%+v", name, got)
		}
	}
	if routeCalls.Load() != 3 || directCalls.Load() != 4 {
		t.Fatalf("route calls=%d direct calls=%d", routeCalls.Load(), directCalls.Load())
	}
}

type qoeRoundTripFunc func(*http.Request) (*http.Response, error)

func (function qoeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func qoeResponse(statusCode int, body []byte) *http.Response {
	return qoeResponseBody(statusCode, io.NopCloser(bytes.NewReader(body)))
}

func qoeResponseBody(statusCode int, body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode:    statusCode,
		Header:        make(http.Header),
		Body:          body,
		ContentLength: -1,
	}
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

type canceledBlockingBody struct {
	started chan struct{}
	closed  chan struct{}
	release chan struct{}
}

func newCanceledBlockingBody() *canceledBlockingBody {
	return &canceledBlockingBody{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (body *canceledBlockingBody) Read([]byte) (int, error) {
	close(body.started)
	<-body.release
	return 0, io.EOF
}

func (body *canceledBlockingBody) Close() error {
	close(body.closed)
	return nil
}

func (body *trackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

func (body *trackingBody) Closed() bool { return body.closed.Load() }

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type stepClock struct {
	mu    sync.Mutex
	times []time.Time
}

func newStepClock(times ...time.Time) *stepClock {
	return &stepClock{times: times}
}

func (clock *stepClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if len(clock.times) == 0 {
		panic("step clock exhausted")
	}
	now := clock.times[0]
	clock.times = clock.times[1:]
	return now
}
