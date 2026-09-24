package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/socks5"
)

const (
	defaultQoEEndpoint      = "https://speed.cloudflare.com/__down"
	defaultQoEBytes         = int64(262144)
	defaultQoEDeadline      = 10 * time.Second
	directReserve           = 2 * time.Second
	applicationGateDeadline = 3 * time.Second
	dnsGateDeadline         = 4 * time.Second
	failureWindow           = 30 * time.Second
	failureThreshold        = 3
	recoveryInterval        = time.Minute

	qoeRouteTimeout                = qoe.ReasonRouteTimeout
	qoeRouteTLS                    = qoe.ReasonRouteTLS
	qoeRouteTransport              = qoe.ReasonRouteTransport
	qoeEndpointHTTP                = "qoe_endpoint_http"
	qoeEndpointSize                = "qoe_endpoint_size"
	qoeEndpointMalformed           = "qoe_endpoint_malformed"
	qoeEndpointUnavailable         = "qoe_endpoint_unavailable"
	qoeApplicationGates            = qoe.ReasonApplicationGates
	qoeApplicationGatesUnavailable = "qoe_application_gates_unavailable"
	qoeDNSUnavailable              = "qoe_dns_unavailable"
	qoeMeasurementCanceled         = "qoe_measurement_canceled"
)

type ApplicationGateChecker func(context.Context, *http.Client) HTTPGateResult

type DNSRouteChecker func(context.Context, string, string) error
type DNSDirectChecker func(context.Context, string) error

type QoEMeasurerConfig struct {
	ClientFactory      func(string) *http.Client
	DirectClient       *http.Client
	Endpoint           string
	SampleBytes        int64
	Deadline           time.Duration
	Now                func() time.Time
	Nonce              func() string
	ApplicationGates   ApplicationGateChecker
	ApplicationControl ApplicationGateChecker
	DNSResolver        string
	DNSResolvers       []string
	DNSRouteCheck      DNSRouteChecker
	DNSDirectCheck     DNSDirectChecker
	UDPCheck           func(context.Context, string) bool
}

type QoEMeasurer struct {
	clientFactory      func(string) *http.Client
	directClient       *http.Client
	endpoint           string
	sampleBytes        int64
	deadline           time.Duration
	now                func() time.Time
	nonce              func() string
	applicationGates   ApplicationGateChecker
	applicationControl ApplicationGateChecker
	dnsResolvers       []string
	dnsRouteCheck      DNSRouteChecker
	dnsDirectCheck     DNSDirectChecker
	udpCheck           func(context.Context, string) bool

	mu                 sync.Mutex
	recentFailures     map[string]time.Time
	circuitOpen        bool
	lastControlAttempt time.Time
	lastControlHealthy bool
	control            *qoeControlCall
}

type qoeControlCall struct {
	done     chan struct{}
	healthy  bool
	recovery bool
}

type qoeRequestResult struct {
	statusCode       int
	bytes            int64
	ttfb             time.Duration
	transferDuration time.Duration
	err              error
	endpointError    string
	malformed        bool
}

func NewQoEMeasurer(config QoEMeasurerConfig) *QoEMeasurer {
	if config.Endpoint == "" {
		config.Endpoint = defaultQoEEndpoint
	}
	if config.SampleBytes <= 0 {
		config.SampleBytes = defaultQoEBytes
	}
	if config.Deadline <= 0 {
		config.Deadline = defaultQoEDeadline
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Nonce == nil {
		config.Nonce = func() string {
			return randomQoENonce(rand.Reader)
		}
	}
	if config.DirectClient == nil {
		config.DirectClient = http.DefaultClient
	}
	dnsResolvers := append([]string(nil), config.DNSResolvers...)
	if len(dnsResolvers) == 0 && config.DNSResolver != "" {
		dnsResolvers = []string{config.DNSResolver}
	}
	if len(dnsResolvers) > 0 && config.DNSRouteCheck == nil {
		config.DNSRouteCheck = checkDNSViaSOCKS
	}
	if len(dnsResolvers) > 0 && config.DNSDirectCheck == nil {
		config.DNSDirectCheck = checkDNSDirect
	}
	if config.UDPCheck == nil {
		config.UDPCheck = CheckQUIC
	}
	return &QoEMeasurer{
		clientFactory:      config.ClientFactory,
		directClient:       config.DirectClient,
		endpoint:           config.Endpoint,
		sampleBytes:        config.SampleBytes,
		deadline:           config.Deadline,
		now:                config.Now,
		nonce:              config.Nonce,
		applicationGates:   config.ApplicationGates,
		applicationControl: config.ApplicationControl,
		dnsResolvers:       dnsResolvers,
		dnsRouteCheck:      config.DNSRouteCheck,
		dnsDirectCheck:     config.DNSDirectCheck,
		udpCheck:           config.UDPCheck,
		recentFailures:     make(map[string]time.Time),
	}
}

func randomQoENonce(reader io.Reader) string {
	randomBytes := make([]byte, 18)
	if _, err := io.ReadFull(reader, randomBytes); err != nil {
		panic("probe: secure QoE nonce generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

func (measurer *QoEMeasurer) Measure(
	ctx context.Context,
	candidateID string,
	socksAddress string,
) qoe.Observation {
	return measurer.measure(ctx, candidateID, socksAddress, nil)
}

func (measurer *QoEMeasurer) MeasureVLESS(
	ctx context.Context,
	candidateID string,
	socksAddress string,
	_ string,
) qoe.Observation {
	return measurer.measure(ctx, candidateID, socksAddress, measurer.udpCheck)
}

// MeasureAvailability performs only the routed DNS check and its direct
// control. It is cheap enough for the active liveness cadence and deliberately
// excludes bulk HTTP, application gates, and QUIC.
func (measurer *QoEMeasurer) MeasureAvailability(
	ctx context.Context,
	candidateID string,
	socksAddress string,
) qoe.Observation {
	observation := qoe.Observation{At: measurer.now()}
	if len(measurer.dnsResolvers) == 0 || measurer.dnsRouteCheck == nil {
		observation.Infrastructure = true
		observation.ErrorCode = qoeDNSUnavailable
		return observation
	}
	availabilityCtx, cancel := context.WithTimeout(ctx, dnsGateDeadline)
	defer cancel()
	resolver, err := dataplane.SelectDNSResolver(candidateID, measurer.dnsResolvers)
	if err != nil {
		observation.Infrastructure = true
		observation.ErrorCode = qoeDNSUnavailable
		return observation
	}
	routeBudget := dnsGateDeadline / 2
	if deadline, ok := availabilityCtx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			observation.Infrastructure = true
			observation.ErrorCode = qoeMeasurementCanceled
			return observation
		}
		routeBudget = remaining / 2
	}
	routeCtx, routeCancel := context.WithTimeout(availabilityCtx, routeBudget)
	routeErr := measurer.dnsRouteCheck(routeCtx, socksAddress, resolver)
	routeCancel()
	if routeErr == nil {
		observation.Success = true
		return observation
	}
	if ctx.Err() != nil {
		observation.Infrastructure = true
		observation.ErrorCode = qoeMeasurementCanceled
		return observation
	}
	if !measurer.anyDNSDirectHealthy(availabilityCtx, resolver) {
		observation.Infrastructure = true
		observation.ErrorCode = qoeDNSUnavailable
		return observation
	}
	observation.ErrorCode = qoe.ReasonDNSRoute
	return observation
}

func (measurer *QoEMeasurer) measure(
	ctx context.Context,
	candidateID string,
	socksAddress string,
	udpCheck func(context.Context, string) bool,
) qoe.Observation {
	at := measurer.now()
	observation := qoe.Observation{At: at}
	ctx, cancel := context.WithTimeout(ctx, measurer.deadline)
	defer cancel()

	allowed, recovered := measurer.circuitAllowsRoute(ctx, at)
	if !allowed {
		observation.Infrastructure = true
		observation.ErrorCode = qoeEndpointUnavailable
		return observation
	}
	if len(measurer.dnsResolvers) > 0 && measurer.dnsRouteCheck != nil {
		resolver, resolverErr := dataplane.SelectDNSResolver(candidateID, measurer.dnsResolvers)
		if resolverErr != nil {
			observation.Infrastructure = true
			observation.ErrorCode = qoeDNSUnavailable
			return observation
		}
		dnsCtx, dnsCancel := context.WithTimeout(ctx, dnsGateDeadline)
		dnsErr := measurer.dnsRouteCheck(dnsCtx, socksAddress, resolver)
		dnsCancel()
		if dnsErr != nil {
			if ctx.Err() != nil {
				observation.Infrastructure = true
				observation.ErrorCode = qoeMeasurementCanceled
				return observation
			}
			if !measurer.anyDNSDirectHealthy(ctx, resolver) {
				observation.Infrastructure = true
				observation.ErrorCode = qoeDNSUnavailable
				return observation
			}
			observation.ErrorCode = qoe.ReasonDNSRoute
			return observation
		}
	}
	var udpResult <-chan bool
	udpCancel := func() {}
	if udpCheck != nil {
		udpCtx, cancelUDP := context.WithCancel(ctx)
		udpCancel = cancelUDP
		results := make(chan bool, 1)
		udpResult = results
		go func() { results <- udpCheck(udpCtx, socksAddress) }()
	}
	defer func() {
		udpCancel()
		// The Xray probe slot is cleared as soon as Measure returns. Join an
		// outstanding UDP association first so it cannot outlive its outbound,
		// cross a runtime epoch, or leave the local SOCKS inbound half-closed.
		if udpResult != nil {
			<-udpResult
		}
	}()

	routeStarted := at
	if recovered {
		routeStarted = measurer.now()
	}
	routeCtx, routeCancel := context.WithDeadline(ctx, measurer.routeDeadline(ctx))
	routeClient := measurer.routeClient(socksAddress)
	defer routeClient.CloseIdleConnections()
	result := measurer.request(routeCtx, routeClient, true, routeStarted)
	routeCancel()
	observation.TTFB = result.ttfb
	observation.TransferDuration = result.transferDuration
	observation.Bytes = result.bytes

	if result.endpointError != "" {
		observation.Infrastructure = true
		observation.ErrorCode = result.endpointError
		return observation
	}
	if result.err != nil {
		if ctx.Err() != nil {
			observation.Infrastructure = true
			observation.ErrorCode = qoeMeasurementCanceled
			return observation
		}
		candidateError := classifyQoERouteError(result.err)
		failureAt := measurer.now()
		measurer.recordCandidateFailure(candidateID, failureAt)
		if measurer.directControlHealthy(ctx, failureAt, false) {
			observation.ErrorCode = candidateError
			return observation
		}
		observation.Infrastructure = true
		observation.ErrorCode = qoeEndpointUnavailable
		return observation
	}
	if result.malformed {
		observation.Infrastructure = true
		observation.ErrorCode = qoeEndpointMalformed
		return observation
	}
	if result.statusCode < http.StatusOK || result.statusCode >= http.StatusMultipleChoices {
		observation.Infrastructure = true
		observation.ErrorCode = qoeEndpointHTTP
		return observation
	}
	if result.bytes != measurer.sampleBytes {
		observation.Infrastructure = true
		observation.ErrorCode = qoeEndpointSize
		return observation
	}
	if measurer.applicationGates != nil {
		// Service reachability is user-facing latency, not a bulk-transfer
		// measurement. Bound it independently so a route that regularly stalls
		// YouTube or Telegram for several seconds cannot remain healthy merely
		// because the overall QoE measurement still has time left.
		gateCtx, gateCancel := context.WithTimeout(ctx, applicationGateDeadline)
		routeGates := measurer.applicationGates(gateCtx, routeClient)
		gateCancel()
		if !applicationRouteGatesHealthy(routeGates) {
			if measurer.applicationControl == nil ||
				!applicationRouteGatesHealthy(
					measurer.applicationControl(ctx, measurer.directClient),
				) {
				observation.Infrastructure = true
				observation.ErrorCode = qoeApplicationGatesUnavailable
				return observation
			}
			observation.ErrorCode = qoeApplicationGates
			return observation
		}
	}

	observation.Success = true
	if result.transferDuration > 0 {
		observation.ThroughputMbps = float64(result.bytes*8) /
			result.transferDuration.Seconds() / 1_000_000
	}
	if udpResult != nil {
		select {
		case reachable := <-udpResult:
			udpResult = nil
			observation.UDPReachable = &reachable
		case <-ctx.Done():
			// An exhausted overall QoE deadline is not UDP-specific evidence.
		}
	}
	return observation
}

func (measurer *QoEMeasurer) anyDNSDirectHealthy(
	ctx context.Context,
	selected string,
) bool {
	if measurer.dnsDirectCheck == nil || len(measurer.dnsResolvers) == 0 {
		return false
	}
	ordered := make([]string, 0, len(measurer.dnsResolvers))
	ordered = append(ordered, selected)
	for _, resolver := range measurer.dnsResolvers {
		if resolver != selected {
			ordered = append(ordered, resolver)
		}
	}
	controlCtx, controlCancel := context.WithTimeout(ctx, dnsGateDeadline)
	defer controlCancel()
	results := make(chan error, len(ordered))
	for _, resolver := range ordered {
		resolver := resolver
		go func() {
			results <- measurer.dnsDirectCheck(controlCtx, resolver)
		}()
	}
	healthy := false
	for range ordered {
		if err := <-results; err == nil {
			healthy = true
			controlCancel()
		}
	}
	return healthy
}

func checkDNSViaSOCKS(
	ctx context.Context,
	socksAddress string,
	resolver string,
) error {
	dialer := socks5.Dialer{ProxyAddress: socksAddress}
	var lastErr error
	connection, err := dialer.DialContext(
		ctx, "tcp", net.JoinHostPort(resolver, "53"),
	)
	if err == nil {
		defer connection.Close()
		if dnsErr := exchangeDNSOverTCP(ctx, connection); dnsErr == nil {
			return nil
		} else {
			lastErr = dnsErr
		}
	} else {
		lastErr = err
	}
	conn443, err443 := dialer.DialContext(ctx, "tcp", net.JoinHostPort(resolver, "443"))
	if err443 == nil {
		_ = conn443.Close()
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return err443
}

func checkDNSDirect(ctx context.Context, resolver string) error {
	connection, err := (&net.Dialer{}).DialContext(
		ctx, "tcp", net.JoinHostPort(resolver, "53"),
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	return exchangeDNSOverTCP(ctx, connection)
}

func exchangeDNSOverTCP(ctx context.Context, connection net.Conn) error {
	if deadline, exists := ctx.Deadline(); exists {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	query := []byte{
		0x48, 0x59, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w',
		0x07, 'y', 'o', 'u', 't', 'u', 'b', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if err := writeFull(connection, framed); err != nil {
		return err
	}
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, lengthBytes); err != nil {
		return err
	}
	responseLength := int(binary.BigEndian.Uint16(lengthBytes))
	if responseLength < 12 || responseLength > 4096 {
		return fmt.Errorf("invalid DNS response length %d", responseLength)
	}
	response := make([]byte, responseLength)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if response[0] != query[0] || response[1] != query[1] ||
		response[2]&0x80 == 0 || response[3]&0x0f != 0 {
		return errors.New("invalid DNS response header")
	}
	if binary.BigEndian.Uint16(response[6:8]) == 0 {
		return errors.New("DNS response contains no answers")
	}
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

// YouTube and Telegram are mandatory and not interchangeable with the two AI
// endpoints: a route that intermittently blocks either one is broken for
// clients. ChatGPT and OpenAI remain redundant with each other because a
// service-specific policy response can affect either one independently.
func applicationRouteGatesHealthy(gates HTTPGateResult) bool {
	return gates.YouTubeWeb && gates.TelegramWeb &&
		(gates.ChatGPTWeb || gates.OpenAI401)
}

func (measurer *QoEMeasurer) routeClient(socksAddress string) *http.Client {
	if measurer.clientFactory != nil {
		return withHTTPTimeout(measurer.clientFactory(socksAddress), measurer.deadline)
	}
	dialer := socks5.Dialer{ProxyAddress: socksAddress}
	return &http.Client{Timeout: measurer.deadline, Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		DisableKeepAlives:     true,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   minDuration(4*time.Second, measurer.deadline),
		ResponseHeaderTimeout: minDuration(5*time.Second, measurer.deadline),
	}}
}

func (measurer *QoEMeasurer) routeDeadline(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	now := time.Now()
	remaining := deadline.Sub(now)
	if remaining > directReserve {
		return deadline.Add(-directReserve)
	}
	return now.Add(remaining / 2)
}

func (measurer *QoEMeasurer) request(
	ctx context.Context,
	client *http.Client,
	measureTiming bool,
	started time.Time,
) qoeRequestResult {
	endpoint, err := url.Parse(measurer.endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return qoeRequestResult{malformed: true}
	}
	query := endpoint.Query()
	query.Set("bytes", strconv.FormatInt(measurer.sampleBytes, 10))
	query.Set("nonce", measurer.nonce())
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return qoeRequestResult{malformed: true}
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")
	request.Header.Set("Pragma", "no-cache")

	var timingMu sync.Mutex
	var firstByte time.Time
	if measureTiming {
		trace := &httptrace.ClientTrace{GotFirstResponseByte: func() {
			timingMu.Lock()
			if firstByte.IsZero() {
				firstByte = measurer.now()
			}
			timingMu.Unlock()
		}}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	}

	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return qoeRequestResult{err: err}
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return qoeRequestResult{malformed: true}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_ = response.Body.Close()
		return qoeRequestResult{statusCode: response.StatusCode}
	}
	if response.ContentLength < -1 {
		_ = response.Body.Close()
		return qoeRequestResult{statusCode: response.StatusCode, malformed: true}
	}
	if response.ContentLength >= 0 && response.ContentLength != measurer.sampleBytes {
		_ = response.Body.Close()
		return qoeRequestResult{statusCode: response.StatusCode, endpointError: qoeEndpointSize}
	}

	bytesRead, readErr := readQoEBody(ctx, response.Body, measurer.sampleBytes+1)
	result := qoeRequestResult{statusCode: response.StatusCode, bytes: bytesRead, err: readErr}
	if readErr != nil && !errors.Is(readErr, context.Canceled) &&
		!errors.Is(readErr, context.DeadlineExceeded) && errors.Is(readErr, io.ErrUnexpectedEOF) {
		result.err = nil
		result.endpointError = qoeEndpointSize
	}
	if measureTiming {
		completed := measurer.now()
		timingMu.Lock()
		capturedFirstByte := firstByte
		timingMu.Unlock()
		if capturedFirstByte.IsZero() {
			result.malformed = true
		} else {
			result.ttfb = capturedFirstByte.Sub(started)
			result.transferDuration = completed.Sub(capturedFirstByte)
		}
	}
	return result
}

func readQoEBody(ctx context.Context, body io.ReadCloser, limit int64) (int64, error) {
	type readResult struct {
		bytes int64
		err   error
	}
	done := make(chan readResult, 1)
	go func() {
		bytesRead, err := io.Copy(io.Discard, io.LimitReader(body, limit))
		done <- readResult{bytes: bytesRead, err: err}
	}()
	select {
	case result := <-done:
		closeErr := body.Close()
		if result.err != nil {
			return result.bytes, result.err
		}
		return result.bytes, closeErr
	case <-ctx.Done():
		_ = body.Close()
		result := <-done
		return result.bytes, ctx.Err()
	}
}

func (measurer *QoEMeasurer) circuitAllowsRoute(ctx context.Context, at time.Time) (bool, bool) {
	measurer.mu.Lock()
	if !measurer.circuitOpen {
		measurer.mu.Unlock()
		return true, false
	}
	if at.Sub(measurer.lastControlAttempt) < recoveryInterval {
		measurer.mu.Unlock()
		return false, false
	}
	measurer.mu.Unlock()
	healthy := measurer.directControlHealthy(ctx, at, true)
	return healthy, healthy
}

func (measurer *QoEMeasurer) directControlHealthy(
	ctx context.Context,
	at time.Time,
	recovery bool,
) bool {
	measurer.mu.Lock()
	if measurer.control != nil {
		call := measurer.control
		measurer.mu.Unlock()
		select {
		case <-call.done:
			return call.healthy
		case <-ctx.Done():
			return false
		}
	}
	if measurer.circuitOpen && !recovery {
		measurer.mu.Unlock()
		return false
	}
	controlAge := at.Sub(measurer.lastControlAttempt)
	if !measurer.circuitOpen && measurer.lastControlHealthy &&
		controlAge < failureWindow {
		measurer.mu.Unlock()
		return true
	}
	if recovery && at.Sub(measurer.lastControlAttempt) < recoveryInterval {
		measurer.mu.Unlock()
		return false
	}
	call := &qoeControlCall{done: make(chan struct{}), recovery: recovery}
	measurer.control = call
	if at.After(measurer.lastControlAttempt) {
		measurer.lastControlAttempt = at
	}
	measurer.mu.Unlock()

	controlContext := context.WithoutCancel(ctx)
	controlContext, cancelControl := context.WithDeadline(controlContext, contextDeadline(ctx))
	go measurer.runDirectControl(call, controlContext, cancelControl, at)
	select {
	case <-call.done:
		return call.healthy
	case <-ctx.Done():
		return false
	}
}

func (measurer *QoEMeasurer) runDirectControl(
	call *qoeControlCall,
	ctx context.Context,
	cancel context.CancelFunc,
	at time.Time,
) {
	defer cancel()
	result := measurer.request(
		ctx,
		withHTTPTimeout(measurer.directClient, measurer.deadline),
		false,
		at,
	)
	healthy := result.err == nil && !result.malformed &&
		result.endpointError == "" &&
		result.statusCode >= http.StatusOK && result.statusCode < http.StatusMultipleChoices &&
		result.bytes == measurer.sampleBytes

	measurer.mu.Lock()
	call.healthy = healthy
	if healthy {
		measurer.circuitOpen = false
	} else if call.recovery || measurer.hasFailureQuorumLocked(at) {
		measurer.circuitOpen = true
	}
	measurer.lastControlHealthy = healthy
	measurer.control = nil
	close(call.done)
	measurer.mu.Unlock()
}

func (measurer *QoEMeasurer) recordCandidateFailure(candidateID string, at time.Time) {
	measurer.mu.Lock()
	defer measurer.mu.Unlock()
	measurer.pruneCandidateFailuresLocked(at)
	if candidateID != "" {
		measurer.recentFailures[candidateID] = at
	}
}

func (measurer *QoEMeasurer) hasFailureQuorumLocked(at time.Time) bool {
	measurer.pruneCandidateFailuresLocked(at)
	return len(measurer.recentFailures) >= failureThreshold
}

func (measurer *QoEMeasurer) pruneCandidateFailuresLocked(at time.Time) {
	cutoff := at.Add(-failureWindow)
	for id, failedAt := range measurer.recentFailures {
		if failedAt.Before(cutoff) {
			delete(measurer.recentFailures, id)
		}
	}
}

func classifyQoERouteError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return qoeRouteTimeout
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return qoeRouteTimeout
	}
	var recordHeaderError tls.RecordHeaderError
	var certificateError *tls.CertificateVerificationError
	var unknownAuthorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	if errors.As(err, &recordHeaderError) || errors.As(err, &certificateError) ||
		errors.As(err, &unknownAuthorityError) || errors.As(err, &hostnameError) {
		return qoeRouteTLS
	}
	return qoeRouteTransport
}

func minDuration(one, two time.Duration) time.Duration {
	if one < two {
		return one
	}
	return two
}

func contextDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(defaultQoEDeadline)
}
