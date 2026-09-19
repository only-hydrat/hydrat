//go:build xrayintegration

package xrayapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	feasibilityTimeout     = 3 * time.Second
	fixtureVLESSPort       = 22101
	fixtureXrayAPIPort     = 22102
	fixtureDNSIngressPort  = 22153
	http2FrameHeaderLength = 9
)

func TestPinnedXrayDNSAndRoutingFeasibility(t *testing.T) {
	binaryPath := os.Getenv("HYDRAT_XRAY_BINARY")
	if binaryPath == "" {
		t.Fatal("HYDRAT_XRAY_BINARY is required")
	}
	if output, err := exec.Command(binaryPath, "version").CombinedOutput(); err != nil {
		t.Fatalf("read pinned Xray version: %v: %s", err, strings.TrimSpace(string(output)))
	} else if !bytes.Contains(output, []byte("52a412d")) {
		t.Fatalf("unexpected Xray build (want pinned 52a412d): %s", strings.TrimSpace(string(output)))
	}

	dns := startTCPDNSFixture(t)
	vlessRelay := startTCPRelayFixture(t, dns.address)
	torSOCKS := startSOCKSFixture(t, dns.address)
	directTrap := startUDPDNSFixture(t)

	vlessPort := fixtureVLESSPort
	apiPort := fixtureXrayAPIPort
	dnsIngressPort := fixtureDNSIngressPort
	fixtureID := "00000000-0000-4000-8000-000000000001"

	vlessServerConfig := map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"tag": "vless-fixture", "listen": "127.0.0.1", "port": vlessPort, "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": fixtureID}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{"network": "tcp", "security": "none"},
		}},
		"outbounds": []any{map[string]any{
			"tag": "fixture-relay", "protocol": "freedom",
			"settings": map[string]any{
				"redirect":   vlessRelay.address,
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
	vlessServer := startXray(t, binaryPath, vlessServerConfig, net.JoinHostPort("127.0.0.1", strconv.Itoa(vlessPort)))
	defer vlessServer.stop(t)

	unreachableDNS := "192.0.2.53"
	directTrapHost, directTrapPortText, err := net.SplitHostPort(directTrap.address)
	if err != nil {
		t.Fatal(err)
	}
	directTrapPort, err := strconv.Atoi(directTrapPortText)
	if err != nil {
		t.Fatal(err)
	}
	gatewayConfig := map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "debug"},
		"api": map[string]any{
			"tag": "api", "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)),
			"services": []string{"RoutingService"},
		},
		"inbounds": []any{
			map[string]any{
				"tag": "dns-in", "listen": "127.0.0.1", "port": dnsIngressPort, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": directTrapHost, "port": directTrapPort, "network": "udp"},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
			map[string]any{"tag": "api", "protocol": "blackhole", "settings": map[string]any{}},
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
			dnsOutbound("dns-vless", "vless-fixture", unreachableDNS),
			map[string]any{
				"tag": "vless-fixture", "protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": vlessPort,
					"users": []any{map[string]any{"id": fixtureID, "encryption": "none"}},
				}}},
				"streamSettings": map[string]any{"network": "tcp", "security": "none"},
			},
			dnsOutbound("dns-tor", "tor-socks-fixture", unreachableDNS),
			map[string]any{
				"tag": "tor-socks-fixture", "protocol": "socks",
				"settings": map[string]any{"servers": []any{map[string]any{
					"address": "127.0.0.1", "port": torSOCKS.port,
				}}},
			},
		},
		"routing": completeRules("dns-vless"),
	}
	gateway := startXray(t, binaryPath, gatewayConfig, net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)))
	defer gateway.stop(t)

	dnsIngress := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsIngressPort))
	if err := exchangeDNS(dnsIngress, 0x1001); err != nil {
		t.Fatalf(
			"initial VLESS DNS exchange: %v; relay_hit=%q dns_hit=%q socks_hit=%q gateway_log=%q vless_log=%q",
			err, optionalFixtureHit(vlessRelay.hits), optionalFixtureHit(dns.hits), optionalFixtureHit(torSOCKS.hits),
			gateway.evidence(), vlessServer.evidence(),
		)
	}
	requireFixtureHit(t, vlessRelay.hits, "VLESS relay")
	requireFixtureHit(t, dns.hits, "TCP DNS")
	t.Log("FEASIBILITY transport=vless input=udp dns_rewrite=tcp proxy_chain=confirmed")

	apiAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort))
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, completeRules("dns-tor")); err != nil {
		t.Fatalf("replace complete rules with Tor fixture: %v: %s", err, output)
	}
	requireDNSQuery(t, dnsIngress, 0x1002)
	target := requireFixtureHit(t, torSOCKS.hits, "Tor SOCKS")
	if target != net.JoinHostPort(unreachableDNS, "53") {
		t.Fatalf("Tor SOCKS target=%q want=%q", target, net.JoinHostPort(unreachableDNS, "53"))
	}
	requireFixtureHit(t, dns.hits, "TCP DNS")
	t.Log("FEASIBILITY transport=tor-socks input=udp dns_rewrite=tcp proxy_chain=confirmed rules=switch-complete")

	type commandResult struct {
		output string
		err    error
	}

	canceledBeforeDispatch, cancelBeforeDispatch := context.WithCancel(context.Background())
	cancelBeforeDispatch()
	if _, err := replaceRules(canceledBeforeDispatch, binaryPath, apiAddress, stagingRules()); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-dispatch cancellation error=%v want context.Canceled", err)
	}
	requireDNSQuery(t, dnsIngress, 0x1003)
	requireFixtureHit(t, torSOCKS.hits, "Tor SOCKS after pre-dispatch cancellation")
	requireFixtureHit(t, dns.hits, "TCP DNS after pre-dispatch cancellation")
	t.Log("FEASIBILITY phase=stage fault=before-dispatch state=old-service")

	runGatedReplacement := func(routing map[string]any, observe func()) {
		t.Helper()
		responseGate := startGRPCResponseGate(t, apiAddress)
		inFlight, cancelInFlight := context.WithCancel(context.Background())
		result := make(chan commandResult, 1)
		go func() {
			output, replaceErr := replaceRules(inFlight, binaryPath, responseGate.address, routing)
			result <- commandResult{output: output, err: replaceErr}
		}()
		select {
		case <-responseGate.responseBlocked:
			// A non-control HTTP/2 response frame exists only after Xray handled
			// the AddRule RPC. The gate deliberately withholds it from the CLI.
		case early := <-result:
			cancelInFlight()
			t.Fatalf("adrules returned before its response could be gated: %v: %s", early.err, early.output)
		case <-time.After(feasibilityTimeout):
			cancelInFlight()
			t.Fatal("Xray did not handle the in-flight adrules RPC")
		}
		observe()
		cancelInFlight()
		select {
		case canceled := <-result:
			if !errors.Is(canceled.err, context.Canceled) {
				t.Fatalf("in-flight adrules error=%v want context.Canceled: %s", canceled.err, canceled.output)
			}
		case <-time.After(feasibilityTimeout):
			t.Fatal("in-flight adrules CLI did not stop after cancellation")
		}
		responseGate.close()
	}

	runGatedReplacement(stagingRules(), func() {
		requireDNSBlocked(t, dnsIngress, 0x1004)
		requireNoFixtureHit(t, directTrap.hits, "direct UDP trap during unknown staging outcome")
	})
	t.Log("FEASIBILITY phase=stage fault=response-lost state=explicit-block direct_evidence=zero")
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, stagingRules()); err != nil {
		t.Fatalf("retry staging rules: %v: %s", err, output)
	}
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, completeRules("dns-vless")); err != nil {
		t.Fatalf("retry final rules: %v: %s", err, output)
	}
	requireDNSQuery(t, dnsIngress, 0x1005)
	requireFixtureHit(t, vlessRelay.hits, "VLESS relay after staging retry")
	requireFixtureHit(t, dns.hits, "TCP DNS after staging retry")

	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, stagingRules()); err != nil {
		t.Fatalf("stage before final cancellation: %v: %s", err, output)
	}
	requireDNSBlocked(t, dnsIngress, 0x1006)
	canceledFinal, cancelFinal := context.WithCancel(context.Background())
	cancelFinal()
	if _, err := replaceRules(canceledFinal, binaryPath, apiAddress, completeRules("dns-tor")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-dispatch final cancellation error=%v want context.Canceled", err)
	}
	requireDNSBlocked(t, dnsIngress, 0x1007)
	requireNoFixtureHit(t, directTrap.hits, "direct UDP trap after pre-dispatch final cancellation")
	t.Log("FEASIBILITY phase=final fault=before-dispatch state=explicit-block direct_evidence=zero")
	runGatedReplacement(completeRules("dns-tor"), func() {
		requireDNSQuery(t, dnsIngress, 0x1008)
		requireFixtureHit(t, torSOCKS.hits, "Tor SOCKS during unknown final outcome")
		requireFixtureHit(t, dns.hits, "TCP DNS during unknown final outcome")
	})
	t.Log("FEASIBILITY phase=final fault=response-lost state=final-service acknowledged=false")
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, stagingRules()); err != nil {
		t.Fatalf("retry stage after final unknown: %v: %s", err, output)
	}
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, completeRules("dns-tor")); err != nil {
		t.Fatalf("retry final after unknown: %v: %s", err, output)
	}
	requireDNSQuery(t, dnsIngress, 0x1009)
	requireFixtureHit(t, torSOCKS.hits, "Tor SOCKS after final retry")
	requireFixtureHit(t, dns.hits, "TCP DNS after final retry")

	failedRules := completeRules("dns-vless")
	failedRules["balancers"] = []any{
		map[string]any{"tag": "duplicate", "selector": []string{"fixture"}, "strategy": map[string]any{"type": "random"}},
		map[string]any{"tag": "duplicate", "selector": []string{"fixture"}, "strategy": map[string]any{"type": "random"}},
	}
	output, err := replaceRules(context.Background(), binaryPath, apiAddress, failedRules)
	if err == nil {
		t.Fatal("API-side invalid adrules unexpectedly succeeded")
	}
	if !strings.Contains(output, "duplicate balancer tag") {
		t.Fatalf("failed adrules did not reach API-side reload: %v: %s", err, output)
	}
	requireDNSQuery(t, dnsIngress, 0x1010)
	requireFixtureHit(t, torSOCKS.hits, "Tor SOCKS after rejected reload")
	requireFixtureHit(t, dns.hits, "TCP DNS after rejected reload")
	requireNoFixtureHit(t, directTrap.hits, "direct UDP trap after rejected reload")
	t.Logf("FEASIBILITY native_rules=atomic state=old-service direct_evidence=zero api_error=%q", sanitizeEvidence(output))

	// The API remains reachable after a rejected reload, so staged retries can
	// still converge without exposing direct traffic.
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, stagingRules()); err != nil {
		t.Fatalf("static API did not survive empty matcher: %v: %s", err, output)
	}
	requireDNSBlocked(t, dnsIngress, 0x1011)
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, completeRules("dns-vless")); err != nil {
		t.Fatalf("recover final rules after destructive reload: %v: %s", err, output)
	}
	requireDNSQuery(t, dnsIngress, 0x1012)
	requireFixtureHit(t, vlessRelay.hits, "VLESS relay after destructive reload recovery")
	requireFixtureHit(t, dns.hits, "TCP DNS after destructive reload recovery")
	t.Log("FEASIBILITY static_api=reachable empty_matcher=fail-closed retry=converged")

	const latencySamples = 20
	latencies := make([]time.Duration, 0, latencySamples)
	for sample := 0; sample < latencySamples; sample++ {
		started := time.Now()
		if output, err := replaceRules(context.Background(), binaryPath, apiAddress, stagingRules()); err != nil {
			t.Fatalf("latency sample %d staging: %v: %s", sample, err, output)
		}
		finalTag := "dns-vless"
		if sample%2 == 1 {
			finalTag = "dns-tor"
		}
		if output, err := replaceRules(context.Background(), binaryPath, apiAddress, completeRules(finalTag)); err != nil {
			t.Fatalf("latency sample %d final: %v: %s", sample, err, output)
		}
		latencies = append(latencies, time.Since(started))
	}
	sortedLatencies := append([]time.Duration(nil), latencies...)
	sort.Slice(sortedLatencies, func(i, j int) bool { return sortedLatencies[i] < sortedLatencies[j] })
	p95 := sortedLatencies[(len(sortedLatencies)*95+99)/100-1]
	maximum := sortedLatencies[len(sortedLatencies)-1]
	if maximum > 350*time.Millisecond {
		t.Fatalf("staged replacement latency max=%s exceeds 350ms p95=%s", maximum, p95)
	}
	t.Logf("FEASIBILITY PASS branch=staged-fail-closed latency_samples=%d p95=%s max=%s", latencySamples, p95, maximum)
}

func TestPinnedXrayAcceptsProductionSizedRoutingUpdate(t *testing.T) {
	binaryPath := os.Getenv("HYDRAT_XRAY_BINARY")
	if binaryPath == "" {
		t.Fatal("HYDRAT_XRAY_BINARY is required")
	}

	apiAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixtureXrayAPIPort+1))
	xray := startXray(t, binaryPath, map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "warning"},
		"api": map[string]any{
			"tag": "api", "listen": apiAddress, "services": []string{"RoutingService"},
		},
		"outbounds": []any{
			map[string]any{"tag": "api", "protocol": "blackhole", "settings": map[string]any{}},
			map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
		},
		"routing": stagingRules(),
	}, apiAddress)
	defer xray.stop(t)

	domains := make([]string, 75_000)
	for index := range domains {
		domains[index] = fmt.Sprintf("full:%06d.%s.example", index, strings.Repeat("a", 48))
	}
	routing := map[string]any{
		"domainStrategy": "AsIs",
		"rules": []any{
			map[string]any{"type": "field", "ruleTag": "large-api", "inboundTag": []string{"api"}, "outboundTag": "api"},
			map[string]any{"type": "field", "ruleTag": "large-domains", "domain": domains, "outboundTag": "block"},
			map[string]any{"type": "field", "ruleTag": "large-fail-closed", "network": "tcp,udp", "outboundTag": "block"},
		},
	}
	body, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 4*1024*1024 {
		t.Fatalf("routing fixture is only %d bytes; want more than the default gRPC limit", len(body))
	}
	if output, err := replaceRules(context.Background(), binaryPath, apiAddress, routing); err != nil {
		t.Fatalf("replace %d-byte routing document: %v: %s", len(body), err, output)
	}
}

func TestPinnedXrayAcceptsLegacyInsecureVLESSOutbound(t *testing.T) {
	binaryPath := os.Getenv("HYDRAT_XRAY_BINARY")
	if binaryPath == "" {
		t.Fatal("HYDRAT_XRAY_BINARY is required")
	}

	apiAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixtureXrayAPIPort+2))
	xray := startXray(t, binaryPath, map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "warning"},
		"api": map[string]any{
			"tag": "api", "listen": apiAddress, "services": []string{"HandlerService"},
		},
		"outbounds": []any{
			map[string]any{"tag": "api", "protocol": "blackhole", "settings": map[string]any{}},
			map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
		},
		"routing": stagingRules(),
	}, apiAddress)
	defer xray.stop(t)

	outbound := map[string]any{
		"tag": "legacy-vless-grpc", "protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "8.8.8.8", "port": 2083,
			"users": []any{map[string]any{
				"id": "00000000-0000-4000-8000-000000000002", "encryption": "none",
			}},
		}}},
		"streamSettings": map[string]any{
			"network": "grpc", "grpcSettings": map[string]any{"serviceName": "vless"},
		},
	}
	if output, err := addOutbounds(context.Background(), binaryPath, apiAddress, outbound); err != nil {
		t.Fatalf("add legacy insecure VLESS outbound: %v: %s", err, output)
	}
}

func dnsOutbound(tag, proxyTag, rewriteAddress string) map[string]any {
	return map[string]any{
		"tag": tag, "protocol": "dns",
		"settings": map[string]any{
			"rewriteNetwork": "tcp",
			"rewriteAddress": rewriteAddress,
			"rewritePort":    53,
			"rules":          []any{map[string]any{"action": "direct"}},
		},
		"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": proxyTag}},
	}
}

func completeRules(dnsTag string) map[string]any {
	return map[string]any{
		"domainStrategy": "AsIs",
		"rules": []any{
			map[string]any{"type": "field", "ruleTag": "fixture-api", "inboundTag": []string{"api"}, "outboundTag": "api"},
			map[string]any{"type": "field", "ruleTag": "fixture-dns", "inboundTag": []string{"dns-in"}, "network": "udp", "outboundTag": dnsTag},
			map[string]any{"type": "field", "ruleTag": "fixture-fail-closed", "network": "tcp,udp", "outboundTag": "block"},
		},
	}
}

func stagingRules() map[string]any {
	return map[string]any{
		"domainStrategy": "AsIs",
		"rules": []any{
			map[string]any{"type": "field", "ruleTag": "fixture-api", "inboundTag": []string{"api"}, "outboundTag": "api"},
			map[string]any{"type": "field", "ruleTag": "fixture-dns-block", "inboundTag": []string{"dns-in"}, "network": "udp", "outboundTag": "block"},
			map[string]any{"type": "field", "ruleTag": "fixture-fail-closed", "network": "tcp,udp", "outboundTag": "block"},
		},
	}
}

func replaceRules(parent context.Context, binaryPath, apiAddress string, routing map[string]any) (string, error) {
	body, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		return "", fmt.Errorf("encode routing rules: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, feasibilityTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, "api", "adrules", "--server="+apiAddress)
	command.Stdin = bytes.NewReader(body)
	output, err := command.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		return strings.TrimSpace(string(output)), ctx.Err()
	}
	return strings.TrimSpace(string(output)), err
}

func addOutbounds(parent context.Context, binaryPath, apiAddress string, outbounds ...any) (string, error) {
	body, err := json.Marshal(map[string]any{"outbounds": outbounds})
	if err != nil {
		return "", fmt.Errorf("encode outbounds: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, feasibilityTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, "api", "ado", "--server="+apiAddress)
	command.Stdin = bytes.NewReader(body)
	output, err := command.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		return strings.TrimSpace(string(output)), ctx.Err()
	}
	return strings.TrimSpace(string(output)), err
}

type xrayProcess struct {
	cancel context.CancelFunc
	done   chan error
	log    *os.File
}

func (process *xrayProcess) evidence() string {
	if process == nil || process.log == nil {
		return ""
	}
	output, err := os.ReadFile(process.log.Name())
	if err != nil {
		return "unreadable"
	}
	if len(output) > 1200 {
		output = output[len(output)-1200:]
	}
	normalized := strings.Join(strings.Fields(string(output)), " ")
	if len(normalized) > 900 {
		normalized = normalized[len(normalized)-900:]
	}
	return normalized
}

func startXray(t *testing.T, binaryPath string, config map[string]any, readyAddress string) *xrayProcess {
	t.Helper()
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "xray-*.log")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binaryPath, "run", "-config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		t.Fatalf("start Xray: %v", err)
	}
	process := &xrayProcess{cancel: cancel, done: make(chan error, 1), log: logFile}
	go func() {
		process.done <- command.Wait()
	}()

	deadline := time.Now().Add(feasibilityTimeout)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", readyAddress, 50*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return process
		}
		select {
		case processErr := <-process.done:
			cancel()
			_, _ = logFile.Seek(0, io.SeekStart)
			output, _ := io.ReadAll(io.LimitReader(logFile, 4096))
			_ = logFile.Close()
			t.Fatalf("Xray exited before listening on %s: %v: %s", readyAddress, processErr, strings.TrimSpace(string(output)))
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.stop(t)
	t.Fatalf("Xray did not listen on %s within %s", readyAddress, feasibilityTimeout)
	return nil
}

func (process *xrayProcess) stop(t *testing.T) {
	t.Helper()
	if process == nil || process.cancel == nil {
		return
	}
	process.cancel()
	select {
	case <-process.done:
	case <-time.After(feasibilityTimeout):
		t.Error("Xray did not stop after cancellation")
	}
	_ = process.log.Close()
	process.cancel = nil
}

type grpcResponseGate struct {
	address         string
	listener        net.Listener
	target          string
	responseBlocked chan struct{}
	release         chan struct{}
	blockOnce       sync.Once
	closeOnce       sync.Once
}

func startGRPCResponseGate(t *testing.T, target string) *grpcResponseGate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := &grpcResponseGate{
		address:         listener.Addr().String(),
		listener:        listener,
		target:          target,
		responseBlocked: make(chan struct{}),
		release:         make(chan struct{}),
	}
	t.Cleanup(gate.close)
	go gate.serve()
	return gate
}

func (gate *grpcResponseGate) serve() {
	client, err := gate.listener.Accept()
	if err != nil {
		return
	}
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", gate.target, feasibilityTimeout)
	if err != nil {
		return
	}
	defer upstream.Close()

	requestDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		close(requestDone)
	}()
	_ = gate.forwardControlFrames(client, upstream)
	<-requestDone
}

func (gate *grpcResponseGate) forwardControlFrames(client net.Conn, upstream net.Conn) error {
	for {
		var header [http2FrameHeaderLength]byte
		if _, err := io.ReadFull(upstream, header[:]); err != nil {
			return err
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		payload := make([]byte, length)
		if _, err := io.ReadFull(upstream, payload); err != nil {
			return err
		}
		streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff
		if streamID != 0 {
			gate.blockOnce.Do(func() { close(gate.responseBlocked) })
			<-gate.release
		}
		if _, err := client.Write(header[:]); err != nil {
			return err
		}
		if _, err := client.Write(payload); err != nil {
			return err
		}
	}
}

func (gate *grpcResponseGate) close() {
	gate.closeOnce.Do(func() {
		close(gate.release)
		_ = gate.listener.Close()
	})
}

type tcpFixture struct {
	address  string
	listener net.Listener
	hits     chan string
	once     sync.Once
}

type udpFixture struct {
	address    string
	connection *net.UDPConn
	hits       chan string
	once       sync.Once
}

func startUDPDNSFixture(t *testing.T) *udpFixture {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &udpFixture{
		address: connection.LocalAddr().String(), connection: connection,
		hits: make(chan string, 16),
	}
	t.Cleanup(func() { fixture.once.Do(func() { _ = fixture.connection.Close() }) })
	go func() {
		buffer := make([]byte, 512)
		for {
			size, client, readErr := connection.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if size < 12 {
				continue
			}
			fixture.hits <- "direct-udp"
			response := append([]byte(nil), buffer[:size]...)
			response[2] |= 0x80
			response[3] |= 0x80
			_, _ = connection.WriteToUDP(response, client)
		}
	}()
	return fixture
}

func startTCPDNSFixture(t *testing.T) *tcpFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tcpFixture{
		address: listener.Addr().String(), listener: listener,
		hits: make(chan string, 16),
	}
	t.Cleanup(func() { fixture.close() })
	go fixture.serveDNS()
	return fixture
}

func (fixture *tcpFixture) serveDNS() {
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(feasibilityTimeout))
			var size [2]byte
			if _, err := io.ReadFull(connection, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(connection, query); err != nil || len(query) < 12 {
				return
			}
			fixture.hits <- "tcp"
			response := append([]byte(nil), query...)
			response[2] |= 0x80
			response[3] |= 0x80
			binary.BigEndian.PutUint16(size[:], uint16(len(response)))
			_, _ = connection.Write(append(size[:], response...))
		}()
	}
}

func startTCPRelayFixture(t *testing.T, target string) *tcpFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tcpFixture{
		address: listener.Addr().String(), listener: listener,
		hits: make(chan string, 16),
	}
	t.Cleanup(func() { fixture.close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				upstream, dialErr := net.DialTimeout("tcp", target, feasibilityTimeout)
				if dialErr != nil {
					return
				}
				defer upstream.Close()
				fixture.hits <- "vless"
				proxyTCP(connection, upstream)
			}()
		}
	}()
	return fixture
}

func (fixture *tcpFixture) close() {
	fixture.once.Do(func() {
		_ = fixture.listener.Close()
	})
}

type socksFixture struct {
	port     int
	listener net.Listener
	target   string
	hits     chan string
	once     sync.Once
}

func startSOCKSFixture(t *testing.T, target string) *socksFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &socksFixture{
		port: listener.Addr().(*net.TCPAddr).Port, listener: listener,
		target: target, hits: make(chan string, 16),
	}
	t.Cleanup(func() { fixture.once.Do(func() { _ = fixture.listener.Close() }) })
	go fixture.serve()
	return fixture
}

func (fixture *socksFixture) serve() {
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			return
		}
		go fixture.handle(connection)
	}
}

func (fixture *socksFixture) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(feasibilityTimeout))
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	host, err := readSOCKSAddress(connection, request[3])
	if err != nil {
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(connection, portBytes[:]); err != nil {
		return
	}
	requested := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:]))))
	upstream, err := net.DialTimeout("tcp", fixture.target, feasibilityTimeout)
	if err != nil {
		_, _ = connection.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	fixture.hits <- requested
	proxyTCP(connection, upstream)
}

func readSOCKSAddress(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		address := make([]byte, net.IPv4len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", err
		}
		address := make([]byte, int(size[0]))
		_, err := io.ReadFull(reader, address)
		return string(address), err
	case 4:
		address := make([]byte, net.IPv6len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
}

func proxyTCP(left, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		done <- struct{}{}
	}()
	<-done
}

func requireDNSQuery(t *testing.T, address string, id uint16) {
	t.Helper()
	if err := exchangeDNS(address, id); err != nil {
		t.Fatal(err)
	}
}

func exchangeDNS(address string, id uint16) error {
	return exchangeDNSWithTimeout(address, id, feasibilityTimeout)
}

func exchangeDNSWithTimeout(address string, id uint16, timeout time.Duration) error {
	connection, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return fmt.Errorf("dial UDP DNS ingress: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	query := dnsQuery(id)
	if _, err := connection.Write(query); err != nil {
		return fmt.Errorf("write UDP DNS query: %w", err)
	}
	response := make([]byte, 512)
	size, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("read UDP DNS response: %w", err)
	}
	if size < 12 || binary.BigEndian.Uint16(response[:2]) != id || response[2]&0x80 == 0 {
		return fmt.Errorf("invalid UDP DNS response: size=%d", size)
	}
	return nil
}

func requireDNSBlocked(t *testing.T, address string, id uint16) {
	t.Helper()
	if err := exchangeDNSWithTimeout(address, id, 250*time.Millisecond); err == nil {
		t.Fatal("DNS exchange unexpectedly escaped fail-closed routing")
	}
}

func dnsQuery(id uint16) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{"fixture", "test"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query
}

func requireFixtureHit(t *testing.T, hits <-chan string, fixtureName string) string {
	t.Helper()
	select {
	case hit := <-hits:
		return hit
	case <-time.After(feasibilityTimeout):
		t.Fatalf("%s did not observe the DNS exchange", fixtureName)
		return ""
	}
}

func optionalFixtureHit(hits <-chan string) string {
	select {
	case hit := <-hits:
		return hit
	default:
		return ""
	}
}

func requireNoFixtureHit(t *testing.T, hits <-chan string, fixtureName string) {
	t.Helper()
	if hit := optionalFixtureHit(hits); hit != "" {
		t.Fatalf("%s observed forbidden egress: %q", fixtureName, hit)
	}
}

func sanitizeEvidence(output string) string {
	output = strings.Join(strings.Fields(output), " ")
	if len(output) > 300 {
		return output[:300]
	}
	return output
}
