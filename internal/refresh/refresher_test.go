package refresh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

func TestRefreshDrainsEveryMissingCandidateIncludingWarmTorWithoutDeleting(t *testing.T) {
	ctx := context.Background()
	payload := "vless://one@example.net:443?security=tls#one\n" +
		"Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567\n"
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/lifecycle")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024*1024, 10_000).
		WithRetirementGrace(15 * time.Minute)
	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatal(err)
	}
	initial, err := database.ListCandidates(ctx, listed[0].ID)
	if err != nil || len(initial) != 2 {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	var tor store.Candidate
	for _, candidate := range initial {
		if candidate.Kind == sources.KindTorBridge {
			tor = candidate
		}
	}
	payload = "vless://one@example.net:443?security=tls#one\n"
	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatal(err)
	}
	active, err := database.ListCandidates(ctx, listed[0].ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	routable, err := database.ListRoutableCandidates(ctx, []string{tor.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(routable) != 2 {
		t.Fatalf("referenced draining Tor was not preserved: %+v", routable)
	}
	if payload, err := database.CandidatePayload(ctx, tor.ID); err != nil || payload == "" {
		t.Fatalf("Tor payload=%q err=%v", payload, err)
	}
}

func TestRefreshSubscriptionAtomicallyPreservesLastKnownGood(t *testing.T) {
	ctx := context.Background()
	fail := false
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		if fail {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad gateway"))}, nil
		}
		payload := "vless://one@example.net:443?security=tls#one\nvless://two@example.org:443?security=tls#two\n"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(base64.StdEncoding.EncodeToString([]byte(payload))))}, nil
	})}

	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/list")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024*1024)
	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatal(err)
	}
	candidates, _ := database.ListCandidates(ctx, listed[0].ID)
	if len(candidates) != 2 {
		t.Fatalf("candidates=%+v", candidates)
	}

	fail = true
	if err := refresher.Source(ctx, listed[0].ID); err == nil {
		t.Fatal("expected refresh failure")
	}
	afterFailure, _ := database.ListCandidates(ctx, listed[0].ID)
	if len(afterFailure) != 2 {
		t.Fatalf("last-known-good candidates were removed: %+v", afterFailure)
	}
}

func TestRefreshRejectsSubscriptionWithoutValidCandidates(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("this is not a proxy config"))}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("https://subscription.example/list")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())

	if err := New(database, client, 1024).Source(context.Background(), listed[0].ID); err == nil {
		t.Fatal("invalid subscription must fail closed")
	}
}
func TestDecodeSubscriptionRemovesControlCharactersAndDecodesPrefix(t *testing.T) {
	const cleanLine = "vless://one@example.net:443?security=none#label"
	dirty := cleanLine + "\x10\xd0"
	encoded := base64.StdEncoding.EncodeToString([]byte(dirty))

	decoded := decodeSubscription("base64:" + encoded)
	if decoded != cleanLine {
		t.Fatalf("decoded=%q, want %q", decoded, cleanLine)
	}
}

func TestDecodeSubscriptionSupportsURLSafeBase64WithPrefix(t *testing.T) {
	const cleanLine = "vless://two@example.org:443?security=tls#label"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(cleanLine))

	decoded := decodeSubscription("base64," + encoded)
	if decoded != cleanLine {
		t.Fatalf("decoded=%q, want %q", decoded, cleanLine)
	}
}
func TestDecodeSubscriptionConvertsClashYAMLToVLESSLines(t *testing.T) {
	clash := `proxies:
  - name: ws-example
    type: vless
    server: example.org
    port: 443
    uuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    network: ws
    tls: true
    servername: relay.example.org
    flow: xtls-rprx-vision
    ws-opts:
      path: /?ed=2048
      headers:
        Host: front.example.org`

	decoded := decodeSubscription(clash)
	if decoded == "" {
		t.Fatal("decoded clash yaml must produce vless links")
	}
	parsed, parseErr := url.Parse(decoded)
	if parseErr != nil {
		t.Fatalf("parse decoded=%q err=%v", decoded, parseErr)
	}
	if parsed.Scheme != "vless" || parsed.User == nil || parsed.User.Username() != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
		t.Fatalf("decoded=%q", decoded)
	}
	query := parsed.Query()
	if query.Get("type") != "ws" || query.Get("security") != "tls" || query.Get("flow") != "xtls-rprx-vision" {
		t.Fatalf("query=%v decoded=%q", query, decoded)
	}
	if query.Get("host") != "front.example.org" {
		t.Fatalf("host=%q decoded=%q", query.Get("host"), decoded)
	}
	if query.Get("path") != "/?ed=2048" {
		t.Fatalf("path=%q decoded=%q", query.Get("path"), decoded)
	}
	if query.Get("sni") != "relay.example.org" {
		t.Fatalf("sni=%q decoded=%q", query.Get("sni"), decoded)
	}
	if parsed.Fragment != "ws-example" {
		t.Fatalf("fragment=%q decoded=%q", parsed.Fragment, decoded)
	}
}

func TestDecodeSubscriptionConvertsBase64ClashYAMLToVLESSLines(t *testing.T) {
	clash := `proxies:
  - name: grpc-example
    type: vless
    server: 198.51.100.10
    port: 443
    id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
    network: grpc
    tls: true
    reality-opts:
      public-key: deadbeefcafedecafecafe
      short-id: "12"`
	decoded := decodeSubscription(base64.StdEncoding.EncodeToString([]byte(clash)))
	parsed, parseErr := url.Parse(decoded)
	if parseErr != nil {
		t.Fatalf("parse decoded=%q err=%v", decoded, parseErr)
	}
	query := parsed.Query()
	if query.Get("type") != "grpc" || query.Get("security") != "reality" {
		t.Fatalf("query=%v decoded=%q", query, decoded)
	}
	if query.Get("pbk") != "deadbeefcafedecafecafe" || query.Get("sid") != "12" {
		t.Fatalf("reality query=%v decoded=%q", query, decoded)
	}
}

func TestRefreshSupportsClashYAMLSubscriptions(t *testing.T) {
	const clash = `proxies:
  - name: primary
    type: vless
    server: example.net
    port: 443
    uuid: cccccccc-cccc-cccc-cccc-cccccccccccc
    network: tcp
  - name: ignored
    type: ss
    server: ignored.example
    port: 443
    cipher: aes-128-gcm
    password: secret`

	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(clash)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/clash")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(context.Background())

	if err := New(database, client, 1024).Source(context.Background(), listed[0].ID); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), listed[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates=%+v", candidates)
	}
	if candidates[0].Kind != sources.KindVLESS || candidates[0].Label != "primary" {
		t.Fatalf("primary candidate=%+v", candidates[0])
	}
	payload, err := database.CandidatePayload(context.Background(), candidates[0].ID)
	if err != nil {
		t.Fatalf("candidate payload=%v", err)
	}
	if _, err := xrayconfig.VLESSIdentity(payload); err != nil {
		t.Fatalf("invalid candidate payload=%q err=%v", payload, err)
	}
}

func TestRefreshPopulatesVLESSIdentitiesLeavesTorEmptyAndPreservesDedupOrder(t *testing.T) {
	vless := "vless://secret-id@EXAMPLE.NET.:443" +
		"?type=ws&security=tls&sni=CDN.EXAMPLE.&host=FRONT.EXAMPLE." +
		"&path=%2Fsecret-path&key=secret-key#first-label"
	payload := vless + "\n" +
		strings.Replace(vless, "#first-label", "#duplicate-label", 1) + "\n" +
		"Bridge 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567\n"
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("https://subscription.example/mixed")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(context.Background())

	if err := New(database, client, 1024).Source(context.Background(), listed[0].ID); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), listed[0].ID)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	if candidates[0].Kind != sources.KindVLESS ||
		candidates[1].Kind != sources.KindTorBridge ||
		candidates[0].SourcePosition != 0 ||
		candidates[1].SourcePosition != 1 {
		t.Fatalf("source order or dedup changed: %+v", candidates)
	}
	want, err := xrayconfig.VLESSIdentity(vless)
	if err != nil {
		t.Fatal(err)
	}
	if candidates[0].RouteKey != want.RouteKey ||
		candidates[0].FailureDomain != want.FailureDomain {
		t.Fatalf("VLESS identity=%+v want=%+v", candidates[0], want)
	}
	if candidates[1].RouteKey != "" || candidates[1].FailureDomain != "" {
		t.Fatalf("Tor identity must remain empty: %+v", candidates[1])
	}
}

func TestRefreshInvalidVLESSIdentityPreservesLastKnownGoodWithoutDisclosure(t *testing.T) {
	ctx := context.Background()
	payload := "vless://initial-id@initial.example:443?security=tls#initial\n"
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/list")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024)
	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatal(err)
	}
	before, err := database.ListCandidates(ctx, listed[0].ID)
	if err != nil || len(before) != 1 || before[0].RouteKey == "" || before[0].FailureDomain == "" {
		t.Fatalf("initial candidates=%+v err=%v", before, err)
	}

	payload = "vless://replacement-id@replacement.example:443?security=tls#replacement\n" +
		"vless://secret-uuid@secret-host.example/secret-path?pbk=secret-key#secret-label\n"
	err = refresher.Source(ctx, listed[0].ID)
	if err == nil {
		t.Fatal("invalid VLESS identity must fail the refresh")
	}
	after, listErr := database.ListCandidates(ctx, listed[0].ID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("invalid identity partially replaced last-known-good: before=%+v after=%+v", before, after)
	}

	listed, _ = database.ListSources(ctx)
	for _, message := range []string{err.Error(), listed[0].LastRefreshError} {
		if message != "source refresh failed" {
			t.Fatalf("refresh error=%q, want redacted generic error", message)
		}
		for _, secret := range []string{
			"secret-uuid", "secret-host", "secret-path", "secret-key", "secret-label",
		} {
			if strings.Contains(strings.ToLower(message), secret) {
				t.Fatalf("refresh error %q disclosed %q", message, secret)
			}
		}
	}
}

func TestRefreshRemoteAutoSkipsInvalidVLESSIdentity(t *testing.T) {
	ctx := context.Background()
	payload := "vless://valid-id@valid.example:443?security=tls#valid\n" +
		"vless://broken-sni@broken.example:443?type=tcp&security=reality&pbk=1111111111111111111111111111111111111111111&sni=/?bad@sni#broken\n" +
		"vless://ws-alias@ws.example:443?type=websocket&security=tls#websocket-alias\n"
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("https://subscription.example/remote-auto-feed")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024*1024)
	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatalf("remote_auto source refresh should succeed by skipping invalid candidates: %v", err)
	}
	candidates, err := database.ListCandidates(ctx, listed[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates=%+v, want 2 valid candidates (valid and websocket-alias)", candidates)
	}
}

func TestRefreshStoresFullInventoryBeyondWorkingPoolSize(t *testing.T) {
	payload := candidateSubscription(1284)
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/list")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	refresher := New(database, client, 4*1024*1024, 10_000)
	if err := refresher.Source(context.Background(), listed[0].ID); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), listed[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1284 {
		t.Fatalf("inventory size=%d, want 1284", len(candidates))
	}
}

func TestRefreshStoresCompleteTorTOP100Shape(t *testing.T) {
	payload := torTOP100Fixture()
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("tor-source https://subscription.example/tor-top100")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(context.Background())

	if err := New(database, client, 4*1024*1024, 10_000).Source(context.Background(), listed[0].ID); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), listed[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 100 {
		t.Fatalf("candidate count=%d, want 100", len(candidates))
	}
}

func torTOP100Fixture() string {
	var payload strings.Builder
	for index := 0; index < 60; index++ {
		fmt.Fprintf(&payload, "obfs4 192.0.2.%d:443 %040X cert=redacted iat-mode=0\n", index+1, index+1)
	}
	for index := 0; index < 34; index++ {
		fmt.Fprintf(&payload, "198.51.100.%d:9001 %040X\n", index+1, index+101)
	}
	for index := 0; index < 6; index++ {
		fmt.Fprintf(&payload, "webtunnel [2001:db8::%x]:443 %040X url=https://example.com/%d ver=0.0.1\n", index+1, index+201, index)
	}
	return payload.String()
}

func TestRefreshRejectsCandidateLimitAndPreservesLastKnownGood(t *testing.T) {
	payload := candidateSubscription(3)
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/list")
	_, _ = database.ImportSources(context.Background(), preview.Items)
	listed, _ := database.ListSources(context.Background())
	refresher := New(database, client, 4*1024*1024, 10_000)
	if err := refresher.Source(context.Background(), listed[0].ID); err != nil {
		t.Fatal(err)
	}

	payload = candidateSubscription(10_001)
	err := refresher.Source(context.Background(), listed[0].ID)
	if err == nil || !strings.Contains(err.Error(), "inventory limit") {
		t.Fatalf("error=%v, want inventory limit", err)
	}
	candidates, _ := database.ListCandidates(context.Background(), listed[0].ID)
	if len(candidates) != 3 {
		t.Fatalf("last-known-good inventory was replaced: count=%d", len(candidates))
	}
}

func TestRefreshSendsUserAgentAndHWIDHeaders(t *testing.T) {
	ctx := context.Background()
	var capturedReq *http.Request
	payload := "vless://one@example.net:443?security=tls#one\n"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("proxy-source https://subscription.example/hwid-test")
	if _, err := database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024*1024).
		WithHWID("custom-hwid-12345").
		WithUserAgent("linuxmint_22.3")

	if err := refresher.Source(ctx, listed[0].ID); err != nil {
		t.Fatal(err)
	}
	if capturedReq == nil {
		t.Fatal("request was not captured")
	}
	if ua := capturedReq.Header.Get("User-Agent"); ua != "linuxmint_22.3" {
		t.Errorf("User-Agent = %q, want %q", ua, "linuxmint_22.3")
	}
	if hwid := capturedReq.Header.Get("x-hwid"); hwid != "custom-hwid-12345" {
		t.Errorf("x-hwid = %q, want %q", hwid, "custom-hwid-12345")
	}
	if osHdr := capturedReq.Header.Get("x-device-os"); osHdr == "" {
		t.Errorf("x-device-os is empty")
	}
}

func TestRefreshRejectsHWIDNotSupportedAndMaxDevicesReached(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		headerName string
		wantErr    string
	}{
		{
			name:       "not supported",
			headerName: "x-hwid-not-supported",
			wantErr:    "subscription device/application not supported (x-hwid-not-supported)",
		},
		{
			name:       "max devices reached",
			headerName: "x-hwid-max-devices-reached",
			wantErr:    "subscription device limit reached (x-hwid-max-devices-reached)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set(tc.headerName, "true")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader("vless://dummy@example.net:443#unsupported")),
				}, nil
			})}
			database := refreshStore(t)
			preview := sources.PreviewInput("https://subscription.example/" + tc.name)
			_, _ = database.ImportSources(ctx, preview.Items)
			listed, _ := database.ListSources(ctx)
			refresher := New(database, client, 1024*1024)
			err := refresher.Source(ctx, listed[0].ID)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestRefreshIgnoresDummyUnsupportedCandidate(t *testing.T) {
	ctx := context.Background()
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				"vless://dummy@example.net:443?security=none#Данное приложение не поддерживается\n",
			)),
		}, nil
	})}
	database := refreshStore(t)
	preview := sources.PreviewInput("https://subscription.example/dummy")
	_, _ = database.ImportSources(ctx, preview.Items)
	listed, _ := database.ListSources(ctx)
	refresher := New(database, client, 1024*1024)
	err := refresher.Source(ctx, listed[0].ID)
	if err == nil || !strings.Contains(err.Error(), "no valid VLESS or Tor candidates") {
		t.Fatalf("err = %v, want no valid candidates", err)
	}
}

func candidateSubscription(count int) string {
	var payload strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&payload, "vless://user-%05d@node-%05d.example:443?security=tls#candidate-%05d\n", index, index, index)
	}
	return payload.String()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func refreshStore(t *testing.T) *store.Store {
	t.Helper()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
