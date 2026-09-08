package agentapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/probetimeout"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestClientSendsDesiredPlanAndReadsActivity(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/plan":
			body, _ := io.ReadAll(request.Body)
			if !bytes.Contains(body, []byte(`"generation":9`)) {
				t.Fatalf("plan body=%s", body)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		case "/v1/activity":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"peers":[{"public_key":"peer"}]}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	if err := client.Apply(context.Background(), dataplane.DesiredPlan{Generation: 9}); err != nil {
		t.Fatal(err)
	}
	peers, err := client.Activity(context.Background())
	if err != nil || len(peers) != 1 || peers[0].PublicKey != "peer" {
		t.Fatalf("peers=%+v err=%v", peers, err)
	}
}

func TestClientSendsCriticalActiveProbeToIsolatedEndpoint(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/probes/active-critical" {
			t.Fatalf("critical active path=%q", request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"candidate_id":"candidate","success":true}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	response, err := client.ProbeActiveCritical(context.Background(), ProbeRequest{
		CandidateID: "candidate", Kind: "vless", Payload: "payload",
	})
	if err != nil || !response.Success {
		t.Fatalf("critical active response=%+v err=%v", response, err)
	}
}

func TestClientCriticalActiveTimeoutUsesDedicatedResponseSlack(t *testing.T) {
	var remaining time.Duration
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("critical active request has no deadline")
		}
		remaining = time.Until(deadline)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"candidate_id":"candidate","success":true}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(
		&http.Client{Transport: transport},
		WithClientProbeDeadlines(3*time.Second, 20*time.Second, 550*time.Millisecond, 5*time.Minute, 6*time.Minute),
		WithClientActiveResponseSlack(75*time.Millisecond),
	)
	if _, err := client.ProbeActiveCritical(context.Background(), ProbeRequest{
		CandidateID: "candidate", Kind: "vless", Payload: "payload",
	}); err != nil {
		t.Fatal(err)
	}
	if remaining < 600*time.Millisecond || remaining > 625*time.Millisecond {
		t.Fatalf("critical active timeout=%s want approximately 625ms", remaining)
	}
}

func TestClientPreservesRuntimeRecoveringApplySentinel(t *testing.T) {
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"error":"dataplane runtime is recovering"}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	if err := client.Apply(
		context.Background(), dataplane.DesiredPlan{Generation: 9},
	); !errors.Is(err, dataplane.ErrRuntimeRecovering) {
		t.Fatalf("Apply error=%v want ErrRuntimeRecovering", err)
	}
}

func TestClientPreservesGenericRetryableApplyFailure(t *testing.T) {
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"error":"xray route API unavailable","retryable":true}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	err := client.Apply(context.Background(), dataplane.DesiredPlan{Generation: 9})
	var temporary dataplane.TemporaryError
	if errors.Is(err, dataplane.ErrRuntimeRecovering) ||
		!errors.As(err, &temporary) || !temporary.Temporary() ||
		!bytes.Contains([]byte(err.Error()), []byte("xray route API unavailable")) {
		t.Fatalf("Apply error=%v was not preserved as generic temporary", err)
	}
}

func TestClientKeepsPermanentApplyFailureNonRetryable(t *testing.T) {
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"error":"invalid desired plan"}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	err := client.Apply(context.Background(), dataplane.DesiredPlan{Generation: 9})
	var temporary dataplane.TemporaryError
	if err == nil || errors.As(err, &temporary) {
		t.Fatalf("Apply error=%v unexpectedly retryable", err)
	}
}

func TestClientMarksApplyTransportFailuresTemporary(t *testing.T) {
	cause := errors.New("agent connection refused")
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
		func(*http.Request) (*http.Response, error) { return nil, cause },
	)})
	err := client.Apply(context.Background(), dataplane.DesiredPlan{Generation: 9})
	var temporary dataplane.TemporaryError
	if !errors.Is(err, cause) || !errors.As(err, &temporary) ||
		!temporary.Temporary() {
		t.Fatalf("Apply transport error=%v was not temporary", err)
	}
}

func TestClientMarksApplyResponseReadFailuresTemporary(t *testing.T) {
	cause := errors.New("agent response ended early")
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       failingReadCloser{err: cause},
				Header:     make(http.Header),
			}, nil
		},
	)})
	err := client.Apply(context.Background(), dataplane.DesiredPlan{Generation: 9})
	var temporary dataplane.TemporaryError
	if !errors.Is(err, cause) || !errors.As(err, &temporary) ||
		!temporary.Temporary() {
		t.Fatalf("Apply response read error=%v was not temporary", err)
	}
}

func TestClientPreservesCanceledApplyTransportContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport ignored cancellation")
		},
	)})
	err := client.Apply(ctx, dataplane.DesiredPlan{Generation: 9})
	var temporary dataplane.TemporaryError
	if !errors.Is(err, context.Canceled) || errors.As(err, &temporary) {
		t.Fatalf("Apply cancellation error=%v temporary=%v",
			err, errors.As(err, &temporary))
	}
}

func TestClientProvisionsAndChangesPeerState(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/peers":
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewBufferString(`{"peer":{"name":"phone","address":"10.44.0.3/32","public_key":"public"},"config":"wg"}`)), Header: make(http.Header)}, nil
		case "/v1/peer-state":
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	peer, config, err := client.CreatePeer(context.Background(), "phone", "10.44.0.3/32")
	if err != nil || peer.PublicKey != "public" || config != "wg" {
		t.Fatalf("peer=%+v config=%q err=%v", peer, config, err)
	}
	if err := client.SetPeerPaused(context.Background(), wireguard.Peer{Name: "phone", PublicKey: "public", Address: "10.44.0.3/32"}, true); err != nil {
		t.Fatal(err)
	}
}

func TestClientManagesRemoteTorProfiles(t *testing.T) {
	var requests []string
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"profiles":[{"candidate_id":"bridge","socks_addr":"127.0.0.1:19050"}]}`)), Header: make(http.Header)}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	fetched, err := client.FetchProfiles(context.Background())
	if err != nil || len(fetched) != 1 || fetched[0].CandidateID != "bridge" {
		t.Fatalf("fetched profiles=%+v err=%v", fetched, err)
	}
	profiles, err := client.ReconcileProfiles(context.Background(), []torpool.Candidate{{ID: "bridge", Qualified: true}})
	if err != nil || len(profiles) != 1 || profiles[0].CandidateID != "bridge" {
		t.Fatalf("profiles=%+v err=%v", profiles, err)
	}
	if cached := client.Profiles(); len(cached) != 1 || cached[0].CandidateID != "bridge" {
		t.Fatalf("cached profiles=%+v", cached)
	}
	wantRequests := []string{"GET /v1/profiles", "POST /v1/profiles/reconcile"}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("profile requests=%v want=%v", requests, wantRequests)
	}
}

func TestClientProfileMutationClassifiesOnlyAmbiguousFailures(t *testing.T) {
	t.Run("canceled before request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
			func(*http.Request) (*http.Response, error) {
				t.Fatal("transport called for pre-canceled request")
				return nil, nil
			},
		)})
		_, err := client.ExploreNext(ctx)
		if !errors.Is(err, context.Canceled) || isAmbiguousProfileMutation(err) {
			t.Fatalf("pre-canceled mutation error=%v ambiguous=%v",
				err, isAmbiguousProfileMutation(err))
		}
	})

	t.Run("permanent HTTP rejection", func(t *testing.T) {
		client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
			func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusConflict,
					Body: io.NopCloser(bytes.NewBufferString(
						`{"error":"Tor protected profiles exceed capacity"}`,
					)),
					Header: make(http.Header),
				}, nil
			},
		)})
		_, err := client.ExploreNext(context.Background())
		if err == nil || isAmbiguousProfileMutation(err) {
			t.Fatalf("permanent mutation error=%v ambiguous=%v",
				err, isAmbiguousProfileMutation(err))
		}
		if !strings.Contains(err.Error(), "Tor protected profiles exceed capacity") {
			t.Fatalf("permanent mutation error omitted agent detail: %v", err)
		}
	})

	t.Run("transport failure after send", func(t *testing.T) {
		cause := errors.New("connection reset after request")
		client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
			func(*http.Request) (*http.Response, error) { return nil, cause },
		)})
		_, err := client.ExploreNext(context.Background())
		if !errors.Is(err, cause) || !isAmbiguousProfileMutation(err) {
			t.Fatalf("transport mutation error=%v ambiguous=%v",
				err, isAmbiguousProfileMutation(err))
		}
	})

	t.Run("invalid success response", func(t *testing.T) {
		client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(
			func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"profiles":`)),
					Header:     make(http.Header),
				}, nil
			},
		)})
		_, err := client.ExploreNext(context.Background())
		if err == nil || !isAmbiguousProfileMutation(err) {
			t.Fatalf("decode mutation error=%v ambiguous=%v",
				err, isAmbiguousProfileMutation(err))
		}
	})
}

func TestClientHTTP409PartialProfileMutationRequiresAuthoritativeFetch(t *testing.T) {
	state := "old"
	var requests []string
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		if request.Method == http.MethodPost {
			state = "partial"
			return &http.Response{
				StatusCode: http.StatusConflict,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":"partial"}`)),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(
				`{"profiles":[{"candidate_id":"` + state + `"}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	if _, err := client.FetchProfiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReconcileProfiles(context.Background(), nil); err == nil {
		t.Fatal("HTTP 409 partial mutation returned success")
	}
	profiles, err := client.FetchProfiles(context.Background())
	if err != nil || len(profiles) != 1 || profiles[0].CandidateID != "partial" {
		t.Fatalf("authoritative profiles=%+v err=%v", profiles, err)
	}
	if cached := client.Profiles(); !reflect.DeepEqual(cached, profiles) {
		t.Fatalf("cache=%+v authoritative=%+v", cached, profiles)
	}
	want := []string{
		"GET /v1/profiles", "POST /v1/profiles/reconcile", "GET /v1/profiles",
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests=%v want=%v", requests, want)
	}
}

func isAmbiguousProfileMutation(err error) bool {
	var ambiguous interface {
		AmbiguousMutation() bool
	}
	return errors.As(err, &ambiguous) && ambiguous.AmbiguousMutation()
}

func TestClientHealthRequiresHealthyAgentResponse(t *testing.T) {
	status := http.StatusOK
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/health" {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("healthy agent: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("unhealthy agent was accepted")
	}
}

func TestClientProbeRuntimeHealthDecodesSnapshotAndToleratesUnknownFields(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/health" {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(`{
				"status":"ok",
				"api_version":"v1",
				"future_top_level":{"enabled":true},
				"probe_runtime":{
					"status":"draining",
					"epoch":9,
					"rss_bytes":268435456,
					"fd_count":512,
					"completed_probes":250,
					"recycle_count":4,
					"last_recycle_reason":"probe_limit",
					"future_runtime_field":"ignored"
				}
			}`)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})

	snapshot, err := client.ProbeRuntimeHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := proberuntime.Snapshot{
		Status:            "draining",
		Epoch:             9,
		RSSBytes:          268435456,
		FDCount:           512,
		CompletedProbes:   250,
		RecycleCount:      4,
		LastRecycleReason: "probe_limit",
	}
	if snapshot != want {
		t.Fatalf("snapshot=%+v, want %+v", snapshot, want)
	}
}

func TestClientProbeRuntimeHealthDecodesDegradedSnapshotFromUnavailableHealth(t *testing.T) {
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body: io.NopCloser(bytes.NewBufferString(`{
				"status":"starting",
				"api_version":"v1",
				"probe_runtime":{
					"status":"degraded",
					"epoch":11,
					"recycle_count":5,
					"last_recycle_reason":"readiness_failure"
				}
			}`)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})

	snapshot, err := client.ProbeRuntimeHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := proberuntime.Snapshot{
		Status:            "degraded",
		Epoch:             11,
		RecycleCount:      5,
		LastRecycleReason: "readiness_failure",
	}
	if snapshot != want {
		t.Fatalf("snapshot=%+v, want %+v", snapshot, want)
	}
}

func TestClientProbeRuntimeHealthKeepsMissingLegacySnapshotCompatible(t *testing.T) {
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})

	snapshot, err := client.ProbeRuntimeHealth(context.Background())
	if err != nil || snapshot != (proberuntime.Snapshot{}) {
		t.Fatalf("legacy snapshot=%+v err=%v", snapshot, err)
	}
}

func TestClientActiveProbeRuntimeHealthDecodesDedicatedSnapshot(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/health" {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body: io.NopCloser(bytes.NewBufferString(`{
				"status":"starting",
				"probe_runtime":{"status":"ready","epoch":8},
				"active_probe_runtime":{
					"status":"draining",
					"epoch":3,
					"completed_probes":411,
					"recycle_count":2,
					"last_recycle_reason":"fd_limit",
					"future_runtime_field":"ignored"
				}
			}`)),
			Header: make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(&http.Client{Transport: transport})

	snapshot, err := client.ActiveProbeRuntimeHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := proberuntime.Snapshot{
		Status: "draining", Epoch: 3, CompletedProbes: 411,
		RecycleCount: 2, LastRecycleReason: "fd_limit",
	}
	if snapshot != want {
		t.Fatalf("snapshot=%+v, want %+v", snapshot, want)
	}
}

func TestClientProbeCanOutliveOrdinaryTimeout(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case <-time.After(40 * time.Millisecond):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"candidate_id":"tor","success":true}`)),
				Header:     make(http.Header),
			}, nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})
	client := newClientWithHTTP(&http.Client{Transport: transport, Timeout: 15 * time.Millisecond})

	response, err := client.ProbeFast(context.Background(), ProbeRequest{
		CandidateID: "tor", Kind: "tor_bridge", Payload: "bridge",
	})
	if err != nil {
		t.Fatalf("probe was canceled by ordinary client timeout: %v", err)
	}
	if !response.Success {
		t.Fatalf("probe response=%+v", response)
	}
}

func TestClientProbeTimeoutFollowsConfiguredTorDeadline(t *testing.T) {
	const torFullDeadline = 90 * time.Second
	var remaining time.Duration
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("probe request has no deadline")
		}
		remaining = time.Until(deadline)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"candidate_id":"tor","success":true}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(
		&http.Client{Transport: transport, Timeout: 15 * time.Millisecond},
		WithClientProbeDeadlines(
			3*time.Second,
			20*time.Second,
			2*time.Second,
			50*time.Second,
			torFullDeadline,
		),
	)

	if _, err := client.ProbeFull(context.Background(), ProbeRequest{
		CandidateID: "tor", Kind: "tor_bridge", Payload: "bridge",
	}); err != nil {
		t.Fatal(err)
	}
	if remaining <= torFullDeadline {
		t.Fatalf("probe timeout=%s, want longer than server deadline %s", remaining, torFullDeadline)
	}
	if remaining > torFullDeadline+10*time.Second {
		t.Fatalf("probe response slack is too large: timeout=%s server=%s", remaining, torFullDeadline)
	}
}

func TestClientProbeQoEUsesDedicatedEndpointAndDeadline(t *testing.T) {
	const qoeDeadline = 35 * time.Second
	var remaining time.Duration
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/probes/qoe" {
			t.Fatalf("path=%q, want QoE endpoint", request.URL.Path)
		}
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("QoE request has no deadline")
		}
		remaining = time.Until(deadline)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"candidate_id":"candidate","success":true,"qoe":{"Success":true,"Bytes":65536}}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := newClientWithHTTP(
		&http.Client{Transport: transport},
		WithClientQoEProbeDeadline(qoeDeadline),
	)

	response, err := client.ProbeQoE(context.Background(), ProbeRequest{
		CandidateID: "candidate", Kind: "vless", Payload: "secret-route",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.QoE == nil || response.QoE.Bytes != 65536 {
		t.Fatalf("response=%+v", response)
	}
	want := ProbeRequestTimeout(qoeDeadline)
	if remaining <= qoeDeadline || remaining > want || remaining < want-time.Second {
		t.Fatalf("QoE request timeout=%s, want approximately %s", remaining, want)
	}
}

func TestProbeRequestTimeoutSaturatesAtDurationLimit(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	tests := []struct {
		name           string
		serverDeadline time.Duration
		want           time.Duration
	}{
		{name: "negative fallback", serverDeadline: -time.Second, want: probetimeout.ProbeResponseSlack},
		{name: "zero fallback", serverDeadline: 0, want: probetimeout.ProbeResponseSlack},
		{name: "normal", serverDeadline: time.Minute, want: time.Minute + probetimeout.ProbeResponseSlack},
		{name: "exact boundary", serverDeadline: probetimeout.MaxProbeServerDeadline, want: maxDuration},
		{name: "above boundary", serverDeadline: probetimeout.MaxProbeServerDeadline + 1, want: maxDuration},
		{name: "maximum", serverDeadline: maxDuration, want: maxDuration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ProbeRequestTimeout(test.serverDeadline); got != test.want {
				t.Fatalf("ProbeRequestTimeout(%s)=%s, want %s", test.serverDeadline, got, test.want)
			}
		})
	}
}

func TestProbeRequestTimeoutSaturationDoesNotCancelImmediately(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	ctx, cancel := context.WithTimeout(context.Background(), ProbeRequestTimeout(maxDuration))
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatalf("saturated timeout canceled immediately: %v", ctx.Err())
	case <-time.After(10 * time.Millisecond):
	}
}

func TestClientProbeHonorsCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client := newClientWithHTTP(&http.Client{Transport: transport, Timeout: 15 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.ProbeFull(ctx, ProbeRequest{
			CandidateID: "tor", Kind: "tor_bridge", Payload: "bridge",
		})
		result <- err
	}()
	<-started

	start := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("probe error=%v, want caller cancellation", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("caller cancellation took %s", elapsed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("probe ignored caller cancellation")
	}
}

func TestClientOrdinaryCallsRetainShortTimeout(t *testing.T) {
	transport := clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client := newClientWithHTTP(&http.Client{Transport: transport, Timeout: 15 * time.Millisecond})

	if err := client.Health(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("health error=%v, want short client deadline", err)
	}
	if err := client.Apply(context.Background(), dataplane.DesiredPlan{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("apply error=%v, want short client deadline", err)
	}
}

type clientRoundTripFunc func(*http.Request) (*http.Response, error)

func (function clientRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct {
	err error
}

func (reader failingReadCloser) Read([]byte) (int, error) { return 0, reader.err }
func (failingReadCloser) Close() error                    { return nil }
