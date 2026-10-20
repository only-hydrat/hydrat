package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func TestRecoveryUnsupportedGatewayStillAppliesReplacement(t *testing.T) {
	plan := dataplane.DesiredPlan{Generation: 2, Outbounds: []dataplane.Outbound{{ID: "new", Protocol: dataplane.ProtocolVLESS}},
		Clients:        []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", BlockUDP: true}},
		DirectSuffixes: []string{".ru"}, FailClosed: true}
	scopes := []dataplane.FlowRecovery{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", FailedOutbound: "old", ReplacementOutbound: "new"}}
	for _, status := range []int{404, 501, 400, 409, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var paths []string
			client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				paths = append(paths, req.URL.Path)
				recorder := httptest.NewRecorder()
				if req.URL.Path == "/v1/plan/recovery" {
					recorder.WriteHeader(status)
				} else {
					recorder.WriteHeader(http.StatusNoContent)
				}
				return recorder.Result(), nil
			})})
			err := client.ApplyWithRecovery(t.Context(), plan, scopes)
			if status == 404 || status == 501 {
				if err != nil || len(paths) != 2 || paths[1] != "/v1/plan" {
					t.Fatalf("old gateway blocked failover: paths=%v err=%v", paths, err)
				}
			} else if err == nil || len(paths) != 1 {
				t.Fatalf("ambiguous/rejected request was downgraded: paths=%v err=%v", paths, err)
			}
		})
	}
}

type recoveryApplier struct {
	recordingApplier
	recoveries []dataplane.FlowRecovery
}

func (a *recoveryApplier) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, q []dataplane.FlowRecovery) error {
	a.recoveries = append(a.recoveries, q...)
	return a.Apply(ctx, plan)
}

func TestRecoveryPlanUsesEphemeralEnvelopeAndStrictEndpoint(t *testing.T) {
	applier := &recoveryApplier{}
	handler := NewServer(applier, 64*1024)
	client := newClientWithHTTP(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/plan/recovery" {
			t.Fatalf("path=%s", req.URL.Path)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Result(), nil
	})})
	plan := dataplane.DesiredPlan{Generation: 2, Outbounds: []dataplane.Outbound{{ID: "new", Protocol: dataplane.ProtocolVLESS}}, Clients: []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: "new", UDPOutbound: "new"}}, DirectSuffixes: []string{".ru"}, FailClosed: true}
	scopes := []dataplane.FlowRecovery{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", FailedOutbound: "old", ReplacementOutbound: "new"}}
	if err := client.ApplyWithRecovery(t.Context(), plan, scopes); err != nil {
		t.Fatal(err)
	}
	if len(applier.plans) != 1 || len(applier.recoveries) != 1 || applier.recoveries[0] != scopes[0] {
		t.Fatal("recovery scope lost on wire")
	}
	body, _ := json.Marshal(plan)
	if bytes.Contains(body, []byte("recover")) {
		t.Fatal("ephemeral recovery changed persisted plan contract")
	}
	for _, bad := range []string{
		`{"plan":{},"recoveries":[],"unknown":"secret"}`,
		`{"plan":{},"recoveries":[]} {}`,
		`{"plan":{},"recoveries":[{"source_cidr":"0.0.0.0/0"}]}`,
	} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/plan/recovery", strings.NewReader(bad))
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "secret") {
			t.Fatalf("invalid envelope=%d %s", recorder.Code, recorder.Body.String())
		}
	}
	if len(applier.plans) != 1 {
		t.Fatal("malformed recovery reached applier")
	}
}
