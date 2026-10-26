package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestQoEPeerConfirmsOnlyIndependentFreshServiceEvidence(t *testing.T) {
	for _, test := range []struct {
		name, domain string
		age          time.Duration
		pass, want   bool
	}{
		{"independent", "b", time.Second, true, true},
		{"same domain", "a", time.Second, true, false},
		{"expired", "b", 31 * time.Second, true, false},
		{"common outage", "b", time.Second, false, false},
		{"different policy", "b", time.Second, true, false},
		{"future control", "b", -time.Second, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "target", domain: "a", tcp: true, score: 90}, {name: "peer", domain: test.domain, tcp: true, score: 90}})
			at := time.Unix(1800000000, 0)
			control := healthyQoE(at)
			control.ComparisonPolicy = "same-policy"
			if test.name == "different policy" {
				control.ComparisonPolicy = "other-policy"
			}
			control.ApplicationChecks = []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "ok", OK: test.pass}}
			agent := &recordingQoEAgent{customResponse: true, response: agentapi.ProbeResponse{Success: true, QoE: &control}}
			monitor := &QoEMonitor{Store: database, Agent: agent}
			if err := monitor.probe(context.Background(), at, monitor.clockNow(), candidates["peer"]); err != nil {
				t.Fatal(err)
			}
			failed := qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: "same-policy", ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "timeout"}}}
			agent.response = agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure, QoE: &failed}
			probeAt := at.Add(test.age)
			if err := monitor.probe(context.Background(), probeAt, monitor.clockNow(), candidates["target"]); err != nil {
				t.Fatal(err)
			}
			samples, err := database.ListCandidateQoESamples(context.Background(), candidates["target"].ID, 20)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(samples) > 0; got != test.want {
				t.Fatalf("negative evidence=%t want=%t samples=%+v", got, test.want, samples)
			}
		})
	}
}

func TestQoEComparisonDoesNotRetroactivelyApplyOrReuseFailedControl(t *testing.T) {
	database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "target", domain: "a", tcp: true, score: 90}, {name: "peer", domain: "b", tcp: true, score: 90}})
	at := time.Unix(1800000000, 0)
	agent := &recordingQoEAgent{customResponse: true}
	monitor := &QoEMonitor{Store: database, Agent: agent}
	failed := qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: "policy", ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "timeout"}}}
	probe := func(id string, observation qoe.Observation) {
		t.Helper()
		agent.response = agentapi.ProbeResponse{QoE: &observation}
		if observation.Infrastructure {
			agent.response.FailureClass = agentapi.FailureInfrastructure
		}
		if err := monitor.probe(context.Background(), at, monitor.clockNow(), candidates[id]); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
	}
	count := func(want int) {
		t.Helper()
		if got := mustQoESampleCount(t, database, candidates["target"].ID, 20); got != want {
			t.Fatalf("target samples=%d want=%d", got, want)
		}
	}
	probe("target", failed)
	count(0)
	good := healthyQoE(at)
	good.ComparisonPolicy = "policy"
	good.ApplicationChecks = []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "ok", OK: true}}
	probe("peer", good)
	count(0) // no retrospective negative sample
	probe("target", failed)
	count(1)
	probe("peer", failed)
	probe("target", failed)
	count(1) // newer failed control revoked its success
	probe("peer", good)
	peer := candidates["peer"]
	reservation, err := database.ReserveCandidateObservation(context.Background(), peer, store.ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(context.Background(), peer, reservation, at); err != nil || !commit.Accepted {
		t.Fatalf("commit=%+v %v", commit, err)
	}
	probe("target", failed)
	count(1) // failure generation invalidates control
}

func TestQoEComparisonPolicyAndMandatoryServiceMatrix(t *testing.T) {
	check := func(service string, ok bool) qoe.HTTPCheck {
		return qoe.HTTPCheck{Service: service, Path: "route", Code: "timeout", OK: ok}
	}
	for _, test := range []struct {
		name         string
		target, peer []qoe.HTTPCheck
		want         bool
	}{
		{"youtube", []qoe.HTTPCheck{check("youtube", false)}, []qoe.HTTPCheck{check("youtube", true)}, true},
		{"telegram", []qoe.HTTPCheck{check("telegram", false)}, []qoe.HTTPCheck{check("telegram", true)}, true},
		{"obfuscated Telegram", []qoe.HTTPCheck{check("telegram_obfuscated", false)}, []qoe.HTTPCheck{check("telegram_obfuscated", true)}, true},
		{"padded Telegram", []qoe.HTTPCheck{check("telegram_padded", false)}, []qoe.HTTPCheck{check("telegram_padded", true)}, true},
		{"web cannot confirm native", []qoe.HTTPCheck{check("telegram_obfuscated", false)}, []qoe.HTTPCheck{check("telegram", true)}, false},
		{"different native transport", []qoe.HTTPCheck{check("telegram_padded", false)}, []qoe.HTTPCheck{check("telegram_obfuscated", true)}, false},
		{"common native outage", []qoe.HTTPCheck{check("telegram_padded", false)}, []qoe.HTTPCheck{check("telegram_padded", false)}, false},
		{"native canceled", []qoe.HTTPCheck{{Service: "telegram_padded", Path: "route", Code: "canceled"}}, []qoe.HTTPCheck{check("telegram_padded", true)}, false},
		{"native budget exhausted", []qoe.HTTPCheck{{Service: "telegram_padded", Path: "route", Code: "budget_exhausted"}}, []qoe.HTTPCheck{check("telegram_padded", true)}, false},
		{"unrelated", []qoe.HTTPCheck{check("telegram", false)}, []qoe.HTTPCheck{check("youtube", true)}, false},
		{"instagram optional", []qoe.HTTPCheck{check("instagram", false)}, []qoe.HTTPCheck{check("instagram", true)}, false},
		{"AI disjunction", []qoe.HTTPCheck{check("chatgpt", false), check("openai", false)}, []qoe.HTTPCheck{check("openai", true)}, true},
		{"AI other passed", []qoe.HTTPCheck{check("chatgpt", false), check("openai", true)}, []qoe.HTTPCheck{check("chatgpt", true)}, false},
		{"AI missing", []qoe.HTTPCheck{check("chatgpt", false)}, []qoe.HTTPCheck{check("chatgpt", true)}, false},
		{"budget is not route failure", []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "budget_exhausted"}}, []qoe.HTTPCheck{check("telegram", true)}, false},
		{"cancellation is not route failure", []qoe.HTTPCheck{{Service: "telegram", Path: "route", Code: "canceled"}}, []qoe.HTTPCheck{check("telegram", true)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := confirmsHTTPFailure(qoe.Observation{ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: test.target}, test.peer); got != test.want {
				t.Fatalf("confirmed=%t want=%t", got, test.want)
			}
		})
	}
	if comparableHTTPFailure(qoe.Observation{UnconfirmedHTTP: true, ComparisonPolicy: "policy", ErrorCode: "agent_unavailable"}) {
		t.Fatal("infrastructure failure is comparable")
	}
}

func TestQoEComparisonMemoryAndControlAdmissionAreBounded(t *testing.T) {
	monitor := &QoEMonitor{}
	at := time.Unix(1800000000, 0)
	candidates := make(map[string]store.Candidate)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("route-%03d", i)
		candidate := store.Candidate{ID: id, Fingerprint: id, RouteKey: id, FailureDomain: id}
		candidates[id] = candidate
		observation := healthyQoE(at)
		observation.ComparisonPolicy = "policy"
		for j := 0; j < 100; j++ {
			observation.ApplicationChecks = append(observation.ApplicationChecks, qoe.HTTPCheck{Service: "telegram", Path: "route", OK: true})
		}
		monitor.rememberComparison(candidate, 0, observation, at.Add(time.Duration(i)*time.Millisecond))
		monitor.requestQoEControl(candidate, at)
	}
	if len(monitor.comparisons) > 64 || len(monitor.controlRequests) > 64 {
		t.Fatalf("unbounded evidence=%d requests=%d", len(monitor.comparisons), len(monitor.controlRequests))
	}
	for _, entry := range monitor.comparisons {
		if len(entry.checks) > 16 {
			t.Fatal("unbounded HTTP evidence")
		}
	}
	controls := monitor.requestedQoEControls(at, candidates, func(string) bool { return true })
	if len(controls) != 2 {
		t.Fatalf("controls=%d want=2", len(controls))
	}
	if controls := monitor.requestedQoEControls(at.Add(2*time.Minute), candidates, func(string) bool { return true }); len(controls) != 0 {
		t.Fatal("stale control requests survived")
	}
}

func TestQoENativeTelegramPeerEvidenceSurvivesSafeProjection(t *testing.T) {
	for _, service := range []string{"telegram_obfuscated", "telegram_padded"} {
		for _, peerService := range []string{service, "telegram"} {
			t.Run(service+"/peer_"+peerService, func(t *testing.T) {
				database, candidates := qoeMonitorStore(t, []qoeCandidateSpec{{name: "target", domain: "a", tcp: true, score: 90}, {name: "peer", domain: "b", tcp: true, score: 90}})
				at := time.Unix(1800000000, 0)
				good := healthyQoE(at)
				good.ComparisonPolicy = "native-policy"
				good.ApplicationChecks = []qoe.HTTPCheck{{Service: peerService, Path: "route", Code: "ok", OK: true}}
				agent := &recordingQoEAgent{customResponse: true, response: agentapi.ProbeResponse{Success: true, QoE: &good}}
				monitor := &QoEMonitor{Store: database, Agent: agent}
				if err := monitor.probe(context.Background(), at, monitor.clockNow(), candidates["peer"]); err != nil {
					t.Fatal(err)
				}
				bad := qoe.Observation{Infrastructure: true, UnconfirmedHTTP: true, ComparisonPolicy: "native-policy", ErrorCode: qoe.ReasonApplicationGates, ApplicationChecks: []qoe.HTTPCheck{{Service: service, Path: "route", Code: "timeout"}}}
				agent.response = agentapi.ProbeResponse{FailureClass: agentapi.FailureInfrastructure, QoE: &bad}
				if err := monitor.probe(context.Background(), at.Add(time.Second), monitor.clockNow(), candidates["target"]); err != nil {
					t.Fatal(err)
				}
				want := 0
				if service == peerService {
					want = 1
				}
				if got := mustQoESampleCount(t, database, candidates["target"].ID, 20); got != want {
					t.Fatalf("negative samples=%d want=%d", got, want)
				}
			})
		}
	}
}
