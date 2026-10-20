package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/agentapi"
	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEDiagnosticsAggregateRepeatsAndKeepDifferentServices(t *testing.T) {
	db, _ := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, score: 90}})
	monitor := &QoEMonitor{Store: db}
	now := time.Unix(1_900_000_000, 0)
	response := agentapi.ProbeResponse{ErrorCode: "qoe_application_gates_unavailable", QoE: &qoe.Observation{ApplicationChecks: []qoe.HTTPCheck{{Path: "route", Service: "youtube", Phase: "headers", Code: "timeout", ElapsedMS: 3000}}}}
	for i := 0; i < 3; i++ {
		if err := monitor.recordInfrastructure(context.Background(), "route", response, nil, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	response.QoE.ApplicationChecks[0].Service = "telegram"
	if err := monitor.recordInfrastructure(context.Background(), "route", response, nil, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	response.QoE.ApplicationChecks[0].Service = "youtube"
	response.QoE.ApplicationChecks[0].ElapsedMS = 3100 // duration must not break deduplication
	if err := monitor.recordInfrastructure(context.Background(), "route", response, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 3 || !strings.Contains(events[0].Message, "suppressed=2") || !strings.Contains(events[0].Message, "route/youtube:headers:timeout") || !strings.Contains(events[1].Message, "telegram") {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestQoEDiagnosticAggregationMemoryIsBounded(t *testing.T) {
	db, _ := qoeMonitorStore(t, []qoeCandidateSpec{{name: "route", tcp: true, score: 90}})
	monitor := &QoEMonitor{Store: db}
	for i := range 100 {
		response := agentapi.ProbeResponse{ErrorCode: "qoe_application_gates_unavailable", QoE: &qoe.Observation{ApplicationChecks: []qoe.HTTPCheck{{Service: "youtube", Path: "route", Code: "http_status", Phase: "status", Status: 400 + i}}}}
		if err := monitor.recordInfrastructure(context.Background(), fmt.Sprint(i), response, nil, time.Unix(1_900_000_000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if len(monitor.infraLast) > 64 {
		t.Fatalf("diagnostic groups=%d", len(monitor.infraLast))
	}
}
