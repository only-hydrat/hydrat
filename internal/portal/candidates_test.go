package portal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/controller"
	"github.com/only-hydrat/hydrat/internal/proberuntime"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestAdminCandidateAndSystemAPIsAreSafeAndBounded(t *testing.T) {
	database := testStore(t)
	const (
		candidateUUID      = "11111111-1111-1111-1111-111111111111"
		sourceURL          = "https://subscription-secret.example/configs"
		responseBodyMarker = "response-body-secret-marker"
		rawProbeError      = "raw-probe-error-marker"
	)
	preview := sources.PreviewInput("proxy-source " + sourceURL)
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := database.ListSources(context.Background())
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	if err := database.ReplaceCandidates(context.Background(), listed[0].ID, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "fast", Fingerprint: "safe-fingerprint",
		Payload: "vless://" + candidateUUID + "@example.net:443?security=tls&body=" +
			responseBodyMarker + "&error=" + rawProbeError,
	}}); err != nil {
		t.Fatal(err)
	}
	candidates, err := database.ListCandidates(context.Background(), "")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	now := time.Unix(1_800_000_000, 0)
	if err := database.SaveCandidateHealth(context.Background(), store.CandidateHealth{
		CandidateID: candidates[0].ID, Score: 91, TCPQualified: true,
		UDPQualified: true, Available: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
		Fingerprint: "safe-fingerprint", CandidateID: candidates[0].ID,
		SourceID: listed[0].ID, Full: true, Success: true, Score: 91, At: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecordCandidateProbe(context.Background(), store.ProbeTransition{
		Fingerprint: "safe-fingerprint", CandidateID: candidates[0].ID,
		SourceID: listed[0].ID, Full: true, Success: false,
		ErrorCode: "qoe_route_timeout", SafeErrorMessage: rawProbeError + ": " + responseBodyMarker,
		At: now.Add(time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}
	policy := qoe.DefaultPolicy()
	for index := 0; index < policy.WindowSize+2; index++ {
		_, _, err := database.RecordCandidateQoE(context.Background(), candidates[0], qoe.Observation{
			At: now.Add(time.Duration(index+1) * time.Second), Success: true,
			TTFB: 200 * time.Millisecond, TransferDuration: 30 * time.Millisecond,
			Bytes: policy.SampleBytes, ThroughputMbps: 20,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < policy.BadSamples; index++ {
		_, _, err := database.RecordCandidateQoE(context.Background(), candidates[0], qoe.Observation{
			At:        now.Add(time.Duration(policy.WindowSize+3+index) * time.Second),
			ErrorCode: "qoe_timeout", Success: false,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
	}
	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})

	response := adminRequest(t, handler, http.MethodGet, "/api/admin/candidates?limit=1&status=unknown", "admin", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Candidates []struct {
			ID  string `json:"id"`
			QoE *struct {
				Status                 qoe.Status `json:"status"`
				TTFBMS                 float64    `json:"ttfb_ms"`
				ThroughputMbps         float64    `json:"throughput_mbps"`
				BaselineTTFBMS         float64    `json:"baseline_ttfb_ms"`
				BaselineThroughputMbps float64    `json:"baseline_throughput_mbps"`
				WindowValid            int        `json:"window_valid"`
				WindowBad              int        `json:"window_bad"`
				LastValidAt            time.Time  `json:"last_valid_at"`
				LastReason             string     `json:"last_reason"`
			} `json:"qoe"`
		} `json:"candidates"`
		Total int `json:"total"`
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		len(body.Candidates) != 1 || body.Total != 1 || body.Limit != 1 {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
	if body.Candidates[0].QoE == nil || body.Candidates[0].QoE.Status != qoe.StatusDegraded ||
		body.Candidates[0].QoE.TTFBMS != 0 || body.Candidates[0].QoE.ThroughputMbps != 0 ||
		body.Candidates[0].QoE.BaselineTTFBMS != 200 ||
		body.Candidates[0].QoE.BaselineThroughputMbps != 20 ||
		body.Candidates[0].QoE.WindowValid != 5 || body.Candidates[0].QoE.WindowBad != 3 ||
		!body.Candidates[0].QoE.LastValidAt.Equal(now.Add(10*time.Second)) ||
		body.Candidates[0].QoE.LastReason != "qoe_timeout" {
		t.Fatalf("payload=%+v", body)
	}
	var wholeResponse any
	if err := json.Unmarshal(response.Body.Bytes(), &wholeResponse); err != nil {
		t.Fatal(err)
	}
	marshaled, err := json.Marshal(wholeResponse)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{candidateUUID, "vless://", sourceURL, responseBodyMarker, rawProbeError} {
		if bytes.Contains(marshaled, []byte(secret)) {
			t.Fatalf("candidate API leaked %q: %s", secret, marshaled)
		}
	}

	if err := database.AppendEvent(context.Background(), store.Event{
		Kind: "assignment.migrated", ClientID: "alice",
		CandidateID: candidates[0].ID,
		Message:     `{"transport":"tcp","from":"old","to":"new","reason":"hard_failure"}`,
		CreatedAt:   now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	summary := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	var system struct {
		CandidateCount   int            `json:"candidate_count"`
		QoEStatuses      map[string]int `json:"qoe_statuses"`
		RecentMigrations []store.Event  `json:"recent_migrations"`
	}
	if err := json.Unmarshal(summary.Body.Bytes(), &system); summary.Code != http.StatusOK || err != nil {
		t.Fatalf("summary status=%d body=%s err=%v", summary.Code, summary.Body.String(), err)
	}
	learning, hasLearning := system.QoEStatuses[string(qoe.StatusLearning)]
	healthy, hasHealthy := system.QoEStatuses[string(qoe.StatusHealthy)]
	degraded, hasDegraded := system.QoEStatuses[string(qoe.StatusDegraded)]
	if system.CandidateCount != 1 || !hasLearning || learning != 0 ||
		!hasHealthy || healthy != 0 || !hasDegraded || degraded != 1 {
		t.Fatalf("summary status=%d body=%s", summary.Code, summary.Body.String())
	}
	if len(system.RecentMigrations) != 1 ||
		system.RecentMigrations[0].Kind != "assignment.migrated" ||
		system.RecentMigrations[0].ClientID != "alice" {
		t.Fatalf("recent migrations=%+v body=%s", system.RecentMigrations, summary.Body.String())
	}

	for _, path := range []string{"/api/admin/candidates", "/api/admin/system"} {
		unauthorized := adminRequest(t, handler, http.MethodGet, path, "wrong", nil)
		if unauthorized.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized %s status=%d", path, unauthorized.Code)
		}
	}
}

func TestSystemQoEStatusesAreStableForEmptyInventory(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin"})
	response := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	assertSystemQoEStatuses(t, response, 0, map[string]int{
		string(qoe.StatusLearning): 0,
		string(qoe.StatusHealthy):  0,
		string(qoe.StatusDegraded): 0,
	})
}

func TestSystemQoEStatusesTreatMissingAndUnknownCurrentStatesAsLearning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database := portalStoreAtPath(t, path)
	candidates := seedPortalCandidates(t, database, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "missing", Fingerprint: "missing", Payload: "vless://missing@example.net:443?security=tls"},
		{Kind: sources.KindVLESS, Label: "unknown", Fingerprint: "unknown", Payload: "vless://unknown@example.net:443?security=tls"},
	})
	if _, _, err := database.RecordCandidateQoE(context.Background(), candidates["unknown"], qoe.Observation{
		Infrastructure: true, ErrorCode: "qoe_endpoint_unavailable",
	}, qoe.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`
		UPDATE candidate_qoe_state SET status = 'unknown-status'
		WHERE candidate_id = ?
	`, candidates["unknown"].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		INSERT INTO candidate_qoe_state(candidate_id, status, updated_at)
		VALUES ('stale-candidate', 'healthy', 1800000000)
	`); err != nil {
		t.Fatal(err)
	}

	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})
	summary := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	assertSystemQoEStatuses(t, summary, 2, map[string]int{
		string(qoe.StatusLearning): 2,
		string(qoe.StatusHealthy):  0,
		string(qoe.StatusDegraded): 0,
	})
}

func TestSystemEffectiveCapacityAndProbeRuntimeAreTruthfulAndSafe(t *testing.T) {
	database := testStore(t)
	const (
		endpointSecret = "capacity-endpoint-secret.example"
		socksSecret    = "127.0.0.1:29999"
	)
	inputs := make([]store.CandidateInput, 0, 100)
	for index := 0; index < 12; index++ {
		domain := "domain-a"
		switch {
		case index >= 8:
			domain = "domain-c"
		case index >= 4:
			domain = "domain-b"
		}
		fingerprint := fmt.Sprintf("vless-%02d", index)
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindVLESS, Label: fingerprint,
			Fingerprint: fingerprint,
			Payload: fmt.Sprintf(
				"vless://candidate-%02d@%s:443?security=tls",
				index, endpointSecret,
			),
			RouteKey:      "route-" + fingerprint,
			FailureDomain: domain,
		})
	}
	for index := 0; index < 88; index++ {
		fingerprint := fmt.Sprintf("tor-%02d", index)
		inputs = append(inputs, store.CandidateInput{
			Kind: sources.KindTorBridge, Label: fingerprint,
			Fingerprint: fingerprint,
			Payload: fmt.Sprintf(
				"obfs4 %s:%d tor-secret-%02d",
				endpointSecret, 20_000+index, index,
			),
		})
	}
	candidates := seedPortalCandidates(t, database, inputs)
	now := time.Unix(1_800_000_000, 0)
	active := make([]string, 0, len(candidates))
	for fingerprint, candidate := range candidates {
		for success := 0; success < 2; success++ {
			if _, err := database.RecordCandidateProbe(
				context.Background(),
				store.ProbeTransition{
					Fingerprint: fingerprint,
					CandidateID: candidate.ID,
					SourceID:    candidate.SourceID,
					Full:        true,
					Success:     true,
					Score:       90,
					At:          now.Add(time.Duration(success) * time.Second),
				},
			); err != nil {
				t.Fatal(err)
			}
		}
		if candidate.Kind == sources.KindVLESS {
			if err := database.SaveCandidateHealth(
				context.Background(),
				store.CandidateHealth{
					CandidateID:  candidate.ID,
					Score:        90,
					TCPQualified: true,
					UDPQualified: true,
					Available:    true,
					UpdatedAt:    now,
				},
			); err != nil {
				t.Fatal(err)
			}
		}
		active = append(active, fingerprint)
	}
	if err := database.ReplaceWorkingPool(
		context.Background(), active, nil,
	); err != nil {
		t.Fatal(err)
	}
	for index := 8; index < 11; index++ {
		fingerprint := fmt.Sprintf("vless-%02d", index)
		candidate := candidates[fingerprint]
		state, err := database.RecordFailureDomainFailure(
			context.Background(),
			candidate.FailureDomain,
			candidate.ID,
			now.Add(time.Duration(index-7)*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if index == 10 && !state.OpenUntil.After(now) {
			t.Fatalf("domain-c did not open: %+v", state)
		}
	}
	runtimeSnapshot := proberuntime.Snapshot{
		Status:            "healthy",
		Epoch:             7,
		RSSBytes:          64 * 1024 * 1024,
		FDCount:           23,
		CompletedProbes:   412,
		RecycleCount:      2,
		LastRecycleReason: "probe_limit",
	}
	handler := New(ServerConfig{
		Store: database, AdminPassword: "admin",
		Profiles: capacityProfiles{profiles: []torpool.Profile{
			{Slot: 0, Role: "warm", CandidateID: "warm-a", SocksAddr: socksSecret},
			{Slot: 1, Role: "warm", CandidateID: "warm-b", SocksAddr: socksSecret},
			{Slot: 2, Role: "warm", CandidateID: "warm-c", SocksAddr: socksSecret},
			{Slot: 3, Role: "explorer", CandidateID: "explorer", SocksAddr: socksSecret},
			{Slot: 4, Role: "warm", CandidateID: "retiring", SocksAddr: socksSecret, Retiring: true},
		}},
		ProbeRuntime: probeRuntimeHealthFunc(func(context.Context) (proberuntime.Snapshot, error) {
			return runtimeSnapshot, nil
		}),
	})

	response := adminRequest(
		t, handler, http.MethodGet, "/api/admin/system", "admin", nil,
	)
	var payload struct {
		WorkingPoolByKind map[string]int `json:"working_pool_by_kind"`
		EffectiveCapacity struct {
			VLESSFailureDomains int `json:"vless_failure_domains"`
			TorWarmProfiles     int `json:"tor_warm_profiles"`
		} `json:"effective_capacity"`
		ProbeRuntime proberuntime.Snapshot `json:"probe_runtime"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK ||
		payload.WorkingPoolByKind[string(sources.KindVLESS)] != 12 ||
		payload.WorkingPoolByKind[string(sources.KindTorBridge)] != 88 ||
		payload.EffectiveCapacity.VLESSFailureDomains != 2 ||
		payload.EffectiveCapacity.TorWarmProfiles != 3 ||
		payload.ProbeRuntime != runtimeSnapshot {
		t.Fatalf("status=%d payload=%+v body=%s", response.Code, payload, response.Body.String())
	}
	for _, secret := range []string{
		endpointSecret, socksSecret, "domain-a", "domain-b", "domain-c",
		"candidate-00", "tor-secret",
	} {
		if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
			t.Fatalf("system API leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestCandidateQoEProjectionOmitsZeroLastValidAt(t *testing.T) {
	database := testStore(t)
	candidates := seedPortalCandidates(t, database, []store.CandidateInput{{
		Kind: sources.KindVLESS, Label: "unknown", Fingerprint: "unknown",
		Payload: "vless://unknown@example.net:443?security=tls",
	}})
	if _, _, err := database.RecordCandidateQoE(context.Background(), candidates["unknown"], qoe.Observation{
		Infrastructure: true, ErrorCode: "qoe_endpoint_unavailable",
	}, qoe.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})
	response := adminRequest(t, handler, http.MethodGet, "/api/admin/candidates?q=unknown", "admin", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("candidate status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Candidates []struct {
			QoE map[string]any `json:"qoe"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Candidates) != 1 {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
	if payload.Candidates[0].QoE == nil || payload.Candidates[0].QoE["status"] != string(qoe.StatusLearning) {
		t.Fatalf("missing learning QoE projection: %s", response.Body.String())
	}
	if _, exists := payload.Candidates[0].QoE["last_valid_at"]; exists {
		t.Fatalf("zero last_valid_at must be omitted: %s", response.Body.String())
	}
}

func assertSystemQoEStatuses(
	t *testing.T,
	response interface {
		Result() *http.Response
	},
	wantCandidates int,
	want map[string]int,
) {
	t.Helper()
	httpResponse := response.Result()
	defer httpResponse.Body.Close()
	var payload struct {
		CandidateCount int            `json:"candidate_count"`
		QoEStatuses    map[string]int `json:"qoe_statuses"`
	}
	if err := json.NewDecoder(httpResponse.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if httpResponse.StatusCode != http.StatusOK || payload.CandidateCount != wantCandidates {
		t.Fatalf("status=%d candidates=%d want=%d", httpResponse.StatusCode, payload.CandidateCount, wantCandidates)
	}
	for status, count := range want {
		got, exists := payload.QoEStatuses[status]
		if !exists || got != count {
			t.Fatalf("qoe_statuses=%v want %s=%d", payload.QoEStatuses, status, count)
		}
	}
}

func portalStoreAtPath(t *testing.T, path string) *store.Store {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func seedPortalCandidates(
	t *testing.T,
	database *store.Store,
	inputs []store.CandidateInput,
) map[string]store.Candidate {
	t.Helper()
	preview := sources.PreviewInput("https://example.net/subscription")
	if _, err := database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	sourceRows, err := database.ListSources(context.Background())
	if err != nil || len(sourceRows) != 1 {
		t.Fatalf("sources=%+v err=%v", sourceRows, err)
	}
	if err := database.ReplaceCandidates(context.Background(), sourceRows[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListCandidates(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]store.Candidate, len(rows))
	for _, candidate := range rows {
		result[candidate.Fingerprint] = candidate
	}
	return result
}

func TestDashboardContainsCompleteOperationalControls(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin"})
	response := adminRequest(t, handler, http.MethodGet, "/", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	for _, hook := range []string{
		`data-view="overview"`, `data-view="clients"`, `data-view="sources"`,
		`data-view="candidates"`, `data-view="system"`, `id="client-create"`,
		`id="source-preview"`, `id="candidate-filter"`,
	} {
		if !bytes.Contains(response.Body.Bytes(), []byte(hook)) {
			t.Fatalf("dashboard missing %s", hook)
		}
	}
}

func TestSystemCandidateStatusesIgnoreHistoricalStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database := portalStoreAtPath(t, path)
	candidates := seedPortalCandidates(t, database, []store.CandidateInput{
		{Kind: sources.KindVLESS, Label: "qualified", Fingerprint: "qualified", Payload: "vless://qualified@example.net:443?security=tls"},
		{Kind: sources.KindVLESS, Label: "missing", Fingerprint: "missing", Payload: "vless://missing@example.net:443?security=tls"},
		{Kind: sources.KindVLESS, Label: "invalid", Fingerprint: "invalid", Payload: "vless://invalid@example.net:443?security=tls"},
		{Kind: sources.KindVLESS, Label: "current-draining", Fingerprint: "current-draining", Payload: "vless://current-draining@example.net:443?security=tls"},
	})

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	now := time.Unix(1_800_000_000, 0).Unix()
	if _, err := raw.Exec(`
		INSERT INTO candidate_probe_state(
			fingerprint, candidate_id, source_id, status,
			in_working_pool, draining, stale, updated_at
		) VALUES
			('qualified', ?, '', 'qualified', 1, 0, 0, ?),
			('invalid', ?, '', 'unexpected-status', 0, 0, 0, ?),
			('current-draining', ?, '', 'draining', 1, 1, 0, ?),
			('historical', 'removed-id', 'removed-source', 'draining', 1, 1, 0, ?)
	`, candidates["qualified"].ID, now, candidates["invalid"].ID, now,
		candidates["current-draining"].ID, now, now); err != nil {
		t.Fatal(err)
	}

	handler := New(ServerConfig{Store: database, AdminPassword: "admin"})
	response := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	var payload struct {
		CandidateCount   int            `json:"candidate_count"`
		WorkingPoolCount int            `json:"working_pool_count"`
		DrainingCount    int            `json:"draining_count"`
		Statuses         map[string]int `json:"candidate_statuses"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || payload.CandidateCount != 4 ||
		payload.WorkingPoolCount != 2 || payload.DrainingCount != 1 {
		t.Fatalf("status=%d payload=%+v", response.Code, payload)
	}
	want := map[string]int{
		"unknown": 2, "preflight": 0, "probing": 0,
		"qualified": 1, "banned": 0, "draining": 1,
	}
	if !reflect.DeepEqual(payload.Statuses, want) {
		t.Fatalf("candidate_statuses=%v want=%v", payload.Statuses, want)
	}
	var total int
	for _, count := range payload.Statuses {
		total += count
	}
	if total != payload.CandidateCount {
		t.Fatalf("status sum=%d candidates=%d", total, payload.CandidateCount)
	}
}

func TestDashboardAssetsExposeQoE(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin"})
	for path, hooks := range map[string][]string{
		"/": {
			"VLESS working", "VLESS domains", "Tor candidates", "Warm Tor",
		},
		"/assets/app.js": {
			"candidate.qoe", "QoE ${qoeText}", "system.qoe_statuses",
			"system.probe_runtime", "system.active_probe_runtime",
			"Active runtime", "value.last_recycle_reason",
		},
		"/assets/styles.css": {".candidate-meta", ".probe-runtime"},
	} {
		response := adminRequest(t, handler, http.MethodGet, path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, response.Code)
		}
		for _, hook := range hooks {
			if !bytes.Contains(response.Body.Bytes(), []byte(hook)) {
				t.Errorf("%s missing %q", path, hook)
			}
		}
	}
}

func TestDashboardAssetsUseInMemoryAdminSessions(t *testing.T) {
	handler := New(ServerConfig{Store: testStore(t), AdminPassword: "admin"})
	assets := make(map[string][]byte, 3)
	for _, path := range []string{"/", "/assets/app.js", "/assets/styles.css"} {
		response := adminRequest(t, handler, http.MethodGet, path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, response.Code)
		}
		assets[path] = response.Body.Bytes()
	}
	for path, hooks := range map[string][]string{
		"/":                  {`id="admin-logout"`, `type="button"`},
		"/assets/app.js":     {`let adminToken = ""`, `"/api/admin/session"`, `X-Hydrat-Admin-Password`, `Authorization`, `Bearer ${adminToken}`, `method:"POST"`, `method:"DELETE"`, `response.status === 401`, `clearAdminSession()`, `adminToken = ""`, `$("admin-password").value = ""`},
		"/assets/styles.css": {"#admin-logout"},
	} {
		for _, hook := range hooks {
			if !bytes.Contains(assets[path], []byte(hook)) {
				t.Errorf("%s missing %q", path, hook)
			}
		}
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "document.cookie", `if (admin) headers.set("X-Hydrat-Admin-Password"`, "let password = \"\""} {
		if bytes.Contains(assets["/assets/app.js"], []byte(forbidden)) {
			t.Errorf("app.js contains forbidden browser auth state %q", forbidden)
		}
	}
}

func TestSystemSummaryIncludesOptionalActiveProbeRuntime(t *testing.T) {
	primary := proberuntime.Snapshot{Status: "ready", Epoch: 7, CompletedProbes: 21}
	active := proberuntime.Snapshot{Status: "ready", Epoch: 3, CompletedProbes: 411}
	handler := New(ServerConfig{
		Store: testStore(t), AdminPassword: "admin",
		ProbeRuntime: dualProbeRuntimeHealth{
			primary: primary,
			active:  active,
		},
	})

	response := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	var payload struct {
		ProbeRuntime       proberuntime.Snapshot `json:"probe_runtime"`
		ActiveProbeRuntime proberuntime.Snapshot `json:"active_probe_runtime"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || payload.ProbeRuntime != primary ||
		payload.ActiveProbeRuntime != active {
		t.Fatalf("status=%d payload=%+v body=%s", response.Code, payload, response.Body.String())
	}
}

func TestSystemSummaryKeepsLegacyProbeRuntimeProviderCompatible(t *testing.T) {
	primary := proberuntime.Snapshot{Status: "ready", Epoch: 7}
	handler := New(ServerConfig{
		Store: testStore(t), AdminPassword: "admin",
		ProbeRuntime: probeRuntimeHealthFunc(func(context.Context) (proberuntime.Snapshot, error) {
			return primary, nil
		}),
	})

	response := adminRequest(t, handler, http.MethodGet, "/api/admin/system", "admin", nil)
	var payload struct {
		ProbeRuntime       proberuntime.Snapshot `json:"probe_runtime"`
		ActiveProbeRuntime proberuntime.Snapshot `json:"active_probe_runtime"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || payload.ProbeRuntime != primary ||
		payload.ActiveProbeRuntime.Status != "unavailable" {
		t.Fatalf("status=%d payload=%+v body=%s", response.Code, payload, response.Body.String())
	}
}

func TestHealthChecksStoreAndGatewayAgent(t *testing.T) {
	checker := &healthCheckerStub{}
	handler := New(ServerConfig{Store: testStore(t), Health: checker})
	response := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("healthy status=%d body=%s", response.Code, response.Body.String())
	}
	checker.err = errors.New("agent unavailable")
	response = adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHealthReportsControllerReadinessCauseUntilNormalized(t *testing.T) {
	readiness := &healthCheckerStub{err: errors.New("active-critical normalization pending")}
	handler := New(ServerConfig{
		Store: testStore(t), Health: &healthCheckerStub{},
		ControllerReadiness: readiness,
	})
	response := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("degraded liveness status=%d body=%s", response.Code, response.Body.String())
	}
	response = adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), "active-critical normalization pending") {
		t.Fatalf("degraded readiness status=%d body=%s", response.Code, response.Body.String())
	}
	readiness.err = nil
	for _, path := range []string{"/api/health", "/api/ready"} {
		response = adminRequest(t, handler, http.MethodGet, path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("recovered %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestReadyReportsFatalControllerCauseWithoutBreakingLiveness(t *testing.T) {
	readiness := &healthCheckerStub{err: errors.New("hard-failure deadline exceeded")}
	handler := New(ServerConfig{
		Store: testStore(t), Health: &healthCheckerStub{},
		ControllerReadiness: readiness,
	})
	health := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
	if health.Code != http.StatusOK || ready.Code != http.StatusServiceUnavailable ||
		!strings.Contains(ready.Body.String(), "hard-failure deadline exceeded") {
		t.Fatalf("health=%d ready=%d body=%s", health.Code, ready.Code, ready.Body.String())
	}
}

func TestSlowNormalizationSlicesKeepHealthLiveAndReadyRedUntilRecovery(t *testing.T) {
	latch := controller.NewReadinessLatch()
	handler := New(ServerConfig{
		Store: testStore(t), Health: &healthCheckerStub{},
		ControllerReadiness: latch,
	})
	var attempts atomic.Int32
	firstAttempt := make(chan struct{})
	normalize := func(context.Context, time.Time) error {
		attempt := attempts.Add(1)
		time.Sleep(20 * time.Millisecond) // simulate a slow 0.5-CPU planner slice
		if attempt == 1 {
			close(firstAttempt)
		}
		if attempt < 3 {
			return &controller.ActiveCriticalCoveragePlanError{
				Limit: 16, SearchExhausted: true, Evaluations: 4096,
			}
		}
		return nil
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	runtime := controller.Runtime{
		StartupNormalize: normalize,
		Place: func(ctx context.Context, at time.Time, reason controller.PlacementReason) error {
			if reason != controller.PlacementStartupNormalization {
				return nil
			}
			return normalize(ctx, at)
		},
		Unready: latch.Unready, Ready: latch.Ready,
		NormalizationRetryInterval: 5 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runCtx) }()
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		t.Fatal("first normalization slice did not complete")
	}
	health := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
	if health.Code != http.StatusOK || ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("during slow recovery health=%d ready=%d body=%s",
			health.Code, ready.Code, ready.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ready = adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
		if ready.Code == http.StatusOK {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ready.Code != http.StatusOK || attempts.Load() < 3 {
		t.Fatalf("eventual readiness status=%d attempts=%d body=%s",
			ready.Code, attempts.Load(), ready.Body.String())
	}
	cancelRun()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProductionActiveCadenceKeepsImpossibleCapacityLiveWithoutRetrySpin(t *testing.T) {
	latch := controller.NewReadinessLatch()
	handler := New(ServerConfig{
		Store: testStore(t), Health: &healthCheckerStub{},
		ControllerReadiness: latch,
	})
	coverageErr := &controller.ActiveCriticalCoveragePlanError{
		Limit: 16, SearchExhausted: true,
		Unsatisfied: []string{"alice:tcp:reserve"},
	}
	var normalizationAttempts atomic.Int32
	var activeAttempts atomic.Int32
	runCtx, cancelRun := context.WithCancel(context.Background())
	runtime := controller.Runtime{
		StartupNormalize: func(context.Context, time.Time) error {
			normalizationAttempts.Add(1)
			return coverageErr
		},
		RecoveryReady: func(context.Context, time.Time) error { return coverageErr },
		CapacityReady: func(context.Context, time.Time) error { return coverageErr },
		Place: func(_ context.Context, _ time.Time, reason controller.PlacementReason) error {
			if reason == controller.PlacementStartupNormalization {
				normalizationAttempts.Add(1)
				return coverageErr
			}
			return nil
		},
		Active: func(context.Context, time.Time) error {
			activeAttempts.Add(1)
			return controller.ErrActiveCriticalCoverageExceeded
		},
		Unready: latch.Unready, Ready: latch.Ready,
		NormalizationRetryInterval: 5 * time.Second,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             250 * time.Millisecond,
		ActiveDeadline:             625 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runCtx) }()
	deadline := time.Now().Add(2 * time.Second)
	for activeAttempts.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if activeAttempts.Load() < 4 {
		cancelRun()
		t.Fatal("production active cadence stopped while capacity stayed impossible")
	}
	health := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
	if health.Code != http.StatusOK || ready.Code != http.StatusServiceUnavailable {
		cancelRun()
		t.Fatalf("unchanged capacity health=%d ready=%d body=%s",
			health.Code, ready.Code, ready.Body.String())
	}
	if attempts := normalizationAttempts.Load(); attempts > 2 {
		cancelRun()
		t.Fatalf("normalization attempts=%d want<=2 before paced 5s retry", attempts)
	}
	select {
	case err := <-done:
		t.Fatalf("unchanged impossible capacity stopped runtime: %v", err)
	default:
	}
	cancelRun()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadinessValidityRecheckAgesGreenToHealth200Ready503Once(t *testing.T) {
	latch := controller.NewReadinessLatch()
	handler := New(ServerConfig{
		Store: testStore(t), Health: &healthCheckerStub{},
		ControllerReadiness: latch,
	})
	var proofAt atomic.Int64
	proofAt.Store(time.Now().UnixNano())
	coverageErr := &controller.ActiveCriticalCoveragePlanError{
		Limit: 16, SearchExhausted: true,
		Unsatisfied: []string{"alice:tcp:reserve"},
	}
	capacityReady := func(context.Context, time.Time) error {
		observedAt := time.Unix(0, proofAt.Load())
		if time.Since(observedAt) > 500*time.Millisecond {
			return coverageErr
		}
		return nil
	}
	capacityChanges := make(chan struct{}, 1)
	var recoveryWakes atomic.Int32
	runCtx, cancelRun := context.WithCancel(context.Background())
	runtime := controller.Runtime{
		StartupNormalize: func(context.Context, time.Time) error { return nil },
		CapacityReady:    capacityReady,
		Place: func(_ context.Context, _ time.Time, reason controller.PlacementReason) error {
			if reason == controller.PlacementStartupNormalization {
				recoveryWakes.Add(1)
			}
			return nil
		},
		// Infrastructure/no-result Active cycles intentionally do not mutate proof.
		Active:          func(context.Context, time.Time) error { return nil },
		CapacityChanges: capacityChanges,
		Unready:         latch.Unready, Ready: latch.Ready,
		NormalizationRetryInterval: 5 * time.Second,
		SourceRefreshInterval:      time.Hour,
		QualificationInterval:      time.Hour,
		PlacementInterval:          time.Hour,
		ActiveInterval:             250 * time.Millisecond,
		ActiveDeadline:             625 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(runCtx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
		if ready.Code == http.StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for time.Now().Before(deadline) {
		ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
		if ready.Code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	health := adminRequest(t, handler, http.MethodGet, "/api/health", "", nil)
	ready := adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
	if health.Code != http.StatusOK || ready.Code != http.StatusServiceUnavailable {
		cancelRun()
		t.Fatalf("aged proof health=%d ready=%d body=%s",
			health.Code, ready.Code, ready.Body.String())
	}
	time.Sleep(300 * time.Millisecond)
	if wakes := recoveryWakes.Load(); wakes != 1 {
		cancelRun()
		t.Fatalf("aged proof recovery wakes=%d want=1", wakes)
	}
	proofAt.Store(time.Now().UnixNano())
	capacityChanges <- struct{}{}
	recoveryDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(recoveryDeadline) {
		ready = adminRequest(t, handler, http.MethodGet, "/api/ready", "", nil)
		if ready.Code == http.StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ready.Code != http.StatusOK {
		cancelRun()
		t.Fatalf("renewed proof readiness=%d body=%s", ready.Code, ready.Body.String())
	}
	cancelRun()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type healthCheckerStub struct {
	err error
}

func (checker *healthCheckerStub) Health(context.Context) error {
	return checker.err
}

type capacityProfiles struct {
	profiles []torpool.Profile
}

func (profiles capacityProfiles) Profiles() []torpool.Profile {
	return profiles.profiles
}

func (capacityProfiles) ExploreNext(context.Context) ([]torpool.Profile, error) {
	return nil, nil
}

type probeRuntimeHealthFunc func(context.Context) (proberuntime.Snapshot, error)

func (function probeRuntimeHealthFunc) ProbeRuntimeHealth(
	ctx context.Context,
) (proberuntime.Snapshot, error) {
	return function(ctx)
}

type dualProbeRuntimeHealth struct {
	primary proberuntime.Snapshot
	active  proberuntime.Snapshot
}

func (provider dualProbeRuntimeHealth) ProbeRuntimeHealth(
	context.Context,
) (proberuntime.Snapshot, error) {
	return provider.primary, nil
}

func (provider dualProbeRuntimeHealth) ActiveProbeRuntimeHealth(
	context.Context,
) (proberuntime.Snapshot, error) {
	return provider.active, nil
}
