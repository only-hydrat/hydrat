package projectcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestCIRunsBrowserSessionTests(t *testing.T) {
	workflow := readText(t, filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml"))
	var config struct {
		Jobs map[string]struct {
			Steps []struct {
				Run             string `yaml:"run"`
				If              string `yaml:"if"`
				ContinueOnError bool   `yaml:"continue-on-error"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(workflow), &config); err != nil {
		t.Fatalf("decode CI workflow: %v", err)
	}
	const command = "node --test internal/portal/web_app_test.mjs"
	for _, step := range config.Jobs["test"].Steps {
		if step.Run == command {
			if step.If != "" || step.ContinueOnError {
				t.Fatal("browser session tests must run unconditionally and fail CI on errors")
			}
			return
		}
	}
	t.Fatalf("CI test job must run %q", command)
}

func TestProbeXrayContainsTwentyDedicatedSOCKSInbounds(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "config/xray/probe.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]struct {
		listen, protocol string
		port             int
	})
	for _, inbound := range config.Inbounds {
		if strings.HasPrefix(inbound.Tag, "probe-slot-") {
			byTag[inbound.Tag] = struct {
				listen, protocol string
				port             int
			}{inbound.Listen, inbound.Protocol, inbound.Port}
		}
	}
	if len(byTag) != 20 {
		t.Fatalf("probe SOCKS inbounds=%d, want 20", len(byTag))
	}
	for slot := 0; slot < 20; slot++ {
		tag := fmt.Sprintf("probe-slot-%d", slot)
		inbound, exists := byTag[tag]
		if !exists {
			t.Errorf("missing %s", tag)
			continue
		}
		if inbound.listen != "127.0.0.1" || inbound.protocol != "socks" || inbound.port != 11080+slot {
			t.Errorf("%s=%+v, want loopback SOCKS port %d", tag, inbound, 11080+slot)
		}
	}
}

func TestProbeXrayClosesCanceledSOCKSConnectionsImmediately(t *testing.T) {
	root := repositoryRoot(t)
	for _, relativePath := range []string{
		"config/xray/probe.json",
		"config/xray/active.json",
	} {
		t.Run(filepath.Base(relativePath), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, relativePath))
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Policy struct {
					Levels map[string]map[string]int `json:"levels"`
				} `json:"policy"`
			}
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			level, exists := config.Policy.Levels["0"]
			if !exists {
				t.Fatal("probe Xray is missing level 0 connection policy")
			}
			want := map[string]int{
				"handshake": 4, "connIdle": 30,
				"uplinkOnly": 0, "downlinkOnly": 0,
			}
			for field, wantValue := range want {
				if got, exists := level[field]; !exists || got != wantValue {
					t.Errorf("probe Xray level 0 %s=%d exists=%t, want %d", field, got, exists, wantValue)
				}
			}
		})
	}
}

func TestMainXrayLeavesDNSPortToContainerResolver(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "config/xray/main.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Address        string `json:"address"`
				Port           int    `json:"port"`
				Network        string `json:"network"`
				FollowRedirect bool   `json:"followRedirect"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "dns-in" || inbound.Port == 53 {
			t.Fatalf("main Xray must not own container DNS listener: %+v", inbound)
		}
	}
	dockerfile := readText(t, filepath.Join(root, "Dockerfile"))
	if !strings.Contains(dockerfile, "dnsmasq-base") {
		t.Fatal("runtime image does not install the supervised container DNS resolver")
	}
}

func TestDeploymentRequiresInContainerReadinessAfterComposeHealth(t *testing.T) {
	root := repositoryRoot(t)
	compose := readText(t, filepath.Join(root, "docker-compose.yml"))
	if !strings.Contains(
		compose,
		`test: ["CMD", "curl", "--fail", "--silent", "http://127.0.0.1:8080/api/health"]`,
	) {
		t.Fatal("Docker healthcheck must remain controller liveness /api/health")
	}
	if strings.Contains(compose, `http://127.0.0.1:8080/api/ready"]`) {
		t.Fatal("Docker healthcheck must not restart a live but unready controller")
	}
	path := filepath.Join(root, "scripts", "deploy.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("scripts/deploy.sh must be executable")
	}
	deploy := readText(t, path)
	for _, required := range []string{
		"ready_attempts=${HYDRAT_READY_ATTEMPTS:-360}",
		"docker compose up", "--wait", "--wait-timeout",
		"docker compose exec -T controller", "curl", "--fail-with-body", "--max-time",
		"http://127.0.0.1:8080/api/ready", "exit 1",
	} {
		if !strings.Contains(deploy, required) {
			t.Errorf("scripts/deploy.sh missing mandatory deploy gate %q", required)
		}
	}
	operations := readText(t, filepath.Join(root, "docs", "operations.md"))
	for _, required := range []string{
		"./scripts/deploy.sh", "/api/ready", "release rejected",
		"ROLLBACK_IMAGE", "BACKUP_PATH", "APPLIED_PLAN_BACKUP_PATH",
		"FAILED_APPLIED_PLAN_PATH", "PREVIOUS_CONFIG_SHA256",
		"sha256sum",
		"Принятый runtime состоит из image, встроенной конфигурации,",
	} {
		if !strings.Contains(operations, required) {
			t.Errorf("operations deploy/rollback gate missing %q", required)
		}
	}
}

func TestDeployCommandRejectsReleaseWhenReadinessNeverSucceeds(t *testing.T) {
	root := repositoryRoot(t)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "docker.log")
	dockerPath := filepath.Join(tempDir, "docker")
	if err := os.WriteFile(dockerPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >>"$HYDRAT_FAKE_DOCKER_LOG"
case "$*" in
  "compose up "*) exit 0 ;;
  "compose exec "*)
    printf '%s\n' '{"status":"controller unavailable: tcp_reserve_capacity"}'
    exit 22
    ;;
esac
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts", "deploy.sh"))
	command.Dir = root
	command.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HYDRAT_FAKE_DOCKER_LOG="+logPath,
		"HYDRAT_READY_ATTEMPTS=2",
		"HYDRAT_READY_DELAY_SECONDS=0",
		"HYDRAT_READY_MAX_TIME_SECONDS=1",
		"HYDRAT_COMPOSE_WAIT_TIMEOUT_SECONDS=1",
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("deploy err=%v output=%s, want exit 1", err, output)
	}
	if !strings.Contains(string(output), "release rejected") {
		t.Fatalf("deploy output=%s, want release rejected", output)
	}
	if !strings.Contains(string(output), "readiness pending at attempt 1/2") ||
		!strings.Contains(string(output), `"status":"controller unavailable: tcp_reserve_capacity"`) {
		t.Fatalf("deploy output=%s, want bounded readiness cause and attempt", output)
	}
	log := readText(t, logPath)
	if strings.Count(log, "compose up ") != 1 ||
		strings.Count(log, "compose exec ") != 2 ||
		!strings.Contains(log, "http://127.0.0.1:8080/api/ready") {
		t.Fatalf("docker calls=%q, want one compose wait and two ready attempts", log)
	}
}

func TestDeployCommandRejectsTransientSingleReadyResponse(t *testing.T) {
	root := repositoryRoot(t)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "docker.log")
	countPath := filepath.Join(tempDir, "ready-count")
	dockerPath := filepath.Join(tempDir, "docker")
	if err := os.WriteFile(dockerPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >>"$HYDRAT_FAKE_DOCKER_LOG"
case "$*" in
  "compose up "*) exit 0 ;;
  "compose exec "*)
    count=0
    if [ -f "$HYDRAT_FAKE_READY_COUNT" ]; then count=$(cat "$HYDRAT_FAKE_READY_COUNT"); fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$HYDRAT_FAKE_READY_COUNT"
    if [ "$count" -eq 1 ]; then exit 0; fi
    exit 1
    ;;
esac
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts", "deploy.sh"))
	command.Dir = root
	command.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HYDRAT_FAKE_DOCKER_LOG="+logPath,
		"HYDRAT_FAKE_READY_COUNT="+countPath,
		"HYDRAT_READY_ATTEMPTS=3",
		"HYDRAT_READY_CONSECUTIVE_SUCCESSES=2",
		"HYDRAT_READY_DELAY_SECONDS=0",
		"HYDRAT_READY_MAX_TIME_SECONDS=1",
		"HYDRAT_COMPOSE_WAIT_TIMEOUT_SECONDS=1",
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("deploy err=%v output=%s, want transient readiness rejection", err, output)
	}
	if strings.Count(readText(t, logPath), "compose exec ") != 3 {
		t.Fatalf("docker calls=%q, want all three readiness checks", readText(t, logPath))
	}
}

func TestActiveXrayContainsFortyEightIsolatedSOCKSInbounds(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "config/xray/active.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]int)
	for _, inbound := range config.Inbounds {
		if strings.HasPrefix(inbound.Tag, "probe-slot-") {
			if inbound.Listen != "127.0.0.1" || inbound.Protocol != "socks" {
				t.Fatalf("active inbound=%+v", inbound)
			}
			byTag[inbound.Tag] = inbound.Port
		}
	}
	if len(byTag) != 48 {
		t.Fatalf("active SOCKS inbounds=%d want=48", len(byTag))
	}
	for slot := 0; slot < 48; slot++ {
		if got := byTag[fmt.Sprintf("probe-slot-%d", slot)]; got != 12080+slot {
			t.Fatalf("active slot %d port=%d want=%d", slot, got, 12080+slot)
		}
	}
}

func TestProbeRuntimeRealXrayStressAssets(t *testing.T) {
	root := repositoryRoot(t)
	dockerfile := readText(t, filepath.Join(root, "Dockerfile"))
	stageStart := strings.Index(
		dockerfile,
		"FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS probe-runtime-test",
	)
	if stageStart < 0 {
		t.Fatal("Dockerfile missing probe-runtime-test stage")
	}
	stageEnd := strings.Index(dockerfile[stageStart+1:], "\nFROM ")
	if stageEnd < 0 {
		t.Fatal("Dockerfile probe-runtime-test stage has no following stage")
	}
	probeRuntimeStage := dockerfile[stageStart : stageStart+1+stageEnd]
	for _, expected := range []string{
		"ARG XRAY_STRESS_SKIP_EPOCH_RESET=0",
		"COPY --from=xray-build /out/xray /usr/local/bin/xray",
		"COPY config ./config",
		"HYDRAT_XRAY_BINARY=/usr/local/bin/xray",
		"HYDRAT_XRAY_STRESS_SKIP_EPOCH_RESET=$XRAY_STRESS_SKIP_EPOCH_RESET",
		"RUN go test -tags=xrayintegration -count=1 -v ./internal/proberuntime",
	} {
		if !strings.Contains(probeRuntimeStage, expected) {
			t.Errorf("Dockerfile missing real-Xray stress contract %q", expected)
		}
	}
	for _, relative := range []string{
		"internal/proberuntime/xray_integration_test.go",
		"internal/proberuntime/testdata/server-raw.json",
		"internal/proberuntime/testdata/server-ws.json",
		"internal/proberuntime/testdata/server-xhttp.json",
		"internal/proberuntime/testdata/probe.json",
	} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Errorf("required real-Xray stress asset %s: %v", relative, err)
		}
	}
	integration := readText(
		t,
		filepath.Join(root, "internal/proberuntime/xray_integration_test.go"),
	)
	for _, missing := range missingRealXrayFinalHardening(integration) {
		t.Errorf("real-Xray integration test missing semantic contract %q", missing)
	}
	for _, expected := range []string{
		"//go:build xrayintegration && linux",
		`RunChurn(t, 520, []string{"raw", "ws", "xhttp"})`,
		"sample.RSSBytes <= 0 || sample.FDCount <= 0",
		"sample.RSSBytes >= 256<<20 || sample.FDCount >= 512",
		"fresh production metric reads=",
		"fixture.OldEpochMutations() != 0 || fixture.ActiveProbeSOCKS() != 0",
		"startMainFreedomChecks",
		"probeNumber != 251",
		"errors.Is(outcome.err, probexray.ErrStaleEpoch)",
		"first post-recycle outbound assertion",
		"errors.Is(result.err, context.Canceled)",
		"errors.Is(result.err, io.EOF)",
		"origin_confirmed=%d",
		"Status:            \"ready\"",
		"Epoch:             3",
		"CompletedProbes:   20",
	} {
		if !strings.Contains(integration, expected) {
			t.Errorf("real-Xray integration test missing contract %q", expected)
		}
	}
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.Walk(filepath.Join(root, directory), func(
			path string,
			info os.FileInfo,
			walkErr error,
		) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "HYDRAT_XRAY_STRESS_SKIP_EPOCH_RESET") {
				t.Errorf(
					"production Go source reads test-only epoch reset switch: %s",
					path,
				)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan production Go source under %s: %v", directory, err)
		}
	}
}

func missingRealXrayFinalHardening(source string) []string {
	file, err := parser.ParseFile(
		token.NewFileSet(),
		"xray_integration_test.go",
		source,
		0,
	)
	if err != nil {
		return []string{fmt.Sprintf("valid Go integration source: %v", err)}
	}
	var testBody *ast.BlockStmt
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "TestRealXrayProbeRuntimeStabilizes" {
			testBody = function.Body
			break
		}
	}
	if testBody == nil {
		return []string{"TestRealXrayProbeRuntimeStabilizes function"}
	}

	var proof struct {
		finalRead          bool
		exactFinal         bool
		finalMismatch      bool
		nonemptySamples    bool
		lastSampleMismatch bool
		noPending          bool
		confirmation       bool
	}
	countsAssigned := false
	for _, statement := range testBody.List {
		if realXrayFinalSnapshotAssignment(statement) {
			proof.finalRead = true
		}
		if exactRealXrayFinalSnapshot(statement) {
			proof.exactFinal = true
		}
		if realXrayArrivalCountsAssignment(statement) {
			countsAssigned = true
		}
		conditional, ok := statement.(*ast.IfStmt)
		if !ok || !blockDirectlyFailsTest(conditional.Body) {
			continue
		}
		switch {
		case proof.finalRead && proof.exactFinal &&
			binaryIdentifiers(conditional.Cond, token.NEQ, "final", "wantFinal"):
			proof.finalMismatch = true
		case zeroLengthSamples(conditional.Cond):
			proof.nonemptySamples = true
		case lastSampleMismatch(conditional.Cond):
			proof.lastSampleMismatch = true
		case noPendingRecycleFailure(conditional):
			proof.noPending = true
		case countsAssigned && exactOriginConfirmationFailure(conditional):
			proof.confirmation = true
		}
	}

	var missing []string
	for _, contract := range []struct {
		ok          bool
		description string
	}{
		{proof.finalRead, "final runtime snapshot read"},
		{proof.exactFinal, "exact final snapshot literal"},
		{proof.finalMismatch, "final snapshot mismatch fails"},
		{proof.nonemptySamples, "empty final sample series fails"},
		{proof.lastSampleMismatch, "last sample mismatch fails"},
		{proof.noPending, "no pending lifecycle error fails"},
		{proof.confirmation, "confirmation counters 520/2/0/0 fail"},
	} {
		if !contract.ok {
			missing = append(missing, contract.description)
		}
	}
	return missing
}

func realXrayFinalSnapshotAssignment(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	return ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 &&
		identifier(assignment.Lhs[0], "final") &&
		fixtureMethodCall(assignment.Rhs[0], "runtime", "Snapshot")
}

func exactRealXrayFinalSnapshot(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
		!identifier(assignment.Lhs[0], "wantFinal") {
		return false
	}
	literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
	if !ok || !identifier(literal.Type, "Snapshot") {
		return false
	}
	fields := make(map[string]ast.Expr)
	for _, element := range literal.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if ok {
			fields[key.Name] = keyValue.Value
		}
	}
	return stringLiteral(fields["Status"], "ready") &&
		integerLiteral(fields["Epoch"], 3) &&
		selectorField(fields["RSSBytes"], "final", "RSSBytes") &&
		selectorField(fields["FDCount"], "final", "FDCount") &&
		integerLiteral(fields["CompletedProbes"], 20) &&
		integerLiteral(fields["RecycleCount"], 2) &&
		identifier(fields["LastRecycleReason"], "reasonProbeLimit")
}

func realXrayArrivalCountsAssignment(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 ||
		!identifier(assignment.Lhs[0], "pendingArrivals") ||
		!identifier(assignment.Lhs[1], "unexpectedArrivals") {
		return false
	}
	return fixtureMethodCall(
		assignment.Rhs[0],
		"originArrivals",
		"counts",
	)
}

func blockDirectlyFailsTest(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	for _, statement := range block.List {
		switch statement.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt:
			return false
		}
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		receiver, receiverOK := selectorReceiver(selector)
		if ok && receiverOK && receiver == "t" &&
			(selector.Sel.Name == "Fatal" || selector.Sel.Name == "Fatalf") {
			return true
		}
	}
	return false
}

func selectorField(expression ast.Expr, receiverName, fieldName string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	receiver, receiverOK := selectorReceiver(selector)
	return ok && receiverOK && receiver == receiverName &&
		selector.Sel.Name == fieldName
}

func binaryIdentifiers(expression ast.Expr, operator token.Token, a, b string) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != operator {
		return false
	}
	return identifier(binary.X, a) && identifier(binary.Y, b) ||
		identifier(binary.X, b) && identifier(binary.Y, a)
}

func zeroLengthSamples(expression ast.Expr) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL {
		return false
	}
	return samplesLength(binary.X) && integerLiteral(binary.Y, 0) ||
		samplesLength(binary.Y) && integerLiteral(binary.X, 0)
}

func lastSampleMismatch(expression ast.Expr) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return false
	}
	return finalSampleIndex(binary.X) && identifier(binary.Y, "final") ||
		finalSampleIndex(binary.Y) && identifier(binary.X, "final")
}

func finalSampleIndex(expression ast.Expr) bool {
	index, ok := expression.(*ast.IndexExpr)
	if !ok || !identifier(index.X, "samples") {
		return false
	}
	offset, ok := index.Index.(*ast.BinaryExpr)
	return ok && offset.Op == token.SUB &&
		samplesLength(offset.X) && integerLiteral(offset.Y, 1)
}

func noPendingRecycleFailure(conditional *ast.IfStmt) bool {
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
		!identifier(assignment.Lhs[0], "err") ||
		!fixtureMethodCall(assignment.Rhs[0], "", "noPendingRecycle") {
		return false
	}
	return binaryIdentifiers(conditional.Cond, token.NEQ, "err", "nil")
}

func exactOriginConfirmationFailure(conditional *ast.IfStmt) bool {
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
		!identifier(assignment.Lhs[0], "confirmed") ||
		!fixtureLoadCall(assignment.Rhs[0], "originConfirmed") {
		return false
	}
	var terms []ast.Expr
	flattenLogicalOr(conditional.Cond, &terms)
	if len(terms) != 4 {
		return false
	}
	want := map[string]int64{
		"confirmed":          520,
		"heldConfirmed":      2,
		"pendingArrivals":    0,
		"unexpectedArrivals": 0,
	}
	seen := make(map[string]bool)
	for _, term := range terms {
		name, value, ok := exactNotEqualCounter(term)
		expected, exists := want[name]
		if !ok || !exists || seen[name] || expected != value {
			return false
		}
		seen[name] = true
	}
	return len(seen) == len(want)
}

func flattenLogicalOr(expression ast.Expr, terms *[]ast.Expr) {
	binary, ok := expression.(*ast.BinaryExpr)
	if ok && binary.Op == token.LOR {
		flattenLogicalOr(binary.X, terms)
		flattenLogicalOr(binary.Y, terms)
		return
	}
	*terms = append(*terms, expression)
}

func exactNotEqualCounter(expression ast.Expr) (string, int64, bool) {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return "", 0, false
	}
	for _, pair := range [][2]ast.Expr{{binary.X, binary.Y}, {binary.Y, binary.X}} {
		value, ok := integerValue(pair[1])
		if !ok {
			continue
		}
		if name, ok := pair[0].(*ast.Ident); ok {
			return name.Name, value, true
		}
		if fixtureLoadCall(pair[0], "heldConfirmed") {
			return "heldConfirmed", value, true
		}
	}
	return "", 0, false
}

func fixtureLoadCall(expression ast.Expr, field string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	load, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || load.Sel.Name != "Load" {
		return false
	}
	counter, ok := load.X.(*ast.SelectorExpr)
	receiver, receiverOK := selectorReceiver(counter)
	return ok && receiverOK && receiver == "fixture" && counter.Sel.Name == field
}

func fixtureMethodCall(expression ast.Expr, field, method string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	if field == "" {
		return identifier(selector.X, "fixture")
	}
	target, ok := selector.X.(*ast.SelectorExpr)
	receiver, receiverOK := selectorReceiver(target)
	return ok && receiverOK && receiver == "fixture" && target.Sel.Name == field
}

func selectorReceiver(selector *ast.SelectorExpr) (string, bool) {
	if selector == nil {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return receiver.Name, true
}

func samplesLength(expression ast.Expr) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok && identifier(call.Fun, "len") && len(call.Args) == 1 &&
		identifier(call.Args[0], "samples")
}

func identifier(expression ast.Expr, name string) bool {
	ident, ok := expression.(*ast.Ident)
	return ok && ident.Name == name
}

func stringLiteral(expression ast.Expr, want string) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == want
}

func integerLiteral(expression ast.Expr, want int64) bool {
	value, ok := integerValue(expression)
	return ok && value == want
}

func integerValue(expression ast.Expr) (int64, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	return value, err == nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRealXrayFinalHardeningContractRejectsMissingAssertions(t *testing.T) {
	complete := `package proberuntime

func TestRealXrayProbeRuntimeStabilizes(t *testing.T) {
	final := fixture.runtime.Snapshot()
	wantFinal := Snapshot{
		Status: "ready",
		Epoch: 3,
		RSSBytes: final.RSSBytes,
		FDCount: final.FDCount,
		CompletedProbes: 20,
		RecycleCount: 2,
		LastRecycleReason: reasonProbeLimit,
	}
	if final != wantFinal {
		t.Fatalf("final mismatch")
	}
	if len(samples) == 0 {
		t.Fatal("empty samples")
	}
	if samples[len(samples)-1] != final {
		t.Fatalf("last sample mismatch")
	}
	if err := fixture.noPendingRecycle(); err != nil {
		t.Fatal(err)
	}
	pendingArrivals, unexpectedArrivals := fixture.originArrivals.counts()
	if confirmed := fixture.originConfirmed.Load(); confirmed != 520 ||
		fixture.heldConfirmed.Load() != 2 ||
		pendingArrivals != 0 || unexpectedArrivals != 0 {
		t.Fatalf("confirmation mismatch")
	}
}
`
	if missing := missingRealXrayFinalHardening(complete); len(missing) != 0 {
		t.Fatalf("complete final hardening reported missing: %v", missing)
	}
	for _, testCase := range []struct {
		name, remove, replacement, wantMissing string
	}{
		{
			"remove final assertion",
			"if final != wantFinal {\n\t\tt.Fatalf(\"final mismatch\")\n\t}",
			`/* removed decoy: if final != wantFinal {
		t.Fatalf("final mismatch")
} */`,
			"final snapshot mismatch fails",
		},
		{
			"invert final comparator",
			"final != wantFinal",
			"final == wantFinal",
			"final snapshot mismatch fails",
		},
		{
			"final branch no-op",
			`t.Fatalf("final mismatch")`,
			`_ = "no-op"`,
			"final snapshot mismatch fails",
		},
		{
			"final branch returns before fatal",
			`t.Fatalf("final mismatch")`,
			`return
		t.Fatalf("final mismatch")`,
			"final snapshot mismatch fails",
		},
		{
			"remove final snapshot read",
			`final := fixture.runtime.Snapshot()`,
			`/* removed final := fixture.runtime.Snapshot() */`,
			"final runtime snapshot read",
		},
		{
			"wrong final resource binding",
			`RSSBytes: final.RSSBytes`,
			`RSSBytes: 0`,
			"exact final snapshot literal",
		},
		{
			"last sample branch no-op",
			`t.Fatalf("last sample mismatch")`,
			`_ = "no-op"`,
			"last sample mismatch fails",
		},
		{
			"invert last sample comparator",
			"samples[len(samples)-1] != final",
			"samples[len(samples)-1] == final",
			"last sample mismatch fails",
		},
		{
			"ignore no pending result",
			"if err := fixture.noPendingRecycle(); err != nil {\n\t\tt.Fatal(err)\n\t}",
			`_ = fixture.noPendingRecycle()`,
			"no pending lifecycle error fails",
		},
		{
			"confirmation branch no-op",
			`t.Fatalf("confirmation mismatch")`,
			`_ = "no-op"`,
			"confirmation counters 520/2/0/0 fail",
		},
		{
			"wrong held confirmation count",
			"fixture.heldConfirmed.Load() != 2",
			"fixture.heldConfirmed.Load() != 3",
			"confirmation counters 520/2/0/0 fail",
		},
		{
			"invert ordinary confirmation comparator",
			"confirmed != 520",
			"confirmed == 520",
			"confirmation counters 520/2/0/0 fail",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			incomplete := strings.Replace(
				complete,
				testCase.remove,
				testCase.replacement,
				1,
			)
			if incomplete == complete {
				t.Fatalf("mutation target %q was not found", testCase.remove)
			}
			missing := missingRealXrayFinalHardening(incomplete)
			if !containsString(missing, testCase.wantMissing) {
				t.Fatalf("missing=%v, want %q", missing, testCase.wantMissing)
			}
		})
	}
}

func TestRepositoryContainsOnlyGoProductionAssets(t *testing.T) {
	root := repositoryRoot(t)
	removed := []string{
		".env",
		"Dockerfile.legacy",
		"docker-compose.legacy.yml",
		"pyproject.toml",
		"pytest.ini",
		"vpn_gateway",
		"tests",
		"ops",
		"internal/migration",
		"config/config-v2.yml",
		"config/source.txt.example",
		"config/tor",
		"config/wireguard/wg0.conf",
		"config/xray/config.template.json",
		"config/xray/main-v2.json",
		"config/xray/probe-v2.json",
		"config/nftables/hydrat-v2.nft",
		"config/nftables/xray.nft.tpl",
	}
	for _, relative := range removed {
		if _, err := os.Stat(filepath.Join(root, relative)); err == nil {
			t.Errorf("legacy or secret path still exists: %s", relative)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", relative, err)
		}
	}

	required := []string{
		"config/config.yml",
		"config/wireguard/wg0.conf.example",
		"config/xray/main.json",
		"config/xray/probe.json",
		"config/xray/active.json",
		"config/nftables/hydrat.nft",
	}
	for _, relative := range required {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Errorf("required production asset %s: %v", relative, err)
		}
	}
}

func TestProductionEnvironmentAndComposeContract(t *testing.T) {
	root := repositoryRoot(t)
	env := readText(t, filepath.Join(root, ".env.example"))
	for _, expected := range []string{
		"DATA_DIR=./data",
		"WIREGUARD_PORT=51820",
		"PORTAL_BIND_ADDRESS=127.0.0.1",
		"WIREGUARD_ENDPOINT=",
		"HYDRAT_ADMIN_PASSWORD=",
	} {
		if !strings.Contains(env, expected) {
			t.Errorf(".env.example missing %q", expected)
		}
	}
	for _, forbidden := range []string{"CLIENT_PORTAL_ADMIN_PASSWORD", "CONFIG_PATH", "039f1b55"} {
		if strings.Contains(env, forbidden) {
			t.Errorf(".env.example contains legacy or secret value %q", forbidden)
		}
	}

	compose := readText(t, filepath.Join(root, "docker-compose.yml"))
	for _, expected := range []string{
		"HYDRAT_ADMIN_PASSWORD",
		"net.ipv4.ip_forward: \"1\"",
		"${PORTAL_BIND_ADDRESS:-127.0.0.1}:${PORTAL_PORT:-8088}:8080",
		"NET_ADMIN",
		"NET_RAW",
	} {
		if !strings.Contains(compose, expected) {
			t.Errorf("docker-compose.yml missing %q", expected)
		}
	}
	if strings.Contains(strings.ToLower(compose), "legacy") {
		t.Error("docker-compose.yml still references legacy runtime")
	}
	if strings.Contains(compose, "./config:/config") {
		t.Error("docker-compose.yml mounts obsolete /config runtime path")
	}
	if strings.Contains(compose, "network_mode:") {
		t.Error("controller must not share the gateway network namespace")
	}
	operations := readText(t, filepath.Join(root, "docs", "operations.md"))
	for _, expected := range []string{
		"X-Hydrat-Admin-Password: ${HYDRAT_ADMIN_PASSWORD}",
		"Authorization: Bearer",
	} {
		if !strings.Contains(operations, expected) {
			t.Errorf("docs/operations.md missing admin authentication contract %q", expected)
		}
	}
	if strings.Contains(operations, `-u "admin:${HYDRAT_ADMIN_PASSWORD}"`) {
		t.Error("docs/operations.md still documents Basic Auth")
	}
	docs := readText(t, filepath.Join(root, "README.md")) +
		readText(t, filepath.Join(root, "docs", "architecture.md")) +
		readText(t, filepath.Join(root, "SECURITY.md"))
	for _, expected := range []string{
		"PORTAL_BIND_ADDRESS",
		"TCP и UDP могут использовать разные маршруты",
		"field-level AES-GCM",
		"NET_ADMIN` и `NET_RAW",
	} {
		if !strings.Contains(docs, expected) {
			t.Errorf("public documentation missing security-default contract %q", expected)
		}
	}
	publicReadme := readText(t, filepath.Join(root, "README.md"))
	for _, expected := range []string{
		"ssh -N -L 8088:127.0.0.1:8088",
		"http://127.0.0.1:8088/",
	} {
		if !strings.Contains(publicReadme, expected) {
			t.Errorf("README.md missing first-login bootstrap %q", expected)
		}
	}
	for _, forbidden := range []string{
		"видеозвонки и загрузки файлов не прерываются",
		"только при отказе или тотальной блокировке всех VLESS-каналов",
		"с единым сервером выхода",
		"SQLite (WAL, encrypted)",
		"Tor участвует в общем TCP-пуле наравне с VLESS",
	} {
		if strings.Contains(docs, forbidden) {
			t.Errorf("public documentation retains misleading claim %q", forbidden)
		}
	}
	for _, expected := range []string{
		"control:", "internal: true",
		`test: ["CMD", "curl", "--fail", "--silent", "http://127.0.0.1:8080/api/health"]`,
	} {
		if !strings.Contains(compose, expected) {
			t.Errorf("docker-compose.yml missing namespace contract %q", expected)
		}
	}
	portalServer := readText(t, filepath.Join(root, "internal", "portal", "server.go"))
	if !strings.Contains(portalServer, `HandleFunc("GET /api/ready"`) {
		t.Error("controller portal does not expose a dedicated /api/ready endpoint")
	}
	config := readText(t, filepath.Join(root, "config/config.yml"))
	for _, expected := range []string{
		"max_candidates: 10000", "working_pool_size: 200",
		"reset_window: 5h", "promotion_ratio: 0.15",
		"fast_workers: 8", "full_workers: 4", "active_workers: 32",
		"active_route_limit: 16", "active_overlap: 2",
		"fast_deadline: 6s", "full_deadline: 20s", "active_deadline: 1900ms",
		"active_interval: 2s", "active_response_slack: 75ms",
		"active_proof_grace: 15s",
		"active_interval: 15s", "window_size: 5", "bad_samples: 3",
		"recovery_good_samples: 4", "availability_window: 20",
		"availability_failures: 2",
		"hard_failover_budget: 800ms", "placement_preempt_timeout: 100ms",
		"probe_data_dir: /data/tor/probe-profiles", "probe_socks_port_base: 19150",
	} {
		if !strings.Contains(config, expected) {
			t.Errorf("config/config.yml missing adaptive runtime contract %q", expected)
		}
	}
	if err := validateProductionTorProbeDeadlines([]byte(config)); err != nil {
		t.Errorf("config/config.yml has invalid Tor probe deadline contract: %v", err)
	}

	ignore := readText(t, filepath.Join(root, ".gitignore"))
	for _, expected := range []string{".env", "config/wireguard/wg0.conf"} {
		if !hasExactLine(ignore, expected) {
			t.Errorf(".gitignore must ignore %s", expected)
		}
	}

	dockerfile := readText(t, filepath.Join(root, "Dockerfile"))
	if !strings.Contains(dockerfile, "FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build") {
		t.Error("Dockerfile must use the patched Go 1.26.5 builder on the native BuildKit platform")
	}
	if !strings.Contains(dockerfile, `GOARCH="$TARGETARCH" \
      go build -trimpath -ldflags="-s -w" -o /out/hydrat ./cmd/hydrat`) {
		t.Error("Dockerfile must cross-compile Hydrat for the requested target platform")
	}
	for _, expected := range []string{
		"AS xray-build",
		"ARG XRAY_COMMIT=035d43897925cde32639c77f84d64a79d5f4cde7",
		"ARG XRAY_SOURCE_SHA256=cdd5a0bee355119db2fce31715f5a1ce22821c69d4f3dcc1fcd02c038429f12d",
		"https://codeload.github.com/XTLS/Xray-core/zip/${XRAY_COMMIT}",
		"-buildvcs=false",
		"-buildid=",
		"-X github.com/xtls/xray-core/core.build=035d438",
		"COPY --from=xray-build /out/xray /usr/local/bin/xray",
		"COPY config/xray/active.json /etc/hydrat/xray-active.json",
	} {
		if !strings.Contains(dockerfile, expected) {
			t.Errorf("Dockerfile missing secure Xray pin %q", expected)
		}
	}
	for _, forbidden := range []string{"ARG XRAY_VERSION", "XRAY_AMD64_SHA256", "XRAY_ARM64_SHA256", "Xray-core/releases/download"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("Dockerfile still uses vulnerable prebuilt Xray contract %q", forbidden)
		}
	}
	for _, expected := range []string{
		"AS lyrebird-build",
		"ARG LYREBIRD_COMMIT=fc105a03c0e0acc2479301c361c012ffed359c43",
		"ARG LYREBIRD_SOURCE_SHA256=e460a90a67c8831d5e8f70b652b39cba0bc05190412c7034bbb8c90fb1b9baff",
		"github.com/pion/interceptor@v0.1.39",
		"golang.org/x/crypto@v0.52.0",
		"golang.org/x/net@v0.55.0",
		"COPY --from=lyrebird-build /out/lyrebird /usr/local/bin/lyrebird",
	} {
		if !strings.Contains(dockerfile, expected) {
			t.Errorf("Dockerfile missing patched lyrebird contract %q", expected)
		}
	}
	for _, forbidden := range []string{"TOR_EXPERT_BUNDLE_VERSION", "tor-expert-bundle", "archive.torproject.org"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("Dockerfile still uses vulnerable bundled lyrebird source %q", forbidden)
		}
	}
	if strings.Contains(compose, "XRAY_VERSION") {
		t.Error("docker-compose.yml must not override the pinned Xray source build")
	}
	var composeConfig struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Logging     struct {
				Driver string `yaml:"driver"`
			} `yaml:"logging"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &composeConfig); err != nil {
		t.Fatalf("decode docker-compose.yml: %v", err)
	}
	for _, serviceName := range []string{"gateway", "controller"} {
		service, exists := composeConfig.Services[serviceName]
		if !exists {
			t.Errorf("docker-compose.yml missing %s service", serviceName)
			continue
		}
		if got := service.Environment["HYDRAT_LOG_DIR"]; got != "/data/logs" {
			t.Errorf("%s HYDRAT_LOG_DIR=%q, want /data/logs", serviceName, got)
		}
		if got := service.Environment["HYDRAT_LOG_RETENTION"]; got != "72h" {
			t.Errorf("%s HYDRAT_LOG_RETENTION=%q, want 72h", serviceName, got)
		}
		if got := service.Logging.Driver; got != "none" {
			t.Errorf("%s logging driver=%q, want none", serviceName, got)
		}
	}

	for _, xrayConfig := range []string{"main.json", "probe.json", "active.json"} {
		data, err := os.ReadFile(filepath.Join(root, "config/xray", xrayConfig))
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Log struct {
				Access   string `json:"access"`
				LogLevel string `json:"loglevel"`
			} `json:"log"`
		}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("decode config/xray/%s: %v", xrayConfig, err)
		}
		if config.Log.Access != "none" {
			t.Errorf("config/xray/%s access=%q, want none", xrayConfig, config.Log.Access)
		}
		if config.Log.LogLevel != "warning" {
			t.Errorf("config/xray/%s loglevel=%q, want warning", xrayConfig, config.Log.LogLevel)
		}
	}
	readme := readText(t, filepath.Join(root, "README.md"))
	for _, expected := range []string{
		`sudo tail -n 100 "${DATA_DIR:-./data}/logs/gateway/gateway-current.log" \`,
		`  "${DATA_DIR:-./data}/logs/controller/controller-current.log"`,
		`sudo tail -F "${DATA_DIR:-./data}/logs/gateway/gateway-current.log" \`,
		"Для чтения сохранённых журналов требуются права root или sudo.",
		"gateway и controller используют изолированные",
	} {
		if !strings.Contains(readme, expected) {
			t.Errorf("README.md missing retained-log access contract %q", expected)
		}
	}
	for _, forbidden := range []string{
		`/logs/gateway-current.log`,
		`/logs/controller-current.log`,
		"\ntail -n 100 \"${DATA_DIR:-./data}/logs/gateway/gateway-current.log\" \\",
		"\ntail -F \"${DATA_DIR:-./data}/logs/gateway/gateway-current.log\" \\",
		"numeric group 10001",
	} {
		if strings.Contains(readme, forbidden) {
			t.Errorf("README.md has unprivileged retained-log tail command %q", forbidden)
		}
	}
	goModule := readText(t, filepath.Join(root, "go.mod"))
	if !strings.Contains(goModule, "\ngo 1.26.5\n") {
		t.Error("go.mod must require the patched Go 1.26.5 toolchain")
	}
	for _, forbidden := range []string{"config-v2.yml", "main-v2.json", "probe-v2.json", "hydrat-v2.nft"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("Dockerfile contains obsolete asset %s", forbidden)
		}
	}
}

func TestContainerDNSAssetsStayInsideGatewayNamespace(t *testing.T) {
	root := repositoryRoot(t)
	configText := readText(t, filepath.Join(root, "config", "config.yml"))
	if !strings.Contains(configText, "\n  dns: 10.44.0.1\n") {
		t.Error("production config must publish the WireGuard gateway as client DNS")
	}
	var hydratConfig struct {
		WireGuard struct {
			DNS string `yaml:"dns"`
		} `yaml:"wireguard"`
		Xray struct {
			DNSResolver  string   `yaml:"dns_resolver"`
			DNSResolvers []string `yaml:"dns_resolvers"`
		} `yaml:"xray"`
		Routing struct {
			DirectSuffixes []string `yaml:"direct_suffixes"`
		} `yaml:"routing"`
	}
	if err := yaml.Unmarshal([]byte(configText), &hydratConfig); err != nil {
		t.Fatalf("decode config/config.yml: %v", err)
	}
	if hydratConfig.WireGuard.DNS != "10.44.0.1" ||
		hydratConfig.Xray.DNSResolver != "1.1.1.1" ||
		!reflect.DeepEqual(hydratConfig.Xray.DNSResolvers, []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}) {
		t.Errorf("production DNS boundary client/upstream=%q/%q, want 10.44.0.1/1.1.1.1",
			hydratConfig.WireGuard.DNS, hydratConfig.Xray.DNSResolver)
	}

	nft := readText(t, filepath.Join(root, "config", "nftables", "hydrat.nft"))
	if !strings.HasPrefix(nft, "add table inet hydrat\ndelete table inet hydrat\n") {
		t.Error("nftables asset must atomically replace only the Hydrat table on repeated bootstrap")
	}
	localDrop := strings.Index(nft, `iifname "wg0" ip daddr 10.44.0.1 drop`)
	if localDrop < 0 {
		t.Fatal("nftables asset is missing the fail-closed gateway-local drop")
	}
	for _, rule := range []string{
		`iifname "wg0" udp dport 53 accept`,
		`iifname "wg0" tcp dport 53 accept`,
	} {
		position := strings.Index(nft, rule)
		if position < 0 {
			t.Errorf("nftables asset missing %q", rule)
		} else if position >= localDrop {
			t.Errorf("nftables DNS intercept must precede gateway-local drop: %q", rule)
		}
	}
	for _, redirect := range []string{
		`iifname "wg0" udp dport 53 redirect to :53`,
		`iifname "wg0" tcp dport 53 redirect to :53`,
	} {
		if !strings.Contains(nft, redirect) {
			t.Errorf("nftables asset missing %q", redirect)
		}
	}
	if strings.Contains(nft, `dport 53 tproxy`) {
		t.Fatal("production DNS must bypass the transparent traffic inbound")
	}

	compose := readText(t, filepath.Join(root, "docker-compose.yml"))
	var document struct {
		Services map[string]struct {
			DNS         []string `yaml:"dns"`
			NetworkMode string   `yaml:"network_mode"`
			Ports       []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &document); err != nil {
		t.Fatalf("decode docker-compose.yml: %v", err)
	}
	for name, service := range document.Services {
		if len(service.DNS) != 0 {
			t.Errorf("%s must not alter container or host resolver settings: dns=%v", name, service.DNS)
		}
		if service.NetworkMode != "" {
			t.Errorf("%s must not use host/shared network mode: %q", name, service.NetworkMode)
		}
	}
	gateway := document.Services["gateway"]
	if len(gateway.Ports) != 1 || gateway.Ports[0] != "${WIREGUARD_PORT:-51820}:51820/udp" {
		t.Errorf("gateway ports=%v, want only the existing WireGuard UDP port", gateway.Ports)
	}
	if !reflect.DeepEqual(hydratConfig.Routing.DirectSuffixes, []string{".ru", ".su", ".xn--p1ai"}) {
		t.Errorf("production direct suffixes=%v, want [.ru .su .xn--p1ai]", hydratConfig.Routing.DirectSuffixes)
	}

	architecture := readText(t, filepath.Join(root, "docs", "architecture.md"))
	for _, expected := range []string{
		"wireguard.dns", "xray.dns_resolvers", "1.1.1.1", "9.9.9.9", "8.8.8.8",
	} {
		if !strings.Contains(architecture, expected) {
			t.Errorf("DNS architecture documentation missing %q", expected)
		}
	}
}

func TestStickyRoutingProductionContract(t *testing.T) {
	root := repositoryRoot(t)
	config := readText(t, filepath.Join(root, "config", "config.yml"))
	if !strings.Contains(config, "alternative_speedup: 1.3") ||
		!strings.Contains(config, "improve_ratio: 0.30") ||
		!strings.Contains(config, "max_moves: 1") {
		t.Fatalf("production config is missing the sticky 30%% migration policy")
	}
	adapter := readText(t, filepath.Join(root, "internal", "xrayapi", "adapter.go"))
	if strings.Contains(adapter, "hydrat-stage-") ||
		strings.Contains(adapter, "install fail-closed staging rules") {
		t.Fatal("Xray route replacement still contains an intentional blocking stage")
	}
	architecture := readText(t, filepath.Join(root, "docs", "architecture.md"))
	for _, expected := range []string{
		"Tor участвует в общем TCP-пуле",
		"минимум на 30%",
		"трёх последовательных",
		"без промежуточного `block`",
	} {
		if !strings.Contains(architecture, expected) {
			t.Errorf("sticky routing architecture documentation missing %q", expected)
		}
	}
	operations := readText(t, filepath.Join(root, "docs", "operations.md"))
	for _, expected := range []string{
		"recent_migrations",
		"shadow",
		"one-client canary",
		"DNS хоста не изменяется",
	} {
		if !strings.Contains(operations, expected) {
			t.Errorf("sticky routing operations documentation missing %q", expected)
		}
	}
}

func TestProductionTorProbeDeadlineYAMLContract(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantValid    bool
		wantRawMatch bool
	}{
		{
			name: "plain scalars",
			input: `probes:
  tor_fast_deadline: 5m
  tor_full_deadline: 6m
`,
			wantValid:    true,
			wantRawMatch: true,
		},
		{
			name: "quoted scalars",
			input: `probes:
  tor_fast_deadline: "5m"
  tor_full_deadline: '6m'
`,
			wantValid:    true,
			wantRawMatch: false,
		},
		{
			name: "commented values",
			input: `probes:
  fast_deadline: 3s
  # tor_fast_deadline: 5m
  # tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: true,
		},
		{
			name: "prefixed keys",
			input: `probes:
  old_tor_fast_deadline: 5m
  old_tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: true,
		},
		{
			name: "wrong section",
			input: `legacy:
  tor_fast_deadline: 5m
  tor_full_deadline: 6m
probes:
  fast_deadline: 3s
`,
			wantValid:    false,
			wantRawMatch: true,
		},
		{
			name: "duplicate deadline key",
			input: `probes:
  tor_fast_deadline: 5m
  tor_fast_deadline: 5m
  tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: true,
		},
		{
			name: "duplicate probes section",
			input: `probes:
  tor_fast_deadline: 5m
probes:
  tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: true,
		},
		{
			name: "wrong duration",
			input: `probes:
  tor_fast_deadline: 6m
  tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: false,
		},
		{
			name: "non scalar duration",
			input: `probes:
  tor_fast_deadline: [5m]
  tor_full_deadline: 6m
`,
			wantValid:    false,
			wantRawMatch: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawMatch := rawTorProbeDeadlineContains(test.input)
			if rawMatch != test.wantRawMatch {
				t.Fatalf("raw Contains match=%t, want %t", rawMatch, test.wantRawMatch)
			}
			err := validateProductionTorProbeDeadlines([]byte(test.input))
			if test.wantValid && err != nil {
				t.Fatalf("valid contract rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}

func rawTorProbeDeadlineContains(input string) bool {
	return strings.Contains(input, "tor_fast_deadline: 5m") &&
		strings.Contains(input, "tor_full_deadline: 6m")
}

func validateProductionTorProbeDeadlines(input []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(input, &document); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fmt.Errorf("expected one YAML document")
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("root must be a mapping")
	}
	probes, err := uniqueYAMLMappingValue(root, "probes")
	if err != nil {
		return err
	}
	if probes.Kind != yaml.MappingNode {
		return fmt.Errorf("root probes must be a mapping")
	}
	for _, expected := range []struct {
		key      string
		duration time.Duration
	}{
		{key: "tor_fast_deadline", duration: 5 * time.Minute},
		{key: "tor_full_deadline", duration: 6 * time.Minute},
	} {
		value, err := uniqueYAMLMappingValue(probes, expected.key)
		if err != nil {
			return err
		}
		if value.Kind != yaml.ScalarNode {
			return fmt.Errorf("root probes %s must be a scalar", expected.key)
		}
		var raw string
		if err := value.Decode(&raw); err != nil {
			return fmt.Errorf("decode root probes %s: %w", expected.key, err)
		}
		duration, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("parse root probes %s: %w", expected.key, err)
		}
		if duration != expected.duration {
			return fmt.Errorf(
				"root probes %s=%s, want %s",
				expected.key,
				duration,
				expected.duration,
			)
		}
	}
	return nil
}

func uniqueYAMLMappingValue(mapping *yaml.Node, key string) (*yaml.Node, error) {
	var found *yaml.Node
	count := 0
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		keyNode := mapping.Content[index]
		if keyNode.Kind != yaml.ScalarNode || keyNode.Value != key {
			continue
		}
		count++
		found = mapping.Content[index+1]
	}
	switch count {
	case 0:
		return nil, fmt.Errorf("explicit key %q is missing", key)
	case 1:
		return found, nil
	default:
		return nil, fmt.Errorf("explicit key %q appears %d times", key, count)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func hasExactLine(input, expected string) bool {
	for _, line := range strings.Split(input, "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}
