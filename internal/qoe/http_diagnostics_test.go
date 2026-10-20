package qoe

import (
	"fmt"
	"strings"
	"testing"
)

func TestHTTPDiagnosticsBoundAndRedactUntrustedFields(t *testing.T) {
	checks := make([]HTTPCheck, 100)
	for i := range checks {
		checks[i] = HTTPCheck{Service: "secret", Path: "secret", Phase: "secret", Code: "secret", Status: 9999, ElapsedMS: -1}
	}
	safe := SafeHTTPChecks(checks)
	if len(safe) != 16 || strings.Contains(fmt.Sprint(safe), "secret") || safe[0].Status != 0 || safe[0].ElapsedMS != 0 {
		t.Fatalf("unsafe: %+v", safe)
	}
}

func TestHTTPDiagnosticsLimitEachPath(t *testing.T) {
	checks := make([]HTTPCheck, 32)
	for i := range checks {
		checks[i] = HTTPCheck{Path: "route", Service: "youtube", Code: "timeout", Phase: "headers"}
	}
	if got := SafeHTTPChecks(checks); len(got) != 16 {
		t.Fatalf("unbounded route checks=%d", len(got))
	}
}
