package dataplane

import (
	"bytes"
	"context"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanDiagnosticsIncludePhaseAndGenerationWithoutSecretsOrNoops(t *testing.T) {
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	adapter := &recordingAdapter{routeError: errors.New("private-token")}
	r, err := NewReconciler(adapter, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := singleRoutePlan(7, "private-route", nil)
	for range 3 {
		if r.Apply(context.Background(), plan) == nil {
			t.Fatal("expected route error")
		}
	}
	adapter.routeError = nil
	if err := r.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, "plan_apply") != 2 || !strings.Contains(text, "generation=7 phase=routes outcome=failed") || !strings.Contains(text, "outcome=applied") || !strings.Contains(text, "suppressed=2") || strings.Contains(text, "private") {
		t.Fatalf("logs=%s", text)
	}
}
