package proberuntime

import (
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

type diagnosticBuffer struct {
	sync.Mutex
	text strings.Builder
}

func (b *diagnosticBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.text.Write(p)
}
func (b *diagnosticBuffer) String() string { b.Lock(); defer b.Unlock(); return b.text.String() }

func TestRuntimeRecycleDiagnosticsReportOutcomeWithoutErrors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "failure"}[fail], func(t *testing.T) {
			var output diagnosticBuffer
			old := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(old)
			fixture := newRuntimeFixture(t)
			if fail {
				fixture.failReadinessAfter(2, 0, errors.New("private-token"))
			}
			manager := fixture.manager(Config{MaxProbes: 1, ReadinessTimeout: 30 * time.Millisecond})
			if err := manager.Start(fixture.ctx); err != nil {
				t.Fatal(err)
			}
			manager.Release(fixture.acquire(manager), nil)
			if fail {
				fixture.waitForStatus(manager, "degraded")
			} else {
				fixture.waitForEpoch(manager, 2)
			}
			// Join the worker before inspecting deferred lifecycle output.
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.Contains(text, "event=recycle_start") || !strings.Contains(text, "event=recycle_end") || !strings.Contains(text, "reason=probe_limit") || strings.Contains(text, "private-token") {
				t.Fatalf("logs=%s", text)
			}
			if fail && !strings.Contains(text, "phase=readiness outcome=failed") {
				t.Fatalf("missing failure phase: %s", text)
			}
		})
	}
}
