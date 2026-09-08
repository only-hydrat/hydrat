package qualifier

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/probexray"
)

func TestVLESSQualifierUsesFourPersistentSlotsAndServiceGates(t *testing.T) {
	control := &qualifierControl{}
	measurer := measureFunc(func(_ context.Context, socksAddr string, _ health.Protocol) (health.Metrics, error) {
		return health.Metrics{
			SuccessRatio: 1, Latency: 100 * time.Millisecond, ThroughputMbps: 50,
			ChatGPTWeb: true, OpenAI401: true, TelegramWeb: true, TelegramMTProto: true, YouTubeWeb: true, InstagramWeb: true, UDP: true,
		}, nil
	})
	qualifier := NewVLESS(control, measurer, 11080, 4)
	inputs := make([]Input, 5)
	for index := range inputs {
		inputs[index] = Input{ID: string(rune('a' + index)), Payload: "vless://id@example.net:443?security=tls"}
	}
	results := qualifier.Qualify(context.Background(), inputs)
	if len(results) != 5 || len(control.batches) != 2 || len(control.batches[0]) != 4 || len(control.batches[1]) != 1 {
		t.Fatalf("results=%d batches=%+v", len(results), control.batches)
	}
	for _, result := range results {
		if !result.Evaluation.TCPQualified || !result.Evaluation.UDPQualified {
			t.Fatalf("result=%+v", result)
		}
	}
}

type qualifierControl struct{ batches [][]probexray.SlotCandidate }

func (control *qualifierControl) Configure(_ context.Context, batch []probexray.SlotCandidate) error {
	control.batches = append(control.batches, append([]probexray.SlotCandidate(nil), batch...))
	return nil
}

type measureFunc func(context.Context, string, health.Protocol) (health.Metrics, error)

func (function measureFunc) Measure(ctx context.Context, socksAddr string, protocol health.Protocol) (health.Metrics, error) {
	return function(ctx, socksAddr, protocol)
}
