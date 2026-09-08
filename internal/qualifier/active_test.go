package qualifier

import (
	"context"
	"testing"

	"github.com/only-hydrat/hydrat/internal/health"
)

func TestActiveVLESSKeepsCandidateToProbeSlotMapping(t *testing.T) {
	control := &qualifierControl{}
	active := NewActiveVLESS(control, observeFunc(func(_ context.Context, address string) health.Observation {
		return health.Observation{PrimaryOK: address == "127.0.0.1:11080", ConfirmationOK: true}
	}), 11080, 4)

	results := active.Observe(context.Background(), []Input{
		{ID: "first", Payload: "vless://id@example.net:443?security=tls"},
		{ID: "second", Payload: "vless://id@example.org:443?security=tls"},
	})
	if len(results) != 2 || results[0].CandidateID != "first" || !results[0].Observation.PrimaryOK {
		t.Fatalf("results=%+v", results)
	}
	if results[1].CandidateID != "second" || results[1].Observation.PrimaryOK {
		t.Fatalf("results=%+v", results)
	}
}

type observeFunc func(context.Context, string) health.Observation

func (function observeFunc) Observe(ctx context.Context, address string) health.Observation {
	return function(ctx, address)
}
