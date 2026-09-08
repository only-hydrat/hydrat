package qualifier

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/only-hydrat/hydrat/internal/health"
	"github.com/only-hydrat/hydrat/internal/probexray"
	"github.com/only-hydrat/hydrat/internal/xrayconfig"
)

type LivenessObserver interface {
	Observe(context.Context, string) health.Observation
}

type ActiveResult struct {
	CandidateID string
	Observation health.Observation
	Err         error
}

// ActiveVLESS reuses the persistent probe-Xray SOCKS slots for low-cost
// liveness checks. Callers keep the input set within the configured slot count.
type ActiveVLESS struct {
	control  Control
	observer LivenessObserver
	portBase int
	slots    int
}

func NewActiveVLESS(control Control, observer LivenessObserver, portBase, slots int) *ActiveVLESS {
	return &ActiveVLESS{control: control, observer: observer, portBase: portBase, slots: slots}
}

func (active *ActiveVLESS) Observe(ctx context.Context, inputs []Input) []ActiveResult {
	if active.slots <= 0 {
		active.slots = 4
	}
	if len(inputs) > active.slots {
		inputs = inputs[:active.slots]
	}
	results := make([]ActiveResult, len(inputs))
	batch := make([]probexray.SlotCandidate, 0, len(inputs))
	valid := make([]bool, len(inputs))
	for index, input := range inputs {
		results[index].CandidateID = input.ID
		config, err := xrayconfig.VLESSOutbound(input.Payload, fmt.Sprintf("probe-outbound-%d", index))
		if err != nil {
			results[index].Err = err
			continue
		}
		encoded, err := json.Marshal(config)
		if err != nil {
			results[index].Err = err
			continue
		}
		batch = append(batch, probexray.SlotCandidate{Slot: index, Config: encoded})
		valid[index] = true
	}
	if err := active.control.Configure(ctx, batch); err != nil {
		for index := range inputs {
			if valid[index] {
				results[index].Err = err
			}
		}
		return results
	}
	var wait sync.WaitGroup
	for index := range inputs {
		if !valid[index] {
			continue
		}
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index].Observation = active.observer.Observe(ctx, fmt.Sprintf("127.0.0.1:%d", active.portBase+index))
		}(index)
	}
	wait.Wait()
	return results
}
