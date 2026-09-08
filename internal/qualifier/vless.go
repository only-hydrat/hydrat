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

type Input struct {
	ID      string
	Payload string
}

type Result struct {
	CandidateID           string
	Metrics               health.Metrics
	Evaluation            health.Evaluation
	Err                   error
	InfrastructureFailure bool
}

type Control interface {
	Configure(context.Context, []probexray.SlotCandidate) error
}

type Measurer interface {
	Measure(context.Context, string, health.Protocol) (health.Metrics, error)
}

type VLESS struct {
	control  Control
	measurer Measurer
	portBase int
	slots    int
}

func NewVLESS(control Control, measurer Measurer, portBase, slots int) *VLESS {
	return &VLESS{control: control, measurer: measurer, portBase: portBase, slots: slots}
}

func (qualifier *VLESS) Qualify(ctx context.Context, inputs []Input) []Result {
	if qualifier.slots <= 0 {
		qualifier.slots = 4
	}
	results := make([]Result, len(inputs))
	for offset := 0; offset < len(inputs); offset += qualifier.slots {
		end := offset + qualifier.slots
		if end > len(inputs) {
			end = len(inputs)
		}
		batchInputs := inputs[offset:end]
		batch := make([]probexray.SlotCandidate, 0, len(batchInputs))
		valid := make([]bool, len(batchInputs))
		for index, input := range batchInputs {
			results[offset+index].CandidateID = input.ID
			config, err := xrayconfig.VLESSOutbound(input.Payload, fmt.Sprintf("probe-outbound-%d", index))
			if err != nil {
				results[offset+index].Err = err
				continue
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				results[offset+index].Err = err
				continue
			}
			batch = append(batch, probexray.SlotCandidate{Slot: index, Config: encoded})
			valid[index] = true
		}
		if err := qualifier.control.Configure(ctx, batch); err != nil {
			for index := range batchInputs {
				if valid[index] {
					results[offset+index].Err = err
					results[offset+index].InfrastructureFailure = true
				}
			}
			continue
		}
		var wait sync.WaitGroup
		for index := range batchInputs {
			if !valid[index] {
				continue
			}
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				metrics, err := qualifier.measurer.Measure(ctx, fmt.Sprintf("127.0.0.1:%d", qualifier.portBase+index), health.ProtocolVLESS)
				results[offset+index].Metrics = metrics
				results[offset+index].Err = err
				if err == nil {
					results[offset+index].Evaluation = health.Evaluate(metrics, health.ProtocolVLESS)
				}
			}(index)
		}
		wait.Wait()
	}
	return results
}
