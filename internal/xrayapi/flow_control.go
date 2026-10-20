package xrayapi

import (
	"context"
	"errors"

	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

// ConfigureFlowControl must run before the adapter is shared with workers.
func (adapter *Adapter) ConfigureFlowControl(socketPath string) {
	adapter.flowControl = xrayflow.NewClient(socketPath)
}

func (adapter *Adapter) FlowSnapshot(ctx context.Context) (xrayflow.Snapshot, error) {
	if adapter.flowControl == nil {
		return xrayflow.Snapshot{}, errors.New("flow control is not configured")
	}
	return adapter.flowControl.Snapshot(ctx)
}

func (adapter *Adapter) ResetFlow(ctx context.Context, request xrayflow.ResetRequest) (int, error) {
	if adapter.flowControl == nil {
		return 0, errors.New("flow control is not configured")
	}
	return adapter.flowControl.Reset(ctx, request)
}
