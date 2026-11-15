package torpool

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (ExecRunner) Start(context.Context, string, ...string) (Process, error) {
	return nil, platform.Unsupported("Tor process groups")
}
