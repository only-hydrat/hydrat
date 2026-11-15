package proberuntime

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (execProcessStarter) Start(context.Context, Config) (ownedProcess, error) {
	return nil, platform.Unsupported("probe Xray process signals")
}
