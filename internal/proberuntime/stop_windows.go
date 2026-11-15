package proberuntime

import (
	"time"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (*execProcess) Stop(time.Duration) error {
	return platform.Unsupported("probe Xray process signals")
}
