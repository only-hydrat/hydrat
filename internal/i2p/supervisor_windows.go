package i2p

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func ServeSupervisor(context.Context, string, string, string) error {
	return platform.Unsupported("I2P supervisor Unix socket")
}
