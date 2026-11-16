package i2p

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (*ExecRouter) Start(context.Context) error {
	return platform.Unsupported("I2P router process groups")
}
func (*ExecRouter) Stop(context.Context) error {
	return platform.Unsupported("I2P router process groups")
}
