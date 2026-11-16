package gateway

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (ExecRunner) Output(context.Context, string, ...string) ([]byte, error) {
	return nil, platform.Unsupported("Linux gateway commands (nftables and ip route)")
}
