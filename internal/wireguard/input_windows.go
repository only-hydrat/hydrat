package wireguard

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (ExecInputRunner) RunInput(context.Context, string, string, ...string) ([]byte, error) {
	return nil, platform.Unsupported("WireGuard configuration commands")
}
