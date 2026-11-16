package i2p

import (
	"context"
	"encoding/json"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (*ExecRouter) rpc(context.Context, string, map[string]any) (map[string]json.RawMessage, error) {
	return nil, platform.Unsupported("I2P control Unix socket")
}
