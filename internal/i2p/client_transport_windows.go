package i2p

import (
	"context"
	"io"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (ControlClient) Do(context.Context, string, string, io.Reader) ([]byte, error) {
	return nil, platform.Unsupported("I2P supervisor Unix socket")
}
