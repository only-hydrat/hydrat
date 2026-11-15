package i2p

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/platform"
	"io"
)

func (ControlClient) Do(context.Context, string, string, io.Reader) ([]byte, error) {
	return nil, platform.Unsupported("I2P supervisor Unix socket")
}
