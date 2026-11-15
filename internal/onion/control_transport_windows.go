package onion

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (Control) commands(context.Context, [][2]string) error {
	return platform.Unsupported("Tor control Unix socket")
}
