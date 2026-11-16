package xrayflow

import (
	"os"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func StartFromEnvironment() error {
	if os.Getenv(SocketEnvironment) == "" {
		return nil
	}
	return platform.Unsupported("Xray flow control Unix socket")
}
