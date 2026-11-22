package xrayflow

import (
	"net/http"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func Listen(string, *Registry) (*http.Server, error) {
	return nil, platform.Unsupported("Xray flow control Unix socket")
}
