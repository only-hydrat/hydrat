package main

import (
	"net"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func listenUnix(string) (net.Listener, error) {
	return nil, platform.Unsupported("gateway Unix socket")
}
