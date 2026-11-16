package main

import "github.com/only-hydrat/hydrat/internal/platform"

func requireGateway() error {
	return platform.Unsupported("hydrat is a Linux gateway; the controller/agent need WireGuard, nftables and a Linux netns")
}
