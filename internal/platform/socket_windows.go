package platform

import (
	"context"
	"net"
)

func DialUnix(context.Context, *net.Dialer, string) (net.Conn, error) {
	return nil, Unsupported("Unix socket transport")
}
