//go:build unix

package platform

import (
	"context"
	"net"
)

func DialUnix(ctx context.Context, d *net.Dialer, path string) (net.Conn, error) {
	return d.DialContext(ctx, "unix", path)
}
