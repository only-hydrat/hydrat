//go:build unix

package i2p

import (
	"context"
	"errors"
	"github.com/only-hydrat/hydrat/internal/platform"
	"io"
	"net"
	"net/http"
	"time"
)

func (c ControlClient) Do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return platform.DialUnix(ctx, &net.Dialer{}, c.Socket)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://i2p"+path, body)
	if err != nil {
		return nil, err
	}
	res, err := (&http.Client{Transport: tr, Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, errors.New("I2P supervisor unavailable")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, errors.New("I2P operation rejected")
	}
	return b, nil
}
