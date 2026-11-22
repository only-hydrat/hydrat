//go:build unix

package i2p

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (r *ExecRouter) rpc(ctx context.Context, method string, params map[string]any) (map[string]json.RawMessage, error) {
	cert, err := os.ReadFile(filepath.Join(r.Directory, "control.crt"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("I2P control certificate unavailable")
	}
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := platform.DialUnix(ctx, &net.Dialer{}, filepath.Join(r.Directory, "control.sock"))
		if err != nil {
			return nil, err
		}
		t := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || subtle.ConstantTimeCompare(s.PeerCertificates[0].Raw, block.Bytes) != 1 {
				return errors.New("I2P control certificate mismatch")
			}
			return nil
		}})
		if err = t.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return t, nil
	}}
	defer transport.CloseIdleConnections()
	payload, _ := json.Marshal(map[string]any{"id": 1, "jsonrpc": "2.0", "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost/", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var reply struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  json.RawMessage            `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&reply); err != nil {
		return nil, err
	}
	if len(reply.Error) > 0 || reply.Result == nil {
		return nil, errors.New("I2P control rejected request")
	}
	return reply.Result, nil
}
