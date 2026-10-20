package xrayflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Client struct{ http *http.Client }

func NewClient(path string) *Client {
	transport := &http.Transport{MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 15 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "unix", path)
		}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 750 * time.Millisecond}}
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	err := c.call(ctx, http.MethodGet, "/v1/snapshot", nil, &snapshot)
	if err == nil && (len(snapshot.Instance) != 32 || snapshot.Active < 0 || uint64(snapshot.Active) > snapshot.BeforeID) {
		err = ErrInvalidRequest
	}
	return snapshot, err
}

func (c *Client) Reset(ctx context.Context, q ResetRequest) (int, error) {
	if err := q.Validate(); err != nil {
		return 0, err
	}
	var result ResetResponse
	if err := c.call(ctx, http.MethodPost, "/v1/reset", q, &result); err != nil {
		return 0, err
	}
	if result.Closed < 0 || uint64(result.Closed) > q.Snapshot.BeforeID {
		return 0, ErrInvalidRequest
	}
	return result.Closed, nil
}

func (c *Client) call(ctx context.Context, method, path string, body, result any) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return decodeJSON(io.LimitReader(resp.Body, 8192), result)
	case http.StatusBadRequest:
		return ErrInvalidRequest
	case http.StatusConflict:
		return ErrStaleInstance
	default:
		return fmt.Errorf("flow control returned HTTP%d", resp.StatusCode)
	}
}
