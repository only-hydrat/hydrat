package xrayflow

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
)

var (
	processRegistry atomic.Pointer[Registry]
	startOnce       sync.Once
	startError      error
)

func Track(ctx context.Context, tag, source, network string, interrupt func()) (context.Context, func()) {
	if r := processRegistry.Load(); r != nil {
		return r.Track(ctx, tag, source, network, interrupt)
	}
	return ctx, func() {}
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}
