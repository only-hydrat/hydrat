package proberuntime

import (
	"context"
	"io"
	"sync"
	"time"
)

// WithEmbeddedCore replaces the process with a closable instance inside the
// host application. Readiness, leases and epoch recycling still use Manager.
func WithEmbeddedCore(start func(context.Context, string) (io.Closer, error)) Option {
	if start == nil {
		return nil
	}
	starter := processStarterFunc(func(ctx context.Context, config Config) (ownedProcess, error) {
		core, err := start(ctx, config.ConfigPath)
		if err != nil {
			return nil, err
		}
		return &embeddedCore{core: core, done: make(chan struct{})}, nil
	})
	return func(deps *dependencies) {
		deps.starter = starter
		deps.embedded = true
	}
}

type embeddedCore struct {
	core io.Closer
	done chan struct{}
	once sync.Once
	err  error
}

func (*embeddedCore) PID() int                   { return 0 }
func (core *embeddedCore) Done() <-chan struct{} { return core.done }
func (core *embeddedCore) BeginStop() bool       { return !channelClosed(core.done) }

func (core *embeddedCore) Stop(timeout time.Duration) error {
	core.once.Do(func() {
		go func() {
			core.err = core.core.Close()
			close(core.done)
		}()
	})
	select {
	case <-core.done:
		return core.err
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-core.done:
		return core.err
	case <-timer.C:
		return context.DeadlineExceeded
	}
}
