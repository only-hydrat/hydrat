// Package i2p owns the optional I2P web runtime. It never routes ordinary VPN traffic.
package i2p

import (
	"context"
	"errors"
	"sync"
	"time"
)

type RouterStatus struct {
	Ready   bool `json:"ready"`
	Transit int  `json:"transit_tunnels"`
}
type Router interface {
	Start(context.Context) error
	Stop(context.Context) error
	Inspect(context.Context) (RouterStatus, error)
}
type Status struct {
	State        string    `json:"state"`
	Streams      int       `json:"streams"`
	LastActivity time.Time `json:"last_activity"`
	SleepAt      time.Time `json:"sleep_at"`
	Transit      int       `json:"transit_tunnels"`
}

// Runtime serializes process transitions. Only client requests or an explicit
// warmup call update lastActivity; monitoring never does.
type Runtime struct {
	mu      sync.Mutex
	router  Router
	idle    time.Duration
	status  Status
	running bool
	closed  bool
}

func NewRuntime(router Router, idle time.Duration) *Runtime {
	if idle <= 0 {
		idle = 2 * time.Hour
	}
	return &Runtime{router: router, idle: idle, status: Status{State: "sleeping"}}
}
func (m *Runtime) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Runtime) wake(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed {
		return errors.New("I2P runtime closed")
	}
	if m.status.State == "error" {
		return errors.New("I2P safety gate failed")
	}
	if !m.running {
		if err := m.router.Start(ctx); err != nil {
			return err
		}
		m.running = true
		m.status.State = "starting"
	}
	m.status.LastActivity = now
	m.status.SleepAt = now.Add(m.idle)
	return nil
}
func (m *Runtime) Wake(ctx context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wake(ctx, now)
}
func (m *Runtime) Acquire(ctx context.Context, now time.Time) (func(time.Time), error) {
	m.mu.Lock()
	err := m.wake(ctx, now)
	if err == nil {
		m.status.Streams++
	}
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func(at time.Time) {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.status.Streams--
			m.status.LastActivity = at
			m.status.SleepAt = at.Add(m.idle)
		})
	}, nil
}
func (m *Runtime) Tick(ctx context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return nil
	}
	status, err := m.router.Inspect(ctx)
	if err != nil || status.Transit != 0 {
		stopErr := m.router.Stop(ctx)
		m.running = false
		m.status.State = "error"
		m.status.Transit = status.Transit
		return errors.Join(errors.New("I2P safety verification failed"), err, stopErr)
	}
	m.status.Transit = 0
	if m.status.Streams == 0 && !now.Before(m.status.SleepAt) {
		if err := m.router.Stop(ctx); err != nil {
			return err
		}
		m.running = false
		m.status.State = "sleeping"
		return nil
	}
	switch {
	case !status.Ready:
		m.status.State = "starting"
	case m.status.Streams > 0:
		m.status.State = "active"
	default:
		m.status.State = "warm"
	}
	return nil
}
func (m *Runtime) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return nil
	}
	err := m.router.Stop(ctx)
	if err == nil {
		m.running = false
		m.status.State = "sleeping"
	}
	return err
}
func (m *Runtime) SetIdle(idle time.Duration) error {
	if idle < 15*time.Minute || idle > 24*time.Hour {
		return errors.New("warm timeout must be between 15 minutes and 24 hours")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idle = idle
	if !m.status.LastActivity.IsZero() {
		m.status.SleepAt = m.status.LastActivity.Add(idle)
	}
	return nil
}

func (m *Runtime) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if !m.running {
		return nil
	}
	err := m.router.Stop(ctx)
	if err == nil {
		m.running = false
		m.status.State = "sleeping"
	}
	return err
}
