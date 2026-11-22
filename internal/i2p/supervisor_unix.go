//go:build unix

package i2p

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ServeSupervisor keeps only a small control process alive while i2pd sleeps.
// Leases expire if a gateway dies, so crashed clients cannot pin warmup forever.
func ServeSupervisor(ctx context.Context, binary, dir, socket string) error {
	r := NewRuntime(&ExecRouter{Binary: binary, Directory: dir}, 2*time.Hour)
	defer r.Close(context.Background())
	lastState := r.Status().State
	mux, expire := supervisorHandler(r)
	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return err
	}
	// Refuse to replace an active socket owned by another supervisor.
	if c, err := net.DialTimeout("unix", socket, time.Second); err == nil {
		c.Close()
		return errors.New("I2P supervisor already running")
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(socket)
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	if err = os.Chown(socket, -1, 10001); err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case now := <-tick.C:
				expire(now)
				bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
				err := r.Tick(bounded, now)
				state := r.Status().State
				if state != lastState {
					log.Printf("I2P state=%s transit=%d verification_failed=%t", state, r.Status().Transit, err != nil)
					lastState = state
				}
				cancel()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}
