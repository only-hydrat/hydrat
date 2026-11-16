//go:build unix

package torpool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

func (runner ExecRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	gracePeriod := runner.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 2 * time.Second
	}
	killWait := runner.KillWait
	if killWait <= 0 {
		killWait = 2 * time.Second
	}
	process := &execProcess{
		command: command, done: make(chan struct{}),
		gracePeriod: gracePeriod, killWait: killWait, processGroup: true,
	}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	return process, nil
}

type execProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	gracePeriod  time.Duration
	killWait     time.Duration
	processGroup bool
	stopMu       sync.Mutex
}

func (process *execProcess) Exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *execProcess) Stop() error {
	process.stopMu.Lock()
	defer process.stopMu.Unlock()
	if process.command.Process == nil {
		return nil
	}
	if process.Exited() {
		return nil
	}
	if err := process.signal(syscall.SIGTERM); err != nil {
		if process.Exited() {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	gracePeriod := process.gracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 2 * time.Second
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(gracePeriod):
	}
	if err := process.signal(syscall.SIGKILL); err != nil {
		if process.Exited() {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	killWait := process.killWait
	if killWait <= 0 {
		killWait = 2 * time.Second
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(killWait):
		return errors.New("timed out waiting for forced Tor process exit")
	}
}

func (process *execProcess) signal(signal syscall.Signal) error {
	if process.processGroup {
		return syscall.Kill(-process.command.Process.Pid, signal)
	}
	return process.command.Process.Signal(signal)
}
