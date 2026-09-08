package proberuntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type execProcessStarter struct{}

func (execProcessStarter) Start(ctx context.Context, config Config) (ownedProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.Command(config.Binary, "run", "-config", config.ConfigPath)
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &execProcess{
		command: command,
		done:    make(chan struct{}),
	}
	go func() {
		_ = command.Wait()
		process.publishExit()
	}()
	return process, nil
}

type execProcess struct {
	command    *exec.Cmd
	done       chan struct{}
	stopMu     sync.Mutex
	stateMu    sync.Mutex
	exited     bool
	stopIntent bool
}

func (process *execProcess) PID() int {
	if process == nil || process.command == nil || process.command.Process == nil {
		return 0
	}
	return process.command.Process.Pid
}

func (process *execProcess) Done() <-chan struct{} {
	return process.done
}

func (process *execProcess) BeginStop() bool {
	if process == nil {
		return false
	}
	process.stateMu.Lock()
	defer process.stateMu.Unlock()
	if process.stopIntent {
		return true
	}
	if process.exited {
		return false
	}
	process.stopIntent = true
	return true
}

func (process *execProcess) publishExit() {
	if process == nil {
		return
	}
	process.stateMu.Lock()
	defer process.stateMu.Unlock()
	if process.exited {
		return
	}
	process.exited = true
	close(process.done)
}

func (process *execProcess) Stop(timeout time.Duration) error {
	if process == nil {
		return nil
	}
	process.stopMu.Lock()
	defer process.stopMu.Unlock()
	if process.command == nil || process.command.Process == nil || !process.BeginStop() ||
		channelClosed(process.done) {
		return nil
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		if channelClosed(process.done) {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil
	case <-timer.C:
	}
	if err := process.command.Process.Kill(); err != nil {
		if channelClosed(process.done) {
			return nil
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	timer.Reset(timeout)
	select {
	case <-process.done:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for forced probe Xray exit after %s", timeout)
	}
}
