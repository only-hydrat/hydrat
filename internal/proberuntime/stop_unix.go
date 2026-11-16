//go:build unix

package proberuntime

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

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
