package torpool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcess struct {
	done     chan struct{}
	command  *exec.Cmd
	killWait time.Duration
}

func (runner ExecRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	// Closing the job after Tor exits also terminates its managed transports.
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	command := exec.CommandContext(ctx, name, args...)
	if filepath.IsAbs(name) {
		command.Dir = filepath.Dir(name)
	}
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := command.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(command.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, handle)
		_ = windows.CloseHandle(handle)
	}
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = windows.CloseHandle(job)
		return nil, err
	}
	wait := runner.KillWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	process := &windowsProcess{command: command, done: make(chan struct{}), killWait: wait}
	go func() {
		_ = command.Wait()
		_ = windows.CloseHandle(job)
		close(process.done)
	}()
	return process, nil
}

func (process *windowsProcess) Exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *windowsProcess) Stop() error {
	if err := process.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	timer := time.NewTimer(process.killWait)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil
	case <-timer.C:
		return errors.New("timed out waiting for Tor process exit")
	}
}

// Tor separates ClientTransportPlugin arguments at whitespace. The packaged
// transport is relative to the Tor executable so spaces in the install path
// do not get interpreted as additional transport arguments.
func transportPath(tor, executable string) string {
	if !filepath.IsAbs(tor) || !filepath.IsAbs(executable) {
		return executable
	}
	relative, err := filepath.Rel(filepath.Dir(tor), executable)
	if err != nil || strings.ContainsAny(relative, " \t") {
		return executable
	}
	return `.\` + relative
}
