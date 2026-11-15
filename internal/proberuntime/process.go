package proberuntime

import (
	"os/exec"
	"sync"
)

type execProcessStarter struct{}

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
