//go:build unix

package proberuntime

import (
	"context"
	"os/exec"
)

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
