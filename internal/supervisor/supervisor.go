package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type Spec struct {
	Name string
	Path string
	Args []string
}

type Process interface{ Wait() error }

type Runner interface {
	Start(context.Context, string, ...string) (Process, error)
}

type Supervisor struct {
	Runner  Runner
	Backoff time.Duration
}

func (supervisor Supervisor) Run(ctx context.Context, spec Spec) error {
	if spec.Path == "" {
		return errors.New("supervised process path is required")
	}
	runner := supervisor.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	backoff := supervisor.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		process, err := runner.Start(ctx, spec.Path, spec.Args...)
		if err == nil {
			err = process.Wait()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type ExecRunner struct {
	Output io.Writer
}

func (runner ExecRunner) Start(ctx context.Context, path string, args ...string) (Process, error) {
	command := exec.CommandContext(ctx, path, args...)
	output := runner.Output
	if output == nil {
		output = os.Stdout
	}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", path, err)
	}
	return command, nil
}
