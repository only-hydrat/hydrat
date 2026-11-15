//go:build unix

package xrayapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(stdin)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	runErr := command.Run()
	if runErr == nil {
		return ctx.Err()
	}
	message := output.String()
	if len(message) > 4096 {
		message = message[:4096]
	}
	commandErr := fmt.Errorf("xray API command failed: %w: %s", runErr, strings.TrimSpace(message))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, commandErr)
	}
	return commandErr
}
