//go:build unix

package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func (ExecInputRunner) RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(output.String()))
	}
	return output.Bytes(), nil
}
