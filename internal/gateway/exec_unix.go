//go:build unix

package gateway

import (
	"context"
	"fmt"
	"os/exec"
)

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", name, err, string(output))
	}
	return output, nil
}
