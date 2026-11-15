package xrayapi

import (
	"context"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (ExecRunner) Run(context.Context, string, string, ...string) error {
	return platform.Unsupported("Xray gateway API commands")
}
