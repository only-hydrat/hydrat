//go:build unix

package main

import (
	"github.com/only-hydrat/hydrat/internal/retainedlog"
)

func openServiceLog(command string) (*retainedlog.Writer, error) {
	return openServiceLogWithDirectoryPreparer(command, retainedlog.PrepareDirectory)
}
