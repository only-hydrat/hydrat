package main

import (
	"github.com/only-hydrat/hydrat/internal/retainedlog"
)

// openServiceLog is a no-op on Windows: the CLI keeps logging to stderr instead
// of opening retained service segments, so startup on a non-Linux host still
// validates and reports configuration errors.
func openServiceLog(string) (*retainedlog.Writer, error) { return nil, nil }
