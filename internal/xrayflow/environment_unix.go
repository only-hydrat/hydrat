//go:build unix

package xrayflow

import (
	"errors"
	"os"
	"path/filepath"
)

// StartFromEnvironment is called only by the patched Xray outbound factory.
// Hydrat sets the variable on its main Xray child, never CLI or probe children.
func StartFromEnvironment() error {
	path := os.Getenv(SocketEnvironment)
	if path == "" {
		return nil
	}
	startOnce.Do(func() {
		if !filepath.IsAbs(path) {
			startError = ErrInvalidRequest
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			startError = errors.New("flow control directory unavailable")
			return
		}
		r := NewRegistry()
		if _, err := Listen(path, r); err != nil {
			startError = errors.New("flow control listener unavailable")
			return
		}
		processRegistry.Store(r)
	})
	return startError
}
