//go:build !windows

package xrayflow

import "os"

func privateSocketDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir() && info.Mode().Perm()&0077 == 0
}

func secureSocket(path string) error { return os.Chmod(path, 0600) }
