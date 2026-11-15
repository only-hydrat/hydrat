//go:build unix

package platform

import "os"

func SyncDirectory(directory *os.File) error { return directory.Sync() }
