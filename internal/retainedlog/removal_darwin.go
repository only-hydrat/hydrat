//go:build darwin

package retainedlog

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

func anchoredRemovalPath(directoryFD int, name string) (string, error) {
	path := make([]byte, 4096)
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(directoryFD), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&path[0])))
	if errno != 0 {
		return "", fmt.Errorf("get retained directory path from fd: %w", errno)
	}
	return filepath.Join(unix.ByteSliceToString(path), name), nil
}
