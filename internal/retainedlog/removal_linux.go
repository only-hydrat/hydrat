//go:build linux

package retainedlog

import "fmt"

func anchoredRemovalPath(directoryFD int, name string) (string, error) {
	return fmt.Sprintf("/proc/self/fd/%d/%s", directoryFD, name), nil
}
