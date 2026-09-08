//go:build darwin

package retainedlog

import "strings"

func platformDirectoryPath(directory string) string {
	for _, alias := range []string{"/var", "/tmp", "/etc"} {
		if directory == alias || strings.HasPrefix(directory, alias+"/") {
			return "/private" + directory
		}
	}
	return directory
}
