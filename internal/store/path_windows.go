package store

import "path/filepath"

// A drive path needs a leading slash in a file URI, otherwise net/url treats
// the drive as an authority. Keep escaping of spaces, # and ? in net/url.
func databaseURIPath(path string) string {
	path = filepath.ToSlash(path)
	if len(path) >= 2 && path[1] == ':' {
		path = "/" + path
	}
	return path
}
