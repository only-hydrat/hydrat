package retainedlog

import "github.com/only-hydrat/hydrat/internal/platform"
import "time"

type Writer struct{}

func Open(Config) (*Writer, error) { return nil, platform.Unsupported("retained log writer (openat)") }
func PrepareDirectory(string, int, int) error {
	return platform.Unsupported("secure log directory ownership and permissions")
}
func (*Writer) Write([]byte) (int, error) {
	return 0, platform.Unsupported("retained log writer (openat)")
}
func (*Writer) Maintain(time.Time) error { return platform.Unsupported("retained log maintenance") }
func (*Writer) Close() error             { return nil }
