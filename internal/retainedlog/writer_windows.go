package retainedlog

import (
	"time"

	"github.com/only-hydrat/hydrat/internal/platform"
)

// Writer is an empty placeholder: the Windows build never opens a log segment,
// it refuses the operation through platform.Unsupported.
type Writer struct{}

func Open(Config) (*Writer, error) { return nil, platform.Unsupported("retained log writer (openat)") }
func PrepareDirectory(string, int, int) error {
	return platform.Unsupported("secure log directory ownership and permissions")
}
func (*Writer) Write([]byte) (int, error) {
	return 0, platform.Unsupported("retained log writer (openat)")
}
func (*Writer) Maintain(time.Time) error { return platform.Unsupported("retained log maintenance") }

// Close stays safe on a writer that was never opened, so callers can defer it
// without a nil check on every platform.
func (*Writer) Close() error { return nil }
