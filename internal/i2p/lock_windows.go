package i2p

import (
	"os"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func openBookLock(string) (*os.File, error) {
	return nil, platform.Unsupported("i2p address book advisory locks")
}
func lockBook(*os.File) error { return platform.Unsupported("i2p address book advisory locks") }
