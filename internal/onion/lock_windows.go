package onion

import (
	"os"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func openBookLock(string) (*os.File, error) {
	return nil, platform.Unsupported("onion address book advisory locks")
}
func lockBook(*os.File) error { return platform.Unsupported("onion address book advisory locks") }
