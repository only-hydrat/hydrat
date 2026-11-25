package refresh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"runtime"
	"strings"
)

var validHWIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

var ErrInvalidHWID = errors.New("invalid subscription HWID")

// WithHWID configures an explicit hardware identifier (HWID) for subscription requests.
func (refresher *Refresher) WithHWID(hwid string) *Refresher {
	_ = refresher.SetHWID(hwid)
	return refresher
}

// SetHWID replaces a custom identifier. An empty value restores auto-detection.
func (refresher *Refresher) SetHWID(hwid string) error {
	trimmed, err := NormalizeHWID(hwid)
	if err != nil {
		return err
	}
	refresher.hwid = trimmed
	return nil
}

func NormalizeHWID(hwid string) (string, error) {
	trimmed := strings.TrimSpace(hwid)
	if trimmed != "" && !validHWIDRegexp.MatchString(trimmed) {
		return "", ErrInvalidHWID
	}
	return trimmed, nil
}

// HWID returns the configured or auto-detected hardware identifier.
func (refresher *Refresher) HWID() string {
	if refresher.hwid != "" {
		return refresher.hwid
	}
	return getSystemHWID()
}

func getSystemHWID() string {
	if envHWID := strings.TrimSpace(os.Getenv("HYDRAT_HWID")); validHWIDRegexp.MatchString(envHWID) {
		return envHWID
	}

	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil {
			id := strings.TrimSpace(string(data))
			if validHWIDRegexp.MatchString(id) {
				return id
			}
		}
	}

	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		hash := sha256.Sum256([]byte("hydrat:" + strings.TrimSpace(hostname)))
		return hex.EncodeToString(hash[:16]) // 32 hex chars
	}

	return ""
}

func runtimeOS() string {
	switch runtime.GOOS {
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "freebsd":
		return "FreeBSD"
	case "openbsd":
		return "OpenBSD"
	default:
		return runtime.GOOS
	}
}
