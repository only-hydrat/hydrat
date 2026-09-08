package refresh

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"runtime"
	"strings"
)

var validHWIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

// WithHWID configures an explicit hardware identifier (HWID) for subscription requests.
func (refresher *Refresher) WithHWID(hwid string) *Refresher {
	trimmed := strings.TrimSpace(hwid)
	if validHWIDRegexp.MatchString(trimmed) {
		refresher.hwid = trimmed
	}
	return refresher
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
