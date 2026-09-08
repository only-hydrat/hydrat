package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const portalTokenBytes = 32

func LoadOrCreatePortalToken(path string, groupID int) (string, error) {
	if token, err := ReadPortalToken(path); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	raw := make([]byte, portalTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate portal token: %w", err)
	}
	token := hex.EncodeToString(raw)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		return ReadPortalToken(path)
	}
	if err != nil {
		return "", fmt.Errorf("create portal token: %w", err)
	}
	if _, err := file.WriteString(token + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if groupID >= 0 {
		if err := os.Chown(path, -1, groupID); err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("set portal token group: %w", err)
		}
	}
	return token, nil
}

func ReadPortalToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != portalTokenBytes {
		return "", errors.New("portal token is invalid")
	}
	return token, nil
}
