package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func EnsureServerConfig(ctx context.Context, path, network string, listenPort int, runner InputRunner) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat WireGuard server config: %w", err)
	}
	if listenPort <= 0 || listenPort > 65535 {
		return errors.New("WireGuard listen port must be between 1 and 65535")
	}
	ip, subnet, err := net.ParseCIDR(network)
	if err != nil || ip.To4() == nil {
		return errors.New("WireGuard network must be an IPv4 CIDR")
	}
	prefix, bits := subnet.Mask.Size()
	if bits != 32 || prefix > 30 {
		return errors.New("WireGuard network must have room for a server and clients")
	}
	serverIP := append(net.IP(nil), subnet.IP.To4()...)
	serverIP[3]++
	if runner == nil {
		runner = ExecInputRunner{}
	}
	keyBytes, err := runner.RunInput(ctx, "", "wg", "genkey")
	if err != nil {
		return fmt.Errorf("generate WireGuard server private key: %w", err)
	}
	privateKey := strings.TrimSpace(string(keyBytes))
	if privateKey == "" {
		return errors.New("WireGuard returned an empty server private key")
	}
	config := fmt.Sprintf(
		"[Interface]\nAddress = %s/%d\nListenPort = %d\nSaveConfig = false\nPrivateKey = %s\n",
		serverIP.String(), prefix, listenPort, privateKey,
	)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create WireGuard data directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create WireGuard server config: %w", err)
	}
	removeIncomplete := true
	defer func() {
		_ = file.Close()
		if removeIncomplete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(config); err != nil {
		return fmt.Errorf("write WireGuard server config: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync WireGuard server config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close WireGuard server config: %w", err)
	}
	removeIncomplete = false
	return nil
}
