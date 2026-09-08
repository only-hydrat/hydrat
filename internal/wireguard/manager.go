package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

type ManagerConfig struct {
	Interface string
	Endpoint  string
	DNS       string
	MTU       int
}

type Peer struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type InputRunner interface {
	RunInput(context.Context, string, string, ...string) ([]byte, error)
}

type Manager struct {
	Runner InputRunner
	Config ManagerConfig
}

func (manager Manager) Create(ctx context.Context, name, address string) (Peer, string, error) {
	if err := validateClientAddress(address); err != nil {
		return Peer{}, "", err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(manager.Config.Endpoint) == "" ||
		strings.TrimSpace(manager.Config.DNS) == "" {
		return Peer{}, "", errors.New("client name, WireGuard endpoint and DNS are required")
	}
	dnsAddress, err := netip.ParseAddr(manager.Config.DNS)
	if err != nil || !dnsAddress.Is4() {
		return Peer{}, "", errors.New("WireGuard client DNS must be a canonical IPv4 address")
	}
	runner := manager.runner()
	privateBytes, err := runner.RunInput(ctx, "", "wg", "genkey")
	if err != nil {
		return Peer{}, "", fmt.Errorf("generate private key: %w", err)
	}
	privateKey := strings.TrimSpace(string(privateBytes))
	publicBytes, err := runner.RunInput(ctx, privateKey+"\n", "wg", "pubkey")
	if err != nil {
		return Peer{}, "", fmt.Errorf("derive public key: %w", err)
	}
	publicKey := strings.TrimSpace(string(publicBytes))
	serverBytes, err := runner.RunInput(ctx, "", "wg", "show", manager.interfaceName(), "public-key")
	if err != nil {
		return Peer{}, "", fmt.Errorf("read server public key: %w", err)
	}
	serverPublicKey := strings.TrimSpace(string(serverBytes))
	if privateKey == "" || publicKey == "" || serverPublicKey == "" {
		return Peer{}, "", errors.New("WireGuard returned an empty key")
	}
	peer := Peer{Name: name, Address: address, PublicKey: publicKey}
	if _, err := runner.RunInput(ctx, "", "wg", "set", manager.interfaceName(), "peer", publicKey, "allowed-ips", address); err != nil {
		return Peer{}, "", fmt.Errorf("add WireGuard peer: %w", err)
	}
	if err := manager.save(ctx, runner); err != nil {
		_, _ = runner.RunInput(ctx, "", "wg", "set", manager.interfaceName(), "peer", publicKey, "remove")
		return Peer{}, "", err
	}
	mtu := manager.Config.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	dnsLine := "DNS = " + dnsAddress.String() + "\n"
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n%sMTU = %d\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		privateKey, address, dnsLine, mtu, serverPublicKey, manager.Config.Endpoint)
	return peer, config, nil
}

func (manager Manager) SetPaused(ctx context.Context, peer Peer, paused bool) error {
	runner := manager.runner()
	args := []string{"set", manager.interfaceName(), "peer", peer.PublicKey}
	if paused {
		args = append(args, "remove")
	} else {
		if err := validateClientAddress(peer.Address); err != nil {
			return err
		}
		args = append(args, "allowed-ips", peer.Address)
	}
	if _, err := runner.RunInput(ctx, "", "wg", args...); err != nil {
		return err
	}
	return manager.save(ctx, runner)
}

func (manager Manager) Delete(ctx context.Context, peer Peer) error {
	return manager.SetPaused(ctx, peer, true)
}

func (manager Manager) save(ctx context.Context, runner InputRunner) error {
	if _, err := runner.RunInput(ctx, "", "wg-quick", "save", manager.interfaceName()); err != nil {
		return fmt.Errorf("persist WireGuard interface: %w", err)
	}
	return nil
}

func (manager Manager) interfaceName() string {
	if manager.Config.Interface == "" {
		return "wg0"
	}
	return manager.Config.Interface
}

func (manager Manager) runner() InputRunner {
	if manager.Runner == nil {
		return ExecInputRunner{}
	}
	return manager.Runner
}

func validateClientAddress(address string) error {
	ip, network, err := net.ParseCIDR(address)
	if err != nil || ip.To4() == nil {
		return errors.New("client address must be an IPv4 CIDR")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 32 {
		return errors.New("client address must be a /32 host route")
	}
	return nil
}

type ExecInputRunner struct{}

func (ExecInputRunner) RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(output.String()))
	}
	return output.Bytes(), nil
}
