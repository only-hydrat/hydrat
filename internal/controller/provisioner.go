package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

type PeerClient interface {
	CreatePeer(context.Context, string, string) (wireguard.Peer, string, error)
	SetPeerPaused(context.Context, wireguard.Peer, bool) error
}

type Provisioner struct {
	store   *store.Store
	agent   PeerClient
	network netip.Prefix
}

func NewProvisioner(database *store.Store, agent PeerClient, cidr string) (*Provisioner, error) {
	network, err := netip.ParsePrefix(cidr)
	if err != nil || !network.Addr().Is4() || network.Bits() > 30 {
		return nil, errors.New("WireGuard client network must be an IPv4 prefix of /30 or larger")
	}
	if database == nil || agent == nil {
		return nil, errors.New("client provisioner requires store and agent")
	}
	return &Provisioner{store: database, agent: agent, network: network.Masked()}, nil
}

func (provisioner *Provisioner) Create(ctx context.Context, name string) (store.ClientRecord, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return store.ClientRecord{}, "", errors.New("client name is required")
	}
	clients, err := provisioner.store.ListClients(ctx)
	if err != nil {
		return store.ClientRecord{}, "", err
	}
	used := make(map[netip.Addr]bool, len(clients))
	for _, client := range clients {
		if strings.EqualFold(client.Name, name) {
			return store.ClientRecord{}, "", errors.New("client name already exists")
		}
		prefix, err := netip.ParsePrefix(client.Address)
		if err == nil {
			used[prefix.Addr()] = true
		}
	}
	address, err := provisioner.nextAddress(used)
	if err != nil {
		return store.ClientRecord{}, "", err
	}
	peer, config, err := provisioner.agent.CreatePeer(ctx, name, address.String()+"/32")
	if err != nil {
		return store.ClientRecord{}, "", err
	}
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		_ = provisioner.agent.SetPeerPaused(ctx, peer, true)
		return store.ClientRecord{}, "", err
	}
	return store.ClientRecord{
		ID: "client-" + hex.EncodeToString(idBytes), Name: name,
		Address: peer.Address, PublicKey: peer.PublicKey,
	}, config, nil
}

func (provisioner *Provisioner) SetPaused(ctx context.Context, client store.ClientRecord, paused bool) error {
	return provisioner.agent.SetPeerPaused(ctx, wireguard.Peer{
		Name: client.Name, Address: client.Address, PublicKey: client.PublicKey,
	}, paused)
}

func (provisioner *Provisioner) Delete(ctx context.Context, client store.ClientRecord) error {
	return provisioner.SetPaused(ctx, client, true)
}

func (provisioner *Provisioner) nextAddress(used map[netip.Addr]bool) (netip.Addr, error) {
	start := provisioner.network.Addr().Next().Next()
	for address := start; provisioner.network.Contains(address); address = address.Next() {
		if !used[address] && provisioner.network.Contains(address.Next()) {
			return address, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("WireGuard client network %s is full", provisioner.network)
}
