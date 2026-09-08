package controller

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestProvisionerReservesAddressesOfPausedClients(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_ = database.PutClient(context.Background(), store.ClientRecord{
		ID: "old", Name: "old", Address: "10.44.0.2/32", PublicKey: "old-key", Paused: true,
	}, "old config")
	agent := &peerClientRecorder{}
	provisioner, err := NewProvisioner(database, agent, "10.44.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	client, config, err := provisioner.Create(context.Background(), "phone")
	if err != nil {
		t.Fatal(err)
	}
	if client.Address != "10.44.0.3/32" || config != "new config" {
		t.Fatalf("client=%+v config=%s", client, config)
	}
}

type peerClientRecorder struct{}

func (*peerClientRecorder) CreatePeer(_ context.Context, name, address string) (wireguard.Peer, string, error) {
	return wireguard.Peer{Name: name, Address: address, PublicKey: "new-key"}, "new config", nil
}
func (*peerClientRecorder) SetPeerPaused(context.Context, wireguard.Peer, bool) error { return nil }
