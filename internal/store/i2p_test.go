package store

import (
	"context"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"testing"
)

func TestI2PPermissionDefaultsAndPreservesOtherOptions(t *testing.T) {
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	db, err := Open(t.TempDir()+"/db", box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PutClient(ctx, ClientRecord{ID: "a", Name: "a", Address: "10.44.0.2/32"}, "config"); err != nil {
		t.Fatal(err)
	}
	cs, err := db.ListClients(ctx)
	if err != nil || cs[0].I2PEnabled {
		t.Fatal(cs, err)
	}
	if err := db.SetI2PEnabled(ctx, "a", true); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateClient(ctx, "a", "renamed", false); err != nil {
		t.Fatal(err)
	}
	cs, err = db.ListClients(ctx)
	if err != nil || !cs[0].I2PEnabled {
		t.Fatal(cs, err)
	}
}
