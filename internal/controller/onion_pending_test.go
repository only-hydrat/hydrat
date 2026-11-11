package controller

import (
	"context"
	"errors"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingOnionGrantMustRespectLaterRevocation(t *testing.T) {
	for _, action := range []string{"revoke", "pause", "delete"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1800000000, 0)
			box, _ := secretbox.New(make([]byte, secretbox.KeySize))
			db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			preview := sources.PreviewInput("tor-bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567")
			if _, err := db.ImportSources(ctx, preview.Items); err != nil {
				t.Fatal(err)
			}
			listed, _ := db.ListSources(ctx)
			if err := db.ReplaceCandidates(ctx, listed[0].ID, []store.CandidateInput{{Kind: sources.KindTorBridge, Label: "tor", Fingerprint: "tor", Payload: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"}}); err != nil {
				t.Fatal(err)
			}
			rows, _ := db.ListCandidates(ctx, listed[0].ID)
			id := rows[0].ID
			if err := db.SaveCandidateHealth(ctx, store.CandidateHealth{CandidateID: id, Score: 100, TCPQualified: true, Available: true, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := db.PutClient(ctx, store.ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "test"); err != nil {
				t.Fatal(err)
			}
			if err := db.PutClient(ctx, store.ClientRecord{ID: "bob", Name: "Bob", Address: "10.44.0.3/32"}, "test"); err != nil {
				t.Fatal(err)
			}
			if err := db.SetOnionEnabled(ctx, "bob", true); err != nil {
				t.Fatal(err)
			}
			p := []torpool.Profile{{Slot: 0, CandidateID: id, SocksAddr: "127.0.0.1:19050", Role: "warm", OnionReady: true}}
			a := &engineAgent{}
			e := NewEngine(db, a, profileProviderFunc(func() []torpool.Profile { return p }), scheduler.New(scheduler.PolicyDefaults()), []byte("test"))
			if err := e.Cycle(ctx, now); err != nil {
				t.Fatal(err)
			}

			if err := db.SetOnionEnabled(ctx, "alice", true); err != nil {
				t.Fatal(err)
			}
			a.applyErr = errors.New("temporary agent outage")
			if err := e.Cycle(ctx, now.Add(time.Second)); err == nil {
				t.Fatal("setup did not leave pending grant")
			}
			state, err := db.LoadPlanState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if state.DesiredGeneration <= state.AppliedGeneration {
				t.Fatal("no pending desired plan")
			}
			switch action {
			case "revoke":
				err = db.SetOnionEnabled(ctx, "alice", false)
			case "pause":
				err = db.UpdateClient(ctx, "alice", "Alice", true)
			case "delete":
				err = db.DeleteClient(ctx, "alice")
			}
			if err != nil {
				t.Fatal(err)
			}
			start := len(a.plans)
			a.applyErr = nil
			if err := e.Cycle(ctx, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, p := range a.plans[start:] {
				for _, r := range p.Clients {
					if r.ClientID == "alice" && r.OnionEnabled {
						t.Fatalf("stale onion permission reapplied after revoke in generation %d", p.Generation)
					}
				}
			}

		})
	}
}
