package controller

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/store"
)

type lifecycleApplyAgent struct {
	engineAgent
	onApply func()
}

func (a *lifecycleApplyAgent) Apply(ctx context.Context, plan dataplane.DesiredPlan) error {
	if a.onApply != nil {
		f := a.onApply
		a.onApply = nil
		f()
	}
	return a.engineAgent.Apply(ctx, plan)
}

func TestClientLifecycleDuringPendingApplyConverges(t *testing.T) {
	for _, timing := range []string{"pending", "before_save", "during_apply"} {
		for _, action := range []string{"delete", "pause", "add", "delete_paused", "unpause", "replace"} {
			t.Run(timing+"/"+action, func(t *testing.T) {
				ctx := context.Background()
				now := time.Unix(1800000000, 0)
				box, err := secretbox.New(make([]byte, secretbox.KeySize))
				if err != nil {
					t.Fatal(err)
				}
				db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				for i, id := range []string{"alice", "bob"} {
					address := []string{"10.44.0.2/32", "10.44.0.3/32"}[i]
					if err := db.PutClient(ctx, store.ClientRecord{ID: id, Name: id, Address: address, Paused: id == "alice" && (action == "delete_paused" || action == "unpause")}, "test"); err != nil {
						t.Fatal(err)
					}
				}
				if err := db.SetI2PEnabled(ctx, "bob", true); err != nil {
					t.Fatal(err)
				}
				a := &lifecycleApplyAgent{}
				e := NewEngine(db, a, nil, nil, []byte("test"))
				if err := e.Cycle(ctx, now); err != nil {
					t.Fatal(err)
				}
				// A pending revocation does not grant Alice either overlay. Her
				// deletion still invalidates its complete assignment snapshot.
				if err := db.SetI2PEnabled(ctx, "bob", false); err != nil {
					t.Fatal(err)
				}
				mutate := func() {
					var err error
					switch action {
					case "delete", "delete_paused":
						err = db.DeleteClient(ctx, "alice")
					case "pause":
						err = db.UpdateClient(ctx, "alice", "alice", true)
					case "unpause":
						err = db.UpdateClient(ctx, "alice", "alice", false)
					case "replace":
						if err = db.DeleteClient(ctx, "alice"); err == nil {
							err = db.PutClient(ctx, store.ClientRecord{ID: "charlie", Name: "charlie", Address: "10.44.0.4/32"}, "test")
						}
					case "add":
						err = db.PutClient(ctx, store.ClientRecord{ID: "charlie", Name: "charlie", Address: "10.44.0.4/32"}, "test")
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				switch timing {
				case "pending":
					a.applyErr = errors.New("agent unavailable")
					if err := e.Cycle(ctx, now.Add(time.Second)); err == nil {
						t.Fatal("expected pending plan")
					}
					a.applyErr = nil
					mutate()
				case "before_save":
					e.beforeDesiredPlanSave = func() { e.beforeDesiredPlanSave = nil; mutate() }
				case "during_apply":
					a.onApply = mutate
				}
				start := len(a.plans)
				converged := false
				for attempt := 0; attempt < 3; attempt++ {
					err := e.CycleForReason(ctx, now.Add(time.Duration(attempt+2)*time.Second), PlacementStartupNormalization)
					if err == nil {
						converged = true
						break
					}
					if !retryablePlacementError(err) {
						t.Fatalf("client change caused fatal placement error: %v", err)
					}
				}
				if !converged {
					t.Fatal("client lifecycle did not converge")
				}
				state, err := db.LoadPlanState(ctx)
				if err != nil || state.DesiredGeneration != state.AppliedGeneration {
					t.Fatalf("pending state: %+v %v", state, err)
				}
				var plan dataplane.DesiredPlan
				plan, _, err = decodePersistedPlan("applied", state.AppliedGeneration, state.AppliedPlan)
				if err != nil {
					t.Fatal(err)
				}
				for _, route := range plan.Clients {
					if route.ClientID == "alice" && action != "add" && action != "unpause" {
						t.Fatal("obsolete Alice route remains")
					}
					if route.I2PEnabled {
						t.Fatal("revoked I2P access remains")
					}
				}
				if timing == "pending" && action != "add" && action != "unpause" {
					for _, p := range a.plans[start:] {
						for _, r := range p.Clients {
							if r.ClientID == "alice" {
								t.Fatal("stale pending route replayed")
							}
						}
					}
				}
			})
		}
	}
}
