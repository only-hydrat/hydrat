package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"path/filepath"
	"testing"
)

func TestOnionPermissionDefaultsAndSurvivesClientUpdates(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(bytes.Repeat([]byte{7}, secretbox.KeySize))
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range []string{"alice", "bob"} {
		if err := db.PutClient(ctx, ClientRecord{ID: id, Name: id, Address: id}, "config"); err != nil {
			t.Fatal(err)
		}
	}
	clients, err := db.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		if c.OnionEnabled {
			t.Fatal("enabled by default")
		}
	}
	if err := db.SetOnionEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateClient(ctx, "alice", "renamed", true); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	clients, err = db.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		if c.OnionEnabled != (c.ID == "alice") {
			t.Fatal("permission lost or crossed clients")
		}
	}
	if err := db.SetOnionEnabled(ctx, "missing", true); err == nil {
		t.Fatal("missing client accepted")
	}
	if err := db.SetOnionEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	clients, _ = db.ListClients(ctx)
	for _, c := range clients {
		if c.OnionEnabled {
			t.Fatal("revoke failed")
		}
	}
}

func TestOnionProfilesProtectedUntilAppliedRevocation(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(bytes.Repeat([]byte{7}, secretbox.KeySize))
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ImportSources(ctx, sources.PreviewInput("tor-source https://bridges.example/list.txt").Items); err != nil {
		t.Fatal(err)
	}
	listed, _ := db.ListSources(ctx)
	var inputs []CandidateInput
	for _, id := range []string{"primary", "reserve", "unused"} {
		inputs = append(inputs, CandidateInput{Kind: sources.KindTorBridge, Fingerprint: id, Label: id, Payload: "Bridge 192.0.2.1:443"})
	}
	if err := db.ReplaceCandidates(ctx, listed[0].ID, inputs); err != nil {
		t.Fatal(err)
	}
	candidates, _ := db.ListCandidates(ctx, listed[0].ID)
	ids := make(map[string]string)
	var forced []string
	plan := dataplane.DesiredPlan{Generation: 1, DirectSuffixes: []string{".ru"}, FailClosed: true}
	for _, c := range candidates {
		ids[c.Label] = c.ID
		forced = append(forced, c.ID)
		plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{ID: c.ID + "-profile-0-client-onion-alice", Protocol: dataplane.ProtocolTor})
	}
	plan.Clients = []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", BlockTCP: true, BlockUDP: true, OnionEnabled: true, OnionOutbound: ids["primary"] + "-profile-0-client-onion-alice", OnionReserveOutbound: ids["reserve"] + "-profile-0-client-onion-alice"}}
	old, _ := json.Marshal(plan)
	plan.Generation++
	plan.Clients[0].OnionEnabled = false
	plan.Clients[0].OnionOutbound, plan.Clients[0].OnionReserveOutbound = "", ""
	revoked, _ := json.Marshal(plan)
	for _, applied := range []bool{false, true} {
		encoded, gen := old, int64(1)
		if applied {
			encoded, gen = revoked, 2
		}
		if _, err := db.db.ExecContext(ctx, `UPDATE plan_state SET desired_generation=2, desired_plan=?, applied_generation=?, applied_plan=? WHERE singleton=1`, revoked, gen, encoded); err != nil {
			t.Fatal(err)
		}
		snapshot, err := db.LoadTorProfileSetSnapshot(ctx, TorProfileSetRequest{ForceCandidateIDs: forced})
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Candidates) != 3 {
			t.Fatal("missing test candidates")
		}
		for _, c := range snapshot.Candidates {
			want := !applied && c.Candidate.Label != "unused"
			if c.Assigned != want {
				t.Fatalf("applied=%v candidate=%s assigned=%v want=%v", applied, c.Candidate.Label, c.Assigned, want)
			}
		}
		// Even after qualification expires, retain only occupied profiles long
		// enough for the controller to withdraw their applied routes.
		snapshot, err = db.LoadTorProfileSetSnapshot(ctx, TorProfileSetRequest{})
		if err != nil {
			t.Fatal(err)
		}
		wantCount := 2
		if applied {
			wantCount = 0
		}
		if len(snapshot.Candidates) != wantCount {
			t.Fatalf("retained %d profiles, want %d", len(snapshot.Candidates), wantCount)
		}
		for _, c := range snapshot.Candidates {
			if !c.Assigned || !c.Draining {
				t.Fatal("unqualified occupied profile must retire gracefully")
			}
		}
	}
}

func TestOnionDesiredPlanCannotRegrantRevokedPermission(t *testing.T) {
	ctx := context.Background()
	box, _ := secretbox.New(bytes.Repeat([]byte{7}, secretbox.KeySize))
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutClient(ctx, ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "test"); err != nil {
		t.Fatal(err)
	}
	plan := dataplane.DesiredPlan{Clients: []dataplane.ClientRoute{{ClientID: "alice", OnionEnabled: true, BlockTCP: true, BlockUDP: true}}}
	for _, allowed := range []bool{true, false} {
		if err := db.SetOnionEnabled(ctx, "alice", allowed); err != nil {
			t.Fatal(err)
		}
		tx, err := db.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = validateAndEncodeDesiredAssignmentSnapshotTx(ctx, tx, plan, nil, []AssignmentRecord{{ClientID: "alice"}})
		tx.Rollback()
		if allowed && err != nil {
			t.Fatal(err)
		}
		if !allowed && !errors.Is(err, ErrCandidateInventoryChanged) {
			t.Fatalf("stale grant accepted: %v", err)
		}
	}
}
