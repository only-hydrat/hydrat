package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

func TestRouteRecoveryDebtFencesAppliedIdentityAndNewerResults(t *testing.T) {
	for _, change := range []string{"none", "reservation", "second_failure", "healthy", "healthy_then_soft_failure", "paused", "address", "client_key", "source_disabled", "deleted", "applied_route"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			database, candidates := observationTestStore(t)
			candidate := candidates["candidate"]
			now := time.Unix(1900000000, 0)
			saveObservationHealth(t, database, candidate.ID, now, 91)
			client := ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}
			if err := database.PutClient(ctx, client, "private WG config"); err != nil {
				t.Fatal(err)
			}
			plan := dataplane.DesiredPlan{Generation: 1, FailClosed: true, Outbounds: []dataplane.Outbound{{ID: candidate.ID, Protocol: dataplane.ProtocolVLESS}}, Clients: []dataplane.ClientRoute{{ClientID: client.ID, SourceCIDR: client.Address, TCPOutbound: candidate.ID, UDPOutbound: candidate.ID}}}
			publish := func() {
				t.Helper()
				encoded, _ := json.Marshal(plan)
				if err := database.SaveDesiredPlan(ctx, plan.Generation, encoded); err != nil {
					t.Fatal(err)
				}
				if err := database.MarkAppliedPlan(ctx, plan.Generation, encoded); err != nil {
					t.Fatal(err)
				}
			}
			fail := func() {
				t.Helper()
				reservation, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
				if err != nil {
					t.Fatal(err)
				}
				if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, candidate, reservation, now.Add(time.Second)); err != nil || !commit.Accepted {
					t.Fatalf("commit=%+v %v", commit, err)
				}
			}
			// A startup assignment or historical flag alone must not create debt.
			fail()
			if rows, err := database.PendingRouteRecoveries(ctx); err != nil || len(rows) != 0 {
				t.Fatalf("pre-applied debt=%+v %v", rows, err)
			}
			publish()
			fail()
			rows, err := database.PendingRouteRecoveries(ctx)
			if err != nil || len(rows) != 2 {
				t.Fatalf("new debt=%+v %v", rows, err)
			}
			switch change {
			case "reservation":
				_, err = database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
			case "second_failure":
				fail()
			case "healthy":
				saveObservationHealth(t, database, candidate.ID, now.Add(2*time.Second), 91)
			case "healthy_then_soft_failure":
				observation, reserveErr := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
				if reserveErr != nil {
					t.Fatal(reserveErr)
				}
				if commit, commitErr := database.CommitCandidateActiveObservation(ctx, candidate, observation, true, now.Add(2*time.Second)); commitErr != nil || !commit.Accepted {
					t.Fatalf("success=%+v %v", commit, commitErr)
				}
				observation, reserveErr = database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
				if reserveErr != nil {
					t.Fatal(reserveErr)
				}
				if commit, commitErr := database.CommitCandidateActiveOutcome(ctx, candidate, observation, ActiveObservationOutcome{}, now.Add(3*time.Second)); commitErr != nil || !commit.Accepted {
					t.Fatalf("soft failure=%+v %v", commit, commitErr)
				}
			case "paused":
				err = database.UpdateClient(ctx, client.ID, client.Name, true)
			case "address":
				client.Address = "10.44.0.9/32"
				err = database.PutClient(ctx, client, "new WG config")
			case "client_key":
				client.PublicKey = "replacement-key"
				err = database.PutClient(ctx, client, "new WG config")
			case "source_disabled":
				err = database.UpdateSource(ctx, candidate.SourceID, "disabled by operator", false)
			case "deleted":
				err = database.DeleteClient(ctx, client.ID)
			case "applied_route":
				plan.Generation++
				plan.Clients[0].TCPOutbound = "other"
				publish()
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err = database.PendingRouteRecoveries(ctx)
			want := 2
			if change == "healthy" || change == "healthy_then_soft_failure" || change == "paused" || change == "address" || change == "client_key" || change == "source_disabled" || change == "deleted" {
				want = 0
			}
			if change == "applied_route" {
				want = 1
			}
			if err != nil || len(rows) != want {
				t.Fatalf("remaining debt=%+v want=%d %v", rows, want, err)
			}
		})
	}
}

func TestRouteRecoveryMigrationIsEmptyAdditiveAndBackupSafe(t *testing.T) {
	database, _ := observationTestStore(t)
	ctx := context.Background()
	if _, err := database.db.ExecContext(ctx, `DROP TABLE route_recovery`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := database.migrateRouteRecovery(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := database.PendingRouteRecoveries(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("upgrade backfilled historical failures: %+v %v", rows, err)
	}
	// The previous binary's unchanged SQL projection still reads health.
	if _, err := database.ListCandidateHealth(ctx); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/recovery.db"
	if err := database.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(path, database.box); err != nil {
		t.Fatal(err)
	}
}

func TestRouteRecoveryEnqueueAndFailureObservationAreOneTransaction(t *testing.T) {
	ctx := context.Background()
	database, candidates := observationTestStore(t)
	candidate := candidates["candidate"]
	now := time.Unix(1900000000, 0)
	saveObservationHealth(t, database, candidate.ID, now, 91)
	if err := database.PutClient(ctx, ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "private config"); err != nil {
		t.Fatal(err)
	}
	plan := dataplane.DesiredPlan{Generation: 1, FailClosed: true, Clients: []dataplane.ClientRoute{{ClientID: "alice", SourceCIDR: "10.44.0.2/32", TCPOutbound: candidate.ID}}}
	encoded, _ := json.Marshal(plan)
	if err := database.SaveDesiredPlan(ctx, 1, encoded); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAppliedPlan(ctx, 1, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`CREATE TRIGGER recovery_write_fault BEFORE INSERT ON route_recovery BEGIN SELECT RAISE(ABORT,'injected write fault'); END`); err != nil {
		t.Fatal(err)
	}
	reservation, err := database.ReserveCandidateObservation(ctx, candidate, ObservationActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, commit, err := database.CommitCandidateActiveHardFailureObservation(ctx, candidate, reservation, now.Add(time.Second)); err == nil || commit.Accepted {
		t.Fatal("partial hard-failure transaction committed")
	}
	health, generation := observationHealth(t, database, candidate.ID)
	if !health.Available || health.ActiveHardFailure || generation != 0 {
		t.Fatalf("enqueue rollback lost health atomicity: %+v generation=%d", health, generation)
	}
}
