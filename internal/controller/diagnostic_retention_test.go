package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/store"
)

func TestDiagnosticRetentionRunsBatchesUntilExactCutoffIsEmpty(t *testing.T) {
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.Unix(1_800_000_000, 0)
	cutoff := now.Add(-72 * time.Hour)
	for index := 0; index < 1_001; index++ {
		createdAt := cutoff.Add(-time.Duration(index) * time.Second)
		if err := database.AppendEvent(context.Background(), store.Event{
			Kind: "retention-test", Message: "old", CreatedAt: createdAt,
		}); err != nil {
			t.Fatal(err)
		}
		if err := database.AppendProbeSample(
			context.Background(),
			store.ProbeSample{
				CandidateID: "candidate", Success: true, CreatedAt: createdAt,
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.AppendEvent(context.Background(), store.Event{
		Kind: "retention-test", Message: "new",
		CreatedAt: cutoff.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendProbeSample(
		context.Background(),
		store.ProbeSample{
			CandidateID: "candidate", Success: true,
			CreatedAt: cutoff.Add(time.Second),
		},
	); err != nil {
		t.Fatal(err)
	}

	retention := DiagnosticRetention{
		Store: database, Retention: 72 * time.Hour, BatchSize: 1_000,
	}
	if err := retention.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	events, err := database.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 ||
		events[0].Message != "new" ||
		!events[0].CreatedAt.Equal(cutoff.Add(time.Second)) {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	remaining, err := database.PruneDiagnostics(
		context.Background(), cutoff, 1_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != (store.DiagnosticPruneResult{}) {
		t.Fatalf("eligible diagnostics remain=%+v", remaining)
	}
}

func TestDiagnosticRetentionValidatesConfigurationAndReturnsStoreError(
	t *testing.T,
) {
	now := time.Unix(1_800_000_000, 0)
	for name, retention := range map[string]DiagnosticRetention{
		"missing store": {Retention: 72 * time.Hour, BatchSize: 1_000},
		"zero retention": {
			Store: diagnosticRetentionStore(t), BatchSize: 1_000,
		},
		"zero batch": {
			Store: diagnosticRetentionStore(t), Retention: 72 * time.Hour,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := retention.Run(context.Background(), now); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}

	database := diagnosticRetentionStore(t)
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	retention := DiagnosticRetention{
		Store: database, Retention: 72 * time.Hour, BatchSize: 1_000,
	}
	if err := retention.Run(context.Background(), now); err == nil {
		t.Fatal("expected closed-store error")
	}
}

func diagnosticRetentionStore(t *testing.T) *store.Store {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(t.TempDir(), "state.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
