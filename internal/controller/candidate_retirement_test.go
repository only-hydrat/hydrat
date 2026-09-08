package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
	"github.com/only-hydrat/hydrat/internal/torpool"
)

func TestCandidateRetirementStateMachineSurvivesRestartAndReactivation(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindVLESS)
	ctx := context.Background()
	drainedAt := fixture.drain(t)
	now := drainedAt.Add(2 * time.Second)
	collector := CandidateRetirement{
		Store: fixture.database, RetiredRetention: time.Minute,
	}

	if err := collector.Run(ctx, drainedAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleDraining)
	fixture.reopen(t)
	collector.Store = fixture.database
	if err := collector.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleRetired)
	if payload, err := fixture.database.CandidatePayload(ctx, fixture.candidate.ID); err != nil || payload != fixture.payload {
		t.Fatalf("retired encrypted payload=%q err=%v", payload, err)
	}

	fixture.reopen(t)
	collector.Store = fixture.database
	if err := collector.Run(ctx, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleRetired)

	fixture.replace(t, true)
	requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleActive)
	if err := collector.Run(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleActive)

	drainedAt = fixture.drain(t)
	now = drainedAt.Add(2 * time.Second)
	if err := collector.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := collector.Run(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.CandidateForRetirement(ctx, fixture.candidate.ID); !errors.Is(err, store.ErrCandidateNotFound) {
		t.Fatalf("deleted candidate lookup err=%v", err)
	}
	if _, err := fixture.database.CandidatePayload(ctx, fixture.candidate.ID); err == nil {
		t.Fatal("deleted candidate payload remains readable")
	}
}

func TestCandidateRetirementFinalizesPendingSourceAfterLastCandidate(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindVLESS)
	fixture.saveEqualPlan(t, 1, "")
	ctx := context.Background()
	if err := fixture.database.DeleteSource(
		ctx, fixture.sourceID, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	target, err := fixture.database.CandidateForRetirement(
		ctx, fixture.candidate.ID,
	)
	if err != nil || target.DrainAfter == nil {
		t.Fatalf("pending target=%+v err=%v", target, err)
	}
	now := time.Unix(*target.DrainAfter, 0).Add(time.Second)
	collector := CandidateRetirement{
		Store: fixture.database, RetiredRetention: time.Second,
	}
	if err := collector.Run(ctx, now); err != nil {
		t.Fatal(err)
	}
	if rows, _ := fixture.database.ListSources(ctx); len(rows) != 1 ||
		!rows[0].PendingDelete {
		t.Fatalf("pending source removed before retention: %+v", rows)
	}
	if err := collector.Run(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if rows, _ := fixture.database.ListSources(ctx); len(rows) != 0 {
		t.Fatalf("pending source survived last candidate collection: %+v", rows)
	}
}

func TestCandidateRetirementRetainsEveryPersistedReference(t *testing.T) {
	tests := []struct {
		name string
		seed func(*testing.T, *retirementFixture)
	}{
		{
			name: "assignment",
			seed: func(t *testing.T, fixture *retirementFixture) {
				ctx := context.Background()
				if err := fixture.database.PutClient(ctx, store.ClientRecord{
					ID: "client", Name: "client", Address: "10.44.0.2/32", PublicKey: "key",
				}, "config"); err != nil {
					t.Fatal(err)
				}
				if err := fixture.database.SetAssignment(ctx, store.AssignmentRecord{
					ClientID: "client", TCPOutbound: fixture.candidate.ID,
					TCPSince: time.Now(), UDPSince: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "working pool",
			seed: func(t *testing.T, fixture *retirementFixture) {
				ctx := context.Background()
				if _, err := fixture.database.RecordCandidateProbe(ctx, store.ProbeTransition{
					Fingerprint: fixture.candidate.Fingerprint,
					CandidateID: fixture.candidate.ID,
					SourceID:    fixture.candidate.SourceID,
					Success:     true, At: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				if err := fixture.database.ReplaceWorkingPool(
					ctx, []string{fixture.candidate.Fingerprint}, nil,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "desired and applied plans",
			seed: func(t *testing.T, fixture *retirementFixture) {
				fixture.saveEqualPlan(t, 1, fixture.candidate.ID)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetirementFixture(t, sources.KindVLESS)
			test.seed(t, fixture)
			drainedAt := fixture.drain(t)
			collector := CandidateRetirement{
				Store: fixture.database, RetiredRetention: time.Minute,
			}
			if err := collector.Run(context.Background(), drainedAt.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleDraining)
		})
	}
}

func TestCandidateRetirementAbortsOnGenerationChangesAroundTorAck(t *testing.T) {
	t.Run("unequal before reconcile", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		if err := fixture.database.SaveDesiredPlan(
			context.Background(), 1, retirementPlan(t, 1),
		); err != nil {
			t.Fatal(err)
		}
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		}
		if err := collector.Run(context.Background(), drainedAt.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleDraining)
		if len(agent.calls) != 0 {
			t.Fatalf("Tor reconciled with unequal generations: %+v", agent.calls)
		}
	})

	t.Run("new desired after reconcile ack", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		fixture.saveEqualPlan(t, 1, "")
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		}
		collector.beforeFinalize = func(store.Candidate) {
			if err := fixture.database.SaveDesiredPlan(
				context.Background(), 2, retirementPlan(t, 2),
			); err != nil {
				t.Fatal(err)
			}
		}
		if err := collector.Run(context.Background(), drainedAt.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, store.CandidateLifecycleDraining)
		requireCachedTorProfileAbsent(t, agent, fixture.candidate.ID)
	})
}

func TestCandidateRetirementRequiresExactTorReconcileAcknowledgement(t *testing.T) {
	tests := []struct {
		name     string
		profiles func(*retirementFixture) []torpool.Profile
	}{
		{
			name: "retained target",
			profiles: func(fixture *retirementFixture) []torpool.Profile {
				return []torpool.Profile{{
					Role: "warm", CandidateID: fixture.candidate.ID,
				}}
			},
		},
		{
			name: "empty candidate identity",
			profiles: func(*retirementFixture) []torpool.Profile {
				return []torpool.Profile{{Role: "warm"}}
			},
		},
		{
			name: "unexpected candidate identity",
			profiles: func(*retirementFixture) []torpool.Profile {
				return []torpool.Profile{{
					Role: "warm", CandidateID: "cand_unexpected",
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetirementFixture(t, sources.KindTorBridge)
			fixture.saveEqualPlan(t, 1, "")
			drainedAt := fixture.drain(t)
			agent := &retirementTorAgent{
				reconcile: func([]torpool.Candidate) ([]torpool.Profile, error) {
					return test.profiles(fixture), nil
				},
			}
			collector := CandidateRetirement{
				Store: fixture.database, Tor: agent,
				RetiredRetention: time.Minute,
			}
			if err := collector.Run(
				context.Background(), drainedAt.Add(2*time.Second),
			); err == nil {
				t.Fatal("collector accepted invalid Tor acknowledgement")
			}
			requireCandidateLifecycle(
				t, fixture.database, fixture.candidate.ID,
				store.CandidateLifecycleDraining,
			)
		})
	}
}

func TestCandidateRetirementAllowsCapacityLimitedOptionalProfileSubset(
	t *testing.T,
) {
	fixture, _, drainedAt := retirementWithQualifiedSentinel(t, 100)
	agent := &retirementTorAgent{
		reconcile: func([]torpool.Candidate) ([]torpool.Profile, error) {
			return nil, nil
		},
	}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleRetired,
	)
}

func TestCandidateRetirementReloadsReferencesAndTorProfilesAfterAck(t *testing.T) {
	tests := []struct {
		name       string
		wantTarget bool
		race       func(*testing.T, *retirementFixture, *retirementTorAgent)
	}{
		{
			name: "persisted assignment", wantTarget: true,
			race: func(t *testing.T, fixture *retirementFixture, _ *retirementTorAgent) {
				ctx := context.Background()
				if err := fixture.database.PutClient(ctx, store.ClientRecord{
					ID: "late-client", Name: "late-client",
					Address: "10.44.0.3/32", PublicKey: "key",
				}, "config"); err != nil {
					t.Fatal(err)
				}
				if err := fixture.database.SetAssignment(ctx, store.AssignmentRecord{
					ClientID: "late-client", TCPOutbound: fixture.candidate.ID,
					TCPSince: time.Now(), UDPSince: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "live Tor profile",
			race: func(_ *testing.T, fixture *retirementFixture, agent *retirementTorAgent) {
				agent.mu.Lock()
				agent.profiles = []torpool.Profile{{
					Role: "warm", CandidateID: fixture.candidate.ID,
				}}
				agent.mu.Unlock()
			},
		},
		{
			name: "candidate reactivation", wantTarget: true,
			race: func(t *testing.T, fixture *retirementFixture, _ *retirementTorAgent) {
				fixture.replace(t, true)
			},
		},
		{
			name: "desired and applied plan reference", wantTarget: true,
			race: func(t *testing.T, fixture *retirementFixture, _ *retirementTorAgent) {
				fixture.saveEqualPlan(t, 2, fixture.candidate.ID)
			},
		},
		{
			name: "inventory epoch",
			race: func(t *testing.T, fixture *retirementFixture, _ *retirementTorAgent) {
				if err := fixture.database.UpdateSource(
					context.Background(), fixture.sourceID, "changed", true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetirementFixture(t, sources.KindTorBridge)
			fixture.saveEqualPlan(t, 1, "")
			drainedAt := fixture.drain(t)
			agent := &retirementTorAgent{}
			collector := CandidateRetirement{
				Store: fixture.database, Tor: agent,
				RetiredRetention: time.Minute,
			}
			collector.beforeFinalize = func(store.Candidate) {
				test.race(t, fixture, agent)
			}
			err := collector.Run(
				context.Background(), drainedAt.Add(2*time.Second),
			)
			if test.name == "live Tor profile" && err == nil {
				t.Fatal("collector accepted a Tor profile added after acknowledgement")
			}
			if test.name != "live Tor profile" && err != nil {
				t.Fatal(err)
			}
			want := store.CandidateLifecycleDraining
			if test.name == "candidate reactivation" {
				want = store.CandidateLifecycleActive
			}
			requireCandidateLifecycle(t, fixture.database, fixture.candidate.ID, want)
			if test.wantTarget {
				requireCachedTorProfile(t, agent, fixture.candidate.ID)
			} else if test.name != "live Tor profile" {
				requireCachedTorProfileAbsent(
					t, agent, fixture.candidate.ID,
				)
			}
		})
	}
}

func TestCandidateRetirementValidatesCurrentDueStateBeforeTorRPC(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	drainedAt := fixture.drain(t)
	agent := &retirementTorAgent{}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		beforeSnapshot: func(store.Candidate) {
			fixture.replace(t, true)
		},
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if calls := agent.snapshotCalls(); len(calls) != 0 {
		t.Fatalf("Tor called after candidate stopped being due: %+v", calls)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleActive,
	)
}

func TestCandidateRetirementCompensatesAdvanceStoreError(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	drainedAt := fixture.drain(t)
	agent := &retirementTorAgent{}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		advance: func(
			context.Context,
			string,
			int64,
			int64,
			string,
			time.Time,
			time.Duration,
		) (store.CandidateRetirementResult, error) {
			return store.CandidateRetirementResult{}, errors.New("injected DB error")
		},
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err == nil {
		t.Fatal("collector ignored retirement DB error")
	}
	requireCachedTorProfileAbsent(t, agent, fixture.candidate.ID)
	requireLastTorRequestExcludes(t, agent, fixture.candidate.ID)
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
}

func TestCandidateRetirementJoinsAdvanceAndCompensationErrors(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	drainedAt := fixture.drain(t)
	advanceErr := errors.New("advance failed")
	compensationErr := errors.New("compensation failed")
	var calls int
	agent := &retirementTorAgent{
		reconcile: func(candidates []torpool.Candidate) ([]torpool.Profile, error) {
			calls++
			if calls > 1 {
				return nil, compensationErr
			}
			return profilesForTorCandidates(candidates), nil
		},
	}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		advance: func(
			context.Context,
			string,
			int64,
			int64,
			string,
			time.Time,
			time.Duration,
		) (store.CandidateRetirementResult, error) {
			return store.CandidateRetirementResult{}, advanceErr
		},
	}
	err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	)
	if !errors.Is(err, advanceErr) || !errors.Is(err, compensationErr) {
		t.Fatalf("joined error=%v", err)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
}

func TestCandidateRetirementCompensatesPartialInitialReconcileError(t *testing.T) {
	tests := []struct {
		name                 string
		failCompensation     bool
		wantCompensationFail bool
	}{
		{name: "converges latest authoritative set"},
		{
			name:             "joins compensation failure",
			failCompensation: true, wantCompensationFail: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, active, drainedAt := retirementWithQualifiedSentinel(
				t, 10,
			)
			partialErr := errors.New("partial reconcile failure")
			compensationErr := errors.New("restore failure")
			var calls int
			agent := &retirementTorAgent{
				profiles: []torpool.Profile{{
					Role: "warm", CandidateID: fixture.candidate.ID,
				}},
				reconcile: func(candidates []torpool.Candidate) ([]torpool.Profile, error) {
					calls++
					if calls == 1 {
						return profilesForTorCandidates(candidates), partialErr
					}
					if test.failCompensation {
						return nil, compensationErr
					}
					return profilesForTorCandidates(candidates), nil
				},
			}
			collector := CandidateRetirement{
				Store: fixture.database, Tor: agent,
				RetiredRetention: time.Minute,
			}
			err := collector.Run(
				context.Background(), drainedAt.Add(2*time.Second),
			)
			if !errors.Is(err, partialErr) {
				t.Fatalf("initial reconcile error lost: %v", err)
			}
			if test.wantCompensationFail {
				if !errors.Is(err, compensationErr) {
					t.Fatalf("compensation error not joined: %v", err)
				}
			} else {
				requireCachedTorProfile(t, agent, active.ID)
				requireCachedTorProfileAbsent(
					t, agent, fixture.candidate.ID,
				)
			}
			requireCandidateLifecycle(
				t, fixture.database, fixture.candidate.ID,
				store.CandidateLifecycleDraining,
			)
		})
	}
}

func TestCandidateRetirementCompensationRequiresMaterializedProtectedTarget(
	t *testing.T,
) {
	t.Run("empty acknowledgement fails", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		fixture.saveEqualPlan(t, 1, "")
		drainedAt := fixture.drain(t)
		var calls int
		agent := &retirementTorAgent{
			reconcile: func(candidates []torpool.Candidate) ([]torpool.Profile, error) {
				calls++
				if calls == 1 {
					return profilesForTorCandidates(candidates), nil
				}
				return nil, nil
			},
		}
		collector := retirementAdvanceFailureCollector(
			fixture, agent, errors.New("advance failed"),
		)
		collector.beforeFinalize = func(store.Candidate) {
			fixture.assign(t, "late-mandatory-empty", fixture.candidate.ID)
		}
		err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		)
		if err == nil {
			t.Fatal("empty compensation acknowledgement was accepted")
		}
		if !strings.Contains(err.Error(), "mandatory") {
			t.Fatalf("missing mandatory-target compensation error: %v", err)
		}
		requireCandidateLifecycle(
			t, fixture.database, fixture.candidate.ID,
			store.CandidateLifecycleDraining,
		)
	})

	t.Run("forced low score target survives capacity", func(t *testing.T) {
		fixture, active, drainedAt := retirementWithQualifiedSentinel(t, 100)
		var calls int
		agent := &retirementTorAgent{
			reconcile: func(candidates []torpool.Candidate) ([]torpool.Profile, error) {
				calls++
				if calls == 1 {
					return profilesForTorCandidates(candidates), nil
				}
				selected := candidates[0]
				for _, candidate := range candidates {
					if candidate.Assigned {
						selected = candidate
						break
					}
					if candidate.Score > selected.Score {
						selected = candidate
					}
				}
				return profilesForTorCandidates(
					[]torpool.Candidate{selected},
				), nil
			},
		}
		collector := retirementAdvanceFailureCollector(
			fixture, agent, errors.New("advance failed"),
		)
		collector.beforeFinalize = func(store.Candidate) {
			fixture.assign(
				t, "late-mandatory-capacity", fixture.candidate.ID,
			)
		}
		if err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		); err == nil {
			t.Fatal("advance failure was lost")
		}
		requireCachedTorProfile(t, agent, fixture.candidate.ID)
		if candidate := requireLastTorRequestCandidate(
			t, agent, fixture.candidate.ID,
		); !candidate.Assigned {
			t.Fatalf(
				"forced target not protected against %s: %+v",
				active.ID, candidate,
			)
		}
	})
}

func TestCandidateRetirementSemanticFenceCompensatesNonTargetChanges(
	t *testing.T,
) {
	tests := []struct {
		name   string
		change func(*testing.T, *retirementFixture, store.Candidate)
	}{
		{
			name: "assignment protection",
			change: func(t *testing.T, fixture *retirementFixture, active store.Candidate) {
				fixture.assign(t, "late-other", active.ID)
			},
		},
		{
			name: "conservative score",
			change: func(t *testing.T, fixture *retirementFixture, active store.Candidate) {
				if _, err := fixture.database.RecordCandidateProbe(
					context.Background(),
					store.ProbeTransition{
						Fingerprint: active.Fingerprint,
						CandidateID: active.ID,
						SourceID:    active.SourceID,
						Full:        true,
						Success:     true,
						Score:       3,
						At:          time.Now().Add(time.Second),
						ResetWindow: 5 * time.Hour,
					},
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, active, drainedAt := retirementWithQualifiedSentinel(t, 7)
			agent := &retirementTorAgent{}
			collector := CandidateRetirement{
				Store: fixture.database, Tor: agent,
				RetiredRetention: time.Minute,
				beforeFinalize: func(store.Candidate) {
					test.change(t, fixture, active)
				},
			}
			if err := collector.Run(
				context.Background(), drainedAt.Add(2*time.Second),
			); err != nil {
				t.Fatal(err)
			}
			requireCandidateLifecycle(
				t, fixture.database, fixture.candidate.ID,
				store.CandidateLifecycleDraining,
			)
			requireCachedTorProfileAbsent(
				t, agent, fixture.candidate.ID,
			)
			requireCachedTorProfile(t, agent, active.ID)
		})
	}
}

func TestCandidateRetirementDoesNotRematerializeRetiredTargetOnChurn(
	t *testing.T,
) {
	tests := []struct {
		name   string
		change func(*testing.T, *retirementFixture, store.Candidate)
	}{
		{
			name: "inventory",
			change: func(
				t *testing.T,
				fixture *retirementFixture,
				_ store.Candidate,
			) {
				if err := fixture.database.UpdateSource(
					context.Background(),
					fixture.sourceID,
					"inventory churn",
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "score",
			change: func(
				t *testing.T,
				fixture *retirementFixture,
				active store.Candidate,
			) {
				if _, err := fixture.database.RecordCandidateProbe(
					context.Background(),
					store.ProbeTransition{
						Fingerprint: active.Fingerprint,
						CandidateID: active.ID,
						SourceID:    active.SourceID,
						Full:        true,
						Success:     true,
						Score:       2,
						At:          time.Now().Add(time.Second),
						ResetWindow: 5 * time.Hour,
					},
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, active, drainedAt := retirementWithQualifiedSentinel(
				t, 8,
			)
			first := CandidateRetirement{
				Store:            fixture.database,
				Tor:              &retirementTorAgent{},
				RetiredRetention: time.Second,
			}
			now := drainedAt.Add(2 * time.Second)
			if err := first.Run(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			requireCandidateLifecycle(
				t,
				fixture.database,
				fixture.candidate.ID,
				store.CandidateLifecycleRetired,
			)
			agent := &retirementTorAgent{}
			collector := CandidateRetirement{
				Store:            fixture.database,
				Tor:              agent,
				RetiredRetention: time.Second,
				beforeFinalize: func(store.Candidate) {
					test.change(t, fixture, active)
				},
			}
			if err := collector.Run(
				context.Background(), now.Add(2*time.Second),
			); err != nil {
				t.Fatal(err)
			}
			requireCandidateLifecycle(
				t,
				fixture.database,
				fixture.candidate.ID,
				store.CandidateLifecycleRetired,
			)
			requireCachedTorProfileAbsent(
				t, agent, fixture.candidate.ID,
			)
			requireCachedTorProfile(t, agent, active.ID)
		})
	}
}

func TestCandidateRetirementCompensationBoundsInventoryChurn(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	drainedAt := fixture.drain(t)
	var calls int
	agent := &retirementTorAgent{
		reconcile: func(candidates []torpool.Candidate) ([]torpool.Profile, error) {
			calls++
			if calls > 1 {
				if err := fixture.database.UpdateSource(
					context.Background(),
					fixture.sourceID,
					fmt.Sprintf("churn-%d", calls),
					true,
				); err != nil {
					t.Fatal(err)
				}
			}
			return profilesForTorCandidates(candidates), nil
		},
	}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		beforeFinalize: func(store.Candidate) {
			fixture.assign(t, "late-churn", fixture.candidate.ID)
		},
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); !errors.Is(err, store.ErrCandidateInventoryChanged) {
		t.Fatalf("compensation churn err=%v", err)
	}
	if calls != 4 {
		t.Fatalf("Tor calls=%d, want one retirement plus three compensation attempts", calls)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
}

func TestCandidateRetirementUsesAuthoritativeTorPoolSemantics(t *testing.T) {
	t.Run("unqualified active is excluded", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		fixture.saveEqualPlan(t, 1, "")
		active := fixture.candidateByFingerprint(t, "sentinel")
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent,
			RetiredRetention: time.Minute,
		}
		if err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		requireFirstTorRequestExcludes(t, agent, active.ID)
	})

	t.Run("qualified assigned working pool preserves score and protection", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		fixture.saveEqualPlan(t, 1, "")
		active := fixture.candidateByFingerprint(t, "sentinel")
		recordQualifiedTorCandidate(t, fixture.database, active, 7, time.Now())
		if err := fixture.database.ReplaceWorkingPool(
			context.Background(), []string{active.Fingerprint}, nil,
		); err != nil {
			t.Fatal(err)
		}
		fixture.assign(t, "low-score", active.ID)
		state, err := fixture.database.CandidateProbeState(
			context.Background(), active.Fingerprint,
		)
		if err != nil {
			t.Fatal(err)
		}
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent,
			RetiredRetention: time.Minute,
		}
		if err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		got := requireFirstTorRequestCandidate(t, agent, active.ID)
		if got.Score != state.ConservativeScore || !got.Assigned {
			t.Fatalf(
				"authoritative candidate=%+v conservative_score=%v",
				got, state.ConservativeScore,
			)
		}
	})

	t.Run("disabled source referenced candidate remains", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		fixture.saveEqualPlan(t, 1, "")
		disabled := fixture.addDisabledReferencedTor(t)
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent,
			RetiredRetention: time.Minute,
		}
		if err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		got := requireFirstTorRequestCandidate(t, agent, disabled.ID)
		if !got.Assigned {
			t.Fatalf("disabled referenced candidate lost assignment: %+v", got)
		}
	})

	t.Run("referenced draining candidate remains", func(t *testing.T) {
		fixture := newRetirementFixture(t, sources.KindTorBridge)
		continuity := fixture.addContinuityTor(t)
		fixture.saveEqualPlan(t, 1, "")
		fixture.assign(t, "draining-client", continuity.ID)
		drainedAt := fixture.drain(t)
		agent := &retirementTorAgent{}
		collector := CandidateRetirement{
			Store: fixture.database, Tor: agent,
			RetiredRetention: time.Minute,
		}
		if err := collector.Run(
			context.Background(), drainedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		got := requireFirstTorRequestCandidate(t, agent, continuity.ID)
		if !got.Draining || !got.Assigned {
			t.Fatalf("draining continuity candidate=%+v", got)
		}
	})
}

func TestCandidateRetirementTorReconcileErrorFailsSafe(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	drainedAt := fixture.drain(t)
	agent := &retirementTorAgent{
		reconcile: func([]torpool.Candidate) ([]torpool.Profile, error) {
			return nil, errors.New("agent unavailable")
		},
	}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err == nil {
		t.Fatal("collector ignored Tor reconciliation error")
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
}

func TestCandidateRetirementCollectsDeterministicallyAndCleansDependentState(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindVLESS)
	ctx := context.Background()
	rows, err := fixture.database.ListCandidates(ctx, "")
	if err != nil || len(rows) != 2 {
		t.Fatalf("candidates=%+v err=%v", rows, err)
	}
	for _, candidate := range rows {
		if err := fixture.database.SaveCandidateHealth(ctx, store.CandidateHealth{
			CandidateID: candidate.ID, Available: true, UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	drainedAt := fixture.drainAll(t)
	var order []string
	collector := CandidateRetirement{
		Store: fixture.database, RetiredRetention: time.Second,
		beforeFinalize: func(candidate store.Candidate) {
			order = append(order, candidate.ID)
		},
	}
	if err := collector.Run(ctx, drainedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(order) {
		t.Fatalf("collector order=%v", order)
	}
	if err := collector.Run(ctx, drainedAt.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range rows {
		if _, err := fixture.database.CandidateForRetirement(ctx, candidate.ID); !errors.Is(err, store.ErrCandidateNotFound) {
			t.Fatalf("candidate %s remains: %v", candidate.ID, err)
		}
	}
	if health, err := fixture.database.ListCandidateHealth(ctx); err != nil || len(health) != 0 {
		t.Fatalf("orphan health=%+v err=%v", health, err)
	}
}

func TestCandidateRetirementBoundsBatchAndReconcilesTorOnce(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	ctx := context.Background()
	inputs := make([]store.CandidateInput, 0, 71)
	inputs = append(inputs, store.CandidateInput{
		Kind: sources.KindTorBridge, Label: "keeper", Fingerprint: "keeper",
		Payload: fixture.payload + "-keeper",
	})
	for index := 0; index < 70; index++ {
		inputs = append(inputs, store.CandidateInput{
			Kind:        sources.KindTorBridge,
			Label:       fmt.Sprintf("due-%03d", index),
			Fingerprint: fmt.Sprintf("due-%03d", index),
			Payload:     fixture.payload + fmt.Sprintf("-%03d", index),
		})
	}
	if err := fixture.database.ReplaceCandidates(
		ctx, fixture.sourceID, inputs, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := fixture.database.ListCandidates(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	dueIDs := make([]string, 0, 70)
	for _, candidate := range rows {
		if candidate.Fingerprint != "keeper" {
			dueIDs = append(dueIDs, candidate.ID)
		}
	}
	if err := fixture.database.ReplaceCandidates(
		ctx, fixture.sourceID, inputs[:1], time.Second,
	); err != nil {
		t.Fatal(err)
	}
	fixture.saveEqualPlan(t, 1, "")
	due, err := fixture.database.CandidateForRetirement(ctx, dueIDs[0])
	if err != nil || due.DrainAfter == nil {
		t.Fatalf("due=%+v err=%v", due, err)
	}
	now := time.Unix(*due.DrainAfter, 0).Add(time.Second)
	agent := &retirementTorAgent{}
	collector := &CandidateRetirement{
		Store: fixture.database, Tor: agent,
		RetiredRetention: time.Minute,
	}
	retired := 0
	for pass := 0; pass < 3; pass++ {
		beforeCalls := len(agent.snapshotCalls())
		if err := collector.Run(ctx, now); err != nil {
			t.Fatal(err)
		}
		afterCalls := len(agent.snapshotCalls())
		if afterCalls-beforeCalls > 1 {
			t.Fatalf(
				"pass %d Tor calls=%d, want at most one batch RPC",
				pass, afterCalls-beforeCalls,
			)
		}
		afterRetired := 0
		for _, candidateID := range dueIDs {
			candidate, err := fixture.database.CandidateForRetirement(
				ctx, candidateID,
			)
			if err == nil &&
				candidate.Lifecycle == store.CandidateLifecycleRetired {
				afterRetired++
			}
		}
		if afterRetired-retired > 32 {
			t.Fatalf(
				"pass %d collected %d candidates, batch exceeds 32",
				pass, afterRetired-retired,
			)
		}
		retired = afterRetired
	}
	if retired != len(dueIDs) {
		t.Fatalf("retired=%d want=%d; cursor starved candidates", retired, len(dueIDs))
	}
}

func TestCandidateRetirementBlocksInvalidPersistedPlans(t *testing.T) {
	tests := []struct {
		name string
		plan []byte
	}{
		{name: "null", plan: []byte(`null`)},
		{name: "empty object", plan: []byte(`{}`)},
		{
			name: "null arrays",
			plan: []byte(
				`{"generation":1,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true}`,
			),
		},
		{
			name: "generation mismatch",
			plan: []byte(
				`{"generation":2,"outbounds":[],"clients":[],"direct_suffixes":[".ru"],"fail_closed":true}`,
			),
		},
		{
			name: "missing arrays",
			plan: []byte(
				`{"generation":1,"direct_suffixes":[".ru"],"fail_closed":true}`,
			),
		},
		{
			name: "unknown field",
			plan: []byte(
				`{"generation":1,"outbounds":[],"clients":[],"direct_suffixes":[".ru"],"fail_closed":true,"unknown":true}`,
			),
		},
		{name: "malformed", plan: []byte(`{"generation":1`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetirementFixture(t, sources.KindVLESS)
			fixture.saveEqualRawPlan(t, 1, test.plan)
			drainedAt := fixture.drain(t)
			collector := CandidateRetirement{
				Store: fixture.database, RetiredRetention: time.Minute,
			}
			_ = collector.Run(
				context.Background(), drainedAt.Add(2*time.Second),
			)
			requireCandidateLifecycle(
				t, fixture.database, fixture.candidate.ID,
				store.CandidateLifecycleDraining,
			)
		})
	}
}

func TestCandidateRetirementMigratesLegacyNullArraysAndEngineConverges(
	t *testing.T,
) {
	fixture := newRetirementFixture(t, sources.KindVLESS)
	legacy := []byte(
		`{"generation":1,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true}`,
	)
	fixture.saveEqualRawPlan(t, 1, legacy)
	fixture.reopen(t)
	state, err := fixture.database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for kind, encoded := range map[string][]byte{
		"desired": state.DesiredPlan,
		"applied": state.AppliedPlan,
	} {
		if !bytes.Contains(encoded, []byte(`"outbounds":[]`)) ||
			!bytes.Contains(encoded, []byte(`"clients":[]`)) {
			t.Fatalf("%s plan not canonical: %s", kind, encoded)
		}
	}
	agent := &engineAgent{}
	engine := NewEngine(
		fixture.database,
		agent,
		nil,
		scheduler.New(scheduler.PolicyDefaults()),
		[]byte("secret"),
	)
	if err := engine.Cycle(
		context.Background(), time.Unix(1_800_000_000, 0),
	); err != nil {
		t.Fatal(err)
	}
	if len(agent.plans) != 0 {
		t.Fatalf("canonical semantic no-op was republished: %+v", agent.plans)
	}
	drainedAt := fixture.drain(t)
	collector := CandidateRetirement{
		Store: fixture.database, RetiredRetention: time.Minute,
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleRetired,
	)
}

func TestCandidateRetirementMigrationLeavesInvalidPlanBlockingWithoutSecret(
	t *testing.T,
) {
	fixture := newRetirementFixture(t, sources.KindVLESS)
	invalid := []byte(
		`{"generation":1,"outbounds":null,"clients":null,"direct_suffixes":[".ru"],"fail_closed":true,"unknown":"sensitive-marker"}`,
	)
	fixture.saveEqualRawPlan(t, 1, invalid)
	fixture.reopen(t)
	state, err := fixture.database.LoadPlanState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.DesiredPlan, invalid) ||
		!bytes.Equal(state.AppliedPlan, invalid) {
		t.Fatalf("invalid plan was rewritten: %+v", state)
	}
	drainedAt := fixture.drain(t)
	collector := CandidateRetirement{
		Store: fixture.database, RetiredRetention: time.Minute,
	}
	err = collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	)
	if err == nil {
		t.Fatal("invalid migrated plan did not block retirement")
	}
	if strings.Contains(err.Error(), "sensitive-marker") {
		t.Fatalf("retirement error leaked plan contents: %v", err)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
}

func TestCandidateRetirementValidatesAllPersistedCandidateReferences(t *testing.T) {
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	outboundID := fixture.candidate.ID + "-profile-0"
	plan := dataplane.DesiredPlan{
		Generation: 1,
		Outbounds: []dataplane.Outbound{{
			ID: outboundID, Protocol: dataplane.ProtocolTor,
		}},
		Clients: []dataplane.ClientRoute{{
			ClientID: "client", TCPOutbound: outboundID, BlockUDP: true,
		}},
		DirectSuffixes: []string{".ru"},
		FailClosed:     true,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture.saveEqualRawPlan(t, 1, encoded)
	drainedAt := fixture.drain(t)
	agent := &retirementTorAgent{}
	collector := CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
	}
	if err := collector.Run(
		context.Background(), drainedAt.Add(2*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	requireCandidateLifecycle(
		t, fixture.database, fixture.candidate.ID,
		store.CandidateLifecycleDraining,
	)
	if calls := agent.snapshotCalls(); len(calls) != 0 {
		t.Fatalf("referenced candidate reached Tor reconcile: %+v", calls)
	}
}

type retirementFixture struct {
	path      string
	box       *secretbox.Box
	database  *store.Store
	sourceID  string
	candidate store.Candidate
	payload   string
	kind      sources.Kind
}

func newRetirementFixture(t *testing.T, kind sources.Kind) *retirementFixture {
	t.Helper()
	box, err := secretbox.New(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &retirementFixture{
		path: filepath.Join(t.TempDir(), "state.db"), box: box,
		payload: "vless://retire@example.net:443", kind: kind,
	}
	t.Cleanup(func() {
		if fixture.database != nil {
			_ = fixture.database.Close()
		}
	})
	if kind == sources.KindTorBridge {
		fixture.payload = "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567"
	}
	fixture.open(t)
	preview := sources.PreviewInput("https://retirement.example/subscription")
	if _, err := fixture.database.ImportSources(context.Background(), preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.database.ListSources(context.Background())
	if err != nil || len(listed) != 1 {
		t.Fatalf("sources=%+v err=%v", listed, err)
	}
	fixture.sourceID = listed[0].ID
	fixture.replace(t, true)
	return fixture
}

func (fixture *retirementFixture) open(t *testing.T) {
	t.Helper()
	database, err := store.Open(fixture.path, fixture.box)
	if err != nil {
		t.Fatal(err)
	}
	fixture.database = database
}

func (fixture *retirementFixture) reopen(t *testing.T) {
	t.Helper()
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.open(t)
}

func (fixture *retirementFixture) replace(t *testing.T, includeCandidate bool) {
	t.Helper()
	inputs := []store.CandidateInput{{
		Kind: fixture.kind, Label: "sentinel", Fingerprint: "sentinel",
		Payload: fixture.payload + "-sentinel",
	}}
	if includeCandidate {
		inputs = append(inputs, store.CandidateInput{
			Kind: fixture.kind, Label: "retire", Fingerprint: "retire",
			Payload: fixture.payload,
		})
	}
	if err := fixture.database.ReplaceCandidates(
		context.Background(), fixture.sourceID, inputs, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	if includeCandidate {
		rows, err := fixture.database.ListCandidates(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range rows {
			if candidate.Fingerprint == "retire" {
				fixture.candidate = candidate
				return
			}
		}
		t.Fatal("retirement candidate not found")
	}
}

func (fixture *retirementFixture) drain(t *testing.T) time.Time {
	t.Helper()
	fixture.replace(t, false)
	row, err := fixture.database.CandidateForRetirement(
		context.Background(), fixture.candidate.ID,
	)
	if err != nil || row.DrainAfter == nil {
		t.Fatalf("draining row=%+v err=%v", row, err)
	}
	return time.Unix(*row.DrainAfter, 0)
}

func (fixture *retirementFixture) drainAll(t *testing.T) time.Time {
	t.Helper()
	// Empty refreshes are deliberately refused, so disable the source after
	// setting both rows to draining through a temporary replacement.
	fixture.replace(t, false)
	sentinel, err := fixture.database.ListCandidates(context.Background(), "")
	if err != nil || len(sentinel) != 1 {
		t.Fatalf("sentinel=%+v err=%v", sentinel, err)
	}
	if err := fixture.database.ReplaceCandidates(
		context.Background(), fixture.sourceID, []store.CandidateInput{{
			Kind: fixture.kind, Label: "temporary", Fingerprint: "temporary",
			Payload: fixture.payload + "-temporary",
		}}, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.UpdateSource(
		context.Background(), fixture.sourceID, "retirement", false,
	); err != nil {
		t.Fatal(err)
	}
	row, err := fixture.database.CandidateForRetirement(
		context.Background(), fixture.candidate.ID,
	)
	if err != nil || row.DrainAfter == nil {
		t.Fatalf("draining row=%+v err=%v", row, err)
	}
	return time.Unix(*row.DrainAfter, 0)
}

func (fixture *retirementFixture) saveEqualPlan(t *testing.T, generation int64, candidateID string) {
	t.Helper()
	plan := retirementPlan(t, generation, candidateID)
	fixture.saveEqualRawPlan(t, generation, plan)
}

func (fixture *retirementFixture) saveEqualRawPlan(
	t *testing.T,
	generation int64,
	plan []byte,
) {
	t.Helper()
	if err := fixture.database.SaveDesiredPlan(context.Background(), generation, plan); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.MarkAppliedPlan(context.Background(), generation, plan); err != nil {
		t.Fatal(err)
	}
}

func (fixture *retirementFixture) candidateByFingerprint(
	t *testing.T,
	fingerprint string,
) store.Candidate {
	t.Helper()
	rows, err := fixture.database.ListCandidates(
		context.Background(), fixture.sourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range rows {
		if candidate.Fingerprint == fingerprint {
			return candidate
		}
	}
	t.Fatalf("candidate fingerprint %q not found", fingerprint)
	return store.Candidate{}
}

func (fixture *retirementFixture) assign(
	t *testing.T,
	clientID, candidateID string,
) {
	t.Helper()
	ctx := context.Background()
	address := fmt.Sprintf("10.44.1.%d/32", len(clientID)+2)
	if err := fixture.database.PutClient(ctx, store.ClientRecord{
		ID: clientID, Name: clientID, Address: address, PublicKey: clientID,
	}, "config"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.SetAssignment(ctx, store.AssignmentRecord{
		ClientID: clientID, TCPOutbound: candidateID,
		TCPSince: time.Now(), UDPSince: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *retirementFixture) addDisabledReferencedTor(
	t *testing.T,
) store.Candidate {
	t.Helper()
	ctx := context.Background()
	preview := sources.PreviewInput("https://disabled.example/subscription")
	if _, err := fixture.database.ImportSources(ctx, preview.Items); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.database.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sourceID string
	for _, source := range listed {
		if source.ID != fixture.sourceID {
			sourceID = source.ID
			break
		}
	}
	if sourceID == "" {
		t.Fatal("disabled source not found")
	}
	if err := fixture.database.ReplaceCandidates(ctx, sourceID, []store.CandidateInput{{
		Kind: sources.KindTorBridge, Label: "disabled",
		Fingerprint: "disabled", Payload: fixture.payload + "-disabled",
	}}, time.Second); err != nil {
		t.Fatal(err)
	}
	rows, err := fixture.database.ListCandidates(ctx, sourceID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("disabled candidates=%+v err=%v", rows, err)
	}
	candidate := rows[0]
	fixture.assign(t, "disabled-client", candidate.ID)
	if err := fixture.database.UpdateSource(
		ctx, sourceID, "disabled", false,
	); err != nil {
		t.Fatal(err)
	}
	return candidate
}

func (fixture *retirementFixture) addContinuityTor(
	t *testing.T,
) store.Candidate {
	t.Helper()
	ctx := context.Background()
	inputs := []store.CandidateInput{
		{
			Kind: fixture.kind, Label: "sentinel", Fingerprint: "sentinel",
			Payload: fixture.payload + "-sentinel",
		},
		{
			Kind: fixture.kind, Label: "retire", Fingerprint: "retire",
			Payload: fixture.payload,
		},
		{
			Kind: fixture.kind, Label: "continuity",
			Fingerprint: "continuity",
			Payload:     fixture.payload + "-continuity",
		},
	}
	if err := fixture.database.ReplaceCandidates(
		ctx, fixture.sourceID, inputs, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := fixture.database.ListCandidates(ctx, fixture.sourceID)
	if err != nil {
		t.Fatal(err)
	}
	var continuity store.Candidate
	for _, candidate := range rows {
		switch candidate.Fingerprint {
		case "retire":
			fixture.candidate = candidate
		case "continuity":
			continuity = candidate
		}
	}
	if continuity.ID == "" || fixture.candidate.ID == "" {
		t.Fatalf(
			"continuity=%+v retirement=%+v",
			continuity, fixture.candidate,
		)
	}
	return continuity
}

func retirementPlan(t *testing.T, generation int64, candidateIDs ...string) []byte {
	t.Helper()
	plan := dataplane.DesiredPlan{
		Generation: generation, FailClosed: true,
		Outbounds:      []dataplane.Outbound{},
		Clients:        []dataplane.ClientRoute{},
		DirectSuffixes: []string{".ru"},
	}
	for _, candidateID := range candidateIDs {
		if candidateID != "" {
			plan.Outbounds = append(plan.Outbounds, dataplane.Outbound{
				ID: candidateID, Protocol: dataplane.ProtocolVLESS,
			})
		}
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func retirementWithQualifiedSentinel(
	t *testing.T,
	score float64,
) (*retirementFixture, store.Candidate, time.Time) {
	t.Helper()
	fixture := newRetirementFixture(t, sources.KindTorBridge)
	fixture.saveEqualPlan(t, 1, "")
	active := fixture.candidateByFingerprint(t, "sentinel")
	recordQualifiedTorCandidate(
		t, fixture.database, active, score, time.Now(),
	)
	if err := fixture.database.ReplaceWorkingPool(
		context.Background(), []string{active.Fingerprint}, nil,
	); err != nil {
		t.Fatal(err)
	}
	return fixture, active, fixture.drain(t)
}

func retirementAdvanceFailureCollector(
	fixture *retirementFixture,
	agent *retirementTorAgent,
	injected error,
) CandidateRetirement {
	return CandidateRetirement{
		Store: fixture.database, Tor: agent, RetiredRetention: time.Minute,
		advance: func(
			context.Context,
			string,
			int64,
			int64,
			string,
			time.Time,
			time.Duration,
		) (store.CandidateRetirementResult, error) {
			return store.CandidateRetirementResult{}, injected
		},
	}
}

func requireCandidateLifecycle(
	t *testing.T,
	database *store.Store,
	candidateID string,
	want string,
) {
	t.Helper()
	candidate, err := database.CandidateForRetirement(
		context.Background(), candidateID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Lifecycle != want {
		t.Fatalf("candidate lifecycle=%q, want %q", candidate.Lifecycle, want)
	}
}

type retirementTorAgent struct {
	mu        sync.Mutex
	profiles  []torpool.Profile
	calls     [][]torpool.Candidate
	reconcile func([]torpool.Candidate) ([]torpool.Profile, error)
}

func (agent *retirementTorAgent) ReconcileProfiles(
	_ context.Context,
	candidates []torpool.Candidate,
) ([]torpool.Profile, error) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	copied := append([]torpool.Candidate(nil), candidates...)
	agent.calls = append(agent.calls, copied)
	if agent.reconcile != nil {
		profiles, err := agent.reconcile(copied)
		agent.profiles = append([]torpool.Profile(nil), profiles...)
		return profiles, err
	}
	agent.profiles = profilesForTorCandidates(copied)
	return append([]torpool.Profile(nil), agent.profiles...), nil
}

func (agent *retirementTorAgent) Profiles() []torpool.Profile {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return append([]torpool.Profile(nil), agent.profiles...)
}

func (agent *retirementTorAgent) snapshotCalls() [][]torpool.Candidate {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	result := make([][]torpool.Candidate, len(agent.calls))
	for index := range agent.calls {
		result[index] = append([]torpool.Candidate(nil), agent.calls[index]...)
	}
	return result
}

func requireLastTorRequestContains(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) {
	t.Helper()
	calls := agent.snapshotCalls()
	if len(calls) < 2 {
		t.Fatalf("Tor calls=%+v, want retirement and compensation", calls)
	}
	for _, candidate := range calls[len(calls)-1] {
		if candidate.ID == candidateID {
			return
		}
	}
	t.Fatalf("last Tor request=%+v, missing %s", calls[len(calls)-1], candidateID)
}

func requireLastTorRequestCandidate(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) torpool.Candidate {
	t.Helper()
	calls := agent.snapshotCalls()
	if len(calls) < 2 {
		t.Fatalf("Tor calls=%+v, want retirement and compensation", calls)
	}
	for _, candidate := range calls[len(calls)-1] {
		if candidate.ID == candidateID {
			return candidate
		}
	}
	t.Fatalf("last Tor request=%+v, missing %s", calls[len(calls)-1], candidateID)
	return torpool.Candidate{}
}

func requireLastTorRequestExcludes(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) {
	t.Helper()
	calls := agent.snapshotCalls()
	if len(calls) < 2 {
		t.Fatalf("Tor calls=%+v, want retirement and compensation", calls)
	}
	for _, candidate := range calls[len(calls)-1] {
		if candidate.ID == candidateID {
			t.Fatalf(
				"last Tor request=%+v unexpectedly contains %s",
				calls[len(calls)-1], candidateID,
			)
		}
	}
}

func requireCachedTorProfile(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) {
	t.Helper()
	for _, profile := range agent.Profiles() {
		if profile.CandidateID == candidateID {
			return
		}
	}
	t.Fatalf("cached Tor profiles=%+v, missing %s", agent.Profiles(), candidateID)
}

func requireCachedTorProfileAbsent(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) {
	t.Helper()
	for _, profile := range agent.Profiles() {
		if profile.CandidateID == candidateID {
			t.Fatalf(
				"cached Tor profiles=%+v unexpectedly contain %s",
				agent.Profiles(), candidateID,
			)
		}
	}
}

func profilesForTorCandidates(
	candidates []torpool.Candidate,
) []torpool.Profile {
	result := make([]torpool.Profile, 0, len(candidates))
	for index, candidate := range candidates {
		result = append(result, torpool.Profile{
			Slot: index, Role: "warm", CandidateID: candidate.ID,
			SocksAddr: fmt.Sprintf("127.0.0.1:%d", 19050+index),
		})
	}
	return result
}

func requireFirstTorRequestExcludes(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) {
	t.Helper()
	calls := agent.snapshotCalls()
	if len(calls) == 0 {
		t.Fatal("Tor was not called")
	}
	for _, candidate := range calls[0] {
		if candidate.ID == candidateID {
			t.Fatalf("first Tor request unexpectedly contains %+v", candidate)
		}
	}
}

func requireFirstTorRequestCandidate(
	t *testing.T,
	agent *retirementTorAgent,
	candidateID string,
) torpool.Candidate {
	t.Helper()
	calls := agent.snapshotCalls()
	if len(calls) == 0 {
		t.Fatal("Tor was not called")
	}
	for _, candidate := range calls[0] {
		if candidate.ID == candidateID {
			return candidate
		}
	}
	t.Fatalf("first Tor request=%+v, missing %s", calls[0], candidateID)
	return torpool.Candidate{}
}
