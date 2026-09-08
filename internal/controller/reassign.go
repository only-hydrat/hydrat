package controller

import (
	"context"
	"errors"
	"time"

	"github.com/only-hydrat/hydrat/internal/scheduler"
	"github.com/only-hydrat/hydrat/internal/store"
)

type ManualReassigner struct {
	Store     *store.Store
	Scheduler *scheduler.Scheduler
	Trigger   chan<- struct{}
	Now       func() time.Time
}

func (reassigner ManualReassigner) Reassign(ctx context.Context, clientID string) error {
	if reassigner.Store == nil || reassigner.Scheduler == nil {
		return errors.New("reassignment service is unavailable")
	}
	now := time.Now()
	if reassigner.Now != nil {
		now = reassigner.Now()
	}
	until := now.Add(30 * time.Minute)
	assignments, err := reassigner.Store.ListAssignments(ctx)
	if err != nil {
		return err
	}
	found := false
	seen := make(map[string]bool)
	for _, assignment := range assignments {
		if assignment.ClientID != clientID {
			continue
		}
		found = true
		for _, candidateID := range []string{assignment.TCPOutbound, assignment.UDPOutbound} {
			if candidateID == "" || seen[candidateID] {
				continue
			}
			seen[candidateID] = true
			reassigner.Scheduler.Exclude(clientID, candidateID, until)
			if err := reassigner.Store.SetExclusion(ctx, clientID, candidateID, "manual_reassign", until); err != nil {
				return err
			}
		}
	}
	if !found {
		return errors.New("client has no current assignment")
	}
	if reassigner.Trigger != nil {
		select {
		case reassigner.Trigger <- struct{}{}:
		default:
		}
	}
	return nil
}
