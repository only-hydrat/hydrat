package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/only-hydrat/hydrat/internal/store"
)

type DiagnosticRetention struct {
	Store     *store.Store
	Retention time.Duration
	BatchSize int
}

func (retention DiagnosticRetention) Run(
	ctx context.Context,
	now time.Time,
) error {
	if retention.Store == nil {
		return errors.New("diagnostic retention store is required")
	}
	if retention.Retention <= 0 {
		return errors.New("diagnostic retention duration must be positive")
	}
	if retention.BatchSize <= 0 {
		return errors.New("diagnostic retention batch size must be positive")
	}
	if now.IsZero() {
		return errors.New("diagnostic retention time is required")
	}
	cutoff := now.Add(-retention.Retention)
	for {
		result, err := retention.Store.PruneDiagnostics(
			ctx, cutoff, retention.BatchSize,
		)
		if err != nil {
			return fmt.Errorf("prune diagnostics: %w", err)
		}
		if result.Events < retention.BatchSize &&
			result.ProbeSamples < retention.BatchSize {
			return nil
		}
	}
}
