package freesubs

import (
	"context"
	"fmt"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

// Store is the subset of the persistent store used by the service.
type Store interface {
	ImportSources(ctx context.Context, items []sources.PreviewItem) (store.ImportResult, error)
}

// Result is the outcome of one sync pass, suitable for the panel response.
type Result struct {
	Report   Report `json:"report"`
	Imported int    `json:"imported"`
	Restored int    `json:"restored"`
	Skipped  int    `json:"skipped"`
}

// Total reports how many feeds were added or restored by the pass.
func (result Result) Total() int { return result.Imported + result.Restored }

// Service discovers free feeds and imports the usable ones as sources.
type Service struct {
	Discovery *Discovery
	Store     Store
	// Changed is signalled (non-blocking) after new sources were imported so the
	// controller refreshes and qualifies them right away.
	Changed chan<- struct{}
}

// Sync runs one discovery pass and imports every feed that passed the check.
func (service *Service) Sync(ctx context.Context) (Result, error) {
	if service.Discovery == nil {
		return Result{}, fmt.Errorf("free sources discovery is not configured")
	}
	report := service.Discovery.Run(ctx)
	result := Result{Report: report}
	items := Items(report)
	if len(items) == 0 {
		return result, nil
	}
	if service.Store == nil {
		return result, fmt.Errorf("free sources store is not configured")
	}
	imported, err := service.Store.ImportSources(ctx, items)
	if err != nil {
		return result, fmt.Errorf("import free sources: %w", err)
	}
	result.Imported = imported.Imported
	result.Restored = imported.Restored
	result.Skipped = imported.Skipped
	if service.Changed != nil && result.Total() > 0 {
		select {
		case service.Changed <- struct{}{}:
		default:
		}
	}
	return result, nil
}
