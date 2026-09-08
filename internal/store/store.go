package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	box *secretbox.Box
}

const (
	minActiveObservedAtMilliseconds = int64(100_000_000_000)
	maxActiveObservedAtMilliseconds = int64(9_999_999_999_999)
)

type Source struct {
	ID               string       `json:"id"`
	Kind             sources.Kind `json:"kind"`
	Label            string       `json:"label"`
	Fingerprint      string       `json:"fingerprint"`
	Enabled          bool         `json:"enabled"`
	PendingDelete    bool         `json:"pending_delete"`
	CreatedAt        int64        `json:"created_at"`
	UpdatedAt        int64        `json:"updated_at"`
	LastRefreshAt    *int64       `json:"last_refresh_at,omitempty"`
	LastRefreshError string       `json:"last_refresh_error,omitempty"`
	CandidateCount   int          `json:"candidate_count"`
}

type CandidateInput struct {
	Kind          sources.Kind
	Label         string
	Fingerprint   string
	Payload       string
	RouteKey      string
	FailureDomain string
}

const (
	CandidateLifecycleActive   = "active"
	CandidateLifecycleDraining = "draining"
	CandidateLifecycleRetired  = "retired"
)

type Candidate struct {
	ID             string       `json:"id"`
	SourceID       string       `json:"source_id"`
	Kind           sources.Kind `json:"kind"`
	Label          string       `json:"label"`
	Fingerprint    string       `json:"fingerprint"`
	RouteKey       string       `json:"route_key"`
	FailureDomain  string       `json:"failure_domain"`
	Enabled        bool         `json:"enabled"`
	SourcePosition int          `json:"-"`
	Lifecycle      string       `json:"lifecycle"`
	RetiredAt      *int64       `json:"retired_at,omitempty"`
	DrainAfter     *int64       `json:"drain_after,omitempty"`
	CreatedAt      int64        `json:"created_at"`
	UpdatedAt      int64        `json:"updated_at"`
}

type CandidatePayloadSnapshot struct {
	Candidate Candidate
	Payload   string
}

// Candidate columns deliberately do not use foreign keys. Candidate retirement
// is fenced by loadCandidateRetirementReferencesTx so desired/applied mappings
// survive draining and are removed by the same generation-aware lifecycle as
// plan references; the client foreign key still provides ownership cleanup.
const routeReserveTableDDL = `
	CREATE TABLE route_reserve_mappings (
	  stage TEXT NOT NULL CHECK(stage IN ('desired', 'applied')),
	  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
	  generation INTEGER NOT NULL CHECK(generation > 0),
	  tcp_primary_candidate_id TEXT NOT NULL DEFAULT '',
	  tcp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
	  udp_primary_candidate_id TEXT NOT NULL DEFAULT '',
	  udp_reserve_candidate_id TEXT NOT NULL DEFAULT '',
	  PRIMARY KEY(stage, client_id)
	)
`

type ImportResult struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
}

func Open(path string, box *secretbox.Box) (*Store, error) {
	if box == nil {
		return nil, fmt.Errorf("secret box is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteConnectionDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, box: box}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteConnectionDSN(path string) string {
	uri := &url.URL{Scheme: "file", Path: path}
	query := uri.Query()
	query.Add("_pragma", "foreign_keys=on")
	query.Add("_pragma", "busy_timeout=5000")
	uri.RawQuery = query.Encode()
	return uri.String()
}


func (store *Store) Close() error { return store.db.Close() }
