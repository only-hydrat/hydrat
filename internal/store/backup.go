package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/secretbox"
	"github.com/only-hydrat/hydrat/internal/sources"
)

func (store *Store) Backup(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("backup destination is required")
	}
	if _, err := os.Stat(destination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if _, err := store.db.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return err
	}
	return nil
}

func ValidateBackup(path string, box *secretbox.Box) error {
	if box == nil {
		return errors.New("secret box is required")
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		if err == nil {
			err = fmt.Errorf("SQLite quick_check returned %q", integrity)
		}
		return err
	}
	foreignKeyRows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("validate backup foreign keys: %w", err)
	}
	if foreignKeyRows.Next() {
		var table, parent string
		var rowID, foreignKeyID int64
		if err := foreignKeyRows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
			_ = foreignKeyRows.Close()
			return fmt.Errorf("validate backup foreign keys: %w", err)
		}
		_ = foreignKeyRows.Close()
		return fmt.Errorf(
			"backup foreign key violation in %s row %d referencing %s constraint %d",
			table, rowID, parent, foreignKeyID,
		)
	}
	if err := foreignKeyRows.Err(); err != nil {
		_ = foreignKeyRows.Close()
		return fmt.Errorf("validate backup foreign keys: %w", err)
	}
	if err := foreignKeyRows.Close(); err != nil {
		return fmt.Errorf("validate backup foreign keys: %w", err)
	}
	for _, table := range []string{
		"sources", "candidates", "clients", "candidate_health", "plan_state",
		"candidate_qoe_state", "candidate_qoe_samples",
	} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("backup is missing required table %s", table)
		}
	}
	var hasRouteReserveMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=11
	`).Scan(&hasRouteReserveMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasRouteReserveMigration != 0 {
		if err := validatePlanAssignmentSnapshotSchema(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup route reserves: %w", err)
		}
		if err := validateRouteReserveTable(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup route reserves: %w", err)
		}
		if err := validateRouteReserveIndex(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup route reserves: %w", err)
		}
		if err := validateV11PlanStateConsistency(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup route reserves: %w", err)
		}
	}
	var hasActiveEvidenceMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=12
	`).Scan(&hasActiveEvidenceMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasActiveEvidenceMigration != 0 {
		if err := validateCandidateActiveEvidenceSchema(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup active evidence: %w", err)
		}
	}
	var hasActiveHardFailureMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=13
	`).Scan(&hasActiveHardFailureMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasActiveHardFailureMigration != 0 {
		if err := validateCandidateActiveHardFailureSchema(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup active hard failure: %w", err)
		}
	}
	var hasDesiredReasonMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=14
	`).Scan(&hasDesiredReasonMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasDesiredReasonMigration != 0 {
		if err := validateDesiredPlanReasonSchema(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup desired plan reason: %w", err)
		}
	}
	var hasActiveObservedMillisecondsMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=15
	`).Scan(&hasActiveObservedMillisecondsMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasActiveObservedMillisecondsMigration != 0 {
		if err := validateCandidateActiveObservedAtMilliseconds(
			context.Background(), db,
		); err != nil {
			return fmt.Errorf("validate backup active observation precision: %w", err)
		}
	}
	var hasCandidateProbeLookupIndexMigration int
	if err := db.QueryRow(`
		SELECT count(*) FROM schema_migrations WHERE version=16
	`).Scan(&hasCandidateProbeLookupIndexMigration); err != nil {
		return fmt.Errorf("validate backup migrations: %w", err)
	}
	if hasCandidateProbeLookupIndexMigration != 0 {
		if err := validateCandidateProbeLookupIndex(context.Background(), db); err != nil {
			return fmt.Errorf("validate backup candidate probe lookup: %w", err)
		}
	}
	checks := []struct {
		query  string
		prefix string
	}{
		{query: `SELECT id, encrypted_payload FROM sources LIMIT 1`},
		{query: `SELECT id, encrypted_payload FROM candidates LIMIT 1`},
		{query: `SELECT id, encrypted_config FROM clients LIMIT 1`, prefix: "client:"},
	}
	for _, check := range checks {
		var id string
		var encrypted []byte
		err := db.QueryRow(check.query).Scan(&id, &encrypted)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := box.Open(check.prefix+id, encrypted); err != nil {
			return fmt.Errorf("backup cannot be decrypted with the configured master key: %w", err)
		}
	}
	return nil
}

func validateCandidateActiveEvidenceSchema(
	ctx context.Context,
	querier schemaQuerier,
) error {
	type expectedColumn struct {
		typeName     string
		notNull      int
		defaultValue string
	}
	expected := map[string]expectedColumn{
		"active_observed_at":        {typeName: "INTEGER"},
		"active_success":            {typeName: "INTEGER", notNull: 1, defaultValue: "0"},
		"active_failure_generation": {typeName: "INTEGER", notNull: 1, defaultValue: "0"},
	}
	rows, err := querier.QueryContext(ctx, `PRAGMA table_info(candidate_health)`)
	if err != nil {
		return fmt.Errorf("inspect candidate active evidence schema: %w", err)
	}
	defer rows.Close()
	found := make(map[string]bool, len(expected))
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, typeName string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan candidate active evidence schema: %w", err)
		}
		want, relevant := expected[name]
		if !relevant {
			continue
		}
		defaultMatches := want.defaultValue == "" && !defaultValue.Valid ||
			defaultValue.Valid && defaultValue.String == want.defaultValue
		if !strings.EqualFold(typeName, want.typeName) || notNull != want.notNull || !defaultMatches {
			return fmt.Errorf("candidate_health.%s has incompatible schema", name)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect candidate active evidence schema: %w", err)
	}
	for name := range expected {
		if !found[name] {
			return fmt.Errorf("candidate_health.%s is missing", name)
		}
	}
	return nil
}

func validateCandidateActiveObservedAtMilliseconds(
	ctx context.Context,
	querier schemaQuerier,
) error {
	var invalid int
	if err := querier.QueryRowContext(ctx, `
		SELECT count(*)
		FROM candidate_health
		WHERE active_observed_at IS NOT NULL
		  AND (active_observed_at<? OR active_observed_at>?)
	`, minActiveObservedAtMilliseconds,
		maxActiveObservedAtMilliseconds,
	).Scan(&invalid); err != nil {
		return fmt.Errorf("validate active observation timestamps: %w", err)
	}
	if invalid != 0 {
		return errors.New("candidate_health.active_observed_at is not milliseconds")
	}
	return nil
}

func validateCandidateActiveHardFailureSchema(
	ctx context.Context,
	querier schemaQuerier,
) error {
	var typeName string
	var notNull int
	var defaultValue sql.NullString
	err := querier.QueryRowContext(ctx, `
		SELECT type, "notnull", dflt_value
		FROM pragma_table_info('candidate_health')
		WHERE name='active_hard_failure'
	`).Scan(&typeName, &notNull, &defaultValue)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("candidate_health.active_hard_failure is missing")
	}
	if err != nil {
		return fmt.Errorf("inspect candidate active hard failure schema: %w", err)
	}
	if !strings.EqualFold(typeName, "INTEGER") || notNull != 1 ||
		!defaultValue.Valid || defaultValue.String != "0" {
		return errors.New("candidate_health.active_hard_failure has incompatible schema")
	}
	return nil
}

func validateDesiredPlanReasonSchema(
	ctx context.Context,
	querier schemaQuerier,
) error {
	var typeName string
	var notNull int
	var defaultValue sql.NullString
	err := querier.QueryRowContext(ctx, `
		SELECT type, "notnull", dflt_value
		FROM pragma_table_info('plan_state')
		WHERE name='desired_reason'
	`).Scan(&typeName, &notNull, &defaultValue)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("plan_state.desired_reason is missing")
	}
	if err != nil {
		return fmt.Errorf("inspect desired plan reason schema: %w", err)
	}
	if !strings.EqualFold(typeName, "TEXT") || notNull != 1 ||
		!defaultValue.Valid || defaultValue.String != "''" {
		return errors.New("plan_state.desired_reason has incompatible schema")
	}
	return nil
}

func validateV11PlanStateConsistency(ctx context.Context, querier schemaQuerier) error {
	var singletonRows int
	if err := querier.QueryRowContext(ctx, `
		SELECT count(*) FROM plan_state WHERE singleton=1
	`).Scan(&singletonRows); err != nil {
		return err
	}
	if singletonRows != 1 {
		return fmt.Errorf("plan_state singleton rows=%d", singletonRows)
	}
	var (
		desiredGeneration            int64
		appliedGeneration            int64
		invalidatedGeneration        int64
		desiredPlan                  []byte
		appliedPlan                  []byte
		desiredAssignmentsGeneration int64
		desiredAssignments           []byte
	)
	if err := querier.QueryRowContext(ctx, `
		SELECT desired_generation, applied_generation, invalidated_generation,
		       desired_plan, applied_plan,
		       desired_assignments_generation, desired_assignments
		FROM plan_state WHERE singleton=1
	`).Scan(
		&desiredGeneration, &appliedGeneration, &invalidatedGeneration,
		&desiredPlan, &appliedPlan,
		&desiredAssignmentsGeneration, &desiredAssignments,
	); err != nil {
		return err
	}
	if desiredGeneration < 0 || appliedGeneration < 0 ||
		invalidatedGeneration < 0 || appliedGeneration > desiredGeneration {
		return fmt.Errorf(
			"inconsistent plan generations desired=%d applied=%d",
			desiredGeneration, appliedGeneration,
		)
	}
	if invalidatedGeneration != 0 &&
		(invalidatedGeneration < desiredGeneration || desiredGeneration != appliedGeneration) {
		return fmt.Errorf(
			"inconsistent invalidated generation=%d desired=%d applied=%d",
			invalidatedGeneration, desiredGeneration, appliedGeneration,
		)
	}
	if (desiredGeneration == 0) != (len(desiredPlan) == 0) ||
		(appliedGeneration == 0) != (len(appliedPlan) == 0) {
		return errors.New("plan generation and bytes are inconsistent")
	}
	_, desiredMappings, desiredDigest, err :=
		decodeBackupPlanState(ctx, querier, desiredPlan, desiredGeneration)
	if err != nil {
		return fmt.Errorf("invalid desired plan: %w", err)
	}
	_, appliedMappings, appliedDigest, err :=
		decodeBackupPlanState(ctx, querier, appliedPlan, appliedGeneration)
	if err != nil {
		return fmt.Errorf("invalid applied plan: %w", err)
	}
	if desiredGeneration == appliedGeneration && desiredGeneration != 0 &&
		desiredDigest != appliedDigest {
		return errors.New("equal desired and applied generations have different plans")
	}
	trimmedSnapshot := bytes.TrimSpace(desiredAssignments)
	if desiredAssignmentsGeneration == 0 {
		if len(trimmedSnapshot) != 0 {
			return errors.New("zero assignment snapshot generation has snapshot bytes")
		}
	} else {
		if desiredAssignmentsGeneration != desiredGeneration {
			return errors.New("desired assignment snapshot generation mismatch")
		}
		var assignments []AssignmentRecord
		if bytes.Equal(trimmedSnapshot, []byte("null")) ||
			!decodeStrictJSON(desiredAssignments, &assignments) || assignments == nil {
			return errors.New("desired assignment snapshot is invalid")
		}
		if err := validatePersistedAssignmentSnapshot(
			ctx, querier, desiredPlan, assignments,
		); err != nil {
			return err
		}
	}
	if desiredGeneration > appliedGeneration &&
		desiredAssignmentsGeneration != desiredGeneration {
		return errors.New("pending desired plan has no exact assignment snapshot")
	}
	rows, err := querier.QueryContext(ctx, `
		SELECT stage, client_id, generation,
		       tcp_primary_candidate_id, tcp_reserve_candidate_id,
		       udp_primary_candidate_id, udp_reserve_candidate_id
		FROM route_reserve_mappings
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actualDesiredMappings := make(map[string]RouteReserveMapping)
	actualAppliedMappings := make(map[string]RouteReserveMapping)
	for rows.Next() {
		var stage string
		var mapping RouteReserveMapping
		var generation int64
		if err := rows.Scan(
			&stage, &mapping.ClientID, &generation,
			&mapping.TCPPrimaryCandidateID, &mapping.TCPReserveCandidateID,
			&mapping.UDPPrimaryCandidateID, &mapping.UDPReserveCandidateID,
		); err != nil {
			return err
		}
		switch stage {
		case "desired":
			if generation != desiredGeneration ||
				desiredAssignmentsGeneration != desiredGeneration {
				return errors.New("desired route reserve mapping generation mismatch")
			}
			actualDesiredMappings[mapping.ClientID] = mapping
		case "applied":
			if generation != appliedGeneration {
				return errors.New("applied route reserve mapping generation mismatch")
			}
			actualAppliedMappings[mapping.ClientID] = mapping
		default:
			return errors.New("invalid route reserve mapping stage")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if invalidatedGeneration != 0 {
		desiredMappings = nil
	}
	if !routeReserveMappingSetsEqual(desiredMappings, actualDesiredMappings) {
		return errors.New("desired route reserve mappings do not match the desired plan")
	}
	if !routeReserveMappingSetsEqual(appliedMappings, actualAppliedMappings) {
		return errors.New("applied route reserve mappings do not match the applied plan")
	}
	return nil
}

func decodeBackupPlanState(
	ctx context.Context,
	querier schemaQuerier,
	encoded []byte,
	generation int64,
) (dataplane.DesiredPlan, map[string]RouteReserveMapping, string, error) {
	if generation == 0 {
		return dataplane.DesiredPlan{}, nil, "", nil
	}
	var plan dataplane.DesiredPlan
	if !decodeStrictJSON(encoded, &plan) || plan.Generation != generation {
		return dataplane.DesiredPlan{}, nil, "", errors.New("plan encoding or generation mismatch")
	}
	if err := plan.Validate(); err != nil {
		return dataplane.DesiredPlan{}, nil, "", err
	}
	handlers, err := backupPlanHandlers(ctx, querier, plan)
	if err != nil {
		return dataplane.DesiredPlan{}, nil, "", err
	}
	mappings, err := expectedRouteReserveMappings(plan, handlers)
	if err != nil {
		return dataplane.DesiredPlan{}, nil, "", err
	}
	digest, err := plan.SemanticDigest()
	if err != nil {
		return dataplane.DesiredPlan{}, nil, "", err
	}
	return plan, mappings, digest, nil
}

func backupPlanHandlers(
	ctx context.Context,
	querier schemaQuerier,
	plan dataplane.DesiredPlan,
) (map[string]planHandlerBinding, error) {
	rows, err := querier.QueryContext(ctx, `SELECT id, kind FROM candidates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make(map[string]sources.Kind)
	for rows.Next() {
		var candidateID string
		var kind sources.Kind
		if err := rows.Scan(&candidateID, &kind); err != nil {
			return nil, err
		}
		candidates[candidateID] = kind
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	handlers, err := persistedPlanHandlers(plan)
	if err != nil {
		return nil, err
	}
	for outboundID, binding := range handlers {
		kind, exists := candidates[binding.candidateID]
		switch binding.protocol {
		case dataplane.ProtocolVLESS:
			if !exists || kind != sources.KindVLESS || outboundID != binding.candidateID {
				return nil, errors.New("persisted VLESS handler is not bound to its candidate")
			}
		case dataplane.ProtocolTor:
			if !exists || kind != sources.KindTorBridge {
				return nil, errors.New("persisted Tor handler is not bound to its candidate")
			}
		}
	}
	return handlers, nil
}

func routeReserveMappingSetsEqual(
	expected map[string]RouteReserveMapping,
	actual map[string]RouteReserveMapping,
) bool {
	if len(expected) != len(actual) {
		return false
	}
	for clientID, expectedMapping := range expected {
		if actual[clientID] != expectedMapping {
			return false
		}
	}
	return true
}
