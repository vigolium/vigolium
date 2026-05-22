package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// SaveFinding stores a vulnerability finding linked to HTTP records by UUIDs.
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFinding(ctx context.Context, event *output.ResultEvent, httpRecordUUIDs []string, scanUUID string, projectUUID string) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}

	finding := &Finding{
		HTTPRecordUUIDs: httpRecordUUIDs,
		ScanUUID:        scanUUID,
		ProjectUUID:     defaultProjectUUID(projectUUID),
	}
	if err := finding.FromResultEvent(event); err != nil {
		return fmt.Errorf("failed to convert finding: %w", err)
	}

	// Atomic dedup: INSERT with conflict resolution on finding_hash.
	// If a duplicate hash exists, the row is silently skipped.
	var res sql.Result
	var err error
	if finding.FindingHash != "" {
		res, err = r.db.NewInsert().Model(finding).
			On("CONFLICT (project_uuid, finding_hash) DO NOTHING").
			Exec(ctx)
	} else {
		res, err = r.db.NewInsert().Model(finding).Exec(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to insert finding: %w", err)
	}

	// If ON CONFLICT fired, no row was inserted — append records and evidence to existing finding
	if finding.FindingHash != "" {
		if n, _ := res.RowsAffected(); n == 0 {
			return r.appendRecordsToFinding(ctx, finding.ProjectUUID, finding.FindingHash, httpRecordUUIDs, buildEvidence(finding.Request, finding.Response))
		}
	}

	r.insertFindingRecords(ctx, finding.ID, httpRecordUUIDs)

	return nil
}

// SaveFindingDirect inserts a pre-built Finding directly (without ResultEvent conversion).
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFindingDirect(ctx context.Context, finding *Finding) error {
	if finding == nil {
		return fmt.Errorf("invalid Finding")
	}

	finding.ProjectUUID = defaultProjectUUID(finding.ProjectUUID)

	// Atomic dedup: INSERT with conflict resolution on finding_hash.
	var res sql.Result
	var err error
	if finding.FindingHash != "" {
		res, err = r.db.NewInsert().Model(finding).
			On("CONFLICT (project_uuid, finding_hash) DO NOTHING").
			Exec(ctx)
	} else {
		res, err = r.db.NewInsert().Model(finding).Exec(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to insert finding: %w", err)
	}

	// If ON CONFLICT fired, no row was inserted — append records and evidence to existing finding
	if finding.FindingHash != "" {
		if n, _ := res.RowsAffected(); n == 0 {
			return r.appendRecordsToFinding(ctx, finding.ProjectUUID, finding.FindingHash, finding.HTTPRecordUUIDs, buildEvidence(finding.Request, finding.Response))
		}
	}

	r.insertFindingRecords(ctx, finding.ID, finding.HTTPRecordUUIDs)

	return nil
}

// insertFindingRecords batch-inserts finding↔record junction rows in a single statement.
func (r *Repository) insertFindingRecords(ctx context.Context, findingID int64, recordUUIDs []string) {
	if len(recordUUIDs) == 0 {
		return
	}

	var b strings.Builder
	if r.db.Driver() == "postgres" {
		b.WriteString("INSERT INTO finding_records (finding_id, record_uuid) VALUES ")
	} else {
		b.WriteString("INSERT OR IGNORE INTO finding_records (finding_id, record_uuid) VALUES ")
	}
	args := make([]interface{}, 0, len(recordUUIDs)*2)
	for i, uuid := range recordUUIDs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(?, ?)")
		args = append(args, findingID, uuid)
	}
	if r.db.Driver() == "postgres" {
		b.WriteString(" ON CONFLICT DO NOTHING")
	}
	if _, err := r.db.ExecContext(ctx, b.String(), args...); err != nil {
		zap.L().Warn("Failed to insert finding_records",
			zap.Int64("finding_id", findingID),
			zap.Error(err))
	}
}

// appendRecordsToFinding looks up an existing finding by (project, hash) and appends new
// record UUIDs and additional evidence (request/response pair) to it. The lookup is
// project-scoped so evidence from one project is never merged into another project's
// finding, even when both share a finding_hash.
func (r *Repository) appendRecordsToFinding(ctx context.Context, projectUUID, findingHash string, newUUIDs []string, evidence string) error {
	existing := &Finding{}
	err := r.db.NewSelect().Model(existing).
		Column("id", "http_record_uuids", "additional_evidence").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("finding_hash = ?", findingHash).
		Scan(ctx)
	if err != nil {
		return fmt.Errorf("failed to look up existing finding: %w", err)
	}

	r.insertFindingRecords(ctx, existing.ID, newUUIDs)

	merged := mergeUniqueStrings(existing.HTTPRecordUUIDs, newUUIDs)
	q := r.db.NewUpdate().Model((*Finding)(nil)).
		Set("http_record_uuids = ?", merged).
		Where("id = ?", existing.ID)

	if evidence != "" {
		updated := append(existing.AdditionalEvidence, evidence)
		q = q.Set("additional_evidence = ?", updated)
	}

	_, err = q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update finding record UUIDs: %w", err)
	}
	return nil
}

// GetFindingByID retrieves a single finding by numeric ID.
func (r *Repository) GetFindingByID(ctx context.Context, id int64) (*Finding, error) {
	finding := &Finding{}
	err := r.db.NewSelect().
		Model(finding).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// GetFindingsByRecordUUID retrieves findings that reference a specific HTTP record UUID.
// Since http_record_uuids is a JSONB array, we use json_each to search inside it.
func (r *Repository) GetFindingsByRecordUUID(ctx context.Context, uuid string) ([]*Finding, error) {
	var findings []*Finding
	err := r.db.NewSelect().
		Model(&findings).
		Where("f.id IN (SELECT finding_id FROM finding_records WHERE record_uuid = ?)", uuid).
		Order("found_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// ListFindings runs a filtered findings query and returns the matching
// page plus the total unfiltered count, in a single round-trip. The
// canonical entry point for callers that want paginated results — keeps
// FindingsQueryBuilder behind the repository boundary so they don't need
// to reach for Repository.DB().
func (r *Repository) ListFindings(ctx context.Context, filters QueryFilters) ([]*Finding, int64, error) {
	return NewFindingsQueryBuilder(r.db, filters).ExecuteWithCount(ctx)
}

// GetFindingsBySeverity retrieves findings filtered by severity within a project.
func (r *Repository) GetFindingsBySeverity(ctx context.Context, projectUUID, sev string, limit int) ([]*Finding, error) {
	var findings []*Finding
	q := r.db.NewSelect().
		Model(&findings).
		Where("severity = ?", sev).
		Order("found_at DESC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// IsValidFindingStatus reports whether s is a recognised Finding lifecycle status.
func IsValidFindingStatus(s string) bool {
	switch s {
	case StatusDraft, StatusTriaged, StatusFalsePositive, StatusAcceptedRisk, StatusFixed:
		return true
	}
	return false
}

// UpdateFindingStatus sets the lifecycle status of a single finding by ID.
// Returns sql.ErrNoRows if no finding matches.
func (r *Repository) UpdateFindingStatus(ctx context.Context, id int64, status string) error {
	if !IsValidFindingStatus(status) {
		return fmt.Errorf("UpdateFindingStatus: invalid status %q", status)
	}
	res, err := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("status = ?", status).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingStatus: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateFindingStatusByHash sets the lifecycle status of findings matching a finding_hash
// within an agentic_scan_uuid scope. Used by the swarm triage writeback to promote
// draft findings to triaged / false_positive based on agent verdicts.
// Returns the number of rows updated.
func (r *Repository) UpdateFindingStatusByHash(ctx context.Context, agenticScanUUID, findingHash, status string) (int64, error) {
	if !IsValidFindingStatus(status) {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: invalid status %q", status)
	}
	if findingHash == "" {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: empty finding_hash")
	}
	q := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("status = ?", status).
		Where("finding_hash = ?", findingHash)
	if agenticScanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", agenticScanUUID)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

// IsValidFindingSeverity reports whether s is a recognised Finding severity level.
func IsValidFindingSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeveritySuspect:
		return true
	}
	return false
}

// UpdateFindingSeverity sets the severity of a single finding by ID.
// Returns sql.ErrNoRows if no finding matches.
func (r *Repository) UpdateFindingSeverity(ctx context.Context, id int64, severity string) error {
	if !IsValidFindingSeverity(severity) {
		return fmt.Errorf("UpdateFindingSeverity: invalid severity %q", severity)
	}
	res, err := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("severity = ?", severity).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingSeverity: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateFindingTriage sets severity and description on a single finding in one
// statement. Used by the agent triage flow so a false-positive verdict can't
// land a half-updated row (severity downgraded but reasoning lost) if the
// process is killed between two separate UPDATEs.
func (r *Repository) UpdateFindingTriage(ctx context.Context, id int64, severity, description string) error {
	if !IsValidFindingSeverity(severity) {
		return fmt.Errorf("UpdateFindingTriage: invalid severity %q", severity)
	}
	res, err := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("severity = ?", severity).
		Set("description = ?", description).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingTriage: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteFinding deletes a finding by its numeric ID, including any finding_records junction rows.
func (r *Repository) DeleteFinding(ctx context.Context, id int64) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().TableExpr("finding_records").Where("finding_id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
		}
		return nil
	})
}
