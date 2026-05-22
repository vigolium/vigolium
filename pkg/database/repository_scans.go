package database

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"go.uber.org/zap"
)

// CreateScan inserts a new scan record. When a row with scan.UUID already
// exists, the call is a no-op as long as the existing project_uuid matches —
// this is the get-or-create path used for cross-node sync via --scan-uuid.
// Returns ErrScanProjectMismatch when the existing row belongs to a different
// project.
func (r *Repository) CreateScan(ctx context.Context, scan *Scan) error {
	if scan == nil {
		return fmt.Errorf("invalid Scan")
	}
	scan.ProjectUUID = defaultProjectUUID(scan.ProjectUUID)
	res, err := r.db.NewInsert().Model(scan).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to insert scan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 && scan.UUID != "" {
		existing, getErr := r.GetScanByUUID(ctx, scan.UUID)
		if getErr == nil && existing != nil && existing.ProjectUUID != scan.ProjectUUID {
			return fmt.Errorf("%w: scan %s belongs to project %s, not %s",
				ErrScanProjectMismatch, scan.UUID, existing.ProjectUUID, scan.ProjectUUID)
		}
	}
	return nil
}

// UpdateScan updates an existing scan record
func (r *Repository) UpdateScan(ctx context.Context, scan *Scan) error {
	if scan == nil {
		return fmt.Errorf("invalid Scan")
	}
	if _, err := r.db.NewUpdate().Model(scan).WherePK().Exec(ctx); err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}
	return nil
}

// UpdateScanPartial updates a scan row by UUID, skipping fields whose Go value
// is the zero value. Use this when the caller only wants to touch a subset of
// fields (e.g. an API PATCH that should leave omitted fields unchanged).
// To explicitly clear a field, use a column-level Set via NewUpdate().
func (r *Repository) UpdateScanPartial(ctx context.Context, scan *Scan) error {
	if scan == nil || scan.UUID == "" {
		return fmt.Errorf("invalid Scan: uuid is required")
	}
	if _, err := r.db.NewUpdate().Model(scan).OmitZero().Where("uuid = ?", scan.UUID).Exec(ctx); err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}
	return nil
}

// UpdateScanStorageURL sets the storage_url field on a scan record.
func (r *Repository) UpdateScanStorageURL(ctx context.Context, scanUUID, storageURL string) error {
	_, err := r.db.NewUpdate().Model((*Scan)(nil)).
		Set("storage_url = ?", storageURL).
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}

// GetScanByUUID retrieves a scan by its UUID
func (r *Repository) GetScanByUUID(ctx context.Context, uuid string) (*Scan, error) {
	scan := &Scan{}
	err := r.db.NewSelect().
		Model(scan).
		Where("uuid = ?", uuid).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return scan, nil
}

// scanSeverityCounts holds aggregated finding counts for a scan.
type scanSeverityCounts struct {
	Total    int64
	Critical int64
	High     int64
	Medium   int64
	Low      int64
	Info     int64
	Suspect  int64
}

// aggregateScanFindings queries finding severity counts for a scan.
func (r *Repository) aggregateScanFindings(ctx context.Context, scanUUID string) scanSeverityCounts {
	var rows []SeverityCount
	_ = r.db.NewSelect().
		TableExpr("findings").
		ColumnExpr("severity").
		ColumnExpr("COUNT(*) AS count").
		Where("scan_uuid = ?", scanUUID).
		GroupExpr("severity").
		Scan(ctx, &rows)

	var sc scanSeverityCounts
	for _, row := range rows {
		sc.Total += row.Count
		switch row.Severity {
		case "critical":
			sc.Critical = row.Count
		case "high":
			sc.High = row.Count
		case "medium":
			sc.Medium = row.Count
		case "low":
			sc.Low = row.Count
		case "info":
			sc.Info = row.Count
		case "suspect":
			sc.Suspect = row.Count
		}
	}
	return sc
}

// applySeverityCounts sets severity count fields on an UPDATE query builder.
func applySeverityCounts(q *bun.UpdateQuery, sc scanSeverityCounts) *bun.UpdateQuery {
	q = q.Set("critical_count = ?", sc.Critical).
		Set("high_count = ?", sc.High).
		Set("medium_count = ?", sc.Medium).
		Set("low_count = ?", sc.Low).
		Set("info_count = ?", sc.Info).
		Set("suspect_count = ?", sc.Suspect)
	if sc.Total > 0 {
		q = q.Set("total_findings = ?", sc.Total)
	}
	return q
}

// CompleteScan marks a scan as completed (or failed if errMsg is non-empty)
// and populates severity counts from the findings table.
func (r *Repository) CompleteScan(ctx context.Context, scanUUID string, errMsg string) error {
	status := "completed"
	if errMsg != "" {
		status = "failed"
	}

	// Compute duration from started_at so the scan row doesn't report 0ms after
	// it finishes. We read started_at first rather than using SQL arithmetic to
	// keep the logic portable across SQLite and PostgreSQL.
	var startedAt time.Time
	if err := r.db.NewSelect().
		Model((*Scan)(nil)).
		Column("started_at").
		Where("uuid = ?", scanUUID).
		Scan(ctx, &startedAt); err != nil {
		return fmt.Errorf("load scan start time: %w", err)
	}
	finishedAt := time.Now()
	durationMs := finishedAt.Sub(startedAt).Milliseconds()
	if durationMs < 0 {
		durationMs = 0
	}

	sc := r.aggregateScanFindings(ctx, scanUUID)
	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("status = ?", status).
		Set("error_message = ?", errMsg).
		Set("finished_at = ?", finishedAt).
		Set("duration_ms = ?", durationMs).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID)
	q = applySeverityCounts(q, sc)

	_, err := q.Exec(ctx)
	return err
}

// RefreshScanStats updates running scan stats during long-running scans
// where CompleteScan hasn't been called yet.
func (r *Repository) RefreshScanStats(ctx context.Context, scanUUID string) error {
	sc := r.aggregateScanFindings(ctx, scanUUID)
	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID)
	q = applySeverityCounts(q, sc)

	_, err := q.Exec(ctx)
	return err
}

// ListScans returns scans ordered by created_at descending with limit/offset, filtered by project.
func (r *Repository) ListScans(ctx context.Context, projectUUID string, limit, offset int) ([]*Scan, int64, error) {
	var scans []*Scan
	q := r.db.NewSelect().
		Model(&scans).
		OrderExpr("created_at DESC").
		Limit(limit).
		Offset(offset)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	count, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list scans: %w", err)
	}
	return scans, int64(count), nil
}

// LoadEnabledScopes loads enabled scope rules for a project, ordered by priority.
// Falls back to the default project's scopes if no project-specific scopes exist.
func (r *Repository) LoadEnabledScopes(ctx context.Context, projectUUID string) ([]*Scope, error) {
	var scopes []*Scope

	if projectUUID != "" {
		err := r.db.NewSelect().
			Model(&scopes).
			Where("project_uuid = ?", projectUUID).
			Where("enabled = ?", true).
			Order("priority ASC").
			Scan(ctx)
		if err != nil {
			zap.L().Debug("Failed to load project scopes", zap.Error(err))
			return nil, err
		}
		if len(scopes) > 0 {
			return scopes, nil
		}
		// Fall back to default project scopes
		if projectUUID != DefaultProjectUUID {
			return r.LoadEnabledScopes(ctx, DefaultProjectUUID)
		}
	}

	// No project filter or default project — load all enabled scopes
	err := r.db.NewSelect().
		Model(&scopes).
		Where("enabled = ?", true).
		Order("priority ASC").
		Scan(ctx)
	if err != nil {
		zap.L().Debug("Failed to load scopes", zap.Error(err))
		return nil, err
	}
	return scopes, nil
}

// CreateScanWithCursor creates a Scan record. If mode is "incremental", copies cursor
// from the last completed scan with matching Modules. Otherwise starts at zero.
func (r *Repository) CreateScanWithCursor(ctx context.Context, scan *Scan) error {
	if scan == nil {
		return fmt.Errorf("invalid Scan")
	}

	scan.ProjectUUID = defaultProjectUUID(scan.ProjectUUID)

	if scan.ScanMode == "incremental" && scan.Modules != "" {
		// Find the last completed scan with the same modules to copy cursor
		var prev Scan
		err := r.db.NewSelect().
			Model(&prev).
			Column("cursor_at", "cursor_uuid").
			Where("status = ?", "completed").
			Where("modules = ?", scan.Modules).
			OrderExpr("finished_at DESC").
			Limit(1).
			Scan(ctx)
		if err == nil && !prev.CursorAt.IsZero() {
			scan.StartCursorAt = prev.CursorAt
			scan.StartCursorUUID = prev.CursorUUID
			scan.CursorAt = prev.CursorAt
			scan.CursorUUID = prev.CursorUUID
		}
		// If no previous scan found, cursor stays at zero (scan all records)
	}

	if _, err := r.db.NewInsert().Model(scan).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert scan: %w", err)
	}
	return nil
}

// IncrementProcessedCount adds delta to the scan's processed_count.
// Use this for phases that don't advance the cursor (discovery, spidering, etc.).
func (r *Repository) IncrementProcessedCount(ctx context.Context, scanUUID string, delta int64) error {
	if delta <= 0 {
		return nil
	}
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("processed_count = processed_count + ?", delta).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}

// AdvanceScanCursor updates the cursor position and increments ProcessedCount.
func (r *Repository) AdvanceScanCursor(ctx context.Context, scanUUID string, recordCreatedAt time.Time, recordUUID string) error {
	return r.AdvanceScanCursorBy(ctx, scanUUID, recordCreatedAt, recordUUID, 1)
}

// AdvanceScanCursorBy updates the cursor position and increments ProcessedCount by delta.
func (r *Repository) AdvanceScanCursorBy(ctx context.Context, scanUUID string, recordCreatedAt time.Time, recordUUID string, delta int64) error {
	if delta <= 0 {
		delta = 1
	}
	// Format cursor_at to match SQLite's CURRENT_TIMESTAMP format (no timezone suffix).
	// Go's time.Time serialization adds timezone info that breaks SQLite text comparison.
	cursorAt := recordCreatedAt.UTC().Format("2006-01-02 15:04:05")
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("cursor_at = ?", cursorAt).
		Set("cursor_uuid = ?", recordUUID).
		Set("processed_count = processed_count + ?", delta).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}

// ResetScanCursor resets the scan cursor to the beginning so all records
// are re-read on the next iteration (e.g., between seed and audit phases).
func (r *Repository) ResetScanCursor(ctx context.Context, scanUUID string) error {
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("cursor_at = ?", time.Time{}).
		Set("cursor_uuid = ?", "").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}

// CountRecordsAfterCursor counts records after the given cursor position.
// A zero cursorAt means count all records. When hostnames is non-empty,
// only records matching those hostnames are counted.
func (r *Repository) CountRecordsAfterCursor(ctx context.Context, cursorAt time.Time, cursorUUID string, hostnames ...string) (int64, error) {
	return r.countRecordsAfterCursor(ctx, cursorAt, cursorUUID, nil, hostnames)
}

// CountRecordsAfterCursorBySource is like CountRecordsAfterCursor but also
// filters on http_records.source. Used by scan-on-receive shallow mode to
// report only user-ingested traffic in the "new ingested records" status,
// excluding finding/scanner artefacts produced by the scan itself.
func (r *Repository) CountRecordsAfterCursorBySource(ctx context.Context, cursorAt time.Time, cursorUUID string, sources []string, hostnames []string) (int64, error) {
	return r.countRecordsAfterCursor(ctx, cursorAt, cursorUUID, sources, hostnames)
}

func (r *Repository) countRecordsAfterCursor(ctx context.Context, cursorAt time.Time, cursorUUID string, sources []string, hostnames []string) (int64, error) {
	q := r.db.NewSelect().Model((*HTTPRecord)(nil))

	if !cursorAt.IsZero() {
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", cursorAt, cursorAt, cursorUUID)
	}

	if len(hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.In(hostnames))
	}

	if len(sources) > 0 {
		q = q.Where("source IN (?)", bun.In(sources))
	}

	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count records after cursor: %w", err)
	}
	return int64(count), nil
}

// PauseScan sets a scan's status to "paused".
func (r *Repository) PauseScan(ctx context.Context, scanUUID string) error {
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("status = ?", "paused").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Where("status = ?", "running").
		Exec(ctx)
	return err
}

// ResumeScan sets a scan's status back to "running".
func (r *Repository) ResumeScan(ctx context.Context, scanUUID string) error {
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("status = ?", "running").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Where("status = ?", "paused").
		Exec(ctx)
	return err
}

// CreateScanLog inserts a scan log entry.
func (r *Repository) CreateScanLog(ctx context.Context, log *ScanLog) error {
	if log == nil {
		return fmt.Errorf("invalid ScanLog")
	}
	log.ProjectUUID = defaultProjectUUID(log.ProjectUUID)
	if _, err := r.db.NewInsert().Model(log).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert scan log: %w", err)
	}
	return nil
}

// CreateScanLogBatch inserts multiple scan log entries in a single bulk insert.
func (r *Repository) CreateScanLogBatch(ctx context.Context, logs []*ScanLog) error {
	if len(logs) == 0 {
		return nil
	}
	for _, l := range logs {
		l.ProjectUUID = defaultProjectUUID(l.ProjectUUID)
	}
	if _, err := r.db.NewInsert().Model(&logs).Exec(ctx); err != nil {
		return fmt.Errorf("failed to batch insert scan logs: %w", err)
	}
	return nil
}

// ListScanLogs returns log entries for a scan, ordered by created_at ascending.
// Both level and phase are optional filters; pass "" to skip.
func (r *Repository) ListScanLogs(ctx context.Context, scanUUID string, level, phase string, limit, offset int) ([]*ScanLog, int64, error) {
	var logs []*ScanLog
	q := r.db.NewSelect().
		Model(&logs).
		Where("scan_uuid = ?", scanUUID).
		OrderExpr("created_at ASC")

	if level != "" {
		q = q.Where("level = ?", level)
	}
	if phase != "" {
		q = q.Where("phase = ?", phase)
	}

	q = q.Limit(limit).Offset(offset)

	total, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list scan logs: %w", err)
	}
	return logs, int64(total), nil
}

// DeleteScan deletes a scan record by UUID.
func (r *Repository) DeleteScan(ctx context.Context, uuid string) error {
	_, err := r.db.NewDelete().
		Model((*Scan)(nil)).
		Where("uuid = ?", uuid).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}
	return nil
}
