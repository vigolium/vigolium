package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// Repository handles HTTP record and finding storage
type Repository struct {
	db *DB
}

// ErrScanProjectMismatch is returned by CreateScan / CreateAgenticScan when
// the caller pins a UUID that already exists under a different project. This
// guards against cross-project record corruption when remote nodes sync via
// --scan-uuid.
var ErrScanProjectMismatch = errors.New("scan UUID exists under a different project")

// NewRepository creates a new repository instance
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// defaultProjectUUID returns DefaultProjectUUID when the given value is empty.
// This prevents Bun from inserting an empty string that bypasses the column DEFAULT.
func defaultProjectUUID(v string) string {
	if v == "" {
		return DefaultProjectUUID
	}
	return v
}

// SaveRecord stores a denormalized HTTP record (request + response + host + parameters).
// The source identifies the origin of the record (e.g. "scanner", "ingest-cli", "ingest-server", "ingest-proxy").
// Returns the UUID of the saved record. If a matching record already exists (same method,
// hostname, path, URL, and request body), the existing UUID is returned without inserting.
func (r *Repository) SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if httpRR == nil || httpRR.Request() == nil {
		return "", fmt.Errorf("invalid HttpRequestResponse")
	}

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(httpRR); err != nil {
		return "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = defaultProjectUUID(projectUUID)

	if existingUUID, err := r.findDuplicateRecord(ctx, record); err == nil && existingUUID != "" {
		return existingUUID, nil
	}

	if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to insert record: %w", err)
	}

	return record.UUID, nil
}

// findDuplicateRecord checks whether a record with the same method, hostname,
// path, and URL already exists. For requests with a body, the request_hash is
// also compared to distinguish different payloads to the same endpoint.
func (r *Repository) findDuplicateRecord(ctx context.Context, record *HTTPRecord) (string, error) {
	var existingUUID string
	q := r.db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("uuid").
		Where("project_uuid = ?", record.ProjectUUID).
		Where("method = ?", record.Method).
		Where("hostname = ?", record.Hostname).
		Where("path = ?", record.Path).
		Where("url = ?", record.URL).
		Limit(1)

	if record.RequestContentLength > 0 {
		q = q.Where("request_hash = ?", record.RequestHash)
	}

	err := q.Scan(ctx, &existingUUID)
	return existingUUID, err
}

// SaveRecordBatch converts httpmsg.HttpRequestResponse objects to HTTPRecord models and
// batch-inserts them. This is the high-level batch equivalent of SaveRecord.
func (r *Repository) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	projectUUID = defaultProjectUUID(projectUUID)
	dbRecords := make([]*HTTPRecord, 0, len(records))

	for _, rr := range records {
		rec := &HTTPRecord{}
		if err := rec.FromHttpRequestResponse(rr); err != nil {
			zap.L().Debug("SaveRecordBatch: skipping record", zap.Error(err))
			continue
		}
		rec.Source = source
		rec.ProjectUUID = projectUUID
		dbRecords = append(dbRecords, rec)
	}

	return r.SaveRecordsBatch(ctx, dbRecords)
}

// SaveRecordsBatch inserts multiple HTTP records in a single transaction.
// Returns the UUIDs of all successfully inserted records.
func (r *Repository) SaveRecordsBatch(ctx context.Context, records []*HTTPRecord) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	for _, rec := range records {
		rec.ProjectUUID = defaultProjectUUID(rec.ProjectUUID)
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewInsert().Model(&records).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to batch insert %d records: %w", len(records), err)
	}

	uuids := make([]string, len(records))
	for i, rec := range records {
		uuids[i] = rec.UUID
	}
	return uuids, nil
}

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
			On("CONFLICT (finding_hash) DO NOTHING").
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
			return r.appendRecordsToFinding(ctx, finding.FindingHash, httpRecordUUIDs, buildEvidence(finding.Request, finding.Response))
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
			On("CONFLICT (finding_hash) DO NOTHING").
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
			return r.appendRecordsToFinding(ctx, finding.FindingHash, finding.HTTPRecordUUIDs, buildEvidence(finding.Request, finding.Response))
		}
	}

	r.insertFindingRecords(ctx, finding.ID, finding.HTTPRecordUUIDs)

	return nil
}

// buildEvidence creates an evidence string from a request/response pair.
// Returns empty string if both are empty.
func buildEvidence(request, response string) string {
	if request == "" && response == "" {
		return ""
	}
	return request + EvidenceSeparator + response
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

// EvidenceSeparator is the delimiter between request and response inside an AdditionalEvidence entry.
const EvidenceSeparator = "\n---------\n"

// appendRecordsToFinding looks up an existing finding by hash and appends new record UUIDs
// and additional evidence (request/response pair) to it.
func (r *Repository) appendRecordsToFinding(ctx context.Context, findingHash string, newUUIDs []string, evidence string) error {
	existing := &Finding{}
	err := r.db.NewSelect().Model(existing).
		Column("id", "http_record_uuids", "additional_evidence").
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

// mergeUniqueStrings returns the deduplicated union of two string slices.
func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// GetRecordByUUID retrieves a single HTTP record by UUID
func (r *Repository) GetRecordByUUID(ctx context.Context, uuid string) (*HTTPRecord, error) {
	record := &HTTPRecord{}
	err := r.db.NewSelect().
		Model(record).
		Where("uuid = ?", uuid).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
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

// GetRecordsByHostname retrieves HTTP records for a hostname within a project.
func (r *Repository) GetRecordsByHostname(ctx context.Context, projectUUID, hostname string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Where("hostname = ?", hostname).
		Order("sent_at DESC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetUnprobedRecordsBySource returns records with has_response=false for the given source and hostname.
func (r *Repository) GetUnprobedRecordsBySource(ctx context.Context, projectUUID, source, hostname string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Where("source = ?", source).
		Where("hostname = ?", hostname).
		Where("has_response = ?", false).
		Order("created_at ASC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return records, nil
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

// GetRecordsByUUIDs retrieves HTTP records matching the given UUIDs.
func (r *Repository) GetRecordsByUUIDs(ctx context.Context, uuids []string) ([]*HTTPRecord, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	var records []*HTTPRecord
	err := r.db.NewSelect().
		Model(&records).
		Where("uuid IN (?)", bun.In(uuids)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get records by UUIDs: %w", err)
	}
	return records, nil
}

// DB returns the underlying database handle.
func (r *Repository) DB() *DB { return r.db }

// --- User CRUD ---

// CreateUser inserts a new user.
func (r *Repository) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return fmt.Errorf("invalid User")
	}
	if _, err := r.db.NewInsert().Model(user).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}
	return nil
}

// GetUserByUUID retrieves a user by UUID.
func (r *Repository) GetUserByUUID(ctx context.Context, uuid string) (*User, error) {
	user := &User{}
	err := r.db.NewSelect().Model(user).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ListUsers returns all users.
func (r *Repository) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	err := r.db.NewSelect().Model(&users).Order("created_at ASC").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return users, nil
}

// UpsertUser inserts a new user or updates name/email if the UUID already exists.
// Returns the user's UUID.
func (r *Repository) UpsertUser(ctx context.Context, user *User) error {
	if user == nil || user.UUID == "" {
		return fmt.Errorf("invalid User: UUID is required")
	}
	q := r.db.NewInsert().Model(user).
		On("CONFLICT (uuid) DO UPDATE").
		Set("name = EXCLUDED.name").
		Set("email = EXCLUDED.email").
		Set("updated_at = CURRENT_TIMESTAMP")
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("failed to upsert user: %w", err)
	}
	return nil
}

// --- Project CRUD ---

// CreateProject inserts a new project.
func (r *Repository) CreateProject(ctx context.Context, project *Project) error {
	if project == nil {
		return fmt.Errorf("invalid Project")
	}
	if _, err := r.db.NewInsert().Model(project).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert project: %w", err)
	}
	return nil
}

// GetProjectByUUID retrieves a project by UUID.
func (r *Repository) GetProjectByUUID(ctx context.Context, uuid string) (*Project, error) {
	project := &Project{}
	err := r.db.NewSelect().Model(project).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return project, nil
}

// GetProjectByName retrieves a project by name. Returns an error if zero or
// multiple projects match (names are not guaranteed to be unique).
func (r *Repository) GetProjectByName(ctx context.Context, name string) (*Project, error) {
	var projects []*Project
	err := r.db.NewSelect().Model(&projects).Where("name = ?", name).Limit(2).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query project by name: %w", err)
	}
	switch len(projects) {
	case 0:
		return nil, fmt.Errorf("no project found with name %q", name)
	case 1:
		return projects[0], nil
	default:
		return nil, fmt.Errorf("multiple projects (%d) found with name %q; use --project-uuid to specify by UUID", len(projects), name)
	}
}

// ListProjects returns projects, optionally filtered by owner.
func (r *Repository) ListProjects(ctx context.Context, ownerUUID string) ([]*Project, error) {
	var projects []*Project
	q := r.db.NewSelect().Model(&projects).Order("created_at ASC")
	if ownerUUID != "" {
		q = q.Where("owner_uuid = ?", ownerUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	return projects, nil
}

// UpdateProject updates an existing project.
func (r *Repository) UpdateProject(ctx context.Context, project *Project) error {
	if project == nil {
		return fmt.Errorf("invalid Project")
	}
	if _, err := r.db.NewUpdate().Model(project).WherePK().Exec(ctx); err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}
	return nil
}

// ReassignProjectData moves all data owned by sourceUUID to targetUUID.
// This should be called before deleting a project so its records are not orphaned.
func (r *Repository) ReassignProjectData(ctx context.Context, sourceUUID, targetUUID string) error {
	tables := []string{"scans", "http_records", "findings", "scopes", "oast_interactions", "scan_logs"}
	for _, table := range tables {
		_, err := r.db.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET project_uuid = ? WHERE project_uuid = ?", table),
			targetUUID, sourceUUID)
		if err != nil {
			return fmt.Errorf("failed to reassign %s: %w", table, err)
		}
	}
	return nil
}

// DeleteProject deletes a project by UUID.
func (r *Repository) DeleteProject(ctx context.Context, uuid string) error {
	_, err := r.db.NewDelete().Model((*Project)(nil)).Where("uuid = ?", uuid).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	return nil
}

// PurgeProjectData deletes every row tied to projectUUID across all per-project
// tables. finding_records has no project_uuid, so it's pruned via a subquery on
// findings.id before the findings rows themselves are removed. Runs in a single
// transaction so a partial failure leaves the project intact.
func (r *Repository) PurgeProjectData(ctx context.Context, projectUUID string) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().
			TableExpr("finding_records").
			Where("finding_id IN (SELECT id FROM findings WHERE project_uuid = ?)", projectUUID).
			Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		tables := []string{
			"findings",
			"http_records",
			"scans",
			"scopes",
			"oast_interactions",
			"agentic_scans",
			"authentication_hostnames",
			"scan_logs",
		}
		for _, table := range tables {
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf("DELETE FROM %s WHERE project_uuid = ?", table),
				projectUUID); err != nil {
				return fmt.Errorf("failed to purge %s: %w", table, err)
			}
		}
		return nil
	})
}

// ProjectStatsRow holds per-project aggregated counts used by GetAllProjectsStats.
type ProjectStatsRow struct {
	ProjectUUID      string `bun:"project_uuid"`
	HTTPRecords      int64  `bun:"http_records"`
	HTTP2xx          int64  `bun:"http_2xx"`
	HTTP3xx          int64  `bun:"http_3xx"`
	HTTP4xx          int64  `bun:"http_4xx"`
	HTTP5xx          int64  `bun:"http_5xx"`
	Findings         int64  `bun:"findings"`
	Critical         int64  `bun:"critical"`
	High             int64  `bun:"high"`
	Medium           int64  `bun:"medium"`
	Low              int64  `bun:"low"`
	Info             int64  `bun:"info"`
	Scans            int64  `bun:"scans"`
	AgenticScans     int64  `bun:"agentic_scans"`
	OASTInteractions int64  `bun:"oast_interactions"`
}

// GetProjectStats returns aggregated stats for a single project.
func (r *Repository) GetProjectStats(ctx context.Context, projectUUID string) (*ProjectStatsRow, error) {
	stats := &ProjectStatsRow{ProjectUUID: projectUUID}

	// HTTP records with status breakdown
	type httpRow struct {
		Total   int64 `bun:"total"`
		HTTP2xx int64 `bun:"http_2xx"`
		HTTP3xx int64 `bun:"http_3xx"`
		HTTP4xx int64 `bun:"http_4xx"`
		HTTP5xx int64 `bun:"http_5xx"`
	}
	var hr httpRow
	err := r.db.NewSelect().Model((*HTTPRecord)(nil)).
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS http_2xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS http_3xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS http_4xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS http_5xx").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &hr)
	if err != nil {
		return nil, fmt.Errorf("http record stats: %w", err)
	}
	stats.HTTPRecords = hr.Total
	stats.HTTP2xx = hr.HTTP2xx
	stats.HTTP3xx = hr.HTTP3xx
	stats.HTTP4xx = hr.HTTP4xx
	stats.HTTP5xx = hr.HTTP5xx

	// Findings with severity breakdown
	type findingRow struct {
		Total    int64 `bun:"total"`
		Critical int64 `bun:"critical"`
		High     int64 `bun:"high"`
		Medium   int64 `bun:"medium"`
		Low      int64 `bun:"low"`
		Info     int64 `bun:"info"`
	}
	var fr findingRow
	err = r.db.NewSelect().Model((*Finding)(nil)).
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical").
		ColumnExpr("SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high").
		ColumnExpr("SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium").
		ColumnExpr("SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low").
		ColumnExpr("SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS info").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &fr)
	if err != nil {
		return nil, fmt.Errorf("finding stats: %w", err)
	}
	stats.Findings = fr.Total
	stats.Critical = fr.Critical
	stats.High = fr.High
	stats.Medium = fr.Medium
	stats.Low = fr.Low
	stats.Info = fr.Info

	// Scans
	scanCount, err := r.db.NewSelect().Model((*Scan)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan count: %w", err)
	}
	stats.Scans = int64(scanCount)

	// Agent runs
	agentCount, err := r.db.NewSelect().Model((*AgenticScan)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run count: %w", err)
	}
	stats.AgenticScans = int64(agentCount)

	// OAST interactions
	oastCount, err := r.db.NewSelect().Model((*OASTInteraction)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("oast count: %w", err)
	}
	stats.OASTInteractions = int64(oastCount)

	return stats, nil
}

// GetAllProjectsStats returns aggregated stats for all projects in bulk.
// Uses GROUP BY to avoid N+1 queries when listing projects.
func (r *Repository) GetAllProjectsStats(ctx context.Context) (map[string]*ProjectStatsRow, error) {
	result := make(map[string]*ProjectStatsRow)

	// HTTP records with status breakdown
	type httpGroupRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Total       int64  `bun:"total"`
		HTTP2xx     int64  `bun:"http_2xx"`
		HTTP3xx     int64  `bun:"http_3xx"`
		HTTP4xx     int64  `bun:"http_4xx"`
		HTTP5xx     int64  `bun:"http_5xx"`
	}
	var httpRows []httpGroupRow
	err := r.db.NewSelect().Model((*HTTPRecord)(nil)).
		Column("project_uuid").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS http_2xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS http_3xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS http_4xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS http_5xx").
		Group("project_uuid").
		Scan(ctx, &httpRows)
	if err != nil {
		return nil, fmt.Errorf("http record stats: %w", err)
	}
	for _, row := range httpRows {
		s := getOrCreate(result, row.ProjectUUID)
		s.HTTPRecords = row.Total
		s.HTTP2xx = row.HTTP2xx
		s.HTTP3xx = row.HTTP3xx
		s.HTTP4xx = row.HTTP4xx
		s.HTTP5xx = row.HTTP5xx
	}

	// Findings with severity breakdown
	type findingGroupRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Total       int64  `bun:"total"`
		Critical    int64  `bun:"critical"`
		High        int64  `bun:"high"`
		Medium      int64  `bun:"medium"`
		Low         int64  `bun:"low"`
		Info        int64  `bun:"info"`
	}
	var findingRows []findingGroupRow
	err = r.db.NewSelect().Model((*Finding)(nil)).
		Column("project_uuid").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical").
		ColumnExpr("SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high").
		ColumnExpr("SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium").
		ColumnExpr("SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low").
		ColumnExpr("SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS info").
		Group("project_uuid").
		Scan(ctx, &findingRows)
	if err != nil {
		return nil, fmt.Errorf("finding stats: %w", err)
	}
	for _, row := range findingRows {
		s := getOrCreate(result, row.ProjectUUID)
		s.Findings = row.Total
		s.Critical = row.Critical
		s.High = row.High
		s.Medium = row.Medium
		s.Low = row.Low
		s.Info = row.Info
	}

	// Simple counts: scans, agentic_scans, oast_interactions
	type countRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Count       int64  `bun:"count"`
	}

	tables := []struct {
		model interface{}
		field string
	}{
		{(*Scan)(nil), "scans"},
		{(*AgenticScan)(nil), "agentic_scans"},
		{(*OASTInteraction)(nil), "oast_interactions"},
	}

	for _, t := range tables {
		var rows []countRow
		err = r.db.NewSelect().
			TableExpr("(?) AS sub",
				r.db.NewSelect().Model(t.model).
					Column("project_uuid").
					ColumnExpr("COUNT(*) AS count").
					Group("project_uuid"),
			).Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("%s stats: %w", t.field, err)
		}
		for _, row := range rows {
			s := getOrCreate(result, row.ProjectUUID)
			switch t.field {
			case "scans":
				s.Scans = row.Count
			case "agentic_scans":
				s.AgenticScans = row.Count
			case "oast_interactions":
				s.OASTInteractions = row.Count
			}
		}
	}

	return result, nil
}

// getOrCreate returns an existing ProjectStatsRow for the UUID or creates a new one.
func getOrCreate(m map[string]*ProjectStatsRow, uuid string) *ProjectStatsRow {
	if s, ok := m[uuid]; ok {
		return s
	}
	s := &ProjectStatsRow{ProjectUUID: uuid}
	m[uuid] = s
	return s
}

// GetRelatedRecords finds HTTP records with the same hostname and a path
// matching the path-template of the given UUID's record.
// Default limit 10; excludes the source record itself.
// Results are filtered to the same path depth as the source record.
func (r *Repository) GetRelatedRecords(ctx context.Context, uuid string, limit int) ([]*HTTPRecord, error) {
	source, err := r.GetRecordByUUID(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("GetRelatedRecords: failed to get source record: %w", err)
	}

	if limit <= 0 {
		limit = 10
	}

	template := PathToTemplate(source.Path)
	likePattern := strings.ReplaceAll(template, "*", "%")

	// Fetch more than the limit to allow post-filter by path depth
	fetchLimit := limit * 3
	if fetchLimit < 30 {
		fetchLimit = 30
	}

	var candidates []*HTTPRecord
	err = r.db.NewSelect().
		Model(&candidates).
		Where("hostname = ?", source.Hostname).
		Where("path LIKE ?", likePattern).
		Where("uuid != ?", uuid).
		Order("created_at DESC").
		Limit(fetchLimit).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetRelatedRecords: query failed: %w", err)
	}

	// Filter to same path depth to avoid matching sub-resources
	sourceDepth := strings.Count(source.Path, "/")
	records := make([]*HTTPRecord, 0, limit)
	for _, rec := range candidates {
		if strings.Count(rec.Path, "/") == sourceDepth {
			records = append(records, rec)
			if len(records) >= limit {
				break
			}
		}
	}
	return records, nil
}

// UpdateRecordAnnotations updates the risk_score and/or remarks of an HTTP record.
// Only non-nil fields are updated. Returns an error if no record matches the UUID.
func (r *Repository) UpdateRecordAnnotations(ctx context.Context, uuid string, riskScore *int, remarks []string) error {
	q := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Where("uuid = ?", uuid)

	setCount := 0
	if riskScore != nil {
		q = q.Set("risk_score = ?", *riskScore)
		setCount++
	}
	if remarks != nil {
		remarksJSON, err := json.Marshal(remarks)
		if err != nil {
			return fmt.Errorf("UpdateRecordAnnotations: failed to marshal remarks: %w", err)
		}
		q = q.Set("remarks = ?", string(remarksJSON))
		setCount++
	}

	if setCount == 0 {
		return nil
	}

	result, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateRecordAnnotations: failed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("UpdateRecordAnnotations: no record found with uuid %s", uuid)
	}
	return nil
}

// GetRecordsWithResponseBody returns HTTP records that have a non-empty response body,
// using UUID-based cursor pagination. Only columns needed for batch secret scanning are selected.
func (r *Repository) GetRecordsWithResponseBody(ctx context.Context, projectUUID, afterUUID string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Column("uuid", "hostname", "url", "has_response", "raw_response", "response_content_type").
		Where("has_response = ?", true).
		Where("raw_response IS NOT NULL").
		Where("length(raw_response) > 0")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if afterUUID != "" {
		q = q.Where("uuid > ?", afterUUID)
	}
	err := q.OrderExpr("uuid ASC").Limit(limit).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query records with response body: %w", err)
	}
	return records, nil
}

// SaveOASTInteraction stores an OAST interaction record.
func (r *Repository) SaveOASTInteraction(ctx context.Context, interaction *OASTInteraction) error {
	if interaction == nil {
		return fmt.Errorf("invalid OASTInteraction")
	}
	interaction.ProjectUUID = defaultProjectUUID(interaction.ProjectUUID)
	if _, err := r.db.NewInsert().Model(interaction).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert OAST interaction: %w", err)
	}
	return nil
}

// GetOASTInteractionsByScan retrieves OAST interactions for a specific scan.
func (r *Repository) GetOASTInteractionsByScan(ctx context.Context, scanUUID string) ([]*OASTInteraction, error) {
	var interactions []*OASTInteraction
	err := r.db.NewSelect().
		Model(&interactions).
		Where("scan_uuid = ?", scanUUID).
		Order("interacted_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query OAST interactions: %w", err)
	}
	return interactions, nil
}

// GetOASTInteractionByID retrieves a single OAST interaction by its numeric ID.
func (r *Repository) GetOASTInteractionByID(ctx context.Context, id int64) (*OASTInteraction, error) {
	interaction := &OASTInteraction{}
	err := r.db.NewSelect().
		Model(interaction).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return interaction, nil
}

// ListOASTInteractions returns a paginated, filtered list of OAST interactions.
// Heavy columns (raw_request, raw_response) are excluded for list performance.
func (r *Repository) ListOASTInteractions(ctx context.Context, projectUUID, scanUUID, protocol, moduleID, search string, limit, offset int) ([]*OASTInteraction, int64, error) {
	var interactions []*OASTInteraction
	q := r.db.NewSelect().
		Model(&interactions).
		ExcludeColumn("raw_request", "raw_response").
		Order("interacted_at DESC")

	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if scanUUID != "" {
		q = q.Where("scan_uuid = ?", scanUUID)
	}
	if protocol != "" {
		q = q.Where("protocol = ?", protocol)
	}
	if moduleID != "" {
		q = q.Where("module_id = ?", moduleID)
	}
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("(target_url LIKE ? OR parameter_name LIKE ? OR unique_id LIKE ?)", like, like, like)
	}

	q = q.Limit(limit).Offset(offset)

	total, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query OAST interactions: %w", err)
	}
	return interactions, int64(total), nil
}

// DeleteRecord deletes an HTTP record by UUID, including any finding_records junction rows.
func (r *Repository) DeleteRecord(ctx context.Context, uuid string) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().TableExpr("finding_records").Where("record_uuid = ?", uuid).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid = ?", uuid).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete record: %w", err)
		}
		return nil
	})
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

// DeleteOASTInteraction deletes an OAST interaction by its numeric ID.
func (r *Repository) DeleteOASTInteraction(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*OASTInteraction)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete OAST interaction: %w", err)
	}
	return nil
}

// DeduplicateRecordsBySource removes duplicate HTTP records for a given source that share
// identical (hostname, method, status_code, response_content_length, response_hash).
// Within each group, the record with the shortest path is kept.
// Returns the number of deleted records.
func (r *Repository) DeduplicateRecordsBySource(ctx context.Context, projectUUID, source string) (int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Use ROW_NUMBER window function to identify duplicates, keeping the
	// record with shortest path (then oldest created_at as tiebreaker).
	dupQuery := `
		SELECT uuid FROM (
			SELECT uuid, ROW_NUMBER() OVER (
				PARTITION BY hostname, method, status_code, response_content_length, response_hash
				ORDER BY LENGTH(path) ASC, created_at ASC
			) AS rn
			FROM http_records
			WHERE source = ?
			  AND project_uuid = ?
			  AND has_response = true
			  AND response_hash != ''
		) sub WHERE rn > 1`

	var uuids []string
	if err := r.db.NewRaw(dupQuery, source, projectUUID).Scan(ctx, &uuids); err != nil {
		return 0, fmt.Errorf("failed to identify duplicate %s records: %w", source, err)
	}

	if len(uuids) == 0 {
		return 0, nil
	}

	// Delete junction rows and records in a transaction
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Clean up finding_records junction rows
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		// Delete the duplicate records
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete duplicate records: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return int64(len(uuids)), nil
}

// DeduplicateDeparosRecords removes duplicate deparos HTTP records.
// Delegates to DeduplicateRecordsBySource with source "deparos".
func (r *Repository) DeduplicateDeparosRecords(ctx context.Context, projectUUID string) (int64, error) {
	return r.DeduplicateRecordsBySource(ctx, projectUUID, "deparos")
}

// DeduplicateSoftDeparosRecords removes deparos HTTP records that are "soft duplicates":
// same response characteristics (status, size, word count, content type) under the same
// 2-segment path prefix. This catches cases where the server echoes part of the URL in the
// response body, causing different response_hash values for functionally identical pages.
// Only groups with 3+ members are collapsed. The shortest path per group is kept.
func (r *Repository) DeduplicateSoftDeparosRecords(ctx context.Context, projectUUID string) (int64, map[int]int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Path prefix extraction: first 2 segments (SQLite/PG compatible).
	pathPrefix := `CASE
		WHEN INSTR(SUBSTR(path, 2), '/') = 0 THEN path
		WHEN INSTR(SUBSTR(path, INSTR(SUBSTR(path, 2), '/') + 2), '/') = 0 THEN path
		ELSE SUBSTR(path, 1, INSTR(SUBSTR(path, 2), '/') + INSTR(SUBSTR(path, INSTR(SUBSTR(path, 2), '/') + 2), '/'))
	END`

	dupQuery := fmt.Sprintf(`
		SELECT uuid FROM (
			SELECT uuid,
				ROW_NUMBER() OVER (
					PARTITION BY hostname, method, status_code, response_content_length,
						response_words, response_content_type, %s
					ORDER BY LENGTH(path) ASC, created_at ASC
				) AS rn,
				COUNT(*) OVER (
					PARTITION BY hostname, method, status_code, response_content_length,
						response_words, response_content_type, %s
				) AS group_size
			FROM http_records
			WHERE source = 'deparos'
			  AND project_uuid = ?
			  AND has_response = true
		) sub WHERE rn > 1 AND group_size >= 3`, pathPrefix, pathPrefix)

	var uuids []string
	if err := r.db.NewRaw(dupQuery, projectUUID).Scan(ctx, &uuids); err != nil {
		return 0, nil, fmt.Errorf("failed to identify soft-duplicate deparos records: %w", err)
	}

	if len(uuids) == 0 {
		return 0, nil, nil
	}

	// Collect status code breakdown before deleting
	type statusCount struct {
		StatusCode int   `bun:"status_code"`
		Count      int64 `bun:"cnt"`
	}
	var counts []statusCount
	if err := r.db.NewRaw(
		"SELECT status_code, COUNT(*) AS cnt FROM http_records WHERE uuid IN (?) GROUP BY status_code",
		bun.In(uuids),
	).Scan(ctx, &counts); err != nil {
		zap.L().Debug("Failed to collect status code stats for soft-dedup", zap.Error(err))
	}
	statusCodes := make(map[int]int64, len(counts))
	for _, c := range counts {
		statusCodes[c.StatusCode] = c.Count
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete soft-duplicate records: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	return int64(len(uuids)), statusCodes, nil
}

// DeduplicateFindings merges duplicate findings that share the same
// (module_id, severity, matched_at URL) within a project. This collapses
// findings where the same module fires many times on the same URL with different
// payloads (e.g., input-behavior-probe producing dozens of results per endpoint).
// Within each group, the earliest finding is kept and the request/response pairs
// from duplicates are collected into its AdditionalEvidence field.
// Returns the count of deleted findings and the number of groups that were merged.
func (r *Repository) DeduplicateFindings(ctx context.Context, projectUUID string) (deleted int64, grouped int64, err error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Identify duplicate groups: for each group, get the survivor (rn=1) and duplicates (rn>1).
	groupQuery := `
		SELECT id, request, response, additional_evidence, ROW_NUMBER() OVER (
			PARTITION BY module_id, severity, json_extract(matched_at, '$[0]')
			ORDER BY created_at ASC
		) AS rn,
		-- Stable group key for matching survivors to duplicates
		module_id || '|' || severity || '|' || COALESCE(json_extract(matched_at, '$[0]'), '') AS group_key
		FROM findings
		WHERE project_uuid = ?
		  AND matched_at IS NOT NULL
		  AND matched_at != '[]'
		  AND matched_at != ''`

	type findingRow struct {
		ID                 int64    `bun:"id"`
		Request            string   `bun:"request"`
		Response           string   `bun:"response"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
		RN                 int64    `bun:"rn"`
		GroupKey           string   `bun:"group_key"`
	}

	var rows []findingRow
	if err := r.db.NewRaw(groupQuery, projectUUID).Scan(ctx, &rows); err != nil {
		return 0, 0, fmt.Errorf("failed to identify duplicate findings: %w", err)
	}

	// Build survivor map and collect evidence from duplicates per group.
	type groupData struct {
		survivorID       int64
		existingEvidence []string
		newEvidence      []string
		dupIDs           []int64
	}
	groups := make(map[string]*groupData)
	for _, row := range rows {
		g, ok := groups[row.GroupKey]
		if !ok {
			g = &groupData{}
			groups[row.GroupKey] = g
		}
		if row.RN == 1 {
			g.survivorID = row.ID
			g.existingEvidence = row.AdditionalEvidence
		} else {
			g.dupIDs = append(g.dupIDs, row.ID)
			ev := buildEvidence(row.Request, row.Response)
			if ev != "" {
				g.newEvidence = append(g.newEvidence, ev)
			}
			// Carry forward any evidence the duplicate already had.
			g.newEvidence = append(g.newEvidence, row.AdditionalEvidence...)
		}
	}

	// Collect all duplicate IDs and count groups that actually had duplicates.
	var allDupIDs []int64
	var groupCount int64
	for _, g := range groups {
		if len(g.dupIDs) == 0 {
			continue
		}
		groupCount++
		allDupIDs = append(allDupIDs, g.dupIDs...)
	}

	if len(allDupIDs) == 0 {
		return 0, 0, nil
	}

	// Update survivors with merged evidence, then delete duplicates.
	err = r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, g := range groups {
			if len(g.newEvidence) == 0 {
				continue
			}
			merged := append(g.existingEvidence, g.newEvidence...)
			const maxAdditionalEvidence = 10
			if len(merged) > maxAdditionalEvidence {
				merged = merged[:maxAdditionalEvidence]
			}
			if _, err := tx.NewUpdate().Model((*Finding)(nil)).
				Set("additional_evidence = ?", merged).
				Where("id = ?", g.survivorID).
				Exec(ctx); err != nil {
				return fmt.Errorf("failed to update survivor evidence: %w", err)
			}
		}
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE finding_id IN (?)", bun.In(allDupIDs)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id IN (?)", bun.In(allDupIDs)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete duplicate findings: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return int64(len(allDupIDs)), groupCount, nil
}

// HostTarget represents a distinct scheme+hostname+port combination from HTTP records.
type HostTarget struct {
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
}

// GetDistinctHosts returns distinct scheme+hostname+port combinations from HTTP records, filtered by project.
func (r *Repository) GetDistinctHosts(ctx context.Context, projectUUID string) ([]HostTarget, error) {
	var hosts []HostTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx, &hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct hosts: %w", err)
	}
	return hosts, nil
}

// PathTarget represents a distinct scheme+hostname+port+path combination from HTTP records.
type PathTarget struct {
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
	Path     string `bun:"path"`
}

// GetDistinctPaths returns distinct scheme+hostname+port+path combinations from HTTP records, filtered by project.
func (r *Repository) GetDistinctPaths(ctx context.Context, projectUUID string) ([]PathTarget, error) {
	var paths []PathTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port, path")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx, &paths)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct paths: %w", err)
	}
	return paths, nil
}

// AppendRemarks batch-appends remarks to HTTPRecords identified by UUID.
// Existing remarks are preserved and duplicates within each record are deduplicated.
func (r *Repository) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	if len(annotations) == 0 {
		return nil
	}

	for uuid, newRemarks := range annotations {
		if len(newRemarks) == 0 {
			continue
		}

		// Fetch current remarks
		record := &HTTPRecord{}
		err := r.db.NewSelect().Model(record).Column("remarks").Where("uuid = ?", uuid).Scan(ctx)
		if err != nil {
			continue // skip missing records
		}

		// Merge and deduplicate
		seen := make(map[string]struct{}, len(record.Remarks)+len(newRemarks))
		merged := make([]string, 0, len(record.Remarks)+len(newRemarks))
		for _, r := range record.Remarks {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				merged = append(merged, r)
			}
		}
		for _, r := range newRemarks {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				merged = append(merged, r)
			}
		}

		remarksJSON, err := json.Marshal(merged)
		if err != nil {
			continue
		}

		_, _ = r.db.NewUpdate().
			Model((*HTTPRecord)(nil)).
			Set("remarks = ?", string(remarksJSON)).
			Where("uuid = ?", uuid).
			Exec(ctx)
	}

	return nil
}

// UpdateRiskScores batch-updates risk_score on HTTPRecords identified by UUID.
// Uses CASE/WHEN SQL to update up to 500 records per statement, minimizing roundtrips.
func (r *Repository) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	if len(scores) == 0 {
		return nil
	}

	// Collect UUIDs into ordered slice for deterministic batching
	uuids := make([]string, 0, len(scores))
	for uuid := range scores {
		uuids = append(uuids, uuid)
	}

	const batchSize = 500
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for i := 0; i < len(uuids); i += batchSize {
			end := i + batchSize
			if end > len(uuids) {
				end = len(uuids)
			}
			if err := updateRiskScoreBatch(ctx, tx, scores, uuids[i:end]); err != nil {
				return err
			}
		}
		return nil
	})
}

// updateRiskScoreBatch executes a single CASE/WHEN UPDATE for a batch of UUIDs.
func updateRiskScoreBatch(ctx context.Context, tx bun.Tx, scores map[string]int, uuids []string) error {
	// Build: UPDATE http_records SET risk_score = CASE uuid WHEN ? THEN ? ... END WHERE uuid IN (?,...)
	// Each UUID contributes 2 args to CASE + 1 arg to IN = 3 args per UUID.
	// Batch of 500 = 1500 args, well within SQLITE_MAX_VARIABLE_NUMBER (999 default raised in modern builds).
	args := make([]interface{}, 0, len(uuids)*3)
	var caseSQL strings.Builder
	caseSQL.WriteString("UPDATE http_records SET risk_score = CASE uuid ")
	for _, uuid := range uuids {
		caseSQL.WriteString("WHEN ? THEN ? ")
		args = append(args, uuid, scores[uuid])
	}
	caseSQL.WriteString("END WHERE uuid IN (")
	for i, uuid := range uuids {
		if i > 0 {
			caseSQL.WriteByte(',')
		}
		caseSQL.WriteByte('?')
		args = append(args, uuid)
	}
	caseSQL.WriteByte(')')

	_, err := tx.ExecContext(ctx, caseSQL.String(), args...)
	if err != nil {
		return fmt.Errorf("failed to batch update risk_scores: %w", err)
	}
	return nil
}
