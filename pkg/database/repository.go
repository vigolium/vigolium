package database

import (
	"context"
	"database/sql"
	"encoding/json"
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
// Returns the UUID of the saved record.
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

	if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to insert record: %w", err)
	}

	return record.UUID, nil
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

// CreateScan inserts a new scan record
func (r *Repository) CreateScan(ctx context.Context, scan *Scan) error {
	if scan == nil {
		return fmt.Errorf("invalid Scan")
	}
	scan.ProjectUUID = defaultProjectUUID(scan.ProjectUUID)
	if _, err := r.db.NewInsert().Model(scan).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert scan: %w", err)
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

// CompleteScan marks a scan as completed (or failed if errMsg is non-empty)
// and populates severity counts from the findings table.
func (r *Repository) CompleteScan(ctx context.Context, scanUUID string, errMsg string) error {
	status := "completed"
	if errMsg != "" {
		status = "failed"
	}

	// Populate severity counts from findings associated with this scan
	type severityCount struct {
		Severity string `bun:"severity"`
		Count    int64  `bun:"count"`
	}
	var counts []severityCount
	_ = r.db.NewSelect().
		TableExpr("findings").
		ColumnExpr("severity").
		ColumnExpr("COUNT(*) AS count").
		Where("scan_uuid = ?", scanUUID).
		GroupExpr("severity").
		Scan(ctx, &counts)

	var critical, high, medium, low, info, suspect int64
	var totalFindings int64
	for _, c := range counts {
		totalFindings += c.Count
		switch c.Severity {
		case "critical":
			critical = c.Count
		case "high":
			high = c.Count
		case "medium":
			medium = c.Count
		case "low":
			low = c.Count
		case "info":
			info = c.Count
		case "suspect":
			suspect = c.Count
		}
	}

	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("status = ?", status).
		Set("error_message = ?", errMsg).
		Set("finished_at = CURRENT_TIMESTAMP").
		Set("updated_at = CURRENT_TIMESTAMP").
		Set("critical_count = ?", critical).
		Set("high_count = ?", high).
		Set("medium_count = ?", medium).
		Set("low_count = ?", low).
		Set("info_count = ?", info).
		Set("suspect_count = ?", suspect).
		Where("uuid = ?", scanUUID)

	// Only update total_findings if we got counts (avoid overwriting a value set elsewhere)
	if totalFindings > 0 {
		q = q.Set("total_findings = ?", totalFindings)
	}

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
	// Format cursor_at to match SQLite's CURRENT_TIMESTAMP format (no timezone suffix).
	// Go's time.Time serialization adds timezone info that breaks SQLite text comparison.
	cursorAt := recordCreatedAt.UTC().Format("2006-01-02 15:04:05")
	_, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("cursor_at = ?", cursorAt).
		Set("cursor_uuid = ?", recordUUID).
		Set("processed_count = processed_count + 1").
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
	q := r.db.NewSelect().Model((*HTTPRecord)(nil))

	if !cursorAt.IsZero() {
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", cursorAt, cursorAt, cursorUUID)
	}

	if len(hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.In(hostnames))
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
		return nil, fmt.Errorf("multiple projects (%d) found with name %q; use --project-id to specify by UUID", len(projects), name)
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
	tables := []string{"scans", "http_records", "findings", "scopes", "source_repos", "oast_interactions", "scan_logs"}
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
	AgentRuns        int64  `bun:"agent_runs"`
	SourceRepos      int64  `bun:"source_repos"`
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
	agentCount, err := r.db.NewSelect().Model((*AgentRun)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run count: %w", err)
	}
	stats.AgentRuns = int64(agentCount)

	// Source repos
	repoCount, err := r.db.NewSelect().Model((*SourceRepo)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("source repo count: %w", err)
	}
	stats.SourceRepos = int64(repoCount)

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

	// Simple counts: scans, agent_runs, source_repos, oast_interactions
	type countRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Count       int64  `bun:"count"`
	}

	tables := []struct {
		model interface{}
		field string
	}{
		{(*Scan)(nil), "scans"},
		{(*AgentRun)(nil), "agent_runs"},
		{(*SourceRepo)(nil), "source_repos"},
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
			case "agent_runs":
				s.AgentRuns = row.Count
			case "source_repos":
				s.SourceRepos = row.Count
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
		Column("uuid", "hostname", "url", "response_body", "response_content_type").
		Where("has_response = ?", true).
		Where("response_body IS NOT NULL").
		Where("length(response_body) > 0")
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

// --- Source Repo CRUD ---

// CreateSourceRepo inserts a new source repo record.
func (r *Repository) CreateSourceRepo(ctx context.Context, repo *SourceRepo) error {
	if repo == nil {
		return fmt.Errorf("invalid SourceRepo")
	}
	repo.ProjectUUID = defaultProjectUUID(repo.ProjectUUID)
	repo.CreatedAt = time.Now()
	repo.UpdatedAt = time.Now()
	if _, err := r.db.NewInsert().Model(repo).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert source repo: %w", err)
	}
	return nil
}

// GetSourceRepoByID retrieves a source repo by its ID.
func (r *Repository) GetSourceRepoByID(ctx context.Context, id int64) (*SourceRepo, error) {
	repo := &SourceRepo{}
	err := r.db.NewSelect().
		Model(repo).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// GetSourceReposByHostname retrieves source repos for a hostname within a project.
func (r *Repository) GetSourceReposByHostname(ctx context.Context, projectUUID, hostname string) ([]*SourceRepo, error) {
	var repos []*SourceRepo
	q := r.db.NewSelect().
		Model(&repos).
		Where("hostname = ?", hostname).
		Order("created_at DESC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return repos, nil
}

// ListSourceRepos returns source repos ordered by created_at descending with limit/offset, filtered by project.
func (r *Repository) ListSourceRepos(ctx context.Context, projectUUID string, limit, offset int) ([]*SourceRepo, int64, error) {
	var repos []*SourceRepo
	q := r.db.NewSelect().
		Model(&repos).
		OrderExpr("created_at DESC").
		Limit(limit).
		Offset(offset)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	count, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list source repos: %w", err)
	}
	return repos, int64(count), nil
}

// UpdateSourceRepo updates an existing source repo record.
func (r *Repository) UpdateSourceRepo(ctx context.Context, repo *SourceRepo) error {
	if repo == nil {
		return fmt.Errorf("invalid SourceRepo")
	}
	repo.UpdatedAt = time.Now()
	if _, err := r.db.NewUpdate().Model(repo).WherePK().Exec(ctx); err != nil {
		return fmt.Errorf("failed to update source repo: %w", err)
	}
	return nil
}

// DeleteSourceRepo deletes a source repo by its ID.
func (r *Repository) DeleteSourceRepo(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*SourceRepo)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete source repo: %w", err)
	}
	return nil
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
		ID                 int64  `bun:"id"`
		Request            string `bun:"request"`
		Response           string `bun:"response"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
		RN                 int64  `bun:"rn"`
		GroupKey           string `bun:"group_key"`
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

// ---------------------------------------------------------------------------
// Agent Runs
// ---------------------------------------------------------------------------

// CreateAgentRun inserts a new agent run record.
func (r *Repository) CreateAgentRun(ctx context.Context, run *AgentRun) error {
	run.ProjectUUID = defaultProjectUUID(run.ProjectUUID)
	if _, err := r.db.NewInsert().Model(run).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert agent run: %w", err)
	}
	return nil
}

// GetAgentRun retrieves an agent run by UUID.
func (r *Repository) GetAgentRun(ctx context.Context, uuid string) (*AgentRun, error) {
	run := &AgentRun{}
	err := r.db.NewSelect().Model(run).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run not found: %w", err)
	}
	return run, nil
}

// UpdateAgentRun updates an agent run record (full update by UUID).
func (r *Repository) UpdateAgentRun(ctx context.Context, run *AgentRun) error {
	_, err := r.db.NewUpdate().Model(run).Where("uuid = ?", run.UUID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update agent run: %w", err)
	}
	return nil
}

// ListAgentRuns returns paginated agent runs for a project, ordered by created_at DESC.
func (r *Repository) ListAgentRuns(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgentRun, int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)
	if limit <= 0 {
		limit = 50
	}

	// Count total matching rows (without LIMIT/OFFSET).
	// Exclude child runs (those with a parent) from the default listing.
	countQ := r.db.NewSelect().Model((*AgentRun)(nil)).
		Where("project_uuid = ?", projectUUID).
		Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')")
	if mode != "" {
		countQ = countQ.Where("mode = ?", mode)
	}
	total, countErr := countQ.Count(ctx)

	var runs []*AgentRun
	q := r.db.NewSelect().Model(&runs).
		Where("project_uuid = ?", projectUUID).
		Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')").
		OrderExpr("created_at DESC").
		Limit(limit).
		Offset(offset)

	if mode != "" {
		q = q.Where("mode = ?", mode)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to list agent runs: %w", err)
	}

	// Fall back to page size if count query failed.
	if countErr != nil {
		total = len(runs)
	}
	return runs, int64(total), nil
}

// GetChildAgentRuns returns agent runs whose ParentRunUUID matches the given UUID.
func (r *Repository) GetChildAgentRuns(ctx context.Context, parentUUID string) ([]*AgentRun, error) {
	var runs []*AgentRun
	err := r.db.NewSelect().Model(&runs).
		Where("parent_run_uuid = ?", parentUUID).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get child agent runs: %w", err)
	}
	return runs, nil
}

// DeleteOldAgentRuns removes completed/failed agent runs older than the given duration.
func (r *Repository) DeleteOldAgentRuns(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := r.db.NewDelete().Model((*AgentRun)(nil)).
		Where("status IN (?, ?)", "completed", "failed").
		Where("completed_at < ?", cutoff).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old agent runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---------------------------------------------------------------------------
// Session Hostnames
// ---------------------------------------------------------------------------

// SaveSessionHostname upserts a single session hostname record.
// Conflict key: (project_uuid, hostname, session_name).
func (r *Repository) SaveSessionHostname(ctx context.Context, sh *SessionHostname) error {
	if sh == nil {
		return fmt.Errorf("invalid SessionHostname")
	}
	sh.ProjectUUID = defaultProjectUUID(sh.ProjectUUID)
	now := time.Now()
	sh.CreatedAt = now
	sh.UpdatedAt = now

	_, err := r.db.NewInsert().Model(sh).
		On("CONFLICT (project_uuid, hostname, session_name) DO UPDATE").
		Set("scan_uuid = EXCLUDED.scan_uuid").
		Set("session_role = EXCLUDED.session_role").
		Set("position = EXCLUDED.position").
		Set("session_token = EXCLUDED.session_token").
		Set("headers = EXCLUDED.headers").
		Set("login_url = EXCLUDED.login_url").
		Set("login_method = EXCLUDED.login_method").
		Set("login_content_type = EXCLUDED.login_content_type").
		Set("login_body = EXCLUDED.login_body").
		Set("login_request = EXCLUDED.login_request").
		Set("login_response = EXCLUDED.login_response").
		Set("extract_rules = EXCLUDED.extract_rules").
		Set("source = EXCLUDED.source").
		Set("hydrated_at = EXCLUDED.hydrated_at").
		Set("updated_at = CURRENT_TIMESTAMP").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert session hostname: %w", err)
	}
	return nil
}

// SaveSessionHostnames batch-upserts session hostname records in a transaction.
func (r *Repository) SaveSessionHostnames(ctx context.Context, rows []*SessionHostname) error {
	if len(rows) == 0 {
		return nil
	}
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, sh := range rows {
			sh.ProjectUUID = defaultProjectUUID(sh.ProjectUUID)
			now := time.Now()
			sh.CreatedAt = now
			sh.UpdatedAt = now

			_, err := tx.NewInsert().Model(sh).
				On("CONFLICT (project_uuid, hostname, session_name) DO UPDATE").
				Set("scan_uuid = EXCLUDED.scan_uuid").
				Set("session_role = EXCLUDED.session_role").
				Set("position = EXCLUDED.position").
				Set("session_token = EXCLUDED.session_token").
				Set("headers = EXCLUDED.headers").
				Set("login_url = EXCLUDED.login_url").
				Set("login_method = EXCLUDED.login_method").
				Set("login_content_type = EXCLUDED.login_content_type").
				Set("login_body = EXCLUDED.login_body").
				Set("login_request = EXCLUDED.login_request").
				Set("login_response = EXCLUDED.login_response").
				Set("extract_rules = EXCLUDED.extract_rules").
				Set("source = EXCLUDED.source").
				Set("hydrated_at = EXCLUDED.hydrated_at").
				Set("updated_at = CURRENT_TIMESTAMP").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to upsert session hostname %q: %w", sh.SessionName, err)
			}
		}
		return nil
	})
}

// GetSessionHostnamesByHostname returns session hostnames for a project+hostname, ordered by position.
func (r *Repository) GetSessionHostnamesByHostname(ctx context.Context, projectUUID, hostname string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", hostname).
		Order("position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames: %w", err)
	}
	return rows, nil
}

// GetSessionHostnamesByProject returns all session hostnames for a project, ordered by hostname then position.
func (r *Repository) GetSessionHostnamesByProject(ctx context.Context, projectUUID string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Order("hostname ASC", "position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames by project: %w", err)
	}
	return rows, nil
}

// GetSessionHostnamesByScan returns session hostnames for a project+scan, ordered by hostname then position.
func (r *Repository) GetSessionHostnamesByScan(ctx context.Context, projectUUID, scanUUID string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("scan_uuid = ?", scanUUID).
		Order("hostname ASC", "position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames by scan: %w", err)
	}
	return rows, nil
}

// DeleteSessionHostname deletes a single session hostname by ID.
func (r *Repository) DeleteSessionHostname(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*SessionHostname)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostname: %w", err)
	}
	return nil
}

// DeleteSessionHostnamesByHostname deletes all session hostnames for a project+hostname.
func (r *Repository) DeleteSessionHostnamesByHostname(ctx context.Context, projectUUID, hostname string) error {
	_, err := r.db.NewDelete().
		Model((*SessionHostname)(nil)).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", hostname).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostnames: %w", err)
	}
	return nil
}
