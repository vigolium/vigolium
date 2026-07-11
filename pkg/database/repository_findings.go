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

// FindingWrite bundles the arguments needed to persist a single finding,
// allowing a batch of findings to be coalesced into one transaction.
// See Repository.SaveFindingsBatch.
type FindingWrite struct {
	Event           *output.ResultEvent
	HTTPRecordUUIDs []string
	ScanUUID        string
	ProjectUUID     string
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

	inserted, err := r.saveFindingIDB(ctx, r.db, finding, httpRecordUUIDs)
	if err != nil {
		return err
	}
	if inserted {
		r.emitFindingSaved(finding)
	}
	return nil
}

// SaveFindingsBatch persists a batch of findings in a single transaction,
// coalescing what would otherwise be one transaction (and fsync) per finding.
// Findings are converted up front so a conversion error skips just that finding
// rather than aborting the batch. If the transaction itself fails (e.g. a
// database-level error), every finding is retried individually so one bad
// finding can't drop the rest — preserving the error isolation of per-finding
// SaveFinding while keeping the fast path a single transaction.
func (r *Repository) SaveFindingsBatch(ctx context.Context, writes []FindingWrite) error {
	findings := make([]*Finding, 0, len(writes))
	for i := range writes {
		w := &writes[i]
		if w.Event == nil {
			continue
		}
		f := &Finding{
			HTTPRecordUUIDs: w.HTTPRecordUUIDs,
			ScanUUID:        w.ScanUUID,
			ProjectUUID:     defaultProjectUUID(w.ProjectUUID),
		}
		if err := f.FromResultEvent(w.Event); err != nil {
			zap.L().Warn("SaveFindingsBatch: skipping unconvertible finding", zap.Error(err))
			continue
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		return nil
	}
	return firstResultErr(r.saveFindingsBatchCore(ctx, findings))
}

// saveFindingIDB inserts a single finding using the given bun.IDB, which may be
// the shared *DB (single write) or a bun.Tx (batched write). The dedup/append
// and junction logic is identical in both cases. Returns inserted=true only when
// a new finding row was written (false on a dedup-append to an existing finding),
// so callers fire the OnFindingSaved hook exactly once per genuinely new finding.
func (r *Repository) saveFindingIDB(ctx context.Context, idb bun.IDB, finding *Finding, httpRecordUUIDs []string) (bool, error) {
	// Atomic dedup: INSERT with conflict resolution on finding_hash.
	// If a duplicate hash exists, the row is silently skipped.
	var res sql.Result
	var err error
	if finding.FindingHash != "" {
		res, err = idb.NewInsert().Model(finding).
			On("CONFLICT (project_uuid, finding_hash) DO NOTHING").
			Exec(ctx)
	} else {
		res, err = idb.NewInsert().Model(finding).Exec(ctx)
	}
	if err != nil {
		return false, fmt.Errorf("failed to insert finding: %w", err)
	}

	// If ON CONFLICT fired, no row was inserted — append records and evidence to existing finding
	if finding.FindingHash != "" {
		if n, _ := res.RowsAffected(); n == 0 {
			return false, r.appendRecordsToFinding(ctx, idb, finding.ProjectUUID, finding.FindingHash, httpRecordUUIDs, buildEvidence(finding.Request, finding.Response), finding.ScanUUID)
		}
	}

	r.insertFindingRecords(ctx, idb, finding.ID, httpRecordUUIDs)

	return true, nil
}

// SaveFindingDirect inserts a pre-built Finding directly (without ResultEvent conversion).
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFindingDirect(ctx context.Context, finding *Finding) error {
	if finding == nil {
		return fmt.Errorf("invalid Finding")
	}

	finding.ProjectUUID = defaultProjectUUID(finding.ProjectUUID)

	inserted, err := r.saveFindingIDB(ctx, r.db, finding, finding.HTTPRecordUUIDs)
	if err != nil {
		return err
	}
	if inserted {
		r.emitFindingSaved(finding)
	}
	return nil
}

// FindingSaveResult reports the outcome of persisting one finding in a batched
// direct save, aligned by index with the input slice passed to
// SaveFindingsDirectBatch.
type FindingSaveResult struct {
	Inserted bool  // a new finding row was written (false on a dedup-append to an existing finding)
	Err      error // non-nil if this finding failed to save
}

// SaveFindingsDirectBatch persists a batch of pre-built findings in a single
// transaction — the batch analogue of SaveFindingDirect, used by bulk importers
// to coalesce what would otherwise be one transaction (and fsync) per finding.
// The returned slice is aligned with the input; the top-level error is the first
// per-finding error, if any.
func (r *Repository) SaveFindingsDirectBatch(ctx context.Context, findings []*Finding) ([]FindingSaveResult, error) {
	for _, f := range findings {
		if f != nil {
			f.ProjectUUID = defaultProjectUUID(f.ProjectUUID)
		}
	}
	results := r.saveFindingsBatchCore(ctx, findings)
	return results, firstResultErr(results)
}

// saveFindingsBatchCore persists pre-built findings in one transaction, retrying
// each finding individually if the transaction fails so one bad finding can't
// drop the rest, and firing OnFindingSaved hooks only after commit so a mirror
// never sees a rolled-back finding. nil entries are tolerated (zero-value
// result). The returned slice is aligned with the input. This is the shared
// engine behind SaveFindingsBatch (which adapts []FindingWrite) and
// SaveFindingsDirectBatch (pre-built []*Finding); callers own input conversion
// and ProjectUUID defaulting.
func (r *Repository) saveFindingsBatchCore(ctx context.Context, findings []*Finding) []FindingSaveResult {
	results := make([]FindingSaveResult, len(findings))
	if len(findings) == 0 {
		return results
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for i, f := range findings {
			if f == nil {
				continue
			}
			inserted, err := r.saveFindingIDB(ctx, tx, f, f.HTTPRecordUUIDs)
			if err != nil {
				return err
			}
			results[i].Inserted = inserted
		}
		return nil
	})
	if err == nil {
		for i, f := range findings {
			if results[i].Inserted {
				r.emitFindingSaved(f)
			}
		}
		return results
	}

	zap.L().Warn("saveFindingsBatchCore: transaction failed, retrying findings individually", zap.Error(err))
	for i, f := range findings {
		results[i] = FindingSaveResult{}
		if f == nil {
			continue
		}
		inserted, e := r.saveFindingIDB(ctx, r.db, f, f.HTTPRecordUUIDs)
		results[i].Inserted = inserted
		results[i].Err = e
		if inserted {
			r.emitFindingSaved(f)
		}
	}
	return results
}

// firstResultErr returns the first non-nil per-finding error in a batch result,
// collapsing the aligned results into the single-error contract used by callers
// (e.g. SaveFindingsBatch) that don't need per-finding outcomes.
func firstResultErr(results []FindingSaveResult) error {
	for i := range results {
		if results[i].Err != nil {
			return results[i].Err
		}
	}
	return nil
}

// insertFindingRecords batch-inserts finding↔record junction rows in a single
// statement using the given bun.IDB (the shared *DB or a transaction).
func (r *Repository) insertFindingRecords(ctx context.Context, idb bun.IDB, findingID int64, recordUUIDs []string) {
	if len(recordUUIDs) == 0 {
		return
	}

	// Driver is a property of the connection, identical for *DB and any tx.
	postgres := r.db.Driver() == "postgres"

	var b strings.Builder
	if postgres {
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
	if postgres {
		b.WriteString(" ON CONFLICT DO NOTHING")
	}
	if _, err := idb.ExecContext(ctx, b.String(), args...); err != nil {
		zap.L().Warn("Failed to insert finding_records",
			zap.Int64("finding_id", findingID),
			zap.Error(err))
	}
}

// appendRecordsToFinding looks up an existing finding by (project, hash) and appends new
// record UUIDs and additional evidence (request/response pair) to it. The lookup is
// project-scoped so evidence from one project is never merged into another project's
// finding, even when both share a finding_hash.
func (r *Repository) appendRecordsToFinding(ctx context.Context, idb bun.IDB, projectUUID, findingHash string, newUUIDs []string, evidence string, scanUUID string) error {
	// Only fetch the (potentially large) request/response bodies when there's
	// evidence to append — they're needed solely to dedup against the survivor's
	// own primary pair below.
	existing := &Finding{}
	sel := idb.NewSelect().Model(existing).
		Column("id", "http_record_uuids", "additional_evidence").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("finding_hash = ?", findingHash)
	if evidence != "" {
		sel = sel.Column("request", "response")
	}
	if err := sel.Scan(ctx); err != nil {
		return fmt.Errorf("failed to look up existing finding: %w", err)
	}

	r.insertFindingRecords(ctx, idb, existing.ID, newUUIDs)

	merged := mergeUniqueStrings(existing.HTTPRecordUUIDs, newUUIDs)
	q := idb.NewUpdate().Model((*Finding)(nil)).
		Set("http_record_uuids = ?", merged).
		Where("id = ?", existing.ID)

	// Attribute the finding to the scan that most recently observed it. Finding
	// uniqueness is project-wide, so the earliest row is kept — but leaving its
	// scan_uuid pinned to the FIRST scan means a re-detected finding silently
	// escapes the current scan's fail-on gate, printed summary, and scan-scoped
	// report. Bumping scan_uuid to the re-detecting scan keeps the finding
	// attributed to the run that actually saw it. Skipped when the re-detection
	// carries no scan id (e.g. an out-of-band import).
	if scanUUID != "" {
		q = q.Set("scan_uuid = ?", scanUUID)
	}

	// Skip evidence that just duplicates the survivor's own primary
	// request/response (or an entry it already has) — otherwise re-emitting the
	// same finding shows its response twice (primary + Additional Evidence).
	if evidence != "" {
		primary := buildEvidence(existing.Request, existing.Response)
		if updated := appendUniqueEvidence(existing.AdditionalEvidence, primary, evidence); len(updated) > len(existing.AdditionalEvidence) {
			q = q.Set("additional_evidence = ?", updated)
		}
	}

	if _, err := q.Exec(ctx); err != nil {
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
		Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", RecordKindFinding).
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
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding).
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

// DeleteFindingByHash deletes the finding(s) with the given content hash within a
// project, including their finding_records junction rows. Used by the OAST
// collector to replace a weaker finding (e.g. a DNS-resolution lead) with a
// stronger one (the HTTP-fetch confirmation) for the same callback payload, so each
// payload yields exactly one finding reflecting the strongest evidence. No-op when
// findingHash is empty or no such finding exists.
func (r *Repository) DeleteFindingByHash(ctx context.Context, projectUUID, findingHash string) error {
	if findingHash == "" {
		return nil
	}
	projectUUID = defaultProjectUUID(projectUUID)
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Clear the junction rows via a subquery on the same predicate, then drop the
		// finding(s) — both are no-ops when nothing matches, so no pre-SELECT is needed.
		if _, err := tx.NewRaw(
			"DELETE FROM finding_records WHERE finding_id IN (SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?)",
			projectUUID, findingHash,
		).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).
			Where("project_uuid = ? AND finding_hash = ?", projectUUID, findingHash).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
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
