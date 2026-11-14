package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
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
	_, err := r.SaveFindingInserted(ctx, event, httpRecordUUIDs, scanUUID, projectUUID)
	return err
}

// SaveFindingInserted is SaveFinding reporting whether a NEW finding row was
// written (false on a dedup-append to an existing finding), so a caller can
// notify only on genuinely new findings (SAFE-12).
func (r *Repository) SaveFindingInserted(ctx context.Context, event *output.ResultEvent, httpRecordUUIDs []string, scanUUID string, projectUUID string) (bool, error) {
	if event == nil {
		return false, fmt.Errorf("invalid ResultEvent")
	}

	finding := &Finding{
		HTTPRecordUUIDs: httpRecordUUIDs,
		ScanUUID:        scanUUID,
		ProjectUUID:     defaultProjectUUID(projectUUID),
	}
	if err := finding.FromResultEvent(event); err != nil {
		return false, fmt.Errorf("failed to convert finding: %w", err)
	}

	inserted, err := r.saveFindingTx(ctx, finding, httpRecordUUIDs)
	if err != nil {
		return false, err
	}
	if inserted {
		r.emitFindingSaved(finding)
	}
	return inserted, nil
}

// SaveFindingsBatch persists a batch of findings in a single transaction,
// coalescing what would otherwise be one transaction (and fsync) per finding.
// Findings are converted up front so a conversion error skips just that finding
// rather than aborting the batch. If the transaction itself fails (e.g. a
// database-level error), every finding is retried individually so one bad
// finding can't drop the rest — preserving the error isolation of per-finding
// SaveFinding while keeping the fast path a single transaction.
func (r *Repository) SaveFindingsBatch(ctx context.Context, writes []FindingWrite) error {
	return firstResultErr(r.SaveFindingsBatchResults(ctx, writes))
}

// SaveFindingsBatchResults is SaveFindingsBatch with the per-finding outcomes,
// aligned 1:1 with writes — results[i] describes writes[i], including the entries
// this method itself rejects (a nil Event or one that will not convert, each
// carrying its own Err at its own index).
//
// The alignment is what makes a partial batch countable. SaveFindingsBatch
// collapses to a single error, so FindingWriter could only ever attribute a
// failure to the whole batch: one bad finding in a batch of sixty-four was
// reported as sixty-four dropped findings, and a transaction that failed and then
// succeeded on retry for all but one was reported the same way. Operators read
// those counters to decide whether a scan's results are complete.
func (r *Repository) SaveFindingsBatchResults(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
	results := make([]FindingSaveResult, len(writes))
	if len(writes) == 0 {
		return results
	}

	// findings holds only the convertible entries; index maps each back to its
	// position in writes so the core's aligned result can be scattered home.
	findings := make([]*Finding, 0, len(writes))
	index := make([]int, 0, len(writes))
	for i := range writes {
		w := &writes[i]
		if w.Event == nil {
			results[i].Err = fmt.Errorf("invalid ResultEvent")
			continue
		}
		f := &Finding{
			HTTPRecordUUIDs: w.HTTPRecordUUIDs,
			ScanUUID:        w.ScanUUID,
			ProjectUUID:     defaultProjectUUID(w.ProjectUUID),
		}
		if err := f.FromResultEvent(w.Event); err != nil {
			zap.L().Warn("SaveFindingsBatch: skipping unconvertible finding", zap.Error(err))
			results[i].Err = fmt.Errorf("failed to convert finding: %w", err)
			continue
		}
		findings = append(findings, f)
		index = append(index, i)
	}
	if len(findings) == 0 {
		return results
	}

	for j, res := range r.saveFindingsBatchCore(ctx, findings) {
		results[index[j]] = res
	}
	return results
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

	// A finding row without its evidence links is a finding whose proof cannot be
	// resolved, so surface the failure rather than committing a half-written one.
	// Inside a transaction this rolls the row back with it.
	if err := r.insertFindingRecords(ctx, idb, finding.ID, httpRecordUUIDs); err != nil {
		return false, err
	}
	if err := recordFindingObservation(ctx, idb, finding.ProjectUUID, finding.ID, finding.FindingHash, finding.ScanUUID); err != nil {
		return false, err
	}

	return true, nil
}

// saveFindingTx is saveFindingIDB in its own transaction, for the single-finding
// paths: the finding row, its evidence links and its observation commit
// together or not at all.
func (r *Repository) saveFindingTx(ctx context.Context, finding *Finding, httpRecordUUIDs []string) (bool, error) {
	var inserted bool
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var err error
		inserted, err = r.saveFindingIDB(ctx, tx, finding, httpRecordUUIDs)
		return err
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// SaveFindingDirect inserts a pre-built Finding directly (without ResultEvent conversion).
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFindingDirect(ctx context.Context, finding *Finding) error {
	_, err := r.SaveFindingReported(ctx, finding)
	return err
}

// SaveFindingReported is SaveFindingDirect that additionally reports whether a
// new finding row was inserted (true) vs collapsed into an existing finding by
// dedup (false). The autopilot report_finding tool uses it so its run counter
// only tallies distinct findings.
func (r *Repository) SaveFindingReported(ctx context.Context, finding *Finding) (bool, error) {
	if finding == nil {
		return false, fmt.Errorf("invalid Finding")
	}

	finding.ProjectUUID = defaultProjectUUID(finding.ProjectUUID)

	inserted, err := r.saveFindingTx(ctx, finding, finding.HTTPRecordUUIDs)
	if err != nil {
		return false, err
	}
	if inserted {
		r.emitFindingSaved(finding)
	}
	return inserted, nil
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
		inserted, e := r.saveFindingTx(ctx, f, f.HTTPRecordUUIDs)
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
// It returns the insert error instead of only logging it: a finding whose
// junction rows failed to write looks complete in the findings table while its
// evidence links are missing, and the caller could not tell.
func (r *Repository) insertFindingRecords(ctx context.Context, idb bun.IDB, findingID int64, recordUUIDs []string) error {
	if len(recordUUIDs) == 0 {
		return nil
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
		return fmt.Errorf("insert finding_records for finding %d: %w", findingID, err)
	}
	return nil
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

	if err := r.insertFindingRecords(ctx, idb, existing.ID, newUUIDs); err != nil {
		return err
	}
	// A re-detection is an observation too: without it a finding first seen by
	// an earlier scan would look absent from every later scan that found it again.
	if err := recordFindingObservation(ctx, idb, projectUUID, existing.ID, findingHash, scanUUID); err != nil {
		return err
	}

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
	//
	// Gated on the cap as well: appendUniqueEvidence enforces it, but reaching it
	// still costs a concat of the survivor's whole primary pair plus a hash of
	// every retained pair — on a finding re-detected thousands of times across a
	// large host, all to produce a list that cannot change.
	if evidence != "" && len(existing.AdditionalEvidence) < maxAdditionalEvidence {
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

// FindingProjectUUID returns just the project a finding belongs to, for the
// existence-plus-scope check the mutating handlers perform before acting on it.
// Returns sql.ErrNoRows when the finding does not exist, like GetFindingByID.
//
// Projected on purpose: the callers read only this one field, and a finding
// carries its own inline request/response blobs.
func (r *Repository) FindingProjectUUID(ctx context.Context, id int64) (string, error) {
	finding := &Finding{}
	err := r.db.NewSelect().
		Model(finding).
		Column("project_uuid").
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return "", err
	}
	return finding.ProjectUUID, nil
}

// HydrateFindingRequests populates the Request field on findings that were
// loaded without it — the list query (FindingsQueryBuilder) omits the
// request/response blobs for speed. It fetches id→request for the given findings
// in as few round-trips as one statement's worth of ids allows; findings that
// already carry a Request, or that have no id, are skipped. Used by display
// paths that need a finding's own PoC request (e.g. the tree's attack-URL
// rendering) without pulling the full raw view.
func (r *Repository) HydrateFindingRequests(ctx context.Context, findings []*Finding) {
	idx := make(map[int64]*Finding, len(findings))
	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		if f == nil || f.ID == 0 || f.Request != "" {
			continue
		}
		idx[f.ID] = f
		ids = append(ids, f.ID)
	}
	if len(ids) == 0 {
		return
	}
	for chunk := range slices.Chunk(ids, SQLChunkSize) {
		var loaded []*Finding
		if err := r.db.NewSelect().
			Model(&loaded).
			Column("id", "request").
			Where("id IN (?)", bun.List(chunk)).
			Scan(ctx); err != nil {
			return
		}
		for _, row := range loaded {
			if f, ok := idx[row.ID]; ok {
				f.Request = row.Request
			}
		}
	}
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
		Limit(int64(limit))
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
	return slices.Contains(FindingStatuses, s)
}

// UpdateFindingStatusByHash sets the lifecycle status of findings matching a finding_hash
// within a project and an agentic_scan_uuid scope. Used by the swarm triage writeback to
// promote draft findings to triaged / false_positive based on agent verdicts. Either
// scope may be empty (dropping that predicate); the swarm path passes both so a hash
// shared across projects only ever touches the run's own project.
// Returns the number of rows updated.
func (r *Repository) UpdateFindingStatusByHash(ctx context.Context, projectUUID, agenticScanUUID, findingHash, status string) (int64, error) {
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
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
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
// process is killed between two separate UPDATEs. Project-scoped like
// UpdateFindingStatusScoped: projectUUID == "" drops the predicate, and a
// finding outside the project returns sql.ErrNoRows.
func (r *Repository) UpdateFindingTriage(ctx context.Context, projectUUID string, id int64, severity, description string) error {
	if !IsValidFindingSeverity(severity) {
		return fmt.Errorf("UpdateFindingTriage: invalid severity %q", severity)
	}
	q := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("severity = ?", severity).
		Set("description = ?", description).
		Where("id = ?", id)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingTriage: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteFindingByHash deletes the finding(s) with the given content hash within a
// project, including their findingChildTables rows. Used by the OAST
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
		for _, table := range findingChildTables {
			if _, err := tx.NewRaw(
				"DELETE FROM "+table+" WHERE finding_id IN (SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?)",
				projectUUID, findingHash,
			).Exec(ctx); err != nil {
				return fmt.Errorf("failed to delete %s: %w", table, err)
			}
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).
			Where("project_uuid = ? AND finding_hash = ?", projectUUID, findingHash).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
		}
		return nil
	})
}

// DeleteFinding deletes a finding by its numeric ID, including its
// findingChildTables rows (evidence junction, observations, status history).
func (r *Repository) DeleteFinding(ctx context.Context, id int64) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if err := deleteFindingChildrenTx(ctx, tx, []int64{id}); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
		}
		return nil
	})
}
