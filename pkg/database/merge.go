package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// MergeOptions tunes what a SQLite-to-SQLite merge copies.
type MergeOptions struct {
	// SkipHTTPRecords omits the http_records table from the copy. It is safe for
	// readers that never resolve a finding's linked records: finding_records
	// carries no foreign key to http_records (it is a bare
	// PRIMARY KEY (finding_id, record_uuid) table), and findings embed their own
	// request/response inline, so the junction and every finding still merge
	// intact — a later record lookup simply resolves to nothing.
	//
	// This exists because http_records holds the raw request/response blobs and
	// is ~98% of the bytes in a typical result database. A read that renders
	// purely from findings (the finding tree/table/JSON views) would otherwise
	// pay to copy every blob into the destination only to discard it.
	SkipHTTPRecords bool

	// SkipRecordBodies copies http_records without its raw_request/raw_response
	// columns, which are nullable and hold ~96% of the table's bytes. Every row
	// still lands, with its metadata intact, so row counts and any predicate over
	// metadata (status/method/host/content-type) are unaffected — unlike dropping
	// rows, this changes nothing observable for such a reader.
	//
	// It is only safe when nothing downstream reads the raw corpus: a filter that
	// LIKEs over it (see QueryFilters.UsesRawCorpus) silently matches nothing, and
	// a renderer that prints it silently prints empty. Ignored when
	// SkipHTTPRecords is set, which already omits the table.
	SkipRecordBodies bool
}

// recordBodyColumns are the http_records blob columns holding the raw
// request/response corpus — the bulk of the table's bytes, and what
// MergeOptions.SkipRecordBodies / QueryBuilder.OmitBodies leave out. Both are
// nullable with no default, so a copy that omits them inserts NULL rather than
// failing.
//
// Note oast_interactions has columns of the same names on a different table;
// this list is for http_records only.
var recordBodyColumns = []string{"raw_request", "raw_response"}

// findingBodyColumns are the findings blob columns — the inline request/response
// evidence a finding carries. Excluded from the findings list queries, which
// render from metadata and re-fetch evidence per page.
var findingBodyColumns = []string{"additional_evidence", "request", "response"}

// MergeStats reports what a SQLite-to-SQLite merge copied into the destination.
type MergeStats struct {
	ProjectsMerged       int
	ScansMerged          int
	AgenticScansMerged   int
	RecordsMerged        int
	FindingsMerged       int
	FindingsDeduped      int
	FindingRecordsMerged int
	OASTMerged           int
}

// Add accumulates o's counters into s, for aggregating the stats of several
// merges (e.g. a multi-source import) into a single total.
func (s *MergeStats) Add(o *MergeStats) {
	if o == nil {
		return
	}
	s.ProjectsMerged += o.ProjectsMerged
	s.ScansMerged += o.ScansMerged
	s.AgenticScansMerged += o.AgenticScansMerged
	s.RecordsMerged += o.RecordsMerged
	s.FindingsMerged += o.FindingsMerged
	s.FindingsDeduped += o.FindingsDeduped
	s.FindingRecordsMerged += o.FindingRecordsMerged
	s.OASTMerged += o.OASTMerged
}

// mergeCopyTables lists the uuid-keyed result tables copied set-based with
// OR IGNORE. projects/scans/http_records have a TEXT uuid primary key;
// agentic_scans has an AUTOINCREMENT integer id plus a UNIQUE(uuid) business
// key. The AUTOINCREMENT "id" column is always dropped from the copy (see the
// dropColumn call in mergeOnce) so the destination assigns its own and dedup
// falls on the uuid. findings/finding_records/oast_interactions instead need
// id remapping (findings.id is AUTOINCREMENT, referenced by the junction and
// the OAST FK) and are handled row-by-row below.
//
// Scope boundary: this merges scan *results* only. The other project-scoped
// tables in db.go CreateSchema (scopes, authentication_hostnames, scan_logs)
// are deliberately NOT merged — they are configuration/session/log state, not
// results, and would each need their own dedup key. A new project-scoped
// *result* table must be added here (with a dedup key) to flow through
// --db-isolate. Kept as an allowlist so table names interpolated into DDL/DML
// are never attacker-influenced.
var mergeCopyTables = []string{"projects", "scans", "http_records", "agentic_scans"}

// MergeSQLiteFile merges every native-scan result row from the SQLite database
// at srcPath into dest (which must be an already-open, schema-current SQLite
// database). It is safe to call repeatedly with the same source: rows dedup on
// their natural keys (uuid for records/scans, (project_uuid, finding_hash) for
// findings), so a re-merge is idempotent. project_uuid values are copied
// verbatim, so the merged rows stay scoped to whatever project the scan ran
// under.
//
// The whole operation runs on a single pinned connection inside one
// BEGIN IMMEDIATE transaction, and retries on SQLITE_BUSY/locked so it
// tolerates other processes briefly holding the destination's write lock.
func MergeSQLiteFile(ctx context.Context, dest *DB, srcPath string) (*MergeStats, error) {
	return MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{})
}

// MergeSQLiteFileWithOptions is MergeSQLiteFile with control over what is
// copied; see MergeOptions.
func MergeSQLiteFileWithOptions(ctx context.Context, dest *DB, srcPath string, opts MergeOptions) (*MergeStats, error) {
	if dest.Driver() != "sqlite" {
		return nil, fmt.Errorf("merge requires a SQLite destination, got %q", dest.Driver())
	}
	var stats *MergeStats
	err := retryOnBusy(ctx, func() error {
		var e error
		stats, e = mergeOnce(ctx, dest, srcPath, opts)
		return e
	})
	return stats, err
}

// mergeOnce performs a single merge attempt. Any failure rolls back the
// transaction (so a retry starts clean) and detaches the source.
func mergeOnce(ctx context.Context, dest *DB, srcPath string, opts MergeOptions) (*MergeStats, error) {
	stats := &MergeStats{}

	conn, err := dest.SQLDB().Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire merge connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// ATTACH must run outside a transaction. Escape single quotes defensively;
	// temp paths never contain them, but a quoted literal is safer than relying
	// on driver parameter support for ATTACH filenames.
	escaped := strings.ReplaceAll(srcPath, "'", "''")
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS src", escaped)); err != nil {
		return nil, fmt.Errorf("attach source database: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "DETACH DATABASE src") }()

	// Pre-read the row-by-row tables before opening the write transaction: a
	// SQLite connection cannot run new statements while a result-set cursor is
	// open on it, so these reads must be fully drained first.
	srcFindings, findingCols, err := readRows(ctx, conn, "findings")
	if err != nil {
		return nil, fmt.Errorf("read source findings: %w", err)
	}
	srcFindingRecords, _, err := readRows(ctx, conn, "finding_records")
	if err != nil {
		return nil, fmt.Errorf("read source finding_records: %w", err)
	}
	srcOAST, oastCols, err := readRows(ctx, conn, "oast_interactions")
	if err != nil {
		return nil, fmt.Errorf("read source oast_interactions: %w", err)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin merge transaction: %w", err)
	}
	// Rollback is a no-op once Commit has succeeded, so an unconditional
	// deferred rollback cleanly covers every early-return error path.
	defer func() { _ = tx.Rollback() }()

	// Set-based copies for uuid-keyed tables (OR IGNORE dedups by primary key /
	// unique key). The AUTOINCREMENT "id" column is never copied: tables that
	// have one (agentic_scans) dedup on their UNIQUE(uuid) instead, and letting
	// the destination assign ids avoids cross-database id collisions.
	for _, table := range mergeCopyTables {
		if opts.SkipHTTPRecords && table == "http_records" {
			continue
		}
		cols, err := commonColumns(ctx, conn, table)
		if err != nil {
			return nil, fmt.Errorf("inspect columns for %s: %w", table, err)
		}
		cols = dropColumn(cols, "id")
		if opts.SkipRecordBodies && table == "http_records" {
			for _, c := range recordBodyColumns {
				cols = dropColumn(cols, c)
			}
		}
		if len(cols) == 0 {
			continue
		}
		colList := strings.Join(cols, ", ")
		q := fmt.Sprintf("INSERT OR IGNORE INTO main.%s (%s) SELECT %s FROM src.%s", table, colList, colList, table)
		res, err := tx.ExecContext(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("copy %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		switch table {
		case "projects":
			stats.ProjectsMerged = int(n)
		case "scans":
			stats.ScansMerged = int(n)
		case "http_records":
			stats.RecordsMerged = int(n)
		case "agentic_scans":
			stats.AgenticScansMerged = int(n)
		}
	}

	// findings: insert without id, dedup on (project_uuid, finding_hash), and
	// build a src→dst id map so the junction and OAST rows can be relinked.
	idMap, err := mergeFindings(ctx, tx, srcFindings, findingCols, stats)
	if err != nil {
		return nil, fmt.Errorf("merge findings: %w", err)
	}

	if err := mergeFindingRecords(ctx, tx, srcFindingRecords, idMap, stats); err != nil {
		return nil, fmt.Errorf("merge finding_records: %w", err)
	}

	if err := mergeOAST(ctx, tx, srcOAST, oastCols, idMap, stats); err != nil {
		return nil, fmt.Errorf("merge oast_interactions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit merge: %w", err)
	}
	return stats, nil
}

// bufferedRow holds one source row's column values, copied so they survive the
// cursor advancing (database/sql may reuse []byte buffers across Next()).
type bufferedRow []any

// readRows reads every row of src.<table> into memory and returns the rows
// alongside the table's column names (in physical order).
func readRows(ctx context.Context, conn *sql.Conn, table string) ([]bufferedRow, []string, error) {
	cols, err := tableColumns(ctx, conn, "src", table)
	if err != nil {
		return nil, nil, err
	}
	if len(cols) == 0 {
		return nil, nil, nil
	}
	q := fmt.Sprintf("SELECT %s FROM src.%s", strings.Join(cols, ", "), table)
	rows, err := conn.QueryContext(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []bufferedRow
	for rows.Next() {
		scanDst := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range scanDst {
			ptrs[i] = &scanDst[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		out = append(out, bufferedRow(copyValues(scanDst)))
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return out, cols, nil
}

// copyValues deep-copies []byte values so buffered rows don't alias driver
// scratch buffers reused by the next Scan.
func copyValues(in []any) []any {
	out := make([]any, len(in))
	for i, v := range in {
		if b, ok := v.([]byte); ok {
			cp := make([]byte, len(b))
			copy(cp, b)
			out[i] = cp
			continue
		}
		out[i] = v
	}
	return out
}

// mergeFindings inserts each source finding into main.findings, deduping on
// (project_uuid, finding_hash), and returns a map from the source finding id to
// the destination finding id (whether freshly inserted or pre-existing).
func mergeFindings(ctx context.Context, tx *sql.Tx, rows []bufferedRow, cols []string, stats *MergeStats) (map[int64]int64, error) {
	idMap := make(map[int64]int64, len(rows))
	if len(rows) == 0 {
		return idMap, nil
	}

	idIdx := indexOf(cols, "id")
	projIdx := indexOf(cols, "project_uuid")
	hashIdx := indexOf(cols, "finding_hash")
	if idIdx < 0 || projIdx < 0 || hashIdx < 0 {
		return nil, fmt.Errorf("findings table missing id/project_uuid/finding_hash columns")
	}

	// Insert column list excludes the AUTOINCREMENT id; the destination assigns
	// its own.
	insertCols := make([]string, 0, len(cols)-1)
	for i, c := range cols {
		if i == idIdx {
			continue
		}
		insertCols = append(insertCols, c)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(insertCols)), ", ")
	insertQ := fmt.Sprintf(
		"INSERT INTO main.findings (%s) VALUES (%s) ON CONFLICT (project_uuid, finding_hash) DO NOTHING RETURNING id",
		strings.Join(insertCols, ", "), placeholders)

	for _, row := range rows {
		srcID, ok := toInt64(row[idIdx])
		if !ok {
			continue
		}
		args := make([]any, 0, len(insertCols))
		for i := range row {
			if i == idIdx {
				continue
			}
			args = append(args, row[i])
		}

		var dstID sql.NullInt64
		err := tx.QueryRowContext(ctx, insertQ, args...).Scan(&dstID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Conflict: the finding already exists in the destination. Look up
			// its id so the junction still links correctly.
			var existing sql.NullInt64
			if lookupErr := tx.QueryRowContext(ctx,
				"SELECT id FROM main.findings WHERE project_uuid = ? AND finding_hash = ?",
				row[projIdx], row[hashIdx]).Scan(&existing); lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
				return nil, lookupErr
			}
			if existing.Valid {
				idMap[srcID] = existing.Int64
			}
			stats.FindingsDeduped++
		case err != nil:
			return nil, err
		default:
			if dstID.Valid {
				idMap[srcID] = dstID.Int64
				stats.FindingsMerged++
			}
		}
	}
	return idMap, nil
}

// mergeFindingRecords copies the finding↔record junction, remapping the source
// finding id to the destination id. Rows whose finding was not mapped (e.g. a
// finding that failed to insert) are skipped rather than orphaned.
func mergeFindingRecords(ctx context.Context, tx *sql.Tx, rows []bufferedRow, idMap map[int64]int64, stats *MergeStats) error {
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		srcFID, ok := toInt64(row[0])
		if !ok {
			continue
		}
		dstFID, mapped := idMap[srcFID]
		if !mapped {
			continue
		}
		res, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO main.finding_records (finding_id, record_uuid) VALUES (?, ?)",
			dstFID, row[1])
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			stats.FindingRecordsMerged++
		}
	}
	return nil
}

// mergeOAST copies OAST interactions, remapping the nullable finding_id FK. A
// finding_id that does not map to a destination finding is nulled rather than
// left dangling.
func mergeOAST(ctx context.Context, tx *sql.Tx, rows []bufferedRow, cols []string, idMap map[int64]int64, stats *MergeStats) error {
	if len(rows) == 0 {
		return nil
	}
	idIdx := indexOf(cols, "id")
	findingIdx := indexOf(cols, "finding_id")

	insertCols := dropColumn(cols, "id")
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(insertCols)), ", ")
	insertQ := fmt.Sprintf("INSERT INTO main.oast_interactions (%s) VALUES (%s)",
		strings.Join(insertCols, ", "), placeholders)

	for _, row := range rows {
		args := make([]any, 0, len(insertCols))
		for i, val := range row {
			if i == idIdx {
				continue
			}
			if i == findingIdx {
				if fid, ok := toInt64(val); ok {
					if dst, mapped := idMap[fid]; mapped {
						val = dst
					} else {
						val = nil
					}
				}
			}
			args = append(args, val)
		}
		if _, err := tx.ExecContext(ctx, insertQ, args...); err != nil {
			return err
		}
		stats.OASTMerged++
	}
	return nil
}

// commonColumns returns the columns present in BOTH src.<table> and
// main.<table>, in src's physical order. Guards against schema drift where the
// destination is missing a column the source has.
func commonColumns(ctx context.Context, conn *sql.Conn, table string) ([]string, error) {
	srcCols, err := tableColumns(ctx, conn, "src", table)
	if err != nil {
		return nil, err
	}
	dstCols, err := tableColumns(ctx, conn, "main", table)
	if err != nil {
		return nil, err
	}
	dstSet := make(map[string]bool, len(dstCols))
	for _, c := range dstCols {
		dstSet[c] = true
	}
	out := make([]string, 0, len(srcCols))
	for _, c := range srcCols {
		if dstSet[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

// tableColumns returns the column names of schema.table (e.g. src.findings) in
// physical order via PRAGMA table_info.
func tableColumns(ctx context.Context, conn *sql.Conn, schema, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, fmt.Sprintf("PRAGMA %s.table_info(%s)", schema, table))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var cols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// dropColumn returns s without the named column (order preserved).
func dropColumn(s []string, name string) []string {
	out := make([]string, 0, len(s))
	for _, c := range s {
		if c != name {
			out = append(out, c)
		}
	}
	return out
}

func indexOf(s []string, target string) int {
	for i, v := range s {
		if v == target {
			return i
		}
	}
	return -1
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	default:
		return 0, false
	}
}

// retryOnBusy runs fn, retrying with exponential backoff while it returns a
// SQLite busy/locked error. Gives up after the deadline budget so a genuinely
// wedged destination surfaces an error rather than hanging forever.
func retryOnBusy(ctx context.Context, fn func() error) error {
	const (
		maxAttempts = 12
		baseDelay   = 50 * time.Millisecond
		maxDelay    = 2 * time.Second
	)
	delay := baseDelay
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil || !isBusyErr(lastErr) {
			return lastErr
		}
		zap.L().Debug("merge hit busy destination, retrying",
			zap.Int("attempt", attempt), zap.Duration("delay", delay), zap.Error(lastErr))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return fmt.Errorf("merge gave up after %d attempts on a busy destination: %w", maxAttempts, lastErr)
}

func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "(5)") || // SQLITE_BUSY
		strings.Contains(msg, "(6)") // SQLITE_LOCKED
}
