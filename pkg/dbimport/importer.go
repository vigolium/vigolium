package dbimport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/audit"
	"github.com/vigolium/vigolium/pkg/database"
)

// Result captures what was imported during a single ImportXxx call.
//
// AgenticScan is populated for audit imports (whether a new scan was created
// or an existing one was attached to); for JSONL imports it is populated only
// when Options.AgenticScanUUID was supplied so the caller can correlate
// imported findings with an existing scan row. CreatedNew distinguishes a
// freshly-created agentic scan from an attach.
type Result struct {
	AgenticScan *database.AgenticScan
	CreatedNew  bool

	RecordsImported int
	FindingsTotal   int
	FindingsSaved   int
	FindingsSkipped int
	ParseErrors     int

	// RecordsSkippedDuplicate counts HTTP records whose uuid was already in the
	// destination, so they were not inserted. Reported separately from
	// RecordsImported because "0 imported" out of a 10,000-line export means
	// something very different from "0 imported, 10,000 already present".
	RecordsSkippedDuplicate int

	// FindingsFailed counts findings the destination refused to store. Distinct
	// from FindingsSkipped, which is the benign dedup-append case: a failed
	// finding is data that was in the source and is NOT in the destination, and
	// folding the two together reported a lossy import as a clean one.
	FindingsFailed int

	SeverityCounts map[string]int
	SkippedTypes   map[string]int

	// ImportedByType counts the rows written per envelope type (http_record,
	// finding, scan, oast_interaction, scope); DuplicatesByType counts the
	// rows of each type that were already in the destination.
	ImportedByType   map[string]int
	DuplicatesByType map[string]int

	SessionDir string
	StorageURL string

	// MergeStats is populated only for SQLite-database imports (ImportSQLite):
	// a lossless SQLite→SQLite merge of another vigolium result database into
	// the destination. Nil for audit and JSONL imports.
	MergeStats *database.MergeStats
}

// AgenticScanUUID returns the UUID of the result's agentic scan, or "" if no
// scan was created or attached (the JSONL-without-attach case).
func (r *Result) AgenticScanUUID() string {
	if r == nil || r.AgenticScan == nil {
		return ""
	}
	return r.AgenticScan.UUID
}

// Options carries optional knobs that apply to both audit and JSONL imports.
type Options struct {
	// AgenticScanUUID, if non-empty, attaches imported findings (and HTTP
	// records for JSONL) to an existing agentic_scan row instead of creating a
	// new one. For audit imports the existing row's metadata is preserved and
	// only finding counts/storage_url are touched.
	AgenticScanUUID string

	// OriginalSource carries the user-supplied input string (e.g. gs:// URL or
	// archive path). Recorded as StorageURL on audit scan rows when it has a
	// gs:// prefix.
	OriginalSource string

	// SessionDirArchiver, if non-nil, is invoked after the agentic scan UUID is
	// determined. It receives that UUID and the on-disk audit source dir,
	// and returns the absolute session directory where the source was copied.
	// Used by audit imports only.
	SessionDirArchiver func(scanUUID, srcDir string) (sessionDir string, err error)

	// Source identifies the audit harness flavor (audit vs piolium). When
	// zero-valued, audit.DefaultSource() is used.
	Source *audit.FindingSource

	// SkipHTTPRecords omits the http_records table from a SQLite→SQLite merge;
	// see database.MergeOptions. Ignored by the JSONL/audit/archive importers,
	// which don't carry a separate record table to skip.
	SkipHTTPRecords bool

	// SkipRecordBodies omits the raw_request/raw_response columns from a
	// SQLite→SQLite merge of http_records; see database.MergeOptions. Ignored by
	// the JSONL/audit/archive importers.
	SkipRecordBodies bool

	// SkipFindings omits findings, the finding_records junction, and
	// oast_interactions from a SQLite→SQLite merge; see database.MergeOptions.
	// Ignored by the JSONL/audit/archive importers, whose whole payload is
	// findings.
	SkipFindings bool

	// PreserveProjectUUID keeps each JSONL row's own project_uuid instead of
	// re-homing it onto the projectUUID argument. A row with no project_uuid of
	// its own still gets the argument.
	//
	// It exists for the read-only scratch databases: a `-S --db export.jsonl`
	// load and a --glob-db merge exist to show a file's contents as they are, and
	// stamping the default project over every row made `project_uuid` in the
	// output a statement about the reader rather than about the data — which also
	// made an explicit project filter over such a source meaningless.
	//
	// Persistent `vigolium import` deliberately does NOT set it: importing into a
	// project means the rows join that project.
	PreserveProjectUUID bool

	// MaxLineBytes caps a single JSONL line. 0 means DefaultMaxLineBytes.
	//
	// The reader grows its buffer to whatever a line needs, which is required —
	// an exported http_record carries its whole response body on one line. With
	// no ceiling at all, though, a truncated or non-JSONL file (a tarball, a core
	// dump, a file whose newlines were stripped) is read into memory in full
	// before the first parse error can be reported, so the symptom of pointing
	// `import` at the wrong file is the OOM killer rather than a message.
	MaxLineBytes int

	// ImportScopes stores `scope` envelopes. Scope rows are enabled scan rules,
	// so loading them into a live store would silently change later scans:
	// only the read-only scratch loaders and `import --include-scopes` set it.
	// Without it scope envelopes are counted in SkippedTypes.
	ImportScopes bool
}

// DefaultMaxLineBytes is the ceiling ImportJSONL applies to one line when
// Options.MaxLineBytes is unset. 256 MiB is far above any real exported record
// (the largest observed response body is ~2 orders of magnitude smaller) and far
// below the point where the allocation itself is the failure.
const DefaultMaxLineBytes = 256 << 20

// recordFlushBatch is how many parsed http_records ImportJSONL holds before
// writing them. Buffering the whole file first meant a 16 GB export was 16 GB of
// Go heap before the first INSERT; at 500 rows the peak no longer depends on how
// long the file is.
const recordFlushBatch = 500

// recordFlushBytes caps the same buffer by SIZE, which is the limit that
// actually binds. An exported http_record carries its whole request and response
// inline, so 500 of them is 500 rows on a crawl of small JSON endpoints and
// ~100 MB on a corpus of page responses — and the multi-row INSERT bun builds
// from it costs several times that again while it is being assembled and copied
// through the driver. Measured on a 183 MB single-file export: a count-only
// limit peaked at 1.6 GB RSS in 3.5 s, a 32 MiB budget at 0.8 GB in 1.9 s.
//
// A single record larger than the budget is still written on its own — the
// budget bounds batching, it never rejects data.
const recordFlushBytes = 32 << 20

// ImportPath dispatches based on filesystem inspection of path: directory →
// audit folder, .tar.gz/.tgz/.zip → archive, a vigolium SQLite result database
// → SQLite merge, anything else → JSONL.
func ImportPath(ctx context.Context, repo *database.Repository, path, projectUUID string, opts Options) (*Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access path: %w", err)
	}
	if info.IsDir() {
		return ImportAudit(ctx, repo, path, projectUUID, opts)
	}
	switch ArchiveExt(path) {
	case ".tar.gz", ".tgz", ".zip":
		return ImportArchive(ctx, repo, path, projectUUID, opts)
	}
	// A vigolium SQLite result database (any extension — .sqlite/.sqlite3/.db or
	// none — detected by its magic header) is merged into the destination DB
	// rather than parsed as JSONL text.
	isSQLite, err := database.IsSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	if isSQLite {
		return ImportSQLite(ctx, repo, path, projectUUID, opts)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return ImportJSONL(ctx, repo, f, projectUUID, opts)
}

// ImportSQLite merges another vigolium SQLite result database at srcPath into
// the database behind repo. It is a lossless, idempotent SQLite→SQLite merge of
// the scan-result tables (http_records, findings, finding_records, scans,
// agentic_scans, oast_interactions, projects), deduping rows on their natural
// keys — so importing the same database twice adds nothing the second time.
//
// Each row keeps its original project_uuid, so imported data stays scoped to
// whatever project it was scanned under; the projectUUID argument (the caller's
// active project) is intentionally not applied here. opts is likewise not
// applied: AgenticScanUUID (attach) and OriginalSource (storage-URL recording)
// are single-scan/audit concepts that don't map onto a bulk merge of a whole
// database of scans — findings keep their own agentic_scan_uuid from the source.
// Requires a SQLite destination — a Postgres destination returns a clear error
// from database.MergeSQLiteFile. The destination schema must already exist
// (callers run CreateSchema before ImportPath).
func ImportSQLite(ctx context.Context, repo *database.Repository, srcPath, projectUUID string, opts Options) (*Result, error) {
	stats, err := database.MergeSQLiteFileWithOptions(ctx, repo.DB(), srcPath,
		database.MergeOptions{
			SkipHTTPRecords:  opts.SkipHTTPRecords,
			SkipRecordBodies: opts.SkipRecordBodies,
			SkipFindings:     opts.SkipFindings,
		})
	if err != nil {
		return nil, fmt.Errorf("merge SQLite database %s: %w", srcPath, err)
	}

	res := newResult()
	res.MergeStats = stats
	// Map the merge counters onto the shared Result shape so the common import
	// summary still shows record/finding totals. Deduped findings (already
	// present in the destination) are reported as "skipped".
	res.RecordsImported = stats.RecordsMerged
	res.FindingsSaved = stats.FindingsMerged
	res.FindingsSkipped = stats.FindingsDeduped
	res.FindingsTotal = stats.FindingsMerged + stats.FindingsDeduped
	res.ImportedByType["http_record"] = stats.RecordsMerged
	res.ImportedByType["finding"] = stats.FindingsMerged
	res.DuplicatesByType["finding"] = stats.FindingsDeduped
	res.ImportedByType["scan"] = stats.ScansMerged
	res.ImportedByType["agentic_scan"] = stats.AgenticScansMerged
	res.ImportedByType["oast_interaction"] = stats.OASTMerged
	return res, nil
}

// ImportArchive extracts a .tar.gz / .tgz / .zip and dispatches its contents
// to the audit or JSONL importers. Results across nested imports are merged.
func ImportArchive(ctx context.Context, repo *database.Repository, archivePath, projectUUID string, opts Options) (*Result, error) {
	dir, cleanup, err := ExtractArchiveToDir(archivePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Top-level audit folder?
	if _, err := os.Stat(filepath.Join(dir, "audit-state.json")); err == nil {
		return ImportAudit(ctx, repo, dir, projectUUID, opts)
	}

	// Walk for JSONL files; also detect nested audit folders.
	var jsonls []string
	var auditDirs []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if path == dir {
				return nil
			}
			if _, statErr := os.Stat(filepath.Join(path, "audit-state.json")); statErr == nil {
				auditDirs = append(auditDirs, path)
				return filepath.SkipDir
			}
			return nil
		}
		switch ArchiveExt(info.Name()) {
		case ".jsonl", ".ndjson":
			jsonls = append(jsonls, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(auditDirs) == 0 && len(jsonls) == 0 {
		return nil, fmt.Errorf("no importable data found in %s (need audit-state.json or *.jsonl)", archivePath)
	}

	merged := newResult()
	for _, ad := range auditDirs {
		r, err := ImportAudit(ctx, repo, ad, projectUUID, opts)
		if err != nil {
			return nil, fmt.Errorf("audit import (%s): %w", ad, err)
		}
		mergeResult(merged, r)
	}
	for _, jp := range jsonls {
		f, err := os.Open(jp)
		if err != nil {
			return nil, fmt.Errorf("jsonl open (%s): %w", jp, err)
		}
		r, jerr := ImportJSONL(ctx, repo, f, projectUUID, opts)
		_ = f.Close()
		if jerr != nil {
			return nil, fmt.Errorf("jsonl import (%s): %w", jp, jerr)
		}
		mergeResult(merged, r)
	}
	return merged, nil
}

// tallyFindingSaves splits an aligned SaveFindingsDirectBatch result into saved
// (a new finding row), deduped (collapsed into an existing finding) and failed
// (the destination refused it), tallying the severity of each non-failed finding
// into sev. Shared by the audit and JSONL import paths.
//
// failed used to be folded into the skipped count, so an import that lost
// findings and one that merely re-imported them printed the same line. They are
// opposite outcomes: a deduped finding is already in the destination, a failed
// one is nowhere.
//
// results may be shorter than findings only if a caller passes a mismatched
// pair; the loop is bounded by the shorter of the two so a bug there is a
// missing tally rather than a panic in the middle of an import.
func tallyFindingSaves(findings []*database.Finding, results []database.FindingSaveResult, sev map[string]int) (saved, deduped, failed int) {
	for i, f := range findings {
		if i >= len(results) {
			break
		}
		if results[i].Err != nil {
			failed++
			continue
		}
		if results[i].Inserted {
			saved++
		} else {
			deduped++
		}
		sev[f.Severity]++
	}
	return saved, deduped, failed
}

// ImportAudit imports an audit output folder. When opts.AgenticScanUUID is
// set, the existing scan row is loaded (and project-validated by the caller)
// and findings are attached to it instead of a new row being created.
func ImportAudit(ctx context.Context, repo *database.Repository, folderPath, projectUUID string, opts Options) (*Result, error) {
	parsed, err := audit.ParseFolder(folderPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit output: %w", err)
	}

	src := audit.DefaultSource()
	if opts.Source != nil {
		src = *opts.Source
	}

	res := newResult()

	var agenticScan *database.AgenticScan
	if opts.AgenticScanUUID != "" {
		existing, getErr := repo.GetAgenticScan(ctx, opts.AgenticScanUUID)
		if getErr != nil {
			return nil, fmt.Errorf("agentic_scan_uuid %s not found: %w", opts.AgenticScanUUID, getErr)
		}
		if existing.ProjectUUID != projectUUID {
			return nil, fmt.Errorf("agentic_scan_uuid %s belongs to a different project", opts.AgenticScanUUID)
		}
		agenticScan = existing
		res.CreatedNew = false
	} else {
		agenticScan = audit.BuildAgenticScanWithSource(parsed.State, folderPath, projectUUID, src)
		if err := repo.CreateAgenticScan(ctx, agenticScan); err != nil {
			return nil, fmt.Errorf("failed to create agent run: %w", err)
		}
		res.CreatedNew = true
	}

	auditID := ""
	if len(parsed.State.Audits) > 0 {
		auditID = parsed.State.Audits[0].AuditID
	}
	findings := audit.BuildFindingsWithSource(parsed.RawFindings, auditID, agenticScan.UUID, projectUUID, parsed.RepoName, src)

	sevCounts := map[string]int{}
	// The batch error is the first per-finding error, which `failed` already
	// counts; it is carried in the Result rather than returned so the caller can
	// report everything that DID land alongside what did not. Callers turn a
	// non-zero FindingsFailed into a non-zero exit (cmd_import) or a rolled-back
	// source (openGlobDB).
	results, _ := repo.SaveFindingsDirectBatch(ctx, findings)
	saved, skipped, failed := tallyFindingSaves(findings, results, sevCounts)

	// For new scans we set the full finding count; for attached scans we
	// increment so prior findings on that row aren't clobbered.
	updateScan := &database.AgenticScan{UUID: agenticScan.UUID}
	if res.CreatedNew {
		updateScan.SavedCount = saved
		updateScan.FindingCount = len(findings)
	} else {
		updateScan.SavedCount = agenticScan.SavedCount + saved
		updateScan.FindingCount = agenticScan.FindingCount + len(findings)
	}

	if opts.SessionDirArchiver != nil {
		if sd, sderr := opts.SessionDirArchiver(agenticScan.UUID, folderPath); sderr == nil && sd != "" {
			updateScan.SessionDir = sd
			res.SessionDir = sd
		}
	}
	if strings.HasPrefix(opts.OriginalSource, "gs://") {
		updateScan.StorageURL = opts.OriginalSource
		res.StorageURL = opts.OriginalSource
	}
	// Propagated, not swallowed: this row is the only link between the imported
	// findings and the audit they came from, and a dropped update left `agent ls`
	// reporting a scan with 0 findings next to a database holding hundreds.
	if err := repo.UpdateAgenticScan(ctx, updateScan); err != nil {
		return nil, fmt.Errorf("update agent run %s after import: %w", agenticScan.UUID, err)
	}

	// Mirror the update onto the in-memory copy so the response matches the
	// new DB state without an extra SELECT round-trip.
	agenticScan.SavedCount = updateScan.SavedCount
	agenticScan.FindingCount = updateScan.FindingCount
	if updateScan.SessionDir != "" {
		agenticScan.SessionDir = updateScan.SessionDir
	}
	if updateScan.StorageURL != "" {
		agenticScan.StorageURL = updateScan.StorageURL
	}

	res.AgenticScan = agenticScan
	res.FindingsTotal = len(findings)
	res.FindingsSaved = saved
	res.FindingsSkipped = skipped
	res.FindingsFailed = failed
	res.SeverityCounts = sevCounts
	res.ImportedByType["finding"] = saved
	res.DuplicatesByType["finding"] = skipped
	return res, nil
}

// ImportJSONL imports HTTP records and findings from a JSONL stream of
// envelopes ({"type": "...", "data": {...}}). When opts.AgenticScanUUID is
// supplied, findings are tagged with that UUID; HTTP records are not tagged
// (the schema does not carry an agentic_scan_uuid on records).
func ImportJSONL(ctx context.Context, repo *database.Repository, r io.Reader, projectUUID string, opts Options) (*Result, error) {
	res := newResult()

	var attachedScan *database.AgenticScan
	if opts.AgenticScanUUID != "" {
		existing, getErr := repo.GetAgenticScan(ctx, opts.AgenticScanUUID)
		if getErr != nil {
			return nil, fmt.Errorf("agentic_scan_uuid %s not found: %w", opts.AgenticScanUUID, getErr)
		}
		if existing.ProjectUUID != projectUUID {
			return nil, fmt.Errorf("agentic_scan_uuid %s belongs to a different project", opts.AgenticScanUUID)
		}
		attachedScan = existing
	}

	var (
		records      []*database.HTTPRecord
		findings     []*database.Finding
		scans        []*database.Scan
		oasts        []*database.OASTInteraction
		scopes       []*database.Scope
		lineNum      int
		recordLines  int
		pendingBytes int
	)

	// flushRecords writes the buffered records and empties the buffer. Records
	// are written as they are parsed rather than at the end so peak memory is the
	// batch, not the file; findings stay buffered because SaveFindingsDirectBatch
	// dedups on finding_hash across the whole batch and its per-finding results
	// are what the summary is built from.
	flushRecords := func() error {
		if len(records) == 0 {
			return nil
		}
		inserted, err := repo.SaveRecordsBatchSkipExisting(ctx, records)
		if err != nil {
			return fmt.Errorf("failed to save HTTP records batch: %w", err)
		}
		res.RecordsImported += len(inserted)
		res.RecordsSkippedDuplicate += len(records) - len(inserted)
		records = records[:0]
		pendingBytes = 0
		return nil
	}

	// homeProject decides the project a row lands in: its own when the caller
	// asked to preserve it and the row carries one, otherwise the import target.
	homeProject := func(rowProject string) string {
		if opts.PreserveProjectUUID && rowProject != "" {
			return rowProject
		}
		return projectUUID
	}

	// processLine parses a single JSONL envelope and appends to records/findings.
	// A bare return here behaves like the old `continue` (skip this line, keep going).
	processLine := func(line []byte) {
		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			res.ParseErrors++
			return
		}

		switch envelope.Type {
		case "http_record":
			var rec database.HTTPRecord
			if err := json.Unmarshal(envelope.Data, &rec); err != nil {
				res.ParseErrors++
				return
			}
			rec.ProjectUUID = homeProject(rec.ProjectUUID)
			if rec.UUID == "" {
				rec.UUID = uuid.New().String()
			}
			if rec.SentAt.IsZero() {
				rec.SentAt = time.Now()
			}
			if rec.CreatedAt.IsZero() {
				rec.CreatedAt = time.Now()
			}
			records = append(records, &rec)
			recordLines++
			pendingBytes += len(rec.RawRequest) + len(rec.RawResponse)

		case "scan":
			var scan database.Scan
			if err := json.Unmarshal(envelope.Data, &scan); err != nil || scan.UUID == "" {
				res.ParseErrors++
				return
			}
			scan.ProjectUUID = homeProject(scan.ProjectUUID)
			scans = append(scans, &scan)

		case "oast_interaction":
			var oi database.OASTInteraction
			if err := json.Unmarshal(envelope.Data, &oi); err != nil || oi.FullID == "" {
				res.ParseErrors++
				return
			}
			oi.ProjectUUID = homeProject(oi.ProjectUUID)
			oasts = append(oasts, &oi)

		case "scope":
			if !opts.ImportScopes {
				res.SkippedTypes[envelope.Type]++
				return
			}
			var sc database.Scope
			if err := json.Unmarshal(envelope.Data, &sc); err != nil || sc.RuleType == "" {
				res.ParseErrors++
				return
			}
			sc.ProjectUUID = homeProject(sc.ProjectUUID)
			scopes = append(scopes, &sc)

		case "finding":
			var finding database.Finding
			if err := json.Unmarshal(envelope.Data, &finding); err != nil {
				res.ParseErrors++
				return
			}
			finding.ProjectUUID = homeProject(finding.ProjectUUID)
			if finding.FindingSource == "" {
				finding.FindingSource = database.FindingSourceImport
			}
			if finding.FoundAt.IsZero() {
				finding.FoundAt = time.Now()
			}
			if finding.CreatedAt.IsZero() {
				finding.CreatedAt = time.Now()
			}
			if attachedScan != nil {
				finding.AgenticScanUUID = attachedScan.UUID
			}
			findings = append(findings, &finding)

		default:
			res.SkippedTypes[envelope.Type]++
		}
	}

	maxLine := opts.MaxLineBytes
	if maxLine <= 0 {
		maxLine = DefaultMaxLineBytes
	}

	// Read line-by-line with bufio.Reader rather than bufio.Scanner: an exported
	// http_record can carry a multi-megabyte response/request body on a single
	// line, which overflows Scanner's fixed token cap ("token too long").
	//
	// ReadSlice plus an explicit accumulator rather than ReadBytes, because
	// ReadBytes has no ceiling: pointed at a file with no newlines it allocates
	// the whole file before returning, so the failure mode for naming the wrong
	// input was the OOM killer. Here the accumulator is checked against maxLine
	// on every refill, and the error says which line and what was already written.
	reader := bufio.NewReaderSize(r, 1024*1024)
	var (
		acc     []byte
		partial bool
	)
	tooLong := func() error {
		return fmt.Errorf("line %d exceeds %d bytes (%d records already committed); raise Options.MaxLineBytes if this file is genuinely that wide",
			lineNum+1, maxLine, res.RecordsImported)
	}
	for {
		chunk, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			acc = append(acc, chunk...)
			if len(acc) > maxLine {
				return nil, tooLong()
			}
			partial = true
			continue
		}

		line := chunk
		if partial {
			acc = append(acc, chunk...)
			line = acc
		}
		if len(line) > maxLine {
			return nil, tooLong()
		}
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			lineNum++
			processLine(trimmed)
			if len(records) >= recordFlushBatch || pendingBytes >= recordFlushBytes {
				if err := flushRecords(); err != nil {
					return nil, err
				}
			}
		}
		// Reuse the accumulator for the next wide line, but do not carry an
		// outlier's capacity for the rest of the import: MaxLineBytes allows a
		// single 256 MiB line, and holding that array live behind thousands of
		// small lines would dwarf the whole flush budget this function bounds.
		if cap(acc) > recordFlushBytes {
			acc = nil
		} else {
			acc = acc[:0]
		}
		partial = false

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading JSONL stream: %w", readErr)
		}
	}

	if recordLines == 0 && len(findings) == 0 && len(scans) == 0 && len(oasts) == 0 && len(scopes) == 0 {
		return nil, fmt.Errorf("no importable data found (parsed %d lines, %d errors)", lineNum, res.ParseErrors)
	}
	if err := flushRecords(); err != nil {
		return nil, err
	}

	results, _ := repo.SaveFindingsDirectBatch(ctx, findings)
	saved, skipped, failed := tallyFindingSaves(findings, results, res.SeverityCounts)
	res.FindingsTotal = len(findings)
	res.FindingsSaved = saved
	res.FindingsSkipped = skipped
	res.FindingsFailed = failed

	if err := importSideTables(ctx, repo, res, scans, oasts, scopes); err != nil {
		return nil, err
	}
	res.ImportedByType["http_record"] += res.RecordsImported
	res.DuplicatesByType["http_record"] += res.RecordsSkippedDuplicate
	res.ImportedByType["finding"] += res.FindingsSaved
	res.DuplicatesByType["finding"] += res.FindingsSkipped

	if attachedScan != nil {
		update := &database.AgenticScan{
			UUID:         attachedScan.UUID,
			SavedCount:   attachedScan.SavedCount + saved,
			FindingCount: attachedScan.FindingCount + len(findings),
		}
		// See ImportAudit: the scan row is the link between these findings and the
		// run they belong to, so a failed update is reported rather than dropped.
		if err := repo.UpdateAgenticScan(ctx, update); err != nil {
			return nil, fmt.Errorf("update agent run %s after import: %w", attachedScan.UUID, err)
		}
		attachedScan.SavedCount = update.SavedCount
		attachedScan.FindingCount = update.FindingCount
		res.AgenticScan = attachedScan
	}
	return res, nil
}

func newResult() *Result {
	return &Result{
		SeverityCounts:   map[string]int{},
		SkippedTypes:     map[string]int{},
		ImportedByType:   map[string]int{},
		DuplicatesByType: map[string]int{},
	}
}

// importSideTables stores the scan, OAST-interaction and scope envelopes of a
// JSONL import, each deduplicated against the destination: scans on their
// uuid, interactions on (project, full id, protocol, time), scopes on
// (project, rule type, name, host and path pattern). Row ids are not carried
// over, and an interaction's finding_id is dropped because finding ids are
// local to the store that assigned them. Everything is written in one
// transaction, and the existing interaction and scope keys of each project are
// read once up front rather than probed row by row.
func importSideTables(ctx context.Context, repo *database.Repository, res *Result, scans []*database.Scan, oasts []*database.OASTInteraction, scopes []*database.Scope) error {
	if len(scans)+len(oasts)+len(scopes) == 0 {
		return nil
	}
	return repo.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, sc := range scans {
			r, err := tx.NewInsert().Model(sc).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
			if err != nil {
				return fmt.Errorf("import scan %s: %w", sc.UUID, err)
			}
			if n, _ := r.RowsAffected(); n > 0 {
				res.ImportedByType["scan"]++
			} else {
				res.DuplicatesByType["scan"]++
			}
		}

		oastKey := func(oi *database.OASTInteraction) string {
			return strings.Join([]string{oi.FullID, oi.Protocol, oi.InteractedAt.UTC().Format(time.RFC3339Nano)}, "\x00")
		}
		seenOAST := map[string]map[string]bool{}
		for _, oi := range oasts {
			seen, ok := seenOAST[oi.ProjectUUID]
			if !ok {
				var existing []*database.OASTInteraction
				if err := tx.NewSelect().Model(&existing).Column("full_id", "protocol", "interacted_at").
					Where("project_uuid = ?", oi.ProjectUUID).Scan(ctx); err != nil {
					return fmt.Errorf("import oast interaction %s: %w", oi.FullID, err)
				}
				seen = make(map[string]bool, len(existing))
				for _, e := range existing {
					seen[oastKey(e)] = true
				}
				seenOAST[oi.ProjectUUID] = seen
			}
			if seen[oastKey(oi)] {
				res.DuplicatesByType["oast_interaction"]++
				continue
			}
			oi.ID, oi.FindingID = 0, 0
			if _, err := tx.NewInsert().Model(oi).Exec(ctx); err != nil {
				return fmt.Errorf("import oast interaction %s: %w", oi.FullID, err)
			}
			seen[oastKey(oi)] = true
			res.ImportedByType["oast_interaction"]++
		}

		scopeKey := func(sc *database.Scope) string {
			return strings.Join([]string{sc.RuleType, sc.Name, sc.HostPattern, sc.PathPattern}, "\x00")
		}
		seenScopes := map[string]map[string]bool{}
		for _, sc := range scopes {
			seen, ok := seenScopes[sc.ProjectUUID]
			if !ok {
				var existing []*database.Scope
				if err := tx.NewSelect().Model(&existing).Column("rule_type", "name", "host_pattern", "path_pattern").
					Where("project_uuid = ?", sc.ProjectUUID).Scan(ctx); err != nil {
					return fmt.Errorf("import scope %q: %w", sc.Name, err)
				}
				seen = make(map[string]bool, len(existing))
				for _, e := range existing {
					seen[scopeKey(e)] = true
				}
				seenScopes[sc.ProjectUUID] = seen
			}
			if seen[scopeKey(sc)] {
				res.DuplicatesByType["scope"]++
				continue
			}
			sc.ID = 0
			if _, err := tx.NewInsert().Model(sc).Exec(ctx); err != nil {
				return fmt.Errorf("import scope %q: %w", sc.Name, err)
			}
			seen[scopeKey(sc)] = true
			res.ImportedByType["scope"]++
		}
		return nil
	})
}

func mergeResult(dst, src *Result) {
	if src == nil {
		return
	}
	// Last audit import wins for the "primary" scan reference, since callers
	// typically want a single representative scan for the response. CreatedNew
	// is OR'd so a multi-archive bundle that creates any new scan reports true.
	if src.AgenticScan != nil {
		dst.AgenticScan = src.AgenticScan
		dst.CreatedNew = dst.CreatedNew || src.CreatedNew
	}
	dst.RecordsImported += src.RecordsImported
	dst.RecordsSkippedDuplicate += src.RecordsSkippedDuplicate
	dst.FindingsTotal += src.FindingsTotal
	dst.FindingsSaved += src.FindingsSaved
	dst.FindingsSkipped += src.FindingsSkipped
	dst.FindingsFailed += src.FindingsFailed
	dst.ParseErrors += src.ParseErrors
	for k, v := range src.SeverityCounts {
		dst.SeverityCounts[k] += v
	}
	for k, v := range src.SkippedTypes {
		dst.SkippedTypes[k] += v
	}
	for k, v := range src.ImportedByType {
		dst.ImportedByType[k] += v
	}
	for k, v := range src.DuplicatesByType {
		dst.DuplicatesByType[k] += v
	}
	if src.MergeStats != nil {
		if dst.MergeStats == nil {
			dst.MergeStats = &database.MergeStats{}
		}
		dst.MergeStats.Add(src.MergeStats)
	}
	if src.SessionDir != "" {
		dst.SessionDir = src.SessionDir
	}
	if src.StorageURL != "" {
		dst.StorageURL = src.StorageURL
	}
}

// MergeResults folds several import Results into one aggregate: counts, the
// severity/skipped maps and MergeStats are summed, while the last non-nil
// AgenticScan and session/storage references win (see mergeResult). nil entries
// are ignored. Used to summarize a multi-source import as a single Result.
func MergeResults(results []*Result) *Result {
	agg := newResult()
	for _, r := range results {
		mergeResult(agg, r)
	}
	return agg
}
