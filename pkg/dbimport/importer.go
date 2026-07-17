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

	SeverityCounts map[string]int
	SkippedTypes   map[string]int

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
}

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

// tallyFindingSaves counts saved (newly-inserted) vs skipped (dedup-append or
// errored) findings from an aligned SaveFindingsDirectBatch result, tallying the
// severity of each non-errored finding into sev. Shared by the audit and JSONL
// import paths.
func tallyFindingSaves(findings []*database.Finding, results []database.FindingSaveResult, sev map[string]int) (saved, skipped int) {
	for i, f := range findings {
		if results[i].Err != nil {
			skipped++
			continue
		}
		if results[i].Inserted {
			saved++
		} else {
			skipped++
		}
		sev[f.Severity]++
	}
	return saved, skipped
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
	results, _ := repo.SaveFindingsDirectBatch(ctx, findings)
	saved, skipped := tallyFindingSaves(findings, results, sevCounts)

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
	_ = repo.UpdateAgenticScan(ctx, updateScan)

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
	res.SeverityCounts = sevCounts
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
		records  []*database.HTTPRecord
		findings []*database.Finding
		lineNum  int
	)

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
			rec.ProjectUUID = projectUUID
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

		case "finding":
			var finding database.Finding
			if err := json.Unmarshal(envelope.Data, &finding); err != nil {
				res.ParseErrors++
				return
			}
			finding.ProjectUUID = projectUUID
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

	// Read line-by-line with bufio.Reader rather than bufio.Scanner: an exported
	// http_record can carry a multi-megabyte response/request body on a single
	// line, which overflows Scanner's fixed token cap ("token too long").
	// ReadBytes grows its buffer to the full line length, so any line size loads.
	reader := bufio.NewReaderSize(r, 1024*1024)
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(lineBytes); len(trimmed) > 0 {
			lineNum++
			processLine(trimmed)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading JSONL stream: %w", readErr)
		}
	}

	if len(records) == 0 && len(findings) == 0 {
		return nil, fmt.Errorf("no importable data found (parsed %d lines, %d errors)", lineNum, res.ParseErrors)
	}

	const batchSize = 500
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		uuids, err := repo.SaveRecordsBatch(ctx, records[i:end])
		if err != nil {
			return nil, fmt.Errorf("failed to save HTTP records batch: %w", err)
		}
		res.RecordsImported += len(uuids)
	}

	results, _ := repo.SaveFindingsDirectBatch(ctx, findings)
	saved, skipped := tallyFindingSaves(findings, results, res.SeverityCounts)
	res.FindingsTotal = len(findings)
	res.FindingsSaved = saved
	res.FindingsSkipped = skipped

	if attachedScan != nil {
		update := &database.AgenticScan{
			UUID:         attachedScan.UUID,
			SavedCount:   attachedScan.SavedCount + saved,
			FindingCount: attachedScan.FindingCount + len(findings),
		}
		_ = repo.UpdateAgenticScan(ctx, update)
		attachedScan.SavedCount = update.SavedCount
		attachedScan.FindingCount = update.FindingCount
		res.AgenticScan = attachedScan
	}
	return res, nil
}

func newResult() *Result {
	return &Result{
		SeverityCounts: map[string]int{},
		SkippedTypes:   map[string]int{},
	}
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
	dst.FindingsTotal += src.FindingsTotal
	dst.FindingsSaved += src.FindingsSaved
	dst.FindingsSkipped += src.FindingsSkipped
	dst.ParseErrors += src.ParseErrors
	for k, v := range src.SeverityCounts {
		dst.SeverityCounts[k] += v
	}
	for k, v := range src.SkippedTypes {
		dst.SkippedTypes[k] += v
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
