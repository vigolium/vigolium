package dbimport

import (
	"bufio"
	"context"
	"encoding/json"
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
}

// ImportPath dispatches based on filesystem inspection of path: directory →
// audit folder, .tar.gz/.tgz/.zip → archive, anything else → JSONL.
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
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer func() { _ = f.Close() }()
		return ImportJSONL(ctx, repo, f, projectUUID, opts)
	}
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

	saved, skipped := 0, 0
	sevCounts := map[string]int{}
	for _, f := range findings {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			skipped++
			continue
		}
		if f.ID == 0 {
			skipped++
		} else {
			saved++
		}
		sevCounts[f.Severity]++
	}

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

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			res.ParseErrors++
			continue
		}

		switch envelope.Type {
		case "http_record":
			var rec database.HTTPRecord
			if err := json.Unmarshal(envelope.Data, &rec); err != nil {
				res.ParseErrors++
				continue
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
				continue
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
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL stream: %w", err)
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

	saved, skipped := 0, 0
	for _, f := range findings {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			skipped++
			continue
		}
		if f.ID == 0 {
			skipped++
		} else {
			saved++
		}
		res.SeverityCounts[f.Severity]++
	}
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
	if src.SessionDir != "" {
		dst.SessionDir = src.SessionDir
	}
	if src.StorageURL != "" {
		dst.StorageURL = src.StorageURL
	}
}
