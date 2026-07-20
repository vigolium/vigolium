package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var importBurpBridgeURL string

var importCmd = &cobra.Command{
	Use:   "import [path|gs://...] [more-paths...]",
	Short: "Import scan data, databases, or live Burp Proxy history",
	Long: `Import scan data into the database from various sources.

Supported inputs:
  - Live Burp Proxy history through --burp-bridge-url (no path argument)
  - Audit output folder: contains audit-state.json and findings-draft/
  - JSONL file: exported data with {"type": "...", "data": {...}} envelopes
    Supports http_record and finding types (e.g. from 'vigolium export --format jsonl')
  - Vigolium SQLite database (.sqlite/.sqlite3/.db, detected by header): merged
    into the destination database — HTTP records, findings, scans, agentic scans
    and OAST interactions, deduped on their natural keys (re-importing the same
    database is a no-op). Each row keeps its original project. The destination is
    the --db target, e.g. 'vigolium import --db main.sqlite other-scan.sqlite'
    (or the configured default database when --db is omitted).
  - .tar.gz / .tgz / .zip archive containing an audit folder or JSONL
  - gs://<project-uuid>/<key> URL to any of the above (downloaded then imported)

Multiple sources can be imported in one command — pass several positional paths
('vigolium import a.sqlite b.sqlite c.sqlite', or 'a.jsonl b.jsonl') and/or use
--glob-db to expand a glob of local files ('vigolium import --glob-db
"prefix-*.sqlite"', or '"*.jsonl"'). Each source is imported by its own detected
type, so the same input formats above are all supported. Use one format per run:
mixing formats (e.g. .sqlite with .jsonl) still works but prints a warning.
Sources are imported sequentially into the same destination DB and their results
aggregated into one summary; because SQLite merges and finding imports dedup on
natural keys, re-runs and overlapping inputs are safe.

The Burp bridge is an alternative source and cannot be combined with a path or
--glob-db in the same invocation. It imports all Proxy-history records visible
through the extension's Bridge settings. Re-importing is idempotent: changed
responses are refreshed and unchanged requests are not duplicated.

Use --upload to push the local source to cloud storage after a successful import,
or --upload-key=<key> to choose an explicit storage key (folders are bundled to
tar.gz unless the key ends in .zip).

Use --format with -o/--output to write a report in the same step, e.g.
'vigolium import ./audit --format html -o audit-report.html'. This replaces
the import-then-export two-step: when the import created an audit the
report is scoped to that audit's findings. Formats mirror 'vigolium export':
html, report, pdf, markdown (alias md).

Report customization flags (--report-title, --report-target, --report-duration,
--report-generated-at, --report-url) and finding filters (--severity, --search)
mirror 'vigolium export', so a single import step can emit a fully-branded report:
'vigolium import ./audit --format html -o audit-report.html --report-title "My custom report"'.`,
	Args: cobra.ArbitraryArgs,
	RunE: runImport,
}

func init() {
	importCmd.Flags().StringVarP(
		&importBurpBridgeURL,
		"burp-bridge-url",
		"B",
		burpbridge.URLFromEnvironment(),
		"Import live Burp Proxy history from this loopback bridge URL into the database")
	importCmd.Flags().Bool("upload", false, "Upload the local import source to cloud storage after import")
	importCmd.Flags().String("upload-key", "", "Explicit storage key for --upload (default: imports/<basename>-<ts>.<ext>)")
	importCmd.Flags().StringVar(&globalGlobDB, "glob-db", "", "Glob of local files to import alongside any positional paths (use one format per run), e.g. --glob-db 'prefix-*.sqlite' or '*.jsonl'")
	importCmd.Flags().String("format", "", "Also write a report after import: html, report, pdf, or markdown (md). Mirrors `vigolium export --format`.")
	importCmd.Flags().StringP("output", "o", "", "Report output path or gs://<project>/<key> URL (required when --format is set; supports {ts})")
	// Report customization + finding filters — mirror `vigolium export` so a
	// single import step can emit a fully-branded, filtered report.
	importCmd.Flags().String("report-title", "", "Custom title for the HTML report (default: \"Vigolium Static Report\")")
	importCmd.Flags().String("report-target", "", "Target name for the report (e.g. repository name or URL)")
	importCmd.Flags().String("report-duration", "", "Human-readable scan duration for the report (e.g. \"10h42m5s\")")
	importCmd.Flags().String("report-generated-at", "", "ISO timestamp for report generation (e.g. \"2026-04-18T03:00:00Z\")")
	importCmd.Flags().String("report-url", "", "URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
	importCmd.Flags().String("severity", "", "Filter report findings by severity (comma-separated: critical,high,medium,low,info)")
	importCmd.Flags().String("search", "", "Fuzzy search filter across finding fields included in the report")
	rootCmd.AddCommand(importCmd)
}

// importReportOpts carries the report-customization and finding-filter flag
// overrides from `vigolium import` into emitImportReport. Empty fields fall
// back to the auto-detected scan metadata / defaults, matching `vigolium export`.
type importReportOpts struct {
	title       string
	target      string
	duration    string
	generatedAt string
	reportURL   string
	severity    string
	search      string
}

func runImport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	ctx := context.Background()
	upload, _ := cmd.Flags().GetBool("upload")
	uploadKey, _ := cmd.Flags().GetString("upload-key")
	if uploadKey != "" {
		upload = true
	}
	globDB := globalGlobDB
	bridgeURL := strings.TrimSpace(importBurpBridgeURL)
	if bridgeURL != "" {
		validated, err := burpbridge.ValidateURL(bridgeURL)
		if err != nil {
			return fmt.Errorf("--burp-bridge-url: %w", err)
		}
		bridgeURL = validated
	}
	if bridgeURL != "" && (len(args) > 0 || globDB != "") {
		return fmt.Errorf("--burp-bridge-url is an import source and cannot be combined with path arguments or --glob-db")
	}
	if bridgeURL != "" && upload {
		return fmt.Errorf("--upload and --upload-key are not applicable to a live Burp bridge import")
	}

	// Gather every import source: positional paths plus any local files matched
	// by --glob-db. Positional args are gcs://→gs:// normalized and deduped
	// here so the destination DB, HasPrefix checks and StorageURL stay
	// consistent regardless of ordering.
	var sources []string
	var err error
	if bridgeURL == "" {
		sources, err = gatherImportSources(args, globDB)
		if err != nil {
			return err
		}
	}
	multi := len(sources) > 1
	if multi {
		// Multiple sources are meant to be one format per run; warn (don't fail)
		// when the set mixes formats, since each is still imported by its type.
		warnMixedImportFormats(sources)
	}

	// An explicit --upload-key addresses a single object; with more than one
	// source it would clobber, so reject it up front rather than silently
	// overwrite. Auto-generated per-source keys (empty --upload-key) are fine.
	if uploadKey != "" && multi {
		return fmt.Errorf("--upload-key cannot be used with multiple import sources (%d resolved); drop --upload-key to auto-generate a key per source", len(sources))
	}

	// Validate report flags up front so a typo fails before the import work,
	// not after it has already mutated the database.
	reportFormat, _ := cmd.Flags().GetString("format")
	reportOutput, _ := cmd.Flags().GetString("output")
	if reportFormat != "" {
		if bridgeURL != "" {
			return fmt.Errorf("--format is not applicable to a traffic-only Burp bridge import")
		}
		if _, _, ok := reportGenerator(reportFormat); !ok {
			return fmt.Errorf("--format %q is not a report format; use html, report, pdf, or markdown", reportFormat)
		}
		if reportOutput == "" {
			return fmt.Errorf("--format %s requires -o/--output for the report path", reportFormat)
		}
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	// Ensure the schema exists before any DB work. `import` is often the first
	// command run against a brand-new database (e.g. a fresh --db path), and
	// unlike scan/ingest/agent it otherwise never initializes the schema — which
	// silently drops the imported findings and fails any post-import report with
	// "no such table: findings".
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}
	if err := db.SeedDefaults(ctx); err != nil {
		return fmt.Errorf("failed to seed default data: %w", err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	repo := database.NewRepository(db)
	if bridgeURL != "" {
		if !globalJSON {
			fmt.Fprint(os.Stderr, GetBanner())
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
				terminal.BoldCyan(fmt.Sprintf("Importing live Burp traffic from %s ...", bridgeURL)))
		}
		result, err := importBurpTrafficToDB(ctx, repo, bridgeURL, burpbridge.Query{
			Location: "proxy_history",
		}, projectUUID)
		if err != nil {
			return fmt.Errorf("import Burp traffic: %w", err)
		}
		writeBurpImportResult(os.Stdout, bridgeURL, result, globalJSON)
		return nil
	}

	// One label for both the banner and the summary: the single source path, or
	// "N sources" when there are several.
	label := sources[0]
	if multi {
		label = fmt.Sprintf("%d sources", len(sources))
	}

	// Announce the work before it starts: parsing an audit folder and writing
	// findings/records to the DB can take a while for large runs, and without a
	// progress line the terminal looks frozen until the summary prints.
	if !globalJSON {
		fmt.Fprint(os.Stderr, GetBanner())
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
			terminal.BoldCyan(fmt.Sprintf("Importing scan data from %s ...", label)))
		fmt.Fprintf(os.Stderr, "  %s\n",
			terminal.Gray("Parsing input and writing records to the database — this can take a moment for large audits"))
	}

	results := make([]*dbimport.Result, 0, len(sources))
	for i, src := range sources {
		result, err := importOneSource(ctx, repo, src, projectUUID)
		if err != nil {
			return fmt.Errorf("import %s: %w", src, err)
		}
		results = append(results, result)
		// Per-source progress line for multi-source human runs; the aggregate
		// block follows. JSON stays a single object, emitted below.
		if multi && !globalJSON {
			printImportSourceProgress(i+1, len(sources), src, result)
		}
	}

	// Summary: single source keeps the exact pre-existing shape (full block /
	// single JSON object). Multiple sources fold into one aggregate summary,
	// labelled by the glob pattern when one drove the set.
	if multi {
		if globDB != "" {
			label = globDB
		}
		printImportResult(label, aggregateImportResults(results))
	} else {
		printImportResult(label, results[0])
	}

	if reportFormat != "" {
		reportTitle, _ := cmd.Flags().GetString("report-title")
		reportTarget, _ := cmd.Flags().GetString("report-target")
		reportDuration, _ := cmd.Flags().GetString("report-duration")
		reportGeneratedAt, _ := cmd.Flags().GetString("report-generated-at")
		reportURL, _ := cmd.Flags().GetString("report-url")
		reportSeverity, _ := cmd.Flags().GetString("severity")
		reportSearch, _ := cmd.Flags().GetString("search")
		opts := importReportOpts{
			title:       reportTitle,
			target:      reportTarget,
			duration:    reportDuration,
			generatedAt: reportGeneratedAt,
			reportURL:   reportURL,
			severity:    reportSeverity,
			search:      reportSearch,
		}
		// A single audit source scopes the report to that audit's findings;
		// multiple sources have no single owning scan (nil), so the report
		// covers all findings in the project.
		var reportScan *database.AgenticScan
		if !multi {
			reportScan = results[0].AgenticScan
		}
		if err := emitImportReport(ctx, db, reportScan, reportFormat, reportOutput, opts); err != nil {
			return fmt.Errorf("import succeeded but report generation failed: %w", err)
		}
	}

	if upload {
		for _, src := range sources {
			// A gs:// source is already in cloud storage — nothing to push up.
			if strings.HasPrefix(src, "gs://") {
				fmt.Fprintf(os.Stderr, "%s --upload skipped for %s (already in cloud storage)\n", terminal.WarningSymbol(), src)
				continue
			}
			url, err := uploadImportSource(ctx, src, uploadKey)
			if err != nil {
				return fmt.Errorf("import succeeded but upload failed: %w", err)
			}
			fmt.Printf("%s Source uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(url))
		}
	}
	return nil
}

// gatherImportSources resolves the full ordered, deduplicated list of import
// sources from the positional args and an optional --glob-db pattern.
// Positional args are gcs://→gs:// normalized; glob matches are local paths.
// Returns an error when nothing resolves so the user gets a clear message
// instead of a silent no-op.
func gatherImportSources(args []string, globDB string) ([]string, error) {
	var raw []string
	for _, a := range args {
		// Normalize "gcs://" (alias) to canonical "gs://" so downstream
		// HasPrefix checks and DB-stored StorageURL stay consistent.
		raw = append(raw, storage.NormalizeGCSURI(a))
	}
	if globDB != "" {
		matches, err := filepath.Glob(globDB)
		if err != nil {
			return nil, fmt.Errorf("invalid --glob-db pattern %q: %w", globDB, err)
		}
		if len(matches) == 0 {
			fmt.Fprintf(os.Stderr, "%s --glob-db %q matched no files\n", terminal.WarningSymbol(), globDB)
		}
		// filepath.Glob returns lexically sorted matches, so appending them
		// directly keeps the import order deterministic.
		raw = append(raw, matches...)
	}
	sources := dedupeStrings(raw)
	if len(sources) == 0 {
		return nil, fmt.Errorf("no import sources: provide a path argument or --glob-db <pattern>")
	}
	return sources, nil
}

// importSourceFormat returns a coarse format category for a source path/URL,
// used only to warn when a multi-source import mixes formats. Extension-based
// (SQLite files are otherwise detected by header, but the mixed-format warning
// is a lightweight heuristic that must not stat/open every source). gs:// URLs
// are categorized by their key's extension. Sibling extensions of one format
// (.sqlite/.sqlite3/.db, .jsonl/.ndjson) collapse to the same category so an
// all-SQLite or all-JSONL run never trips the warning.
func importSourceFormat(src string) string {
	s := strings.TrimPrefix(src, "gs://")
	// ArchiveExt already recognizes the archive and JSONL extensions.
	switch dbimport.ArchiveExt(s) {
	case ".tar.gz", ".tgz", ".zip":
		return "archive"
	case ".jsonl", ".ndjson", ".json":
		return "jsonl"
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".sqlite", ".sqlite3", ".db":
		return "sqlite"
	case "":
		// A directory (audit folder) or extension-less path.
		return "folder"
	default:
		return "other"
	}
}

// warnMixedImportFormats prints a warning (to stderr) when the resolved sources
// span more than one format category. Each source is still imported by its own
// detected type — the warning just flags the likely-unintended mix, per the
// "one format per run" contract. Returns the distinct categories in first-seen
// order so callers/tests can inspect the decision.
func warnMixedImportFormats(sources []string) []string {
	kinds := make([]string, 0, len(sources))
	for _, s := range sources {
		kinds = append(kinds, importSourceFormat(s))
	}
	kinds = dedupeStrings(kinds)
	if len(kinds) > 1 && !globalJSON {
		fmt.Fprintf(os.Stderr, "%s Mixed import formats (%s) — each source is imported by its own type, but prefer one format per run for predictable merges\n",
			terminal.WarningSymbol(), strings.Join(kinds, ", "))
	}
	return kinds
}

// importOneSource resolves a single source (downloading gs:// inputs to a temp
// file that is cleaned up before returning) and imports it into repo. Factored
// out of runImport so the multi-source loop cleans up each source's temp file
// as it goes rather than deferring every cleanup to the end of the command.
func importOneSource(ctx context.Context, repo *database.Repository, src, projectUUID string) (*dbimport.Result, error) {
	localPath, cleanup, err := resolveImportInput(ctx, src)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	opts := dbimport.Options{
		OriginalSource:     src,
		SessionDirArchiver: cliSessionDirArchiver,
	}
	return dbimport.ImportPath(ctx, repo, localPath, projectUUID, opts)
}

// aggregateImportResults folds per-source import results into one combined
// Result for the multi-source summary via dbimport.MergeResults (which sums the
// counts and MergeStats). It then applies a presentation rule: the merge-shaped
// summary block is only rendered when *every* source was a SQLite merge (the
// common --glob-db case), so a mix of audit/JSONL/SQLite sources falls back
// to the generic finding-count summary.
func aggregateImportResults(results []*dbimport.Result) *dbimport.Result {
	agg := dbimport.MergeResults(results)
	for _, r := range results {
		if r.MergeStats == nil {
			agg.MergeStats = nil
			break
		}
	}
	return agg
}

// printImportSourceProgress prints a compact one-line summary of a single
// source's import during a multi-source run (human output only). The detailed
// aggregate block is printed once at the end by printImportResult.
func printImportSourceProgress(idx, total int, src string, r *dbimport.Result) {
	fmt.Printf("  %s [%d/%d] %s — %d records, %d findings (%d dup)\n",
		terminal.SuccessSymbol(), idx, total, terminal.Cyan(src),
		r.RecordsImported, r.FindingsSaved, r.FindingsSkipped)
}

// cliSessionDirArchiver copies an audit source folder into the per-run agent
// session directory keyed by scan UUID and returns the resulting session dir.
// Best-effort: failures are logged to stderr and result in an empty return so
// the import still completes. Mirrors the prior in-CLI helper.
func cliSessionDirArchiver(scanUUID, srcDir string) (string, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}
	sessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), scanUUID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create session dir for %s: %v\n", terminal.WarningSymbol(), scanUUID, err)
		return "", nil
	}
	dst := filepath.Join(sessionDir, "audit")
	if entries, statErr := os.ReadDir(dst); statErr == nil && len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "%s Session dir %s already populated; skipping copy\n", terminal.WarningSymbol(), dst)
		return sessionDir, nil
	}
	if err := dbimport.CopyDirContents(srcDir, dst); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to copy audit source into session dir: %v\n", terminal.WarningSymbol(), err)
		return "", nil
	}
	return sessionDir, nil
}

// printImportResult renders a CLI summary for the import (JSON when -j, human
// otherwise). The shape mirrors the pre-refactor format so existing
// CLI consumers and tests don't break.
func printImportResult(localPath string, r *dbimport.Result) {
	if r == nil {
		return
	}

	// A SQLite-database import is a merge, not a parse — summarize the merged
	// tables (records/findings/scans/oast) rather than the JSONL/audit shape.
	if r.MergeStats != nil {
		printMergeResult(localPath, r.MergeStats)
		return
	}

	if globalJSON {
		out := map[string]interface{}{}
		if uuid := r.AgenticScanUUID(); uuid != "" {
			out["agentic_scan_uuid"] = uuid
		}
		if r.RecordsImported > 0 {
			out["records_imported"] = r.RecordsImported
		}
		out["findings_total"] = r.FindingsTotal
		out["findings_saved"] = r.FindingsSaved
		out["findings_skipped"] = r.FindingsSkipped
		if len(r.SeverityCounts) > 0 {
			out["severity"] = r.SeverityCounts
		}
		if r.ParseErrors > 0 {
			out["parse_errors"] = r.ParseErrors
		}
		if r.SessionDir != "" {
			out["session_dir"] = r.SessionDir
		}
		if r.StorageURL != "" {
			out["storage_url"] = r.StorageURL
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}

	if r.AgenticScan != nil {
		scan := r.AgenticScan
		fmt.Printf("%s Imported audit: %d findings (%d new, %d duplicates skipped)\n",
			terminal.SuccessSymbol(), r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped)
		fmt.Printf("  Agent run: %s (mode=%s, status=%s)\n", scan.UUID, scan.Mode, scan.Status)
		if scan.TargetURL != "" {
			fmt.Printf("  Target:   %s\n", terminal.BoldCyan(scan.TargetURL))
		}
		if scan.Model != "" {
			fmt.Printf("  Model:    %s\n", terminal.Cyan(scan.Model))
		}
	} else {
		fmt.Printf("%s Imported JSONL data from %s\n", terminal.SuccessSymbol(), localPath)
		if r.RecordsImported > 0 {
			fmt.Printf("  HTTP records: %d imported\n", r.RecordsImported)
		}
		if r.FindingsTotal > 0 {
			fmt.Printf("  Findings: %d total (%d new, %d duplicates skipped)\n", r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped)
		}
	}

	if sev := r.SeverityCounts; sev["high"] > 0 || sev["critical"] > 0 || sev["medium"] > 0 || sev["low"] > 0 {
		fmt.Printf("  Severity: %s, %s, %s, %s\n",
			terminal.BoldMagenta(fmt.Sprintf("%d critical", sev["critical"])),
			terminal.BoldRed(fmt.Sprintf("%d high", sev["high"])),
			terminal.BoldYellow(fmt.Sprintf("%d medium", sev["medium"])),
			terminal.BoldGreen(fmt.Sprintf("%d low", sev["low"])),
		)
	}
	if r.SessionDir != "" {
		fmt.Printf("  Session:  %s\n", terminal.Gray(r.SessionDir))
	}
	if r.StorageURL != "" {
		fmt.Printf("  Storage:  %s\n", terminal.Gray(r.StorageURL))
	}
	if r.ParseErrors > 0 {
		fmt.Printf("  %s %d lines could not be parsed\n", terminal.WarningSymbol(), r.ParseErrors)
	}
	for typ, count := range r.SkippedTypes {
		fmt.Printf("  Skipped %d %q entries\n", count, typ)
	}
}

// printMergeResult renders the summary for a SQLite-database import — a
// lossless SQLite→SQLite merge of another vigolium result database into the
// current one. JSON when -j, human-readable otherwise.
func printMergeResult(srcPath string, s *database.MergeStats) {
	if globalJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"merged_from":            srcPath,
			"records_merged":         s.RecordsMerged,
			"findings_merged":        s.FindingsMerged,
			"findings_deduped":       s.FindingsDeduped,
			"scans_merged":           s.ScansMerged,
			"agentic_scans_merged":   s.AgenticScansMerged,
			"projects_merged":        s.ProjectsMerged,
			"finding_records_merged": s.FindingRecordsMerged,
			"oast_merged":            s.OASTMerged,
		})
		return
	}

	fmt.Printf("%s Merged SQLite database %s\n", terminal.SuccessSymbol(), terminal.Cyan(srcPath))
	fmt.Printf("  HTTP records: %d merged\n", s.RecordsMerged)
	fmt.Printf("  Findings:     %d merged, %d duplicates skipped\n", s.FindingsMerged, s.FindingsDeduped)
	if s.ScansMerged > 0 || s.AgenticScansMerged > 0 {
		fmt.Printf("  Scans:        %d native, %d agentic\n", s.ScansMerged, s.AgenticScansMerged)
	}
	if s.ProjectsMerged > 0 {
		fmt.Printf("  Projects:     %d merged\n", s.ProjectsMerged)
	}
	if s.OASTMerged > 0 {
		fmt.Printf("  OAST:         %d interactions merged\n", s.OASTMerged)
	}
}

// emitImportReport renders a static report for the data just imported, reusing
// the exact generators behind `vigolium export` (single source of truth via
// reportGenerator). When the import created an audit AgenticScan the report is
// scoped to that audit's findings; otherwise it falls back to all findings in
// the project DB. This collapses the historical import-then-export two-step
// into one command.
func emitImportReport(ctx context.Context, db *database.DB, scan *database.AgenticScan, format, outputArg string, opts importReportOpts) error {
	gen, defaultTitle, ok := reportGenerator(format)
	if !ok {
		return fmt.Errorf("unsupported report format %q", format)
	}

	localOutput, finalize, err := resolveExportOutput(ctx, outputArg)
	if err != nil {
		return err
	}

	scanUUID := ""
	if scan != nil {
		scanUUID = scan.UUID
	}
	var findings []*database.Finding
	q := db.NewSelect().Model(&findings).
		Where("record_kind IS NULL OR record_kind = '' OR record_kind = ?", database.RecordKindFinding).
		OrderExpr("found_at DESC")
	if scanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", scanUUID)
	}
	// Finding filters mirror `vigolium export`'s findings query so the report
	// contents stay consistent between the two commands.
	if opts.search != "" {
		p := "%" + opts.search + "%"
		q = q.Where("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ? OR url LIKE ? OR hostname LIKE ? OR extracted_results LIKE ?)", p, p, p, p, p, p, p, p)
	}
	if opts.severity != "" {
		sevs := strings.Split(strings.ToLower(opts.severity), ",")
		q = q.Where("LOWER(severity) IN (?)", bun.List(sevs))
	}
	if err := q.Scan(ctx); err != nil {
		return fmt.Errorf("query findings for report: %w", err)
	}
	items := make([]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, exportEnvelope{Type: "finding", Data: f})
	}

	title := defaultTitle
	if opts.title != "" {
		title = opts.title
	}
	meta := output.HTMLReportMeta{
		Title:           title,
		Version:         getVersion(),
		GeneratedAt:     opts.generatedAt,
		ReportSharedURL: opts.reportURL,
	}
	if scan != nil {
		meta.ScanTarget = scan.TargetURL
		if meta.ScanTarget == "" {
			meta.ScanTarget = scan.SourcePath
		}
		if scan.DurationMs > 0 {
			meta.ScanDuration = (time.Duration(scan.DurationMs) * time.Millisecond).Round(time.Second).String()
		}
	}
	// Explicit flag overrides win over the auto-detected scan metadata, matching
	// how `vigolium export` lets --report-target/--report-duration override.
	if opts.target != "" {
		meta.ScanTarget = opts.target
	}
	if opts.duration != "" {
		meta.ScanDuration = opts.duration
	}

	if !globalJSON {
		detail := ""
		if format == "pdf" {
			detail = " (headless Chrome)"
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
			terminal.BoldCyan(fmt.Sprintf("Generating %s report%s — %d findings ...", format, detail, len(findings))))
	}
	if err := gen(items, localOutput, meta); err != nil {
		return err
	}
	if err := finalize(); err != nil {
		return err
	}

	scope := "all findings in project"
	if scanUUID != "" {
		scope = "imported audit " + scanUUID
	}
	fmt.Printf("%s Report written: %s (%d findings, %s, format=%s)\n",
		terminal.SuccessSymbol(), terminal.Cyan(outputArg), len(findings), scope, format)
	return nil
}
