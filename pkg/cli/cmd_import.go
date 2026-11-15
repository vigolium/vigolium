package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	importBurpBridgeURL string
	importSearchFilter  string
)

var importCmd = &cobra.Command{
	Use:   "import [path|gs://...] [more-paths...]",
	Short: "Import scan data, databases, or live Burp Proxy history",
	Long: `Import scan data into the database from various sources.

Supported inputs:
  - Live Burp/Caido proxy history through --burp-bridge-url (alias
    --caido-bridge-url; no path argument)
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
html, report, pdf, markdown (alias md), sarif.

Report customization flags (--report-title, --report-target, --report-duration,
--report-generated-at, --report-url) and finding filters (--severity, --search)
mirror 'vigolium export', so a single import step can emit a fully-branded report:
'vigolium import ./audit --format html -o audit-report.html --report-title "My custom report"'.`,
	Args: cobra.ArbitraryArgs,
	RunE: runImport,
}

func init() {
	registerBridgeURLFlag(importCmd, &importBurpBridgeURL,
		"Import live Burp/Caido proxy history from this loopback bridge URL into the database")
	registerImportBridgeFilterFlags(importCmd.Flags())
	importCmd.Flags().Bool("upload", false, "Upload the local import source to cloud storage after import")
	importCmd.Flags().String("upload-key", "", "Explicit storage key for --upload (default: imports/<basename>-<ts>.<ext>)")
	importCmd.Flags().StringVar(&globalGlobDB, "glob-db", "", "Glob of local files to import alongside any positional paths (use one format per run), e.g. --glob-db 'prefix-*.sqlite' or '*.jsonl'")
	// --format is the global flag (a local one would shadow it): here it names
	// the report to write after the import — see importReportFormat.
	importCmd.Flags().StringP("output", "o", "", "Report output path or gs://<project>/<key> URL (required when --format is set; supports {ts})")
	// Report customization + finding filters — mirror `vigolium export` so a
	// single import step can emit a fully-branded, filtered report.
	importCmd.Flags().String("report-title", "", "Custom title for the HTML report (default: \"Vigolium Static Report\")")
	importCmd.Flags().String("report-target", "", "Target name for the report (e.g. repository name or URL)")
	importCmd.Flags().String("report-duration", "", "Human-readable scan duration for the report (e.g. \"10h42m5s\")")
	importCmd.Flags().String("report-generated-at", "", "ISO timestamp for report generation (e.g. \"2026-04-18T03:00:00Z\")")
	importCmd.Flags().String("report-url", "", "URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
	importCmd.Flags().String("severity", "", "Filter report findings by severity (comma-separated: critical,high,medium,low,info)")
	// Bound to a package var, not read back via Flags().GetString: the bridge
	// path needs this value too (see importBridgeSearchTerm), and reaching for
	// importCmd from a function runImport calls would make importCmd's own
	// initializer cyclic.
	registerReportFlags(importCmd.Flags())
	importCmd.Flags().StringVar(&importSearchFilter, "search", "", "Fuzzy search filter across finding fields included in the report; under --burp-bridge-url, narrows which records are imported")
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
			return usageErrorf("--burp-bridge-url: %w", err)
		}
		bridgeURL = validated
	}
	if bridgeURL != "" && (len(args) > 0 || globDB != "") {
		return usageErrorf("--burp-bridge-url is an import source and cannot be combined with path arguments or --glob-db")
	}
	if bridgeURL != "" && upload {
		return usageErrorf("--upload and --upload-key are not applicable to a live Burp bridge import")
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
		return usageErrorf("--upload-key cannot be used with multiple import sources (%d resolved); drop --upload-key to auto-generate a key per source", len(sources))
	}

	// Validate report flags up front so a typo fails before the import work,
	// not after it has already mutated the database.
	reportFormat := importReportFormat(cmd)
	reportOutput, _ := cmd.Flags().GetString("output")
	if reportFormat != "" {
		if bridgeURL != "" {
			return usageErrorf("--format is not applicable to a traffic-only Burp bridge import")
		}
		if _, err := output.Lookup(reportFormat, output.SurfaceImport); err != nil {
			return usageErrorf("--format %q is not a report format; valid formats: %s",
				reportFormat, strings.Join(output.Names(output.SurfaceImport), ", "))
		}
		if err := validateReportFlags(); err != nil {
			return err
		}
		if reportOutput == "" {
			return usageErrorf("--format %s requires -o/--output for the report path", reportFormat)
		}
	}

	// Write intent makes the schema ready before any DB work. `import` is often
	// the first command run against a brand-new database (e.g. a fresh --db
	// path); an uninitialized store silently dropped the imported findings and
	// failed any post-import report with "no such table: findings".
	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
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
		// Build (and therefore validate) the query BEFORE the banner: announcing
		// an import that is about to be refused reads as a run that started and
		// then broke, rather than as a command that was never going to run.
		query, qErr := buildImportBridgeQuery(projectUUID)
		if qErr != nil {
			return qErr
		}
		if !globalJSON {
			emitBanner(GetBanner())
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
				terminal.BoldCyan(fmt.Sprintf("Importing live bridge traffic from %s ...", bridgeURL)))
		}
		client, cErr := burpbridge.New(bridgeURL)
		if cErr != nil {
			return usageErrorf("--burp-bridge-url: %w", cErr)
		}
		// Count first, write second. An operator who asked for one host and is
		// shown 12,400 records across their whole history stops here — which is
		// only possible because nothing has been written yet.
		proceed, pErr := preflightImportBridge(ctx, client, query)
		if pErr != nil {
			return pErr
		}
		if !proceed {
			if globalJSON {
				// Nothing matched (or nothing was confirmed): still one document,
				// saying no state changed, rather than an empty stdout.
				return emitMutation(cmd, "", mutationResult{Action: "noop", Extra: map[string]any{"bridge_url": bridgeURL}})
			}
			return nil
		}
		result, err := importBurpTrafficToDB(ctx, repo, bridgeURL, query, projectUUID)
		if err != nil {
			return fmt.Errorf("import Burp traffic: %w", err)
		}
		if globalJSON {
			extra, err := structFields(burpImportResultJSON(bridgeURL, result))
			if err != nil {
				return err
			}
			return emitMutation(cmd, "", mutationResult{
				Changed: result.Inserted+result.Updated > 0,
				Action:  "import",
				Extra:   extra,
			})
		}
		writeBurpImportResult(os.Stdout, result)
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
		emitBanner(GetBanner())
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
	}
	summary := results[0]
	if multi {
		summary = aggregateImportResults(results)
	}
	// Human output prints now, because the per-stage lines are the progress
	// report. The -j document is held until every requested artifact has landed:
	// see importResultJSON.
	var jsonOut map[string]any
	if globalJSON {
		jsonOut = importResultJSON(label, summary)
	} else {
		printImportResult(label, summary)
	}

	if reportFormat != "" {
		reportTitle, _ := cmd.Flags().GetString("report-title")
		reportTarget, _ := cmd.Flags().GetString("report-target")
		reportDuration, _ := cmd.Flags().GetString("report-duration")
		reportGeneratedAt, _ := cmd.Flags().GetString("report-generated-at")
		reportURL, _ := cmd.Flags().GetString("report-url")
		reportSeverity, _ := cmd.Flags().GetString("severity")
		reportSearch := importSearchFilter
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
		reportPath, err := emitImportReport(ctx, db, reportScan, reportFormat, reportOutput, opts)
		if err != nil {
			// apicontract.CodeExportFailed, not the inferred code: the import landed and the
			// findings are queryable; what failed is the artifact that was asked
			// for, and a driver's correct response is to retry the report rather
			// than the import. Left to inference, a missing parent directory wraps
			// os.ErrNotExist and reports source_missing — which names the import
			// source that was read successfully a moment earlier.
			return codedErrorf(apicontract.CodeExportFailed,
				"import succeeded but report generation failed: %w", err)
		}
		if jsonOut != nil {
			jsonOut["report_path"] = reportPath
		}
	}

	if upload {
		var uploaded []string
		for _, src := range sources {
			// A gs:// source is already in cloud storage — nothing to push up.
			if strings.HasPrefix(src, "gs://") {
				fmt.Fprintf(os.Stderr, "%s --upload skipped for %s (already in cloud storage)\n", terminal.WarningSymbol(), src)
				continue
			}
			url, err := uploadImportSource(ctx, src, uploadKey)
			if err != nil {
				// Same reasoning as the report above: the requested artifact is what
				// failed, not the import.
				return codedErrorf(apicontract.CodeExportFailed,
					"import succeeded but upload failed: %w", err)
			}
			uploaded = append(uploaded, url)
			if !globalJSON {
				fmt.Printf("%s Source uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(url))
			}
		}
		if jsonOut != nil && len(uploaded) > 0 {
			jsonOut["uploaded_to"] = uploaded
		}
	}
	if jsonOut != nil {
		// The counters stay at the top level under the names they always had;
		// the mutation spine (changed/action) is added around them.
		if err := emitMutation(cmd, "", mutationResult{
			Changed: importChanged(summary),
			Action:  "import",
			Extra:   jsonOut,
		}); err != nil {
			return err
		}
	}
	// Reported after the summary, not instead of it. Both counters below mean the
	// same thing — data that was in the source is not in the database — so the
	// command must not exit 0. The operator still needs the counts to know what
	// DID land, and under -j the result document is already on stdout, so
	// emitJSONError suppresses the error envelope and the exit code carries it
	// (one machine document per invocation).
	if err := importIncompleteError(summary); err != nil {
		return err
	}
	return nil
}

// importReportFormat is the report --format names: the global flag, read
// only when typed — its default ("console") is a scan output format and means
// "no report" here. A local --format would shadow the global one, which the
// machine contract forbids outside stream commands.
func importReportFormat(cmd *cobra.Command) string {
	if !flagChanged(cmd, "format") {
		return ""
	}
	return strings.TrimSpace(globalFormat)
}

// importChanged reports whether an import wrote anything: a parsed source that
// stored a record, a finding or an agentic scan row, or a merge that copied any
// row.
func importChanged(r *dbimport.Result) bool {
	if r == nil {
		return false
	}
	if m := r.MergeStats; m != nil {
		return m.ProjectsMerged+m.ScansMerged+m.AgenticScansMerged+m.RecordsMerged+m.FindingsMerged+
			m.FindingRecordsMerged+m.OASTMerged+m.ObservationsMerged+m.StatusEventsMerged > 0
	}
	return r.AgenticScanUUID() != "" || r.RecordsImported > 0 || r.FindingsSaved > 0
}

// importIncompleteError reports a lossy import, or nil when nothing was lost.
//
// A line the parser could not read and a finding the database refused are the
// same outcome from the operator's side: the source had it and the destination
// does not. Both used to be printed as an informational count next to exit 0,
// which is how a truncated transfer passed for a clean import.
func importIncompleteError(r *dbimport.Result) error {
	if r == nil {
		return nil
	}
	var parts []string
	if r.FindingsFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d findings failed to save", r.FindingsFailed))
	}
	if r.ParseErrors > 0 {
		parts = append(parts, fmt.Sprintf("%d lines could not be parsed", r.ParseErrors))
	}
	if len(parts) == 0 {
		return nil
	}
	return fmt.Errorf("import is incomplete: %s (everything else was stored; see the summary above)",
		strings.Join(parts, " and "))
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
		matches, err := filepath.Glob(expandUserHome(globDB))
		if err != nil {
			return nil, usageErrorf("invalid --glob-db pattern %q: %w", globDB, err)
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
		return nil, usageErrorf("no import sources: provide a path argument or --glob-db <pattern>")
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
	fmt.Printf("  %s [%d/%d] %s — %d records, %d findings (%d dup%s)\n",
		terminal.SuccessSymbol(), idx, total, terminal.Cyan(src),
		r.RecordsImported, r.FindingsSaved, r.FindingsSkipped,
		importFailedSuffix(r.FindingsFailed))
}

// cliSessionDirArchiver copies an audit source folder into the per-run agent
// session directory keyed by scan UUID and returns the resulting session dir.
// Best-effort: failures are logged to stderr and result in an empty return so
// the import still completes. Mirrors the prior in-CLI helper.
func cliSessionDirArchiver(scanUUID, srcDir string) (string, error) {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return "", err
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

// importResultJSON builds the -j document for an import, without writing it.
//
// Nothing is encoded here because the import is not finished when the summary is
// known: a --format report and an --upload still have to land, and either can
// fail. Writing the success object at this point produced a stdout carrying an
// ok-looking result followed by the root handler's error envelope — two
// top-level documents, which the --json contract does not allow and no single
// json.Unmarshal reads. The caller holds the map, adds report_path/uploaded_to
// as those artifacts succeed, and emits it once at the end.
func importResultJSON(localPath string, r *dbimport.Result) map[string]any {
	if r == nil {
		return nil
	}
	// A SQLite-database import is a merge, not a parse — summarize the merged
	// tables (records/findings/scans/oast) rather than the JSONL/audit shape.
	if r.MergeStats != nil {
		return mergeResultJSON(localPath, r.MergeStats)
	}
	out := map[string]any{}
	if uuid := r.AgenticScanUUID(); uuid != "" {
		out["agentic_scan_uuid"] = uuid
	}
	if r.RecordsImported > 0 {
		out["records_imported"] = r.RecordsImported
	}
	if r.RecordsSkippedDuplicate > 0 {
		out["records_skipped_duplicate"] = r.RecordsSkippedDuplicate
	}
	out["findings_total"] = r.FindingsTotal
	out["findings_saved"] = r.FindingsSaved
	out["findings_skipped"] = r.FindingsSkipped
	// Always present, unlike the other optional counters: a consumer checking for
	// a lossy import needs "the field is 0" rather than "the field is absent,
	// which might mean 0 or might mean an older vigolium".
	out["findings_failed"] = r.FindingsFailed
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
	return out
}

// mergeResultJSON builds the -j document for a SQLite→SQLite merge import.
func mergeResultJSON(srcPath string, s *database.MergeStats) map[string]any {
	return map[string]any{
		"merged_from":            srcPath,
		"records_merged":         s.RecordsMerged,
		"findings_merged":        s.FindingsMerged,
		"findings_deduped":       s.FindingsDeduped,
		"scans_merged":           s.ScansMerged,
		"agentic_scans_merged":   s.AgenticScansMerged,
		"projects_merged":        s.ProjectsMerged,
		"finding_records_merged": s.FindingRecordsMerged,
		"oast_merged":            s.OASTMerged,
	}
}

// printImportResult renders the human CLI summary for the import. The shape
// mirrors the pre-refactor format so existing CLI consumers and tests don't
// break. The -j document is built by importResultJSON instead.
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

	if r.AgenticScan != nil {
		scan := r.AgenticScan
		fmt.Printf("%s Imported audit: %d findings (%d new, %d duplicates skipped%s)\n",
			terminal.SuccessSymbol(), r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped,
			importFailedSuffix(r.FindingsFailed))
		fmt.Printf("  Agent run: %s (mode=%s, status=%s)\n", scan.UUID, scan.Mode, scan.Status)
		if scan.TargetURL != "" {
			fmt.Printf("  Target:   %s\n", terminal.BoldCyan(scan.TargetURL))
		}
		if scan.Model != "" {
			fmt.Printf("  Model:    %s\n", terminal.Cyan(scan.Model))
		}
	} else {
		fmt.Printf("%s Imported JSONL data from %s\n", terminal.SuccessSymbol(), localPath)
		if r.RecordsImported > 0 || r.RecordsSkippedDuplicate > 0 {
			dup := ""
			if r.RecordsSkippedDuplicate > 0 {
				dup = fmt.Sprintf(", %d already present", r.RecordsSkippedDuplicate)
			}
			fmt.Printf("  HTTP records: %d imported%s\n", r.RecordsImported, dup)
		}
		if r.FindingsTotal > 0 {
			fmt.Printf("  Findings: %d total (%d new, %d duplicates skipped%s)\n",
				r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped, importFailedSuffix(r.FindingsFailed))
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

// importFailedSuffix renders the failed-finding clause of a summary line, empty
// when nothing failed. Separate from the duplicate count on purpose: a duplicate
// is already in the destination, a failure is not in it at all, and the old
// single "skipped" number reported both as the same benign outcome.
func importFailedSuffix(failed int) string {
	if failed <= 0 {
		return ""
	}
	return fmt.Sprintf(", %s", terminal.BoldRed(fmt.Sprintf("%d failed", failed)))
}

// printMergeResult renders the human summary for a SQLite-database import — a
// lossless SQLite→SQLite merge of another vigolium result database into the
// current one. The -j document is built by mergeResultJSON instead.
func printMergeResult(srcPath string, s *database.MergeStats) {
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
//
// It returns the destination the report was actually published to — the
// absolute local path, or the normalized gs:// URI for a cloud target — so the
// -j document can name a location the caller can open. Expanding the
// placeholders here rather than letting the caller re-expand outputArg is not
// cosmetic: {ts} resolves to the current second, so a second expansion names a
// file that does not exist.
func emitImportReport(ctx context.Context, db *database.DB, scan *database.AgenticScan, format, outputArg string, opts importReportOpts) (string, error) {
	rf, ok := reportGenerator(format)
	if !ok {
		return "", fmt.Errorf("unsupported report format %q", format)
	}
	gen, defaultTitle := rf.Render, rf.DefaultTitle

	dest, err := expandOutputPlaceholders(outputArg)
	if err != nil {
		return "", err
	}
	// resolveExportOutput expands again, which is a no-op now that every
	// placeholder is gone.
	localOutput, finalize, err := resolveExportOutput(ctx, dest)
	if err != nil {
		return "", err
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
		p := database.LikeContains(opts.search)
		q = q.Where(database.WithLikeEscape("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ? OR url LIKE ? OR hostname LIKE ? OR extracted_results LIKE ?)"), p, p, p, p, p, p, p, p)
	}
	if opts.severity != "" {
		sevs := strings.Split(strings.ToLower(opts.severity), ",")
		q = q.Where("LOWER(severity) IN (?)", bun.List(sevs))
	}
	if err := q.Scan(ctx); err != nil {
		return "", fmt.Errorf("query findings for report: %w", err)
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
	applyReportFlags(&meta, false)

	if !globalJSON {
		detail := ""
		if rf.NeedsChrome {
			detail = " (headless Chrome)"
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
			terminal.BoldCyan(fmt.Sprintf("Generating %s report%s — %d findings ...", format, detail, len(findings))))
	}
	if err := gen(items, localOutput, meta); err != nil {
		return "", err
	}
	if err := finalize(); err != nil {
		return "", err
	}

	published := dest
	if storage.IsGCSURI(published) {
		published = storage.NormalizeGCSURI(published)
	} else {
		published = absOrRaw(published)
	}
	scope := "all findings in project"
	if scanUUID != "" {
		scope = "imported audit " + scanUUID
	}
	// Human mode only: under -j this line is the `report_path` key of the single
	// result document, which the caller emits after every artifact has landed.
	if !globalJSON {
		fmt.Printf("%s Report written: %s (%d findings, %s, format=%s)\n",
			terminal.SuccessSymbol(), terminal.Cyan(dest), len(findings), scope, format)
	}
	return published, nil
}
