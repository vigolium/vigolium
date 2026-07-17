package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	topExportFormat       string
	topExportOutput       string
	topExportOnly         []string
	topExportExclude      []string
	topExportOmitResponse bool
	topExportSearch       string
	topExportLimit        int
	topExportTitle        string
	topExportSeverity     string
	topExportTarget       string
	topExportDuration     string
	topExportGeneratedAt  string
	topExportReportURL    string
	topExportScanUUIDs    []string
)

// validExportTypes lists all accepted --only values.
var validExportTypes = []string{"http", "findings", "scans", "modules", "oast", "source-repos", "scopes"}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export database tables and module registry",
	Long: `Export the contents of one or more database tables (HTTP records, findings, scans, modules, OAST interactions, source repos, scopes) into JSONL, HTML, Markdown, PDF, or a bundle archive.

Use --only to choose which tables to include, --omit-response to drop raw HTTP request/response bytes (keeps metadata, smaller files), and --search to fuzzy-filter rows before export. HTML and bundle output require -o/--output.

The --format bundle (alias gz) emits a .tar.gz archive containing export.jsonl, report.html, manifest.json, and any agent session directories matching --scan-uuid <uuid> (repeatable).`,
	RunE: runExportCmd,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&topExportFormat, "format", "jsonl", "Export format: html, report, pdf, jsonl, markdown (alias: md), bundle (alias: gz), fs (flat request/response + finding tree)")
	exportCmd.Flags().StringVarP(&topExportOutput, "output", "o", "", "Output file path or gs://<project>/<key> URL (required for html); supports {ts} and {project-uuid} placeholders")
	exportCmd.Flags().StringSliceVar(&topExportOnly, "only", nil,
		"Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes)")
	exportCmd.Flags().BoolVar(&topExportOmitResponse, "omit-response", false,
		"Omit raw HTTP request/response bytes (keeps metadata, smaller files)")
	exportCmd.Flags().StringVar(&topExportSearch, "search", "",
		"Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources")
	exportCmd.Flags().IntVar(&topExportLimit, "limit", 0,
		"Maximum number of records to export per table (0 = unlimited)")
	exportCmd.Flags().StringSliceVar(&topExportExclude, "exclude", []string{"module"},
		"Exclude items by type (comma-separated, e.g. module,scan)")
	exportCmd.Flags().StringVar(&topExportTitle, "report-title", "",
		"Custom title for the HTML report (default: \"Vigolium Static Report\")")
	exportCmd.Flags().StringVar(&topExportTarget, "report-target", "",
		"Target name for the report (e.g. repository name or URL)")
	exportCmd.Flags().StringVar(&topExportDuration, "report-duration", "",
		"Human-readable scan duration for the report (e.g. \"10h42m5s\")")
	exportCmd.Flags().StringVar(&topExportGeneratedAt, "report-generated-at", "",
		"ISO timestamp for report generation (e.g. \"2026-04-18T03:00:00Z\")")
	exportCmd.Flags().StringVar(&topExportReportURL, "report-url", "",
		"URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
	exportCmd.Flags().StringVar(&topExportSeverity, "severity", "",
		"Filter findings by severity (comma-separated: critical,high,medium,low,info)")
	exportCmd.Flags().StringSliceVar(&topExportScanUUIDs, "scan-uuid", nil,
		"Agentic scan UUID(s) whose session directories to include in --format bundle (repeatable)")
	exportCmd.Flags().BoolVarP(&globalStateless, "stateless", "S", false,
		"Read from --db (a standalone .sqlite or .jsonl export) instead of your project DB; never writes to it")
	exportCmd.Flags().StringVar(&globalGlobDB, "glob-db", "",
		"Export across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
}

// shouldExport returns true if the given data type should be included in the export.
// When topExportOnly is empty, all types are exported.
func shouldExport(dataType string) bool {
	if len(topExportOnly) == 0 {
		return true
	}
	for _, t := range topExportOnly {
		if strings.EqualFold(t, dataType) {
			return true
		}
	}
	return false
}

// exportEnvelope wraps each exported item with a type tag for JSONL output.
type exportEnvelope struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// scopeProjectBun applies a project_uuid filter to a single-table bun query when
// projectUUID is non-empty. An empty projectUUID means whole-DB (the default
// `vigolium export` / stateless temp-DB behavior); a non-empty value scopes the
// query to one project (the per-scan `--format jsonl` export).
func scopeProjectBun(q *bun.SelectQuery, projectUUID string) *bun.SelectQuery {
	if projectUUID != "" {
		return q.Where("project_uuid = ?", projectUUID)
	}
	return q
}

func runExportCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Validate --only values
	if len(topExportOnly) > 0 {
		valid := make(map[string]bool, len(validExportTypes))
		for _, v := range validExportTypes {
			valid[v] = true
		}
		for _, t := range topExportOnly {
			if !valid[strings.ToLower(t)] {
				return fmt.Errorf("invalid --only value %q; valid values: %s", t, strings.Join(validExportTypes, ", "))
			}
		}
	}

	// fs writes a directory tree (not a single file), defaults its base to the
	// cwd when no -o is given, and isn't a gs:// upload target — so it bypasses
	// the file-oriented output resolution below.
	if topExportFormat == "fs" {
		return runExportFS()
	}

	needsOutput := topExportFormat == "html" || topExportFormat == "report" || topExportFormat == "pdf" ||
		topExportFormat == "markdown" || topExportFormat == "md" ||
		topExportFormat == "bundle" || topExportFormat == "gz"
	if needsOutput && topExportOutput == "" {
		return fmt.Errorf("--format %s requires -o/--output to specify the report file path", topExportFormat)
	}
	if topExportFormat == "bundle" || topExportFormat == "gz" {
		if !strings.HasSuffix(topExportOutput, ".tar.gz") && !strings.HasSuffix(topExportOutput, ".tgz") {
			return fmt.Errorf("--format %s requires -o ending in .tar.gz or .tgz (got %q)", topExportFormat, topExportOutput)
		}
	}

	// Resolve gs:// outputs to a temp file + uploader, and expand {ts}.
	ctx := context.Background()
	localOutput, finalize, err := resolveExportOutput(ctx, topExportOutput)
	if err != nil {
		return err
	}
	topExportOutput = localOutput

	var dispatchErr error
	switch topExportFormat {
	case "html":
		dispatchErr = runExportHTML()
	case "report":
		dispatchErr = runExportReport()
	case "pdf":
		dispatchErr = runExportPDF()
	case "jsonl":
		dispatchErr = runExportJSONL()
	case "markdown", "md":
		dispatchErr = runExportMarkdown()
	case "bundle", "gz":
		dispatchErr = runExportBundle()
	default:
		return fmt.Errorf("unsupported format %q; valid formats: html, report, pdf, jsonl, markdown, bundle, fs", topExportFormat)
	}
	if dispatchErr != nil {
		return dispatchErr
	}
	return finalize()
}

func runExportWithGenerator(formatLabel, defaultTitle string, generate func([]any, string, output.HTMLReportMeta) error) error {
	db, err := openExportDB()
	if err != nil {
		return err
	}
	defer closeDatabaseOnExit()

	ctx := context.Background()
	items, err := queryExportData(ctx, db, topExportOmitResponse, "")
	if err != nil {
		return err
	}

	title := defaultTitle
	if topExportTitle != "" {
		title = topExportTitle
	}

	autoTarget, autoDuration := computeReportMeta(ctx, db)

	duration := autoDuration
	if topExportDuration != "" {
		duration = topExportDuration
	}
	target := autoTarget
	if topExportTarget != "" {
		target = topExportTarget
	}

	meta := output.HTMLReportMeta{
		Title:           title,
		Version:         getVersion(),
		ScanDuration:    duration,
		ScanTarget:      target,
		GeneratedAt:     topExportGeneratedAt,
		ReportSharedURL: topExportReportURL,
	}
	if err := generate(items, topExportOutput, meta); err != nil {
		return err
	}
	printExportStats(formatLabel, topExportOutput, items)
	return nil
}

// reportGenerator maps a document/report format to its generator and default
// title. It is the single source of truth shared by `vigolium export` and the
// `vigolium import --format <fmt> -o <file>` post-import shortcut, so both
// commands stay in lockstep when a format is added or renamed.
func reportGenerator(format string) (gen func([]any, string, output.HTMLReportMeta) error, defaultTitle string, ok bool) {
	switch format {
	case "html":
		return output.GenerateHTMLReport, "Vigolium Static Report", true
	case "report":
		return output.GenerateDocumentReport, "Vigolium Scan Report", true
	case "pdf":
		return output.GeneratePDFReport, "Vigolium Scan Report", true
	case "markdown", "md":
		return output.GenerateMarkdownReport, "Vigolium Scan Report", true
	}
	return nil, "", false
}

func runExportHTML() error {
	gen, title, _ := reportGenerator("html")
	return runExportWithGenerator("html", title, gen)
}

func runExportReport() error {
	gen, title, _ := reportGenerator("report")
	return runExportWithGenerator("report", title, gen)
}

func runExportPDF() error {
	fmt.Fprintf(os.Stderr, "%s Generating PDF report (headless Chrome)...\n", terminal.InfoSymbol())
	gen, title, _ := reportGenerator("pdf")
	return runExportWithGenerator("pdf", title, gen)
}

// computeReportMeta auto-detects scanTarget and scanDuration from the database.
// It checks agentic_scans first, then falls back to the scans table.
// When multiple rows exist, target becomes "multiple" and duration "N/A".
func computeReportMeta(ctx context.Context, db *database.DB) (target, duration string) {
	// Try agentic_scans first.
	var agenticScans []database.AgenticScan
	err := db.NewSelect().Model(&agenticScans).
		Column("target_url", "duration_ms", "started_at", "completed_at").
		Where("status = ?", "completed").
		OrderExpr("created_at DESC").
		Limit(2).
		Scan(ctx)
	if err == nil && len(agenticScans) > 0 {
		if len(agenticScans) == 1 {
			target = agenticScans[0].TargetURL
			if agenticScans[0].DurationMs > 0 {
				d := time.Duration(agenticScans[0].DurationMs) * time.Millisecond
				duration = d.Round(time.Second).String()
			}
		} else {
			target = "multiple"
			duration = "N/A"
		}
		return
	}

	// Fall back to native scans.
	var scans []database.Scan
	err = db.NewSelect().Model(&scans).
		Column("target", "started_at", "finished_at").
		Where("status = ?", "completed").
		OrderExpr("created_at DESC").
		Limit(2).
		Scan(ctx)
	if err == nil && len(scans) > 0 {
		if len(scans) == 1 {
			target = scans[0].Target
			if !scans[0].FinishedAt.IsZero() {
				d := scans[0].FinishedAt.Sub(scans[0].StartedAt)
				if d > 0 {
					duration = d.Round(time.Second).String()
				}
			}
		} else {
			target = "multiple"
			duration = "N/A"
		}
	}
	return
}

func runExportJSONL() error {
	// Modules don't need DB access, so handle the modules-only case without opening DB.
	needsDB := shouldExport("http") || shouldExport("findings") || shouldExport("scans") ||
		shouldExport("oast") || shouldExport("source-repos") || shouldExport("scopes")

	var db *database.DB
	if needsDB {
		var err error
		db, err = openExportDB()
		if err != nil {
			return err
		}
		defer closeDatabaseOnExit()
	}

	ctx := context.Background()
	items, err := queryExportData(ctx, db, topExportOmitResponse, "")
	if err != nil {
		return err
	}

	// Open output writer
	var w *os.File
	if topExportOutput != "" {
		f, err := os.Create(topExportOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	} else {
		w = os.Stdout
	}

	if _, err := encodeJSONL(w, items); err != nil {
		return fmt.Errorf("failed to encode record: %w", err)
	}

	printExportStats("jsonl", topExportOutput, items)
	return nil
}

func printExportStats(format, outputPath string, items []any) {
	counts := make(map[string]int)
	for _, item := range items {
		if env, ok := item.(exportEnvelope); ok {
			counts[env.Type]++
		}
	}

	fmt.Fprintf(os.Stderr, "\n%s Export summary (format: %s)\n", terminal.InfoSymbol(), terminal.Cyan(format))
	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "  Output: %s\n", terminal.Cyan(outputPath))
	}

	// Print counts in a stable order
	typeOrder := []struct{ key, label string }{
		{"http_record", "HTTP records"},
		{"finding", "Findings"},
		{"scan", "Scans"},
		{"module", "Modules"},
		{"oast_interaction", "OAST interactions"},
		{"source_repo", "Source repos"},
		{"scope", "Scopes"},
	}
	for _, t := range typeOrder {
		if c, ok := counts[t.key]; ok && c > 0 {
			fmt.Fprintf(os.Stderr, "  %-20s %d\n", t.label, c)
		}
	}
	fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Total", len(items))
}

func runExportMarkdown() error {
	gen, title, _ := reportGenerator("markdown")
	return runExportWithGenerator("markdown", title, gen)
}

// runExportFS writes the whole DB to a flat <base>-traffic/ + <base>-findings/
// filesystem tree (the `fs` format). Honors --search, --severity, --limit, and
// --omit-response; defaults the base to "vigolium" in the cwd when no -o is set.
func runExportFS() error {
	db, err := openExportDB()
	if err != nil {
		return err
	}
	defer closeDatabaseOnExit()

	var severities []string
	if topExportSeverity != "" {
		severities = strings.Split(topExportSeverity, ",")
	}
	filters := database.QueryFilters{
		FuzzyTerm: topExportSearch,
		Severity:  severities,
		Limit:     topExportLimit,
	}
	stats, err := writeFSExport(context.Background(), db, filters, topExportOutput, fsExportOptions{omitResponse: topExportOmitResponse})
	if err != nil {
		return err
	}
	fsPrintSummary(stats)
	return nil
}

// queryExportData queries all enabled tables and returns a slice of exportEnvelope
// items ready for serialization. Both HTML and JSONL paths share this function.
// When omitResponse is true, HTTP records keep all metadata but drop the bulky
// raw request/response byte fields, yielding much smaller output files. When
// projectUUID is non-empty, every DB-backed query is scoped to that project
// (used by the per-scan `--format jsonl` export); empty means the whole DB
// (the `vigolium export` and stateless temp-DB behavior).
func queryExportData(ctx context.Context, db *database.DB, omitResponse bool, projectUUID string) ([]any, error) {
	var items []any
	err := streamExportData(ctx, db, omitResponse, projectUUID, "", func(item any) error {
		items = append(items, item)
		return nil
	})
	return items, err
}

// exportExcludeSet builds the lowercased set of envelope types to drop, derived
// from the --exclude flag (topExportExclude). Returns nil when nothing is
// excluded. Keys are envelope type names (scan, http_record, finding, module,
// oast_interaction, scope).
func exportExcludeSet() map[string]bool {
	if len(topExportExclude) == 0 {
		return nil
	}
	set := make(map[string]bool, len(topExportExclude))
	for _, e := range topExportExclude {
		set[strings.ToLower(strings.TrimSpace(e))] = true
	}
	return set
}

// streamExportData emits every export envelope to emit() as soon as it is read
// from the database, so the full result set never lives in memory at once.
// queryExportData is now a thin collector over this, so streamed output is
// byte-identical to the legacy materialized path: same envelope order (scans,
// http_records, findings, modules, oast, scopes), same per-row shape, same
// URL-dedup and --exclude semantics. The two large tables (http_records,
// findings) are read with a row cursor — only one row is live at a time; the
// small tables are loaded then emitted.
//
// Per-table query errors are logged and skipped (best-effort, matching the
// legacy behavior); an error returned by emit (a downstream write failure) is
// fatal and propagated immediately.
//
// When omitResponse is true the bulky raw_request/raw_response columns are not
// selected for http_records (honoring an explicit --omit-response). Report
// renderers must NOT force this on: they derive the displayed request/response
// bodies from the raw bytes via HTTPRecord.MarshalJSON before trimming the
// redundant raw copies, so excluding the columns blanks the report body.
func streamExportData(ctx context.Context, db *database.DB, omitResponse bool, projectUUID, scanUUID string, emit func(any) error) error {
	excluded := exportExcludeSet()
	emitItem := func(typ string, data any) error {
		if excluded[typ] {
			return nil
		}
		return emit(exportEnvelope{Type: typ, Data: data})
	}

	// --- Scans ---
	if shouldExport("scans") && db != nil && !excluded["scan"] {
		var scans []*database.Scan
		q := scopeProjectBun(db.NewSelect().Model(&scans).OrderExpr("created_at DESC"), projectUUID)
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(uuid LIKE ? OR status LIKE ? OR error_message LIKE ?)", p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query scans: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, s := range scans {
				if err := emitItem("scan", s); err != nil {
					return err
				}
			}
		}
	}

	// --- HTTP Records (cursor-streamed) ---
	if shouldExport("http") && db != nil && !excluded["http_record"] {
		if err := streamHTTPRecords(ctx, db, omitResponse, projectUUID, emitItem); err != nil {
			return err
		}
	}

	// --- Findings (cursor-streamed) ---
	if shouldExport("findings") && db != nil && !excluded["finding"] {
		if err := streamFindings(ctx, db, projectUUID, scanUUID, emitItem); err != nil {
			return err
		}
	}

	// --- Modules (in-memory registry, no DB needed) ---
	if shouldExport("modules") && !excluded["module"] {
		emCfg := loadEnabledModulesConfig()

		for _, m := range modules.GetActiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "active",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              isModuleEnabled(m.ID(), emCfg.ActiveModules),
			}
			if err := emitItem("module", entry); err != nil {
				return err
			}
		}
		for _, m := range modules.GetPassiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "passive",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              isModuleEnabled(m.ID(), emCfg.PassiveModules),
			}
			if err := emitItem("module", entry); err != nil {
				return err
			}
		}
	}

	// --- OAST Interactions ---
	if shouldExport("oast") && db != nil && !excluded["oast_interaction"] {
		var interactions []*database.OASTInteraction
		q := scopeProjectBun(db.NewSelect().Model(&interactions).OrderExpr("interacted_at DESC"), projectUUID)
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(protocol LIKE ? OR module_id LIKE ? OR unique_id LIKE ? OR full_id LIKE ? OR target_url LIKE ?)", p, p, p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query OAST interactions: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, i := range interactions {
				if err := emitItem("oast_interaction", i); err != nil {
					return err
				}
			}
		}
	}

	// --- Scopes ---
	if shouldExport("scopes") && db != nil && !excluded["scope"] {
		var scopes []*database.Scope
		q := scopeProjectBun(db.NewSelect().Model(&scopes).Where("enabled = ?", true).OrderExpr("priority ASC"), projectUUID)
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(name LIKE ? OR host_pattern LIKE ? OR path_pattern LIKE ?)", p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query scopes: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, s := range scopes {
				if err := emitItem("scope", s); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// findingReferencedRecordUUIDs returns the set of http_record UUIDs that at least
// one finding links to (via finding_records), scoped to projectUUID (empty =
// whole DB). These records are a finding's exact proof exchange, so streamHTTPRecords
// must never drop them in its per-URL dedup. Best-effort: on error it returns an
// empty set (the caller falls back to plain URL-dedup, the prior behavior). The
// subquery form is dialect-agnostic (SQLite and PostgreSQL).
func findingReferencedRecordUUIDs(ctx context.Context, db *database.DB, projectUUID string) map[string]struct{} {
	referenced := make(map[string]struct{})
	if db == nil {
		return referenced
	}
	sqlText := "SELECT DISTINCT record_uuid FROM finding_records WHERE finding_id IN (SELECT id FROM findings"
	var args []any
	if projectUUID != "" {
		sqlText += " WHERE project_uuid = ?"
		args = append(args, projectUUID)
	}
	sqlText += ")"
	var uuids []string
	if err := db.NewRaw(sqlText, args...).Scan(ctx, &uuids); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to load finding-referenced records: %v\n", terminal.WarningSymbol(), err)
		return referenced
	}
	for _, u := range uuids {
		referenced[u] = struct{}{}
	}
	return referenced
}

// streamHTTPRecords reads http_records with a row cursor and emits one envelope
// per unique URL (first occurrence wins, matching the legacy in-memory dedup),
// holding only a single record in memory at a time. The one exception: a record
// that a finding links to is ALWAYS emitted, even when another record already
// claimed its URL — otherwise the per-URL dedup could drop the exact attack
// exchange a finding proves, leaving replay/Burp/report evidence pointing at a
// different same-URL record. omitResponse drops the raw_request/raw_response
// columns from the SELECT entirely. A query/scan error is logged and ends this
// table (best-effort); only emit errors are returned.
func streamHTTPRecords(ctx context.Context, db *database.DB, omitResponse bool, projectUUID string, emitItem func(string, any) error) error {
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ProjectUUID: projectUUID,
		FuzzyTerm:   topExportSearch,
		Limit:       topExportLimit,
	})
	if omitResponse {
		qb = qb.OmitBodies()
	}
	query := qb.BuildRecordsQuery()
	rows, err := query.Rows(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query HTTP records: %v\n", terminal.WarningSymbol(), err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	referenced := findingReferencedRecordUUIDs(ctx, db, projectUUID)

	seen := make(map[string]struct{})
	for rows.Next() {
		r := new(database.HTTPRecord)
		if err := db.ScanRow(ctx, rows, r); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to scan HTTP record: %v\n", terminal.WarningSymbol(), err)
			return nil
		}
		// A finding-referenced record is that finding's proof — emit it even when
		// its URL was already claimed by an earlier (non-attack) record.
		_, isReferenced := referenced[r.UUID]
		if _, dup := seen[r.URL]; dup && !isReferenced {
			continue
		}
		seen[r.URL] = struct{}{}
		if err := emitItem("http_record", r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s Error reading HTTP records: %v\n", terminal.WarningSymbol(), err)
	}
	return nil
}

// streamFindings reads findings with a row cursor and emits one envelope per
// row, holding only a single finding in memory at a time. Filters mirror the
// legacy findings query exactly (search, severity, limit, found_at DESC). A
// query/scan error is logged and ends this table; only emit errors are returned.
func streamFindings(ctx context.Context, db *database.DB, projectUUID, scanUUID string, emitItem func(string, any) error) error {
	q := scopeProjectBun(db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at DESC"), projectUUID)
	// Confirmed findings only. E0 observations / E1 candidates are persisted in
	// the same table but must not surface in a report's "Findings" section as if
	// they were confirmed vulnerabilities — mirror the default record_kind guard
	// the FindingsQueryBuilder applies everywhere else (query.go applyFindingFilters).
	q = q.Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", database.RecordKindFinding)
	// Post-scan report scope: restrict to the current scan's findings so a re-run's
	// report reflects that run, not the project's whole history. maybeGenerateReports
	// passes the scan uuid; every other export path passes "" (project-wide),
	// parallel to how projectUUID is threaded.
	if scanUUID != "" {
		q = q.Where("f.scan_uuid = ?", scanUUID)
	}
	if topExportSearch != "" {
		p := "%" + topExportSearch + "%"
		q = q.Where("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ? OR url LIKE ? OR hostname LIKE ? OR extracted_results LIKE ?)", p, p, p, p, p, p, p, p)
	}
	if topExportSeverity != "" {
		sevs := strings.Split(strings.ToLower(topExportSeverity), ",")
		q = q.Where("LOWER(severity) IN (?)", bun.List(sevs))
	}
	if topExportLimit > 0 {
		q = q.Limit(topExportLimit)
	}
	rows, err := q.Rows(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query findings: %v\n", terminal.WarningSymbol(), err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		f := new(database.Finding)
		if err := db.ScanRow(ctx, rows, f); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to scan finding: %v\n", terminal.WarningSymbol(), err)
			return nil
		}
		if err := emitItem("finding", f); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s Error reading findings: %v\n", terminal.WarningSymbol(), err)
	}
	return nil
}
