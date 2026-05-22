package cli

import (
	"context"
	"encoding/json"
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
	exportCmd.Flags().StringVar(&topExportFormat, "format", "jsonl", "Export format: html, report, pdf, jsonl, markdown (alias: md), bundle (alias: gz)")
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
		return fmt.Errorf("unsupported format %q; valid formats: html, report, pdf, jsonl, markdown, bundle", topExportFormat)
	}
	if dispatchErr != nil {
		return dispatchErr
	}
	return finalize()
}

func runExportWithGenerator(formatLabel, defaultTitle string, generate func([]any, string, output.HTMLReportMeta) error) error {
	db, err := getDB()
	if err != nil {
		return err
	}
	defer closeDatabaseOnExit()

	ctx := context.Background()
	items, err := queryExportData(ctx, db, topExportOmitResponse)
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
		db, err = getDB()
		if err != nil {
			return err
		}
		defer closeDatabaseOnExit()
	}

	ctx := context.Background()
	items, err := queryExportData(ctx, db, topExportOmitResponse)
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

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("failed to encode record: %w", err)
		}
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

// queryExportData queries all enabled tables and returns a slice of exportEnvelope
// items ready for serialization. Both HTML and JSONL paths share this function.
// When omitResponse is true, HTTP records keep all metadata but drop the bulky
// raw request/response byte fields, yielding much smaller output files.
func queryExportData(ctx context.Context, db *database.DB, omitResponse bool) ([]any, error) {
	var items []any

	// --- Scans ---
	if shouldExport("scans") && db != nil {
		var scans []*database.Scan
		q := db.NewSelect().Model(&scans).OrderExpr("created_at DESC")
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
				items = append(items, exportEnvelope{Type: "scan", Data: s})
			}
		}
	}

	// --- HTTP Records ---
	if shouldExport("http") && db != nil {
		qb := database.NewQueryBuilder(db, database.QueryFilters{
			FuzzyTerm: topExportSearch,
			Limit:     topExportLimit,
		})
		records, err := qb.Execute(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query HTTP records: %v\n", terminal.WarningSymbol(), err)
		} else {
			seen := make(map[string]struct{}, len(records))
			for _, r := range records {
				if _, dup := seen[r.URL]; dup {
					continue
				}
				seen[r.URL] = struct{}{}

				var data any
				if omitResponse {
					rc := *r // shallow copy; drop bulky raw bytes, keep metadata
					rc.RawRequest = nil
					rc.RawResponse = nil
					data = &rc
				} else {
					data = r
				}
				items = append(items, exportEnvelope{Type: "http_record", Data: data})
			}
		}
	}

	// --- Findings ---
	if shouldExport("findings") && db != nil {
		var findings []*database.Finding
		q := db.NewSelect().Model(&findings).OrderExpr("found_at DESC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ? OR url LIKE ? OR hostname LIKE ? OR extracted_results LIKE ?)", p, p, p, p, p, p, p, p)
		}
		if topExportSeverity != "" {
			sevs := strings.Split(strings.ToLower(topExportSeverity), ",")
			q = q.Where("LOWER(severity) IN (?)", bun.In(sevs))
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query findings: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, f := range findings {
				items = append(items, exportEnvelope{Type: "finding", Data: f})
			}
		}
	}

	// --- Modules (in-memory registry, no DB needed) ---
	if shouldExport("modules") {
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
			items = append(items, exportEnvelope{Type: "module", Data: entry})
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
			items = append(items, exportEnvelope{Type: "module", Data: entry})
		}
	}

	// --- OAST Interactions ---
	if shouldExport("oast") && db != nil {
		var interactions []*database.OASTInteraction
		q := db.NewSelect().Model(&interactions).OrderExpr("interacted_at DESC")
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
				items = append(items, exportEnvelope{Type: "oast_interaction", Data: i})
			}
		}
	}

	// --- Scopes ---
	if shouldExport("scopes") && db != nil {
		var scopes []*database.Scope
		q := db.NewSelect().Model(&scopes).Where("enabled = ?", true).OrderExpr("priority ASC")
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
				items = append(items, exportEnvelope{Type: "scope", Data: s})
			}
		}
	}

	// Apply --exclude filter
	if len(topExportExclude) > 0 {
		excludeSet := make(map[string]bool, len(topExportExclude))
		for _, e := range topExportExclude {
			excludeSet[strings.ToLower(strings.TrimSpace(e))] = true
		}
		filtered := items[:0]
		for _, item := range items {
			if env, ok := item.(exportEnvelope); ok && excludeSet[strings.ToLower(env.Type)] {
				continue
			}
			filtered = append(filtered, item)
		}
		items = filtered
	}

	return items, nil
}
