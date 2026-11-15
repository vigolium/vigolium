package cli

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var dbExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export database records",
	Long: `Export stored HTTP traffic, and the findings linked to it, with filters by host, method, status, path, scan, severity, time range and record UUID.

--format jsonl (the default) writes the same {"type": ..., "data": ...} lines as ` + "`vigolium export --format jsonl`" + `: one http_record line per selected record, then one finding line per confirmed finding linked to those records (--severity narrows the findings). ` + "`vigolium import`" + `, ` + "`finding load`" + ` and ` + "`-S --db`" + ` read it back. --limit and --offset count records, not lines. --table http_records keeps only the record lines, --table findings only the finding lines.

--format nuclei keeps the previous jsonl output: one nuclei-style ResultEvent (template-id, matched-at, info{}) per linked finding.`,
	RunE: runDBExport,
}

var (
	exportFormat      string
	exportOutput      string
	exportHost        string
	exportMethods     []string
	exportStatus      []int
	exportPath        string
	exportScanUUID    string
	exportSeverity    string
	exportFrom        string
	exportTo          string
	exportLimit       int
	exportOffset      int
	exportRecordUUID  string
	exportRequestOnly bool
	exportReportURL   string
)

func init() {
	dbCmd.AddCommand(dbExportCmd)
	registerDBSharedFlags(dbExportCmd, dbFlagTable, dbFlagSearch, dbFlagWatch)

	dbExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "jsonl", "Export format: "+output.FormatsHelp(output.SurfaceDBExport))
	dbExportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file path, defaults to stdout")

	dbExportCmd.Flags().StringVar(&exportHost, "host", "", "Filter records by host: hostname, host:port, origin (https://host[:port]) or bracketed IPv6; * wildcards")
	dbExportCmd.Flags().StringSliceVar(&exportMethods, "method", nil, "Filter records by HTTP method (can be specified multiple times)")
	dbExportCmd.Flags().IntSliceVar(&exportStatus, "status", nil, "Filter records by HTTP status code (can be specified multiple times)")
	dbExportCmd.Flags().StringVar(&exportPath, "path", "", "Filter records by URL path pattern")
	dbExportCmd.Flags().StringVar(&exportScanUUID, "scan-uuid", "", "Filter records by scan UUID")
	dbExportCmd.Flags().StringVar(&exportSeverity, "severity", "", "Filter findings by severity level")
	dbExportCmd.Flags().StringVar(&exportFrom, "from", "", fmt.Sprintf("Export records at or after this time — %s (alias: --since)", clicommon.TimeFilterSyntax))
	dbExportCmd.Flags().StringVar(&exportTo, "to", "", fmt.Sprintf("Export records at or before this time — %s; %s (alias: --until)", clicommon.TimeFilterSyntax, clicommon.TimeFilterUpperBoundNote))
	addFlagAliases(dbExportCmd, timeFilterAliases)

	dbExportCmd.Flags().IntVar(&exportLimit, "limit", 0, "Maximum number of records to export, 0 for unlimited")
	dbExportCmd.Flags().IntVar(&exportOffset, "offset", 0, "Number of records to skip before exporting")
	dbExportCmd.Flags().StringVar(&exportRecordUUID, "uuid", "",
		"Export exactly one record by its UUID (or unique 8+ char prefix). Honored by every --format (including fs) and resolved before pagination, so a record outside the --limit window is still found")

	dbExportCmd.Flags().BoolVar(&exportRequestOnly, "request-only", false, "Export only HTTP requests, omitting responses (raw format only)")
	dbExportCmd.Flags().StringVar(&exportReportURL, "report-url", "",
		"URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
}

// validateDBExportFlags rejects everything knowable from the flags alone, before
// the destination is opened. See the call site for why the ordering matters.
//
// It also canonicalizes exportFormat in place. That matters beyond tidiness: the
// membership test used to fold case while the dispatch switch below matched
// exactly, so `--format MARKDOWN` passed validation, reached os.Create — which
// truncates — and only then fell through to "unsupported format". Normalizing
// once means the value that was validated is the value that is dispatched.
//
// The parsed date range is returned so the callers do not re-parse it.
func validateDBExportFlags() (dateFrom, dateTo *time.Time, err error) {
	f, err := output.Lookup(exportFormat, output.SurfaceDBExport)
	if err != nil {
		return nil, nil, usageErrorf("unsupported export format: %s\n\nsupported formats: %s",
			strings.TrimSpace(exportFormat), strings.Join(output.Names(output.SurfaceDBExport), ", "))
	}
	exportFormat = f.Name
	if err := validateDBExportTable(); err != nil {
		return nil, nil, err
	}
	if exportFormat == "bundle" && exportOutput == "" {
		return nil, nil, usageErrorf("--format bundle requires -o/--output to specify the archive path")
	}
	return parseDateRangeFlags(exportFrom, exportTo, timeFilterFromLabel, timeFilterToLabel)
}

// dbExportFilters builds the record selection shared by every export format.
// runDBExport and runDBExportFS had byte-identical copies of this, which is how
// --uuid came to be honored by one and ignored by the other.
func dbExportFilters(db *database.DB, dateFrom, dateTo *time.Time) (database.QueryFilters, error) {
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}
	var severities []string
	if exportSeverity != "" {
		severities = strings.Split(exportSeverity, ",")
	}
	filters := database.QueryFilters{
		ProjectUUID: projectUUID,
		HostPattern: exportHost,
		Methods:     exportMethods,
		StatusCodes: exportStatus,
		PathPattern: exportPath,
		ScanUUID:    exportScanUUID,
		Severity:    severities,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		SearchTerm:  dbSearch,
		Limit:       exportLimit,
		Offset:      exportOffset,
	}
	// Resolve identity in SQL, before pagination: scanning a returned page for
	// the UUID reported an existing record as "not found" whenever it fell
	// outside --limit/--offset.
	if exportRecordUUID != "" {
		resolved, err := resolveRecordRefs(context.Background(), database.NewRepository(db), []string{exportRecordUUID}, projectUUID)
		if err != nil {
			return database.QueryFilters{}, err
		}
		filters.RecordUUIDs = resolved
	}
	return filters, nil
}

func runDBExport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// Validate EVERYTHING that can reject this run before touching the
	// destination. os.Create truncates, so validating afterwards meant a typo in
	// --format or a bad date range destroyed an existing deliverable and only
	// then printed the error. Nothing below this block may fail for a reason that
	// was knowable from the flags alone.
	dateFrom, dateTo, err := validateDBExportFlags()
	if err != nil {
		return err
	}
	if err := validateDBExportJSON(); err != nil {
		return err
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// fs writes a directory tree (filtered by the same flags), not to a single
	// output file — handle it before opening outputFile so no stray file is made.
	if exportFormat == "fs" {
		stats, err := runDBExportFS(db, dateFrom, dateTo)
		if err != nil || !globalJSON {
			return err
		}
		return emitDBExportReceipt(cmd, fsExportOutputs(stats),
			map[string]int{"http_record": stats.Traffic, "finding": stats.Findings})
	}

	// bundle requires -o and handles its own file I/O — resolved before the
	// os.Create below so it never leaves an empty file behind.
	if exportFormat == "bundle" {
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		stats, err := exportDBBundle(context.Background(), db, projectUUID)
		if err != nil || !globalJSON {
			return err
		}
		return emitDBExportReceipt(cmd, []exportedFile{{label: "bundle", path: exportOutput}}, stats.counts)
	}

	ctx := context.Background()

	// A single-shot -o is staged and renamed, so a query that fails — or a
	// cancelled run — leaves the previous export in place instead of a truncated
	// file a consumer cannot distinguish from a complete one. 0o666 under the
	// umask reproduces the os.Create this replaced.
	//
	// --watch is the deliberate exception: it rewrites the same destination on
	// every tick for as long as it runs, so there is no single publication point
	// to rename at. It keeps the open-once-and-append behavior it always had.
	if exportOutput != "" && !dbExportWatching() {
		var n int
		if err := atomicfile.WriteFile(exportOutput, 0o666, func(w *bufio.Writer) error {
			var werr error
			n, werr = writeDBExportCounted(ctx, db, dateFrom, dateTo, w)
			return werr
		}); err != nil || !globalJSON {
			return err
		}
		return emitDBExportReceipt(cmd, []exportedFile{{label: exportFormat, path: exportOutput}},
			map[string]int{"records": n})
	}

	var out io.Writer = os.Stdout
	if exportOutput != "" {
		f, err := os.Create(exportOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	return runWithWatch(func() error {
		return writeDBExport(ctx, db, dateFrom, dateTo, out)
	})
}

// validateDBExportJSON: under -j stdout carries the one result document, so
// the export itself needs a file (fs writes a tree, never stdout), and --watch
// — which rewrites the file on every tick — has no single receipt to print.
func validateDBExportJSON() error {
	if !globalJSON {
		return nil
	}
	if exportOutput == "" && exportFormat != "fs" {
		return usageErrorf("db export -j needs -o <path>: without it the %s export is written to stdout, "+
			"where the -j document goes (drop -j for the stream itself)", exportFormat)
	}
	if dbExportWatching() {
		return usageErrorf("db export -j cannot be combined with --watch: a repeated export has no single receipt")
	}
	return nil
}

// emitDBExportReceipt prints `db export -j`: the files written and what they
// hold.
func emitDBExportReceipt(cmd *cobra.Command, outputs []exportedFile, counts map[string]int) error {
	views := exportFileViews(outputs)
	opts := []envOpt{withExtra("counts", counts)}
	if pu, err := resolveProjectUUID(); err == nil {
		opts = append(opts, withProjectScope(pu))
	}
	return emitRead(cmd, "", views, int64(len(views)), 0, len(views), opts...)
}

// dbExportWatching reports whether --watch asked for a repeating read. An
// unparseable interval is not watching: runWithWatch rejects it as a usage
// error, and treating it as watching here would quietly skip atomic staging on
// the way to that rejection.
func dbExportWatching() bool {
	interval, err := clicommon.ParseWatchInterval(globalWatchRaw)
	return err == nil && interval > 0
}

// writeDBExport runs one query and renders it to w in the requested format. It
// is the whole body of a `db export` iteration, extracted so the atomic -o path
// and the watch loop share it exactly.
func writeDBExport(ctx context.Context, db *database.DB, dateFrom, dateTo *time.Time, out io.Writer) error {
	_, err := writeDBExportCounted(ctx, db, dateFrom, dateTo, out)
	return err
}

// writeDBExportCounted is writeDBExport reporting how many records the query
// selected, for the -j receipt.
func writeDBExportCounted(ctx context.Context, db *database.DB, dateFrom, dateTo *time.Time, out io.Writer) (int, error) {
	filters, err := dbExportFilters(db, dateFrom, dateTo)
	if err != nil {
		return 0, err
	}

	qb := database.NewQueryBuilder(db, filters)
	records, err := qb.Execute(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to query database: %w", err)
	}

	if exportRecordUUID != "" && len(records) == 0 {
		return 0, fmt.Errorf("record UUID %s not found", exportRecordUUID)
	}

	switch exportFormat {
	case "jsonl":
		err = exportDBEnvelopes(ctx, db, filters, records, out)
	case "nuclei":
		err = exportJSONL(ctx, db, records, out)
	case "json":
		err = exportJSON(records, out)
	case "raw":
		err = exportRaw(records, out)
	case "csv":
		err = exportCSV(records, out)
	case "markdown":
		err = exportMarkdown(records, out)
	case "markdown-table":
		err = exportMarkdownTable(records, out)
	default:
		return 0, usageErrorf("unsupported export format: %s", exportFormat)
	}
	return len(records), err
}

// runDBExportFS writes the filtered records + findings to a flat
// <base>-traffic/ + <base>-findings/ tree (the `fs` format). It reuses the same
// host/method/status/path/scan/severity/date/search/limit filters as the other
// db export formats, scoped to the active project; the base defaults to
// "vigolium" in the cwd when no -o is given.
func runDBExportFS(db *database.DB, dateFrom, dateTo *time.Time) (fsExportStats, error) {
	// Same builder as every other format. This branch used to keep its own copy,
	// which is how it came to bind --search to FuzzyTerm while the others used
	// SearchTerm, and to ignore --uuid entirely.
	filters, err := dbExportFilters(db, dateFrom, dateTo)
	if err != nil {
		return fsExportStats{}, err
	}
	stats, err := writeFSExport(context.Background(), db, filters, exportOutput, fsExportOptions{omitResponse: exportRequestOnly})
	if err != nil {
		return fsExportStats{}, err
	}
	fsPrintSummary(stats)
	return stats, nil
}

// dbExportScope is the record-type scope --table selects for the jsonl
// format: both types by default, one of them when --table names it.
func dbExportScope() exportScope {
	if t, ok := lookupExportType(globalTable); ok {
		return exportScope{only: []string{t.Name}}
	}
	return exportScope{only: []string{"http", "findings"}}
}

// validateDBExportTable maps the db group's --table onto the record types db
// export writes. Only http_records and findings are tables it reads; the
// other formats write records alone, so --table findings fits jsonl only.
func validateDBExportTable() error {
	table := strings.TrimSpace(globalTable)
	if table == "" {
		return nil
	}
	t, ok := lookupExportType(table)
	if !ok || (t.Name != "http" && t.Name != "findings") {
		return usageErrorf("db export --table %q: db export reads http_records and the findings linked to them; use `vigolium export --only %s` for other tables",
			table, strings.Join(exportTypeNames(), ","))
	}
	if t.Name == "findings" && exportFormat != "jsonl" {
		return usageErrorf("db export --table findings needs --format jsonl; --format %s writes records only", exportFormat)
	}
	return nil
}

// exportDBEnvelopes writes db export's jsonl: the selected records as
// http_record envelopes, then the confirmed findings linked to them as finding
// envelopes (each once, --severity applied), in the dialect `vigolium export`
// writes and `vigolium import` reads.
func exportDBEnvelopes(ctx context.Context, db *database.DB, filters database.QueryFilters, records []*database.HTTPRecord, out io.Writer) error {
	scope := dbExportScope()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if scope.includes("http") {
		for _, rec := range records {
			if err := enc.Encode(exportEnvelope{Type: "http_record", Data: rec}); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}
	}
	if !scope.includes("findings") || len(records) == 0 {
		return nil
	}
	uuids := make([]string, 0, len(records))
	for _, rec := range records {
		uuids = append(uuids, rec.UUID)
	}
	seen := make(map[int64]struct{})
	// Chunked so a large page stays under the driver's bound-parameter limit.
	for start := 0; start < len(uuids); start += 500 {
		chunk := uuids[start:min(start+500, len(uuids))]
		var findings []*database.Finding
		q := scopeProjectBun(db.NewSelect().Model(&findings), filters.ProjectUUID).
			Where("f.id IN (SELECT finding_id FROM finding_records WHERE record_uuid IN (?))", bun.List(chunk)).
			Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", database.RecordKindFinding).
			OrderExpr("f.found_at DESC")
		if len(filters.Severity) > 0 {
			sevs := make([]string, 0, len(filters.Severity))
			for _, s := range filters.Severity {
				sevs = append(sevs, strings.ToLower(strings.TrimSpace(s)))
			}
			q = q.Where("LOWER(f.severity) IN (?)", bun.List(sevs))
		}
		if err := q.Scan(ctx); err != nil {
			return fmt.Errorf("export linked findings: %w", err)
		}
		for _, f := range findings {
			if _, dup := seen[f.ID]; dup {
				continue
			}
			seen[f.ID] = struct{}{}
			if err := enc.Encode(exportEnvelope{Type: "finding", Data: f}); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}
	}
	return nil
}

// exportJSONL writes the nuclei-style dialect (--format nuclei): one
// ResultEvent per finding linked to each record.
func exportJSONL(ctx context.Context, db *database.DB, records []*database.HTTPRecord, out io.Writer) error {
	for _, rec := range records {
		// Fetch findings for this record
		var findings []*database.Finding
		_ = db.NewSelect().
			Model(&findings).
			Where("f.id IN (SELECT finding_id FROM finding_records WHERE record_uuid = ?)", rec.UUID).
			Scan(ctx)

		for _, finding := range findings {
			event := convertFindingToEvent(finding, rec)
			data, err := json.Marshal(event)
			if err != nil {
				return fmt.Errorf("failed to marshal finding: %w", err)
			}
			if _, err := fmt.Fprintln(out, string(data)); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}
	}
	return nil
}

func exportJSON(records []*database.HTTPRecord, out io.Writer) error {
	result := map[string]interface{}{
		"export_date":   time.Now().Format(time.RFC3339),
		"total_records": len(records),
		"records":       records,
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func exportRaw(records []*database.HTTPRecord, out io.Writer) error {
	for _, rec := range records {
		if exportRequestOnly || !exportRequestOnly {
			if len(rec.RawRequest) > 0 {
				_, _ = fmt.Fprintln(out, string(rec.RawRequest))
				_, _ = fmt.Fprintln(out)
			}
		}

		if !exportRequestOnly {
			if rec.HasResponse && len(rec.RawResponse) > 0 {
				_, _ = fmt.Fprintln(out, string(rec.RawResponse))
				_, _ = fmt.Fprintln(out)
			}

			_, _ = fmt.Fprintln(out, "────────────────────────────────────────")
			_, _ = fmt.Fprintln(out)
		}
	}
	return nil
}

// exportCSV writes the records through the shared safe CSV writer: quoted by
// encoding/csv (commas, quotes, CR/LF) and guarded against formula injection,
// since paths, sources and remarks come from scanned traffic.
func exportCSV(records []*database.HTTPRecord, out io.Writer) error {
	cw := output.NewSafeCSVWriter(out)
	if err := cw.Write([]string{"uuid", "hostname", "port", "method", "path", "status_code", "response_time_ms", "content_type", "source", "risk_score", "surface_score", "remarks", "created_at"}); err != nil {
		return err
	}
	for _, rec := range records {
		statusCode := ""
		responseTime := ""
		if rec.HasResponse {
			statusCode = strconv.Itoa(rec.StatusCode)
			responseTime = strconv.FormatInt(int64(rec.ResponseTimeMs), 10)
		}
		if err := cw.Write([]string{
			rec.UUID,
			rec.Hostname,
			strconv.Itoa(rec.Port),
			rec.Method,
			rec.Path,
			statusCode,
			responseTime,
			rec.RequestContentType,
			rec.Source,
			strconv.Itoa(rec.RiskScore),
			strconv.Itoa(rec.SurfaceScore),
			strings.Join(rec.Remarks, "; "),
			rec.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	return cw.Flush()
}

func convertFindingToEvent(finding *database.Finding, rec *database.HTTPRecord) *output.ResultEvent {
	matched := ""
	if len(finding.MatchedAt) > 0 {
		matched = finding.MatchedAt[0]
	}

	event := &output.ResultEvent{
		ModuleID:      finding.ModuleID,
		RecordKind:    output.RecordKind(finding.RecordKind),
		EvidenceGrade: output.EvidenceGrade(finding.EvidenceGrade),
		Info: output.Info{
			Name:        finding.ModuleName,
			Description: finding.Description,
			Tags:        finding.Tags,
			Severity:    parseSeverity(finding.Severity),
			Confidence:  severity.ToConfidence(finding.Confidence),
		},
		Matched:          matched,
		ExtractedResults: finding.ExtractedResults,
		Request:          finding.Request,
		Response:         finding.Response,
	}

	if rec != nil {
		event.Host = rec.URL
		if rec.HasResponse {
			if event.Metadata == nil {
				event.Metadata = make(map[string]interface{})
			}
			event.Metadata["status_code"] = rec.StatusCode
		}
	}

	return event
}

func parseSeverity(s string) severity.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "info":
		return severity.Info
	default:
		return severity.Info
	}
}

func exportMarkdown(records []*database.HTTPRecord, out io.Writer) error {
	for i, rec := range records {
		renderRecordMarkdown(rec, out, exportRequestOnly, false)
		// Divider between records (skip after last)
		if i < len(records)-1 {
			_, _ = fmt.Fprintln(out, "---")
			_, _ = fmt.Fprintln(out)
		}
	}
	return nil
}

func exportMarkdownTable(records []*database.HTTPRecord, out io.Writer) error {
	// Header
	_, _ = fmt.Fprintln(out, "| HOST | METHOD | PATH | STATUS | TIME | SIZE | CONTENT_TYPE | SOURCE |")
	_, _ = fmt.Fprintln(out, "|------|--------|------|--------|------|------|--------------|--------|")

	for _, rec := range records {
		host := fmt.Sprintf("%s://%s:%d", rec.Scheme, rec.Hostname, rec.Port)

		status := ""
		responseTime := ""
		size := ""
		if rec.HasResponse {
			status = fmt.Sprintf("%d", rec.StatusCode)
			responseTime = fmt.Sprintf("%dms", rec.ResponseTimeMs)
			size = fmt.Sprintf("%d", rec.ResponseContentLength)
		}

		// Escape pipe characters in values
		_, _ = fmt.Fprintf(out, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			mdEscape(clicommon.Truncate(host, 40)),
			rec.Method,
			mdEscape(clicommon.Truncate(rec.Path, 50)),
			status,
			responseTime,
			size,
			mdEscape(clicommon.Truncate(rec.ResponseContentType, 30)),
			mdEscape(rec.Source),
		)
	}
	return nil
}

// mdEscape escapes pipe characters for markdown table cells.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// dbBundleStats is what one bundle run produced, carried back out so the
// summary is printed only after the archive has actually been published.
type dbBundleStats struct {
	counts             map[string]int
	sessionCount       int
	nativeSessionCount int
}

// exportDBBundle publishes the `db export --format bundle` archive. Staging,
// gzip/tar lifetime and the Close-error rule all live in publishTarGz, shared
// with `export --format bundle`; the summary prints only after the archive has
// actually been renamed into place.
func exportDBBundle(ctx context.Context, db *database.DB, projectUUID string) (dbBundleStats, error) {
	stats, err := publishTarGz(exportOutput, func(tw *tar.Writer) (dbBundleStats, error) {
		return writeDBBundleMembers(ctx, db, projectUUID, tw)
	})
	if err != nil {
		return dbBundleStats{}, err
	}
	printDBBundleSummary(projectUUID, stats)
	return stats, nil
}

// writeDBBundleMembers writes every archive member into tw.
func writeDBBundleMembers(ctx context.Context, db *database.DB, projectUUID string, tw *tar.Writer) (dbBundleStats, error) {
	stats := dbBundleStats{counts: make(map[string]int)}
	counts := stats.counts
	var dataLines []byte
	var envelopes []any

	appendEnvelope := func(typeName string, item any) error {
		env := exportEnvelope{Type: typeName, Data: item}
		line, err := json.Marshal(env)
		if err != nil {
			return err
		}
		dataLines = append(dataLines, line...)
		dataLines = append(dataLines, '\n')
		envelopes = append(envelopes, env)
		counts[typeName]++
		return nil
	}

	projectFilter := func(q *bun.SelectQuery) *bun.SelectQuery {
		if projectUUID != "" {
			return q.Where("project_uuid = ?", projectUUID)
		}
		return q
	}

	// --- HTTP Records ---
	qb := database.NewQueryBuilder(db, database.QueryFilters{ProjectUUID: projectUUID})
	records, err := qb.Execute(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query HTTP records: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, r := range records {
			if err := appendEnvelope("http_record", r); err != nil {
				return stats, err
			}
		}
	}

	// --- Findings ---
	var findings []*database.Finding
	fq := projectFilter(db.NewSelect().Model(&findings).OrderExpr("found_at DESC"))
	if err := fq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query findings: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, fi := range findings {
			if err := appendEnvelope("finding", fi); err != nil {
				return stats, err
			}
		}
	}

	// --- Scans ---
	var scans []*database.Scan
	sq := projectFilter(db.NewSelect().Model(&scans).OrderExpr("created_at DESC"))
	if err := sq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query scans: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, s := range scans {
			if err := appendEnvelope("scan", s); err != nil {
				return stats, err
			}
		}
	}

	// --- Agentic Scans ---
	var agenticScans []*database.AgenticScan
	aq := projectFilter(db.NewSelect().Model(&agenticScans).OrderExpr("created_at DESC"))
	if err := aq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query agentic scans: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, a := range agenticScans {
			if err := appendEnvelope("agentic_scan", a); err != nil {
				return stats, err
			}
		}
	}

	// --- OAST Interactions ---
	var interactions []*database.OASTInteraction
	oq := projectFilter(db.NewSelect().Model(&interactions).OrderExpr("interacted_at DESC"))
	if err := oq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query OAST interactions: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, i := range interactions {
			if err := appendEnvelope("oast_interaction", i); err != nil {
				return stats, err
			}
		}
	}

	// --- Scopes ---
	var scopes []*database.Scope
	scq := projectFilter(db.NewSelect().Model(&scopes).Where("enabled = ?", true).OrderExpr("priority ASC"))
	if err := scq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query scopes: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, s := range scopes {
			if err := appendEnvelope("scope", s); err != nil {
				return stats, err
			}
		}
	}

	// Write data.jsonl into the archive. One mtime for every member, so the
	// archive's own timestamps describe one export rather than three moments
	// inside it.
	now := time.Now()
	if len(dataLines) > 0 {
		if err := writeTarBytes(tw, "data.jsonl", dataLines, now); err != nil {
			return stats, fmt.Errorf("failed to write data.jsonl into the bundle: %w", err)
		}
	}

	// --- HTML report ---
	if len(envelopes) > 0 {
		autoTarget, autoDuration := computeReportMeta(ctx, db, projectUUID)
		meta := output.HTMLReportMeta{
			Title:           "Vigolium Export Report",
			Version:         getVersion(),
			ScanDuration:    autoDuration,
			ScanTarget:      autoTarget,
			ReportSharedURL: exportReportURL,
		}
		// report.html is a member of the archive, not a bonus: a bundle without
		// it is not the artifact the operator asked for, and warning about it on
		// stderr while publishing the archive anyway meant nothing downstream
		// could tell the two apart. Same decision as `vigolium export --format
		// bundle`; renderBundleHTML is the shared renderer.
		htmlData, err := renderBundleHTML(envelopes, meta)
		if err != nil {
			return stats, fmt.Errorf("render report.html for bundle: %w", err)
		}
		if err := writeTarBytes(tw, "report.html", htmlData, now); err != nil {
			return stats, fmt.Errorf("failed to write report.html into the bundle: %w", err)
		}
	}

	// --- Agent session directories ---
	sessionCount := 0
	sessionsDir := resolveSessionsDir()
	for _, a := range agenticScans {
		sessionPath := a.SessionDir
		if sessionPath == "" && a.UUID != "" {
			sessionPath = filepath.Join(sessionsDir, a.UUID)
		}
		if archiveSessionDir(tw, sessionPath, "sessions") {
			sessionCount++
		}
	}

	// --- Native scan session directories (contain runtime.log when enabled) ---
	nativeSessionCount := 0
	nativeSessionsDir := resolveNativeSessionsDir()
	for _, s := range scans {
		if s.UUID == "" {
			continue
		}
		sessionPath := filepath.Join(nativeSessionsDir, s.UUID)
		if archiveSessionDir(tw, sessionPath, "native-sessions") {
			nativeSessionCount++
		}
	}

	// Write metadata.json
	meta := map[string]any{
		"export_date":          time.Now().Format(time.RFC3339),
		"project_uuid":         projectUUID,
		"counts":               counts,
		"session_count":        sessionCount,
		"native_session_count": nativeSessionCount,
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaBytes = append(metaBytes, '\n')
	if err := writeTarBytes(tw, "metadata.json", metaBytes, now); err != nil {
		return stats, fmt.Errorf("failed to write metadata.json into the bundle: %w", err)
	}

	stats.sessionCount = sessionCount
	stats.nativeSessionCount = nativeSessionCount
	return stats, nil
}

// printDBBundleSummary reports what the published archive contains. Called after
// the rename, not before: a summary printed next to a file that was never
// published is the same lie the atomic staging exists to prevent.
func printDBBundleSummary(projectUUID string, stats dbBundleStats) {
	total := 0
	fmt.Fprintf(os.Stderr, "\n%s Export summary (format: %s)\n", terminal.InfoSymbol(), terminal.Cyan("bundle"))
	fmt.Fprintf(os.Stderr, "  Output: %s\n", terminal.Cyan(exportOutput))
	typeOrder := []struct{ key, label string }{
		{"http_record", "HTTP records"},
		{"finding", "Findings"},
		{"scan", "Scans"},
		{"agentic_scan", "Agentic scans"},
		{"oast_interaction", "OAST interactions"},
		{"source_repo", "Source repos"},
		{"scope", "Scopes"},
	}
	for _, t := range typeOrder {
		if c, ok := stats.counts[t.key]; ok && c > 0 {
			fmt.Fprintf(os.Stderr, "  %-20s %d\n", t.label, c)
			total += c
		}
	}
	fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Total records", total)
	if stats.sessionCount > 0 {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Agent sessions", stats.sessionCount)
	}
	if stats.nativeSessionCount > 0 {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Native sessions", stats.nativeSessionCount)
	}
	if projectUUID != "" {
		fmt.Fprintf(os.Stderr, "  Project: %s\n", terminal.Cyan(projectUUID))
	}
}

// archiveSessionDir walks sessionPath and streams its contents into tw under
// {prefix}/{basename(sessionPath)}/. Returns true when the directory was
// successfully archived. Silent no-op when sessionPath is empty or missing.
func archiveSessionDir(tw *tar.Writer, sessionPath, prefix string) bool {
	if sessionPath == "" {
		return false
	}
	info, err := os.Stat(sessionPath)
	if err != nil || !info.IsDir() {
		return false
	}
	baseName := filepath.Base(sessionPath)
	walkErr := filepath.WalkDir(sessionPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(sessionPath, path)
		archivePath := filepath.Join(prefix, baseName, rel)

		if d.IsDir() {
			hdr := &tar.Header{
				Typeflag: tar.TypeDir,
				Name:     archivePath + "/",
				Mode:     0755,
				ModTime:  time.Now(),
			}
			return tw.WriteHeader(hdr)
		}

		fi, err := d.Info()
		if err != nil {
			return nil
		}
		hdr := &tar.Header{
			Name:    archivePath,
			Size:    fi.Size(),
			Mode:    0644,
			ModTime: fi.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		_, err = tw.Write(data)
		return err
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to archive session %s: %v\n", terminal.WarningSymbol(), baseName, walkErr)
		return false
	}
	return true
}

// resolveNativeSessionsDir returns the directory where per-scan runtime.log
// files live. Loads settings to honour user overrides; falls back to the
// default when config can't be read.
func resolveNativeSessionsDir() string {
	return settingsOrDefaults().ScanningStrategy.ScanLogs.EffectiveSessionsDir()
}
