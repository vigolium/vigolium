package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var dbExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export database records",
	RunE:  runDBExport,
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
)

func init() {
	dbCmd.AddCommand(dbExportCmd)

	dbExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "jsonl", "Export format: jsonl, json, raw, csv, markdown, markdown-table, bundle")
	dbExportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file path, defaults to stdout")

	dbExportCmd.Flags().StringVar(&exportHost, "host", "", "Filter records by hostname pattern")
	dbExportCmd.Flags().StringSliceVar(&exportMethods, "method", nil, "Filter records by HTTP method (can be specified multiple times)")
	dbExportCmd.Flags().IntSliceVar(&exportStatus, "status", nil, "Filter records by HTTP status code (can be specified multiple times)")
	dbExportCmd.Flags().StringVar(&exportPath, "path", "", "Filter records by URL path pattern")
	dbExportCmd.Flags().StringVar(&exportScanUUID, "scan-id", "", "Filter records by scan session ID")
	dbExportCmd.Flags().StringVar(&exportSeverity, "severity", "", "Filter findings by severity level")
	dbExportCmd.Flags().StringVar(&exportFrom, "from", "", "Export records created after this date (YYYY-MM-DD)")
	dbExportCmd.Flags().StringVar(&exportTo, "to", "", "Export records created before this date (YYYY-MM-DD)")

	dbExportCmd.Flags().IntVar(&exportLimit, "limit", 0, "Maximum number of records to export, 0 for unlimited")
	dbExportCmd.Flags().IntVar(&exportOffset, "offset", 0, "Number of records to skip before exporting")
	dbExportCmd.Flags().StringVar(&exportRecordUUID, "uuid", "", "Export a single record by its UUID")

	dbExportCmd.Flags().BoolVar(&exportRequestOnly, "request-only", false, "Export only HTTP requests, omitting responses (raw format only)")
}

func runDBExport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Open output file once (outside the watch loop)
	var outputFile *os.File
	if exportOutput != "" {
		f, err := os.Create(exportOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		outputFile = f
	} else {
		outputFile = os.Stdout
	}

	// bundle requires -o and handles its own file I/O
	if exportFormat == "bundle" {
		if exportOutput == "" {
			return fmt.Errorf("--format bundle requires -o/--output to specify the archive path")
		}
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		return exportBundle(context.Background(), db, projectUUID)
	}

	return runWithWatch(func() error {
		var dateFrom, dateTo *time.Time
		if exportFrom != "" {
			t, err := parseDate(exportFrom)
			if err != nil {
				return fmt.Errorf("invalid --from date: %w", err)
			}
			dateFrom = &t
		}
		if exportTo != "" {
			t, err := parseDate(exportTo)
			if err != nil {
				return fmt.Errorf("invalid --to date: %w", err)
			}
			dateTo = &t
		}

		var severities []string
		if exportSeverity != "" {
			severities = strings.Split(exportSeverity, ",")
		}

		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
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

		ctx := context.Background()
		qb := database.NewQueryBuilder(db, filters)
		records, err := qb.Execute(ctx)
		if err != nil {
			return fmt.Errorf("failed to query database: %w", err)
		}

		// Handle specific UUID
		if exportRecordUUID != "" {
			var found *database.HTTPRecord
			for _, rec := range records {
				if rec.UUID == exportRecordUUID {
					found = rec
					break
				}
			}
			if found == nil {
				return fmt.Errorf("record UUID %s not found", exportRecordUUID)
			}
			records = []*database.HTTPRecord{found}
		}

		switch exportFormat {
		case "jsonl":
			return exportJSONL(ctx, db, records, outputFile)
		case "json":
			return exportJSON(records, outputFile)
		case "raw":
			return exportRaw(records, outputFile)
		case "csv":
			return exportCSV(records, outputFile)
		case "markdown", "md":
			return exportMarkdown(records, outputFile)
		case "markdown-table", "md-table":
			return exportMarkdownTable(records, outputFile)
		default:
			return fmt.Errorf("unsupported export format: %s", exportFormat)
		}
	})
}

func exportJSONL(ctx context.Context, db *database.DB, records []*database.HTTPRecord, out *os.File) error {
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

func exportJSON(records []*database.HTTPRecord, out *os.File) error {
	result := map[string]interface{}{
		"export_date":   time.Now().Format(time.RFC3339),
		"total_records": len(records),
		"records":       records,
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func exportRaw(records []*database.HTTPRecord, out *os.File) error {
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

func exportCSV(records []*database.HTTPRecord, out *os.File) error {
	_, _ = fmt.Fprintln(out, "uuid,hostname,port,method,path,status_code,response_time_ms,content_type,source,risk_score,remarks,created_at")

	for _, rec := range records {
		statusCode := ""
		responseTime := ""
		if rec.HasResponse {
			statusCode = fmt.Sprintf("%d", rec.StatusCode)
			responseTime = fmt.Sprintf("%d", rec.ResponseTimeMs)
		}

		remarks := strings.Join(rec.Remarks, "; ")

		_, _ = fmt.Fprintf(out, "%s,%s,%d,%s,%s,%s,%s,%s,%s,%d,%s,%s\n",
			rec.UUID,
			rec.Hostname,
			rec.Port,
			rec.Method,
			csvEscape(rec.Path),
			statusCode,
			responseTime,
			csvEscape(rec.RequestContentType),
			csvEscape(rec.Source),
			rec.RiskScore,
			csvEscape(remarks),
			rec.CreatedAt.Format(time.RFC3339),
		)
	}
	return nil
}

func convertFindingToEvent(finding *database.Finding, rec *database.HTTPRecord) *output.ResultEvent {
	matched := ""
	if len(finding.MatchedAt) > 0 {
		matched = finding.MatchedAt[0]
	}

	event := &output.ResultEvent{
		ModuleID: finding.ModuleID,
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

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return fmt.Sprintf("\"%s\"", strings.ReplaceAll(s, "\"", "\"\""))
	}
	return s
}

func exportMarkdown(records []*database.HTTPRecord, out *os.File) error {
	for i, rec := range records {
		// Heading: method, URL, status code, response time
		heading := fmt.Sprintf("## %s %s", rec.Method, rec.URL)
		if rec.HasResponse {
			heading += fmt.Sprintf(" → %d (%dms)", rec.StatusCode, rec.ResponseTimeMs)
		}
		_, _ = fmt.Fprintln(out, heading)
		_, _ = fmt.Fprintln(out)

		// Metadata line
		uuidShort := rec.UUID
		if len(uuidShort) > 8 {
			uuidShort = uuidShort[:8]
		}
		_, _ = fmt.Fprintf(out, "**UUID:** `%s` | **Source:** %s | **Sent:** %s\n",
			uuidShort, rec.Source, rec.SentAt.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintln(out)

		// Request section
		if len(rec.RawRequest) > 0 {
			_, _ = fmt.Fprintln(out, "### Request")
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, "```http")
			_, _ = fmt.Fprintln(out, strings.TrimRight(string(rec.RawRequest), "\n\r"))
			_, _ = fmt.Fprintln(out, "```")
			_, _ = fmt.Fprintln(out)
		}

		// Response section (unless --request-only)
		if !exportRequestOnly && rec.HasResponse && len(rec.RawResponse) > 0 {
			_, _ = fmt.Fprintln(out, "### Response")
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, "```http")
			_, _ = fmt.Fprintln(out, strings.TrimRight(string(rec.RawResponse), "\n\r"))
			_, _ = fmt.Fprintln(out, "```")
			_, _ = fmt.Fprintln(out)
		}

		// Divider between records (skip after last)
		if i < len(records)-1 {
			_, _ = fmt.Fprintln(out, "---")
			_, _ = fmt.Fprintln(out)
		}
	}
	return nil
}

func exportMarkdownTable(records []*database.HTTPRecord, out *os.File) error {
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
			mdEscape(truncate(host, 40)),
			rec.Method,
			mdEscape(truncate(rec.Path, 50)),
			status,
			responseTime,
			size,
			mdEscape(truncate(rec.ResponseContentType, 30)),
			mdEscape(rec.Source),
		)
	}
	return nil
}

// mdEscape escapes pipe characters for markdown table cells.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func exportBundle(ctx context.Context, db *database.DB, projectUUID string) error {
	f, err := os.Create(exportOutput)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()
	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	counts := make(map[string]int)
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
				return err
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
				return err
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
				return err
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
				return err
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
				return err
			}
		}
	}

	// --- Source Repos ---
	var repos []*database.SourceRepo
	rq := projectFilter(db.NewSelect().Model(&repos).OrderExpr("created_at DESC"))
	if err := rq.Scan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to query source repos: %v\n", terminal.WarningSymbol(), err)
	} else {
		for _, r := range repos {
			if err := appendEnvelope("source_repo", r); err != nil {
				return err
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
				return err
			}
		}
	}

	// Write data.jsonl into the archive
	if len(dataLines) > 0 {
		hdr := &tar.Header{
			Name:    "data.jsonl",
			Size:    int64(len(dataLines)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write tar header for data.jsonl: %w", err)
		}
		if _, err := tw.Write(dataLines); err != nil {
			return fmt.Errorf("failed to write tar data for data.jsonl: %w", err)
		}
	}

	// --- HTML report ---
	if len(envelopes) > 0 {
		meta := output.HTMLReportMeta{
			Title:        "Vigolium Export Report",
			Version:      getVersion(),
			ScanDuration: computeScanDuration(ctx, db),
		}
		tmpFile, err := os.CreateTemp("", "vigolium-bundle-report-*.html")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to create temp file for HTML report: %v\n", terminal.WarningSymbol(), err)
		} else {
			tmpPath := tmpFile.Name()
			_ = tmpFile.Close()
			defer os.Remove(tmpPath)

			if err := output.GenerateHTMLReport(envelopes, tmpPath, meta); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to generate HTML report: %v\n", terminal.WarningSymbol(), err)
			} else {
				htmlData, err := os.ReadFile(tmpPath)
				if err == nil {
					hdr := &tar.Header{
						Name:    "report.html",
						Size:    int64(len(htmlData)),
						Mode:    0644,
						ModTime: time.Now(),
					}
					if err := tw.WriteHeader(hdr); err != nil {
						return fmt.Errorf("failed to write tar header for report.html: %w", err)
					}
					if _, err := tw.Write(htmlData); err != nil {
						return fmt.Errorf("failed to write tar data for report.html: %w", err)
					}
				}
			}
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
		"export_date":           time.Now().Format(time.RFC3339),
		"project_uuid":          projectUUID,
		"counts":                counts,
		"session_count":         sessionCount,
		"native_session_count":  nativeSessionCount,
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaBytes = append(metaBytes, '\n')
	hdr := &tar.Header{
		Name:    "metadata.json",
		Size:    int64(len(metaBytes)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed to write tar header for metadata: %w", err)
	}
	if _, err := tw.Write(metaBytes); err != nil {
		return fmt.Errorf("failed to write tar data for metadata: %w", err)
	}

	// Print summary
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
		if c, ok := counts[t.key]; ok && c > 0 {
			fmt.Fprintf(os.Stderr, "  %-20s %d\n", t.label, c)
			total += c
		}
	}
	fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Total records", total)
	if sessionCount > 0 {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Agent sessions", sessionCount)
	}
	if nativeSessionCount > 0 {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Native sessions", nativeSessionCount)
	}
	if projectUUID != "" {
		fmt.Fprintf(os.Stderr, "  Project: %s\n", terminal.Cyan(projectUUID))
	}

	return nil
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
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}
	return settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
}

