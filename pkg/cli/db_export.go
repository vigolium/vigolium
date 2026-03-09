package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/spf13/cobra"
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

	dbExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "jsonl", "Export format: jsonl, json, raw, csv, markdown, markdown-table")
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
