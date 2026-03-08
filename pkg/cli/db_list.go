package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var dbListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List database records (default: http_records)",
	RunE:    runDBList,
}

var (
	listTree    bool
	listRaw     bool
	listLimit   int
	listOffset  int
	listColumns []string
	listExclude []string

	// Filter flags
	listHost     string
	listMethods  []string
	listStatus   []int
	listPath     string
	listScanUUID string
	listSeverity string
	listFrom     string
	listTo       string
	listHeader   string
	listBody     string

	// Risk filtering flags
	listMinRisk int
	listRemark  string

	// Finding type filtering flags
	listModuleType    string
	listFindingSource string

	// Sorting flags
	listSort string
	listAsc  bool

	// Schema inspection flags
	listTables      bool
	listColumnNames bool
)

func init() {
	dbCmd.AddCommand(dbListCmd)
	registerListFlags(dbListCmd)
}

// registerListFlags registers all filter, display, and pagination flags on a command.
// Used by both dbListCmd and findingCmd to share the same flags.
func registerListFlags(cmd *cobra.Command) {
	// Display format flags
	cmd.Flags().BoolVar(&listTree, "tree", false, "Display results in hierarchical tree format")
	cmd.Flags().BoolVar(&listRaw, "raw", false, "Show full raw HTTP request and response")

	// Schema inspection flags
	cmd.Flags().BoolVar(&listTables, "list-tables", false, "List all database table names")
	cmd.Flags().BoolVar(&listColumnNames, "list-columns", false, "List column names for the specified table (default: http_records)")

	// Pagination flags
	cmd.Flags().IntVarP(&listLimit, "limit", "n", 100, "Maximum number of records to display")
	cmd.Flags().IntVarP(&listOffset, "offset", "o", 0, "Number of records to skip before displaying")

	// Column selection flags
	cmd.Flags().StringSliceVar(&listColumns, "columns", nil, "Columns to include in output, comma-separated")
	cmd.Flags().StringSliceVar(&listExclude, "exclude-columns", nil, "Columns to exclude from output, comma-separated")

	// Filter flags
	cmd.Flags().StringVar(&listHost, "host", "", "Filter records by hostname pattern (wildcard supported)")
	cmd.Flags().StringSliceVar(&listMethods, "method", nil, "Filter records by HTTP method (can be specified multiple times)")
	cmd.Flags().IntSliceVar(&listStatus, "status", nil, "Filter records by HTTP status code (can be specified multiple times)")
	cmd.Flags().StringVar(&listPath, "path", "", "Filter records by URL path pattern")
	cmd.Flags().StringVar(&listScanUUID, "scan-id", "", "Filter records by scan session ID")
	cmd.Flags().StringVar(&listSeverity, "severity", "", "Filter findings by severity: critical, high, medium, low")
	cmd.Flags().IntVar(&listMinRisk, "min-risk", 0, "Filter records with risk score >= value")
	cmd.Flags().StringVar(&listRemark, "remark", "", "Filter records by remark substring")
	cmd.Flags().StringVar(&listModuleType, "module-type", "", "Filter findings by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension)")
	cmd.Flags().StringVar(&listFindingSource, "finding-source", "", "Filter findings by source (dynamic-assessment, spa, agent, oast, source-tools, extension)")

	// Date range flags
	cmd.Flags().StringVar(&listFrom, "from", "", "Show records created after this date (YYYY-MM-DD or RFC3339)")
	cmd.Flags().StringVar(&listTo, "to", "", "Show records created before this date (YYYY-MM-DD or RFC3339)")

	// Search flags
	cmd.Flags().StringVar(&listHeader, "header", "", "Search for matching HTTP header pattern")
	cmd.Flags().StringVar(&listBody, "body", "", "Search within request or response body content")

	// Sorting flags
	cmd.Flags().StringVar(&listSort, "sort", "created_at", "Sort results by field: uuid, created_at, sent_at, method, status_code, response_time")
	cmd.Flags().BoolVar(&listAsc, "asc", false, "Sort in ascending order instead of descending")
}

func runDBList(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Handle --list-tables: show all table names and exit (no watch)
	if listTables {
		return runListTables(context.Background(), db)
	}

	// Handle --list-columns: show columns for the table and exit (no watch)
	if listColumnNames {
		tableName := "http_records"
		if globalTable != "" {
			tableName = globalTable
		}
		return runListColumns(context.Background(), db, tableName)
	}

	return runWithWatch(func() error {
		ctx := context.Background()

		// Determine table name from --table flag
		tableName := "http_records"
		if globalTable != "" {
			tableName = globalTable
		}

		// For non-default tables, use generic query
		switch tableName {
		case "http_records":
			return runListHTTPRecords(ctx, db)
		case "findings":
			return runListFindings(ctx, db)
		case "scans":
			return runListScans(ctx, db)
		default:
			return runListGenericTable(ctx, db, tableName)
		}
	})
}

// runListTables displays all table names in the database.
func runListTables(ctx context.Context, db *database.DB) error {
	tables, err := database.ListTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to list tables: %w", err)
	}

	if len(tables) == 0 {
		fmt.Printf("%s No tables found\n", terminal.WarnPrefix())
		return nil
	}

	for _, t := range tables {
		fmt.Printf("  %s\n", terminal.Cyan(t))
	}
	return nil
}

// runListColumns displays column names and types for a table.
func runListColumns(ctx context.Context, db *database.DB, tableName string) error {
	columns, err := database.ListColumns(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to list columns for %q: %w", tableName, err)
	}

	if len(columns) == 0 {
		fmt.Printf("%s No columns found for table %q\n", terminal.WarnPrefix(), tableName)
		return nil
	}

	fmt.Printf("Columns for %s:\n\n", terminal.BoldCyan(tableName))
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "TYPE", "NULLABLE", "DEFAULT")
	for _, col := range columns {
		tbl.AddRow(col.Name, col.Type, col.Nullable, col.Default)
	}
	tbl.Print()
	return nil
}

// runListHTTPRecords handles the default http_records table listing with full filter support.
func runListHTTPRecords(ctx context.Context, db *database.DB) error {
	// Parse date filters
	var dateFrom, dateTo *time.Time
	if listFrom != "" {
		t, err := parseDate(listFrom)
		if err != nil {
			return fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if listTo != "" {
		t, err := parseDate(listTo)
		if err != nil {
			return fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if listSeverity != "" {
		severities = strings.Split(listSeverity, ",")
	}

	filters := database.QueryFilters{
		ProjectUUID:  resolveProjectUUID(),
		HostPattern:  listHost,
		Methods:      listMethods,
		StatusCodes:  listStatus,
		PathPattern:  listPath,
		Severity:     severities,
		MinRiskScore: listMinRisk,
		Remark:       listRemark,
		DateFrom:     dateFrom,
		DateTo:       dateTo,
		SearchTerm:   dbSearch,
		HeaderSearch: listHeader,
		BodySearch:   listBody,
		Limit:        listLimit,
		Offset:       listOffset,
		SortBy:       listSort,
		SortAsc:      listAsc,
	}

	qb := database.NewQueryBuilder(db, filters)
	records, err := qb.Execute(ctx)
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}

	total, err := qb.Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	if globalJSON {
		return displayJSON(records, total, listOffset, listLimit)
	} else if listRaw {
		return displayRaw(records)
	} else if listTree {
		return displayTree(records)
	} else {
		return displayTable(records, total, listOffset, listLimit)
	}
}

// runListFindings handles the findings table listing.
func runListFindings(ctx context.Context, db *database.DB) error {
	var dateFrom, dateTo *time.Time
	if listFrom != "" {
		t, err := parseDate(listFrom)
		if err != nil {
			return fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if listTo != "" {
		t, err := parseDate(listTo)
		if err != nil {
			return fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if listSeverity != "" {
		severities = strings.Split(listSeverity, ",")
	}

	filters := database.QueryFilters{
		ProjectUUID:   resolveProjectUUID(),
		HostPattern:   listHost,
		ScanUUID:      listScanUUID,
		Severity:      severities,
		ModuleType:    listModuleType,
		FindingSource: listFindingSource,
		DateFrom:      dateFrom,
		DateTo:        dateTo,
		SearchTerm:    dbSearch,
		Limit:         listLimit,
		Offset:        listOffset,
		SortBy:        listSort,
		SortAsc:       listAsc,
	}

	fqb := database.NewFindingsQueryBuilder(db, filters)
	findings, err := fqb.Execute(ctx)
	if err != nil {
		return fmt.Errorf("failed to query findings: %w", err)
	}

	total, err := fqb.Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count findings: %w", err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"project_uuid": resolveProjectUUID(),
			"total":        total,
			"offset":       listOffset,
			"limit":        listLimit,
			"findings":     findings,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	// Build severity and confidence breakdown summary
	projectUUID := resolveProjectUUID()
	sevLine := ""
	sevCounts, sevErr := database.CountFindingsBySeverity(ctx, db, projectUUID)
	if sevErr == nil {
		sevLine = fmt.Sprintf("  %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s",
			terminal.BoldMagenta("Critical"), terminal.BoldMagenta(fmt.Sprintf("%d", sevCounts["critical"])),
			terminal.BoldRed("High"), terminal.BoldRed(fmt.Sprintf("%d", sevCounts["high"])),
			terminal.BoldYellow("Medium"), terminal.BoldYellow(fmt.Sprintf("%d", sevCounts["medium"])),
			terminal.Green("Low"), terminal.Green(fmt.Sprintf("%d", sevCounts["low"])),
			terminal.BoldCyan("Suspect"), terminal.BoldCyan(fmt.Sprintf("%d", sevCounts["suspect"])),
			terminal.BoldBlue("Info"), terminal.BoldBlue(fmt.Sprintf("%d", sevCounts["info"])),
		)
	}

	confLine := ""
	confCounts, confErr := database.CountFindingsByConfidence(ctx, db, projectUUID)
	if confErr == nil {
		confLine = fmt.Sprintf("  %s:%s %s:%s %s:%s",
			terminal.HiPurple("Certain"), terminal.HiPurple(fmt.Sprintf("%d", confCounts["certain"])),
			terminal.BoldYellow("Firm"), terminal.BoldYellow(fmt.Sprintf("%d", confCounts["firm"])),
			terminal.Gray("Tentative"), terminal.Gray(fmt.Sprintf("%d", confCounts["tentative"])),
		)
	}

	fmt.Printf("%s Showing %d-%d of %d findings\n",
		terminal.InfoSymbol(),
		listOffset+1,
		min(listOffset+len(findings), int(total)),
		total)
	if sevLine != "" {
		fmt.Printf("  %s Severity:  %s\n", terminal.Cyan(terminal.SymbolSparkle), sevLine)
	}
	if confLine != "" {
		fmt.Printf("  %s Confidence:%s\n", terminal.Cyan(terminal.SymbolSparkle2), confLine)
	}
	fmt.Println()

	tbl := terminal.NewTableFullWidthWeighted(
		terminal.TerminalWidth(),
		[]int{1, 2, 2, 4, 4, 2, 2, 6, 3},
		"ID", "SEVERITY", "CONFIDENCE", "MODULE", "SHORT_DESC", "TYPE", "SOURCE", "MATCHED_AT", "FOUND_AT",
	)
	for _, f := range findings {
		matchedAt := strings.Join(f.MatchedAt, ", ")
		tbl.AddRow(
			f.ID,
			colorSeverity(f.Severity),
			f.Confidence,
			f.ModuleName,
			f.ModuleShort,
			f.ModuleType,
			f.FindingSource,
			matchedAt,
			f.FoundAt.Format("2006-01-02 15:04"),
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}

// runListScans handles the scans table listing with a compact summary view.
func runListScans(ctx context.Context, db *database.DB) error {
	repo := database.NewRepository(db)
	scans, total, err := repo.ListScans(ctx, resolveProjectUUID(), listLimit, listOffset)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"total":  total,
			"offset": listOffset,
			"limit":  listLimit,
			"scans":  scans,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	fmt.Printf("Showing %d-%d of %d scans\n\n",
		listOffset+1,
		min(listOffset+len(scans), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "TARGET", "STATUS", "THREADS", "REQUESTS", "FINDINGS", "C/H/M/L/I/S", "DURATION", "DESCRIPTION")
	for _, s := range scans {
		status := s.Status
		switch status {
		case "completed":
			status = terminal.Green(status)
		case "running":
			status = terminal.Cyan(status)
		case "failed":
			status = terminal.Red(status)
		case "cancelled":
			status = terminal.Yellow(status)
		}

		counts := fmt.Sprintf("%s/%s/%s/%s/%s/%s",
			terminal.BoldMagenta(fmt.Sprintf("%d", s.CriticalCount)),
			terminal.BoldRed(fmt.Sprintf("%d", s.HighCount)),
			terminal.BoldYellow(fmt.Sprintf("%d", s.MediumCount)),
			terminal.Green(fmt.Sprintf("%d", s.LowCount)),
			terminal.BoldBlue(fmt.Sprintf("%d", s.InfoCount)),
			terminal.Cyan(fmt.Sprintf("%d", s.SuspectCount)),
		)

		duration := fmt.Sprintf("%.1fs", float64(s.DurationMs)/1000)

		tbl.AddRow(
			truncate(s.Name, 30),
			truncate(s.Target, 30),
			status,
			s.Threads,
			terminal.Cyan(fmt.Sprintf("%d", s.TotalRequests)),
			terminal.Yellow(fmt.Sprintf("%d", s.TotalFindings)),
			counts,
			duration,
			truncate(s.Description, 40),
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}

// runListGenericTable handles arbitrary table listing via raw SQL.
func runListGenericTable(ctx context.Context, db *database.DB, tableName string) error {
	// Validate table exists
	tables, err := database.ListTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to list tables: %w", err)
	}

	found := false
	for _, t := range tables {
		if strings.EqualFold(t, tableName) {
			tableName = t // use exact casing from DB
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("table %q not found. Use --list-tables to see available tables", tableName)
	}

	rows, headers, total, err := database.QueryGenericTable(ctx, db, tableName, listLimit, listOffset)
	if err != nil {
		return fmt.Errorf("failed to query table %q: %w", tableName, err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"table":   tableName,
			"total":   total,
			"offset":  listOffset,
			"limit":   listLimit,
			"columns": headers,
			"rows":    rows,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	fmt.Printf("Showing %d-%d of %d rows from %s\n\n",
		listOffset+1,
		min(listOffset+len(rows), int(total)),
		total,
		terminal.BoldCyan(tableName))

	// Filter out UUID-related columns by default unless --columns was given
	visibleHeaders := headers
	if len(listColumns) == 0 {
		var filtered []string
		for _, h := range headers {
			lower := strings.ToLower(h)
			if lower == "uuid" || strings.HasSuffix(lower, "_uuid") || strings.HasSuffix(lower, "_id") {
				continue
			}
			filtered = append(filtered, h)
		}
		visibleHeaders = filtered
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, visibleHeaders...)
	for _, row := range rows {
		vals := make([]any, len(visibleHeaders))
		for i, h := range visibleHeaders {
			v := row[h]
			s := fmt.Sprint(v)
			if s == "<nil>" {
				s = "–"
			}
			// Shorten timestamps: strip trailing timezone offset
			if strings.Contains(s, "+0000 +0000") {
				s = strings.TrimSuffix(s, " +0000")
				s = strings.TrimSuffix(s, " +0000")
			}
			if len(s) > 30 {
				s = s[:27] + "..."
			}
			vals[i] = s
		}
		tbl.AddRow(vals...)
	}
	tbl.Print()
	fmt.Println()
	return nil
}

func displayJSON(records []*database.HTTPRecord, total int64, offset, limit int) error {
	output := map[string]interface{}{
		"project_uuid": resolveProjectUUID(),
		"total":        total,
		"offset":       offset,
		"limit":        limit,
		"records":      records,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func displayRaw(records []*database.HTTPRecord) error {
	for _, rec := range records {
		fmt.Println("──────────────────────────────────────────────────────────────────")
		fmt.Printf("Record %s - %s %s\n", rec.UUID[:8], rec.Method, rec.URL)
		fmt.Printf("Sent: %s\n", rec.SentAt.Format("2006-01-02 15:04:05"))
		fmt.Println("──────────────────────────────────────────────────────────────────")
		fmt.Println()

		if len(rec.RawRequest) > 0 {
			fmt.Println(string(rec.RawRequest))
		}

		if rec.HasResponse && len(rec.RawResponse) > 0 {
			fmt.Println()
			fmt.Println("──────────────────────────────────────────────────────────────────")
			fmt.Printf("Response - %d (%dms)\n", rec.StatusCode, rec.ResponseTimeMs)
			fmt.Println("──────────────────────────────────────────────────────────────────")
			fmt.Println()
			fmt.Println(string(rec.RawResponse))
		}

		fmt.Println()
	}
	return nil
}

func displayTree(records []*database.HTTPRecord) error {
	// Group records by host
	hostMap := make(map[string][]*database.HTTPRecord)
	for _, rec := range records {
		key := fmt.Sprintf("%s://%s:%d", rec.Scheme, rec.Hostname, rec.Port)
		hostMap[key] = append(hostMap[key], rec)
	}

	for hostKey, hostRecords := range hostMap {
		fmt.Printf("└── %s %s\n",
			terminal.BoldCyan(hostKey),
			terminal.BoldMagenta(fmt.Sprintf("(%d records)", len(hostRecords))))

		// Group by path prefix
		pathMap := make(map[string][]*database.HTTPRecord)
		for _, rec := range hostRecords {
			pathParts := strings.Split(rec.Path, "/")
			prefix := "/"
			if len(pathParts) > 1 && pathParts[1] != "" {
				prefix = "/" + pathParts[1]
			}
			pathMap[prefix] = append(pathMap[prefix], rec)
		}

		pathIndex := 0
		for pathPrefix, pathRecords := range pathMap {
			pathIndex++
			isLast := pathIndex == len(pathMap)
			connector := "├──"
			if isLast {
				connector = "└──"
			}

			fmt.Printf("    %s %s\n", connector, pathPrefix)

			for reqIndex, rec := range pathRecords {
				isLastReq := reqIndex == len(pathRecords)-1
				reqConnector := "│   ├──"
				if isLast {
					reqConnector = "    ├──"
				}
				if isLastReq {
					if isLast {
						reqConnector = "    └──"
					} else {
						reqConnector = "│   └──"
					}
				}

				headerCount := len(rec.RequestHeaders)
				headerTag := terminal.Gray(fmt.Sprintf("[%dh]", headerCount))

				respPart := ""
				if rec.HasResponse {
					statusColor := terminal.Green
					if rec.StatusCode >= 400 {
						statusColor = terminal.Yellow
					}
					if rec.StatusCode >= 500 {
						statusColor = terminal.Red
					}
					respPart = fmt.Sprintf(" %s %s %s",
						terminal.BoldMagenta("→"),
						statusColor(fmt.Sprintf("%d", rec.StatusCode)),
						terminal.Gray(fmt.Sprintf("(%dms, %dB, %dW)", rec.ResponseTimeMs, rec.ResponseContentLength, rec.ResponseWords)))

					if rec.ResponseContentType != "" {
						ct := rec.ResponseContentType
						if idx := strings.Index(ct, ";"); idx > 0 {
							ct = ct[:idx]
						}
						respPart += " " + terminal.Gray(ct)
					}

					if rec.ResponseTitle != "" {
						title := rec.ResponseTitle
						if len(title) > 40 {
							title = title[:37] + "..."
						}
						respPart += " " + terminal.Cyan(fmt.Sprintf("%q", title))
					}

					if rec.RiskScore > 0 {
						respPart += " " + terminal.BoldYellow(fmt.Sprintf("[risk:%d]", rec.RiskScore))
					}
				}

				fmt.Printf("%s %s %s %s%s\n",
					reqConnector,
					terminal.Cyan(rec.Method),
					terminal.Gray(rec.Path),
					headerTag,
					respPart)
			}
		}
		fmt.Println()
	}

	return nil
}

func displayTable(records []*database.HTTPRecord, total int64, offset, _ int) error {
	fmt.Printf("Showing %d-%d of %d records\n\n",
		offset+1,
		min(offset+len(records), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "HOST", "METHOD", "PATH", "STATUS", "TIME", "SIZE", "WORDS", "CONTENT_TYPE", "TITLE", "RISK")

	for _, rec := range records {
		host := fmt.Sprintf("%s://%s:%d", rec.Scheme, rec.Hostname, rec.Port)

		status := ""
		responseTime := ""
		size := ""
		words := ""
		if rec.HasResponse {
			s := fmt.Sprintf("%d", rec.StatusCode)
			status = colorStatus(s, rec.StatusCode)
			responseTime = fmt.Sprintf("%dms", rec.ResponseTimeMs)
			size = fmt.Sprintf("%d", rec.ResponseContentLength)
			words = fmt.Sprintf("%d", rec.ResponseWords)
		}

		risk := ""
		if rec.RiskScore > 0 {
			risk = fmt.Sprintf("%d", rec.RiskScore)
		}

		tbl.AddRow(
			truncate(host, 30),
			rec.Method,
			truncate(rec.Path, 40),
			status,
			responseTime,
			size,
			words,
			truncate(rec.ResponseContentType, 25),
			truncate(rec.ResponseTitle, 30),
			risk,
		)
	}

	tbl.Print()
	fmt.Println()
	return nil
}

func parseDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// colorSeverity applies color based on finding severity level.
func colorSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return terminal.BoldMagenta(sev)
	case "high":
		return terminal.BoldRed(sev)
	case "medium":
		return terminal.BoldYellow(sev)
	case "low":
		return terminal.Green(sev)
	case "info":
		return terminal.BoldBlue(sev)
	default:
		return sev
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
