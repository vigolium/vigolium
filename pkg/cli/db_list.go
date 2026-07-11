package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbListCmd = &cobra.Command{
	Use:     "list [table]",
	Aliases: []string{"ls"},
	Short:   "List database records (default: http_records)",
	Long:    "Browse rows from any database table. Defaults to http_records but accepts a positional table name (findings, scans, scopes, …). Supports tree view, raw HTTP display, column selection, and filters by host, method, status, scan UUID, severity, and time range. The parent --table flag is a deprecated alias for the positional table name.",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runDBList,
}

// resolveDBListTable determines the target table for `db list [table]`. The
// positional table name is the primary interface; the persistent --table flag is
// kept as a deprecated alias. Supplying both with different values is a conflict
// error rather than a silent pick, so `db list findings` can never quietly query
// http_records. Defaults to http_records when neither is given.
func resolveDBListTable(args []string) (string, error) {
	positional := ""
	if len(args) > 0 {
		positional = strings.TrimSpace(args[0])
	}
	if positional != "" && globalTable != "" && !strings.EqualFold(positional, globalTable) {
		return "", fmt.Errorf("conflicting table selection: positional %q vs --table %q; specify only one (--table is deprecated for db list — prefer the positional table name)", positional, globalTable)
	}
	switch {
	case positional != "":
		return positional, nil
	case globalTable != "":
		return globalTable, nil
	default:
		return "http_records", nil
	}
}

var (
	listTree    bool
	listRaw     bool
	listLimit   int
	listOffset  int
	listColumns []string

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
	listRecordKind    string

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
	cmd.Flags().BoolVar(&listColumnNames, "list-columns", false, "List column names for the current table")

	// Pagination flags
	cmd.Flags().IntVarP(&listLimit, "limit", "n", 100, "Maximum number of records to display")
	cmd.Flags().IntVar(&listOffset, "offset", 0, "Number of records to skip before displaying")

	// Column selection flags
	cmd.Flags().StringSliceVar(&listColumns, "columns", nil, "Columns to include in output, comma-separated")
	registerAgentJSONFlags(cmd.Flags())

	// Filter flags
	cmd.Flags().StringVar(&listHost, "host", "", "Filter records by hostname pattern (wildcard supported)")
	cmd.Flags().StringSliceVar(&listMethods, "method", nil, "Filter records by HTTP method (can be specified multiple times)")
	cmd.Flags().IntSliceVar(&listStatus, "status", nil, "Filter records by HTTP status code (can be specified multiple times)")
	cmd.Flags().StringVar(&listPath, "path", "", "Filter records by URL path pattern")
	cmd.Flags().StringVar(&listScanUUID, "scan-uuid", "", "Filter records by scan UUID")
	cmd.Flags().StringVar(&listSeverity, "severity", "", "Filter findings by severity: critical,high,medium,low,suspect,info (comma-separated; single-letter shorthands ok, e.g. 'h,c')")
	cmd.Flags().IntVar(&listMinRisk, "min-risk", 0, "Show only records with risk score at or above this value")
	cmd.Flags().StringVar(&listRemark, "remark", "", "Filter records containing this text in remarks")
	cmd.Flags().StringVar(&listModuleType, "module-type", "", "Filter findings by module type (active, passive, nuclei, agent, source-tools, oast, extension)")
	cmd.Flags().StringVar(&listFindingSource, "finding-source", "", "Filter findings by source (dynamic-assessment, spa, agent, oast, source-tools, extension)")
	cmd.Flags().StringVar(&listRecordKind, "record-kind", "", "Filter by record kind (finding, candidate, observation; comma-separated). Default: finding")

	// Date range flags
	cmd.Flags().StringVar(&listFrom, "from", "", "Show records created after this date (YYYY-MM-DD or RFC3339)")
	cmd.Flags().StringVar(&listTo, "to", "", "Show records created before this date (YYYY-MM-DD or RFC3339)")

	// Search flags
	cmd.Flags().StringVar(&listHeader, "header", "", "Search within HTTP header names and values")
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

	// Resolve the target table from the positional arg (primary) / --table alias.
	tableName, err := resolveDBListTable(args)
	if err != nil {
		return err
	}

	// Handle --list-columns: show columns for the table and exit (no watch)
	if listColumnNames {
		return runListColumns(context.Background(), db, tableName)
	}

	return runWithWatch(func() error {
		ctx := context.Background()

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
		t, err := clicommon.ParseDate(listFrom)
		if err != nil {
			return fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if listTo != "" {
		t, err := clicommon.ParseDate(listTo)
		if err != nil {
			return fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if listSeverity != "" {
		severities = parseSeverityList(listSeverity)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	filters := database.QueryFilters{
		ProjectUUID:  projectUUID,
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
		t, err := clicommon.ParseDate(listFrom)
		if err != nil {
			return fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if listTo != "" {
		t, err := clicommon.ParseDate(listTo)
		if err != nil {
			return fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if listSeverity != "" {
		severities = parseSeverityList(listSeverity)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	recordKinds, err := parseRecordKinds(listRecordKind)
	if err != nil {
		return err
	}

	filters := database.QueryFilters{
		ProjectUUID:   projectUUID,
		HostPattern:   listHost,
		ScanUUID:      listScanUUID,
		Severity:      severities,
		ModuleType:    listModuleType,
		FindingSource: listFindingSource,
		RecordKinds:   recordKinds,
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
		return writeAgentJSON(map[string]any{
			"project_uuid": projectUUID,
			"total":        total,
			"offset":       listOffset,
			"limit":        listLimit,
			"findings":     findingViews(ctx, db, findings, agentViewOptionsFromFlags(), false),
		})
	}

	// Build severity and confidence breakdown summary
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
			clicommon.ColorSeverity(f.Severity),
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
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	scans, total, err := repo.ListScans(ctx, projectUUID, listLimit, listOffset)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	views := buildScanViews(scans)

	if globalJSON {
		return writeAgentJSON(map[string]any{
			"total":  total,
			"offset": listOffset,
			"limit":  listLimit,
			"scans":  views,
		})
	}

	fmt.Printf("Showing %d-%d of %d scans\n\n",
		listOffset+1,
		min(listOffset+len(scans), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "TARGET", "TYPE", "SOURCE", "STATUS", "MODULES", "REQUESTS", "C/H/M/L/I/S", "DURATION")
	for _, v := range views {
		s := v.Scan
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
		moduleCounts := fmt.Sprintf("%s/%s",
			terminal.Cyan(fmt.Sprintf("%d", v.TotalActiveModules)),
			terminal.Gray(fmt.Sprintf("%d", v.TotalPassiveModules)),
		)

		tbl.AddRow(
			clicommon.Truncate(s.Name, 30),
			clicommon.Truncate(v.Target, 30),
			classifyTarget(s),
			s.ScanSource,
			status,
			moduleCounts,
			terminal.Cyan(fmt.Sprintf("%d", s.TotalRequests)),
			counts,
			duration,
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}

// buildScanViews wraps each scan with display-friendly fields: renders
// "all" when every built-in active module is enabled, attaches active/passive
// counts, and substitutes a generic placeholder for Target when the scan has
// no single target (e.g. scan-on-receive groups traffic from the ingest stream).
func buildScanViews(scans []*database.Scan) []*database.ScanView {
	allActiveCount := len(modules.GetActiveModulesID())
	allPassiveCount := len(modules.GetPassiveModulesID())

	views := make([]*database.ScanView, len(scans))
	for i, s := range scans {
		active := clicommon.SplitCSV(s.Modules)
		modulesDisplay := s.Modules
		if allActiveCount > 0 && len(active) >= allActiveCount {
			modulesDisplay = "all"
		}
		views[i] = &database.ScanView{
			Scan:                s,
			Target:              displayTarget(s),
			Modules:             modulesDisplay,
			TotalActiveModules:  len(active),
			TotalPassiveModules: allPassiveCount,
		}
	}
	return views
}

// displayTarget substitutes a human-readable placeholder for scans that have
// no single target URL — these group traffic from the ingest stream rather
// than scanning one endpoint.
func displayTarget(s *database.Scan) string {
	if s.Target != "" {
		return s.Target
	}
	switch s.ScanSource {
	case "scan-on-receive", "server-catchup":
		return "<grouped-from-ingest-stream>"
	}
	return ""
}

// classifyTarget returns a short label describing what kind of target the scan
// operates on. The scans table stores Target as a free-form string (URL,
// domain, IP, CIDR, or empty for record-triggered scans), so this classifier
// is heuristic — good enough for a summary column.
func classifyTarget(s *database.Scan) string {
	t := strings.TrimSpace(s.Target)
	if t == "" {
		if s.HTTPRecordUUID != "" || s.ScanSource == "scan-on-receive" {
			return "record"
		}
		if s.SourcePath != "" {
			return "source"
		}
		return "–"
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return "url"
	}
	if _, _, err := net.ParseCIDR(t); err == nil {
		return "cidr"
	}
	if ip := net.ParseIP(t); ip != nil {
		return "ip"
	}
	if strings.HasPrefix(t, "/") || strings.Contains(t, "\\") {
		return "file"
	}
	return "domain"
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
		return writeAgentJSON(map[string]any{
			"table":   tableName,
			"total":   total,
			"offset":  listOffset,
			"limit":   listLimit,
			"columns": headers,
			"rows":    rows,
		})
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
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	return writeAgentJSON(map[string]any{
		"project_uuid": projectUUID,
		"total":        total,
		"offset":       offset,
		"limit":        limit,
		"records":      recordViews(records, agentViewOptionsFromFlags()),
	})
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

// warnIfCapped prints a stderr hint when a listing was truncated by the row cap
// (total exceeds what was shown), so the user knows the view is partial and how
// to widen it. A no-op when nothing was cut. Written to stderr to keep piped
// stdout clean.
func warnIfCapped(shown int, total int64) {
	if total > int64(shown) {
		fmt.Fprintf(os.Stderr, "%s Output capped by --limit (%s of %s). Pass %s to show more (%s for all).\n",
			terminal.WarningSymbol(),
			terminal.BoldYellow(fmt.Sprintf("%d", shown)),
			terminal.BoldRed(fmt.Sprintf("%d", total)),
			terminal.BoldCyan("-n/--limit"),
			terminal.BoldCyan("-n 0"))
	}
}

// displayTree renders the queried HTTP records as a database → host → path →
// request tree. The database path is the root node; each level's connectors are
// composed from its ancestors' prefixes (via treeBranch) so the vertical guide
// lines stay aligned all the way down. Under --glob-db there is one db-path root
// per merged source file so each record's origin is visible.
func displayTree(records []*database.HTTPRecord) error {
	for _, root := range splitRecordsBySource(records) {
		fmt.Println(terminal.Bold(root.label))
		renderRecordHostTree(root.records)
	}
	return nil
}

// recordRoot is one traffic-tree root: a db-path label and the records under it.
type recordRoot struct {
	label   string
	records []*database.HTTPRecord
}

// splitRecordsBySource groups records into per-root blocks: a single root (the
// DB path) for a plain read, or one root per --glob-db source file (in merge
// order) so each record is shown beneath the database it came from. Records that
// can't be attributed fall back to a shared root.
func splitRecordsBySource(records []*database.HTTPRecord) []recordRoot {
	if globDBMergedCount() == 0 {
		return []recordRoot{{label: displayDBPath(), records: records}}
	}
	byFile := make(map[string][]*database.HTTPRecord)
	var unattributed []*database.HTTPRecord
	for _, rec := range records {
		if file := globSourceForRecord(rec.UUID); file != "" {
			byFile[file] = append(byFile[file], rec)
		} else {
			unattributed = append(unattributed, rec)
		}
	}
	var roots []recordRoot
	for _, s := range globDBSources {
		if rs := byFile[s.file]; len(rs) > 0 {
			roots = append(roots, recordRoot{label: terminal.ShortenHome(s.file), records: rs})
		}
	}
	if len(unattributed) > 0 {
		roots = append(roots, recordRoot{label: displayDBPath(), records: unattributed})
	}
	return roots
}

// renderRecordHostTree prints the host → path → request subtree beneath an
// already-printed root line.
func renderRecordHostTree(records []*database.HTTPRecord) {
	// Group records by host, preserving first-seen order for stable output.
	hostKeys, hostMap := groupTreeRecords(records, func(rec *database.HTTPRecord) string {
		return fmt.Sprintf("%s://%s:%d", rec.Scheme, rec.Hostname, rec.Port)
	})

	for hi, hostKey := range hostKeys {
		hostRecords := hostMap[hostKey]
		hostConnector, hostChildBar := treeBranch(hi == len(hostKeys)-1)

		fmt.Printf("%s%s %s\n",
			hostConnector,
			terminal.BoldCyan(hostKey),
			terminal.BoldMagenta(fmt.Sprintf("(%d records)", len(hostRecords))))

		// Group by first path segment, preserving first-seen order.
		pathKeys, pathMap := groupTreeRecords(hostRecords, func(rec *database.HTTPRecord) string {
			pathParts := strings.Split(rec.Path, "/")
			if len(pathParts) > 1 && pathParts[1] != "" {
				return "/" + pathParts[1]
			}
			return "/"
		})

		for pi, pathPrefix := range pathKeys {
			pathRecords := pathMap[pathPrefix]
			pathConnector, pathChildBar := treeBranch(pi == len(pathKeys)-1)

			fmt.Printf("%s%s%s\n", hostChildBar, pathConnector, pathPrefix)

			reqPrefix := hostChildBar + pathChildBar
			for reqIndex, rec := range pathRecords {
				reqConnector, _ := treeBranch(reqIndex == len(pathRecords)-1)

				fmt.Printf("%s%s%s %s%s\n",
					reqPrefix,
					reqConnector,
					terminal.Cyan(rec.Method),
					terminal.White(rec.Path),
					treeRecordSuffix(rec))
			}
		}
	}
}

// groupTreeRecords buckets records by key(rec) while preserving the order in
// which each distinct key first appears, so the tree is deterministic and
// reflects record order rather than Go's random map iteration.
func groupTreeRecords(records []*database.HTTPRecord, key func(*database.HTTPRecord) string) ([]string, map[string][]*database.HTTPRecord) {
	var order []string
	groups := make(map[string][]*database.HTTPRecord)
	for _, rec := range records {
		k := key(rec)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rec)
	}
	return order, groups
}

// treeRecordSuffix renders the response summary shown after a request line in
// the tree (status, timing/size, content-type, title, risk score).
func treeRecordSuffix(rec *database.HTTPRecord) string {
	if !rec.HasResponse {
		return ""
	}

	statusColor := terminal.Green
	if rec.StatusCode >= 400 {
		statusColor = terminal.Yellow
	}
	if rec.StatusCode >= 500 {
		statusColor = terminal.Red
	}
	suffix := fmt.Sprintf(" %s %s %s",
		terminal.BoldMagenta("→"),
		statusColor(fmt.Sprintf("%d", rec.StatusCode)),
		terminal.Gray(fmt.Sprintf("(%dms, %dB, %dW)", rec.ResponseTimeMs, rec.ResponseContentLength, rec.ResponseWords)))

	if rec.ResponseContentType != "" {
		suffix += " " + terminal.Orange(shortContentType(rec.ResponseContentType))
	}

	if rec.ResponseTitle != "" {
		suffix += " " + terminal.Cyan(fmt.Sprintf("%q", clicommon.Truncate(rec.ResponseTitle, 40)))
	}

	if rec.RiskScore > 0 {
		suffix += " " + terminal.BoldYellow(fmt.Sprintf("[risk_score:%d]", rec.RiskScore))
	}

	return suffix
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
			clicommon.Truncate(host, 30),
			rec.Method,
			clicommon.Truncate(rec.Path, 40),
			status,
			responseTime,
			size,
			words,
			clicommon.Truncate(rec.ResponseContentType, 25),
			clicommon.Truncate(rec.ResponseTitle, 30),
			risk,
		)
	}

	tbl.Print()
	fmt.Println()
	return nil
}

func colorModuleType(t string) string {
	switch strings.ToLower(t) {
	case "active":
		return terminal.BoldGreen(t)
	case "passive":
		return terminal.BoldCyan(t)
	default:
		return t
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
