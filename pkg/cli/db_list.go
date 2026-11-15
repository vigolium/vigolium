package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

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
	listUUIDs    []string
	listURLs     []string
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
	listMinRisk    int
	listMinSurface int
	listRemark     string

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
	registerJSONOutputFlag(cmd)

	// Filter flags
	cmd.Flags().StringSliceVar(&listUUIDs, "uuid", nil,
		"Select exact stored record(s) by UUID or unique 8+ char prefix (repeatable/comma-separated). Applied before pagination")
	cmd.Flags().StringArrayVar(&listURLs, "url", nil,
		"Select records whose URL matches EXACTLY (repeatable; OR-ed). Compared against the stored URL with no normalization — use --path or --search for substring matching")
	cmd.Flags().StringVar(&listHost, "host", "", "Filter records by hostname pattern (wildcard supported)")
	cmd.Flags().StringSliceVar(&listMethods, "method", nil, "Filter records by HTTP method (can be specified multiple times)")
	cmd.Flags().IntSliceVar(&listStatus, "status", nil, "Filter records by HTTP status code (can be specified multiple times)")
	cmd.Flags().StringVar(&listPath, "path", "", "Filter records by URL path pattern")
	cmd.Flags().StringVar(&listScanUUID, "scan-uuid", "", "Filter records by scan UUID")
	cmd.Flags().StringVar(&listSeverity, "severity", "", "Filter findings by severity: critical,high,medium,low,suspect,info (comma-separated; single-letter shorthands ok, e.g. 'h,c')")
	cmd.Flags().IntVar(&listMinRisk, "min-risk", 0, "Show only records with risk score at or above this value")
	cmd.Flags().IntVar(&listMinSurface, "min-surface", 0, "Show only records with attack-surface score at or above this value (0-100, percent of the attack-surface signals present)")
	cmd.Flags().StringVar(&listRemark, "remark", "", "Filter records containing this text in remarks")
	cmd.Flags().StringVar(&listModuleType, "module-type", "", "Filter findings by module type (active, passive, nuclei, agent, source-tools, oast, extension)")
	cmd.Flags().StringVar(&listFindingSource, "finding-source", "", "Filter findings by source (dynamic-assessment, spa, agent, oast, source-tools, extension)")
	cmd.Flags().StringVar(&listRecordKind, "record-kind", "", "Filter by record kind (finding, candidate, observation; comma-separated). Default: finding")

	// Date range flags
	cmd.Flags().StringVar(&listFrom, "from", "", fmt.Sprintf("Show records at or after this time — %s (alias: --since)", clicommon.TimeFilterSyntax))
	cmd.Flags().StringVar(&listTo, "to", "", fmt.Sprintf("Show records at or before this time — %s; %s (alias: --until)", clicommon.TimeFilterSyntax, clicommon.TimeFilterUpperBoundNote))

	// Search flags
	cmd.Flags().StringVar(&listHeader, "header", "", "Search only the HTTP header block of the request/response (not bodies); use --search to span the whole exchange")
	cmd.Flags().StringVar(&listBody, "body", "", "Search only the HTTP request/response body (not headers); use --search to span the whole exchange")

	// Sorting flags
	cmd.Flags().StringVar(&listSort, "sort", "created_at", "Sort results by field: uuid, created_at, sent_at, method, status_code, response_time, risk_score, surface_score")
	cmd.Flags().BoolVar(&listAsc, "asc", false, "Sort in ascending order instead of descending")

	addFlagAliases(cmd, timeFilterAliases)
}

func runDBList(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// openReadDB, not getDB: `db ls` is a read command, and it was the one that
	// accepted -S without requiring a source. getDB opened the DEFAULT project
	// database, and then effectiveProjectUUID — seeing a stateless read — dropped
	// the project filter, so `db ls findings -S` listed every project's rows in
	// the operator's own store while reading like a scoped read of a standalone
	// file. Going through the shared opener also makes a JSONL export a valid
	// source here, as it already is for finding and traffic.
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Handle --list-tables: show all table names and exit (no watch)
	if listTables {
		return runListTables(context.Background(), cmd, db)
	}

	// Resolve the target table from the positional arg (primary) / --table alias.
	tableName, err := resolveDBListTable(args)
	if err != nil {
		return err
	}

	// Handle --list-columns: show columns for the table and exit (no watch)
	if listColumnNames {
		return runListColumns(context.Background(), cmd, db, tableName)
	}

	// Validate --fields against the view this table will actually render. The
	// scans and generic-table paths emit raw rows whose vocabulary is the table's
	// own column set rather than a curated view, so each validates against that
	// set at its own call site (runListScans via projectTypedViews,
	// runListGenericTable against the headers it already has in hand).
	switch tableName {
	case "http_records":
		if err := validateAgentViewFlags(agentViewOptionsFromFlags(), trafficViewFields); err != nil {
			return err
		}
	case "findings":
		if err := validateAgentViewFlags(agentViewOptionsFromFlags(), findingViewFields); err != nil {
			return err
		}
	}
	// Outside the switch, because --max-output-bytes shapes every table's
	// document, including the two whose --fields are validated elsewhere. The
	// curated-view cases above check it too; running it twice costs nothing and
	// is cheaper than a third place for a new table to forget.
	if err := validateOutputBudgetFlag(globalJSON); err != nil {
		return err
	}
	if err := validateJSONOutputFlag(cmd); err != nil {
		return err
	}

	return runWithWatch(func() error {
		ctx := context.Background()

		// For non-default tables, use generic query
		switch tableName {
		case "http_records":
			return runListHTTPRecords(ctx, cmd, db)
		case "findings":
			return runListFindings(ctx, cmd, db)
		case "scans":
			return runListScans(ctx, cmd, db)
		default:
			return runListGenericTable(ctx, cmd, db, tableName)
		}
	})
}

// runListTables displays all table names in the database.
func runListTables(ctx context.Context, cmd *cobra.Command, db *database.DB) error {
	tables, err := database.ListTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to list tables: %w", err)
	}

	// Schema discovery is the one surface an agent reaches for BEFORE it knows
	// anything about the store, so it emitting ANSI-colored text on stdout under
	// -j was the worst possible exception to the machine contract.
	if globalJSON {
		env := newMachineEnvelope(cmd, kindRead, "rows", tables, int64(len(tables)), 0, len(tables))
		env.DBPath = resolvedReadDBPath()
		env.WithQuery("db", "ls", "<table>", "--json")
		return writeAgentJSON(env)
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
func runListColumns(ctx context.Context, cmd *cobra.Command, db *database.DB, tableName string) error {
	columns, err := database.ListColumns(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to list columns for %q: %w", tableName, err)
	}

	if globalJSON {
		env := newMachineEnvelope(cmd, kindRead, "rows", columns, int64(len(columns)), 0, len(columns))
		env.DBPath = resolvedReadDBPath()
		env.With("table", tableName)
		return writeAgentJSON(env)
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
func runListHTTPRecords(ctx context.Context, cmd *cobra.Command, db *database.DB) error {
	dateFrom, dateTo, err := parseDateRangeFlags(listFrom, listTo,
		timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return err
	}

	var severities []string
	if listSeverity != "" {
		if severities, err = parseSeverityList(listSeverity); err != nil {
			return err
		}
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	// --uuid takes unique prefixes, resolved to exact identity before the query.
	recordUUIDs, err := resolveRecordRefs(ctx, database.NewRepository(db), listUUIDs, projectUUID)
	if err != nil {
		return err
	}

	filters := database.QueryFilters{
		ProjectUUID:     projectUUID,
		RecordUUIDs:     recordUUIDs,
		URLsExact:       listURLs,
		HostPattern:     listHost,
		ScanUUID:        listScanUUID,
		Methods:         listMethods,
		StatusCodes:     listStatus,
		PathPattern:     listPath,
		Severity:        severities,
		MinRiskScore:    listMinRisk,
		MinSurfaceScore: listMinSurface,
		Remark:          listRemark,
		DateFrom:        dateFrom,
		DateTo:          dateTo,
		SearchTerm:      dbSearch,
		HeaderSearch:    listHeader,
		BodySearch:      listBody,
		Limit:           listLimit,
		Offset:          listOffset,
		SortBy:          listSort,
		SortAsc:         listAsc,
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
		return displayJSON(ctx, cmd, db, records, total, listOffset, listLimit)
	} else if listRaw {
		return displayRaw(records)
	} else if listTree {
		return displayTree(ctx, db, records)
	} else {
		return displayTable(records, total, listOffset, listLimit)
	}
}

// runListFindings handles the findings table listing.
func runListFindings(ctx context.Context, cmd *cobra.Command, db *database.DB) error {
	dateFrom, dateTo, err := parseDateRangeFlags(listFrom, listTo,
		timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return err
	}

	var severities []string
	if listSeverity != "" {
		if severities, err = parseSeverityList(listSeverity); err != nil {
			return err
		}
	}

	projectUUID, err := effectiveProjectUUID()
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
		env := newMachineEnvelope(cmd, kindRead, "findings",
			findingViews(ctx, db, findings, agentViewOptionsFromFlags(), false), total, listOffset, listLimit)
		env.WithProjectScope(projectUUID)
		env.DBPath = resolvedReadDBPath()
		env.WithQuery("finding", "--json", "--with-records", "--min-severity", "medium")
		return writeAgentJSON(env)
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
func runListScans(ctx context.Context, cmd *cobra.Command, db *database.DB) error {
	repo := database.NewRepository(db)
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	scans, total, err := repo.ListScans(ctx, projectUUID, listLimit, listOffset)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	views := buildScanViews(scans)

	if globalJSON {
		// The scans path used to hand its typed views straight to the envelope,
		// so --fields was accepted and then ignored: `--fields uuid` returned all
		// 39 keys, byte-identical to no projection. A flag that parses and does
		// nothing is worse than one that does not exist.
		rows, err := projectTypedViews(views, normalizeFieldList(jsonFields))
		if err != nil {
			return err
		}
		env := newMachineEnvelope(cmd, kindRead, "scans", rows, total, listOffset, listLimit)
		env.DBPath = resolvedReadDBPath()
		return writeAgentJSON(env)
	}

	fmt.Printf("Showing %d-%d of %d scans\n\n",
		listOffset+1,
		min(listOffset+len(scans), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "TARGET", "TYPE", "SOURCE", "STATUS", "MODULES", "REQUESTS", "C/H/M/L/I/S", "DURATION")
	for _, v := range views {
		s := v.Scan
		status := scanStatusCell(s)

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

// scanStatusCell renders the STATUS column for a scan listing.
//
// A partial run reads "completed (partial)": the status is still completed — the
// scan reached its end and the vocabulary has not changed — but a listing that
// shows nothing but "completed" for a run that covered two of seven phases is
// how a curtailed scan gets mistaken for a clean baseline. An empty
// completeness is unknown (an older binary wrote the row) and renders as before.
func scanStatusCell(s *database.Scan) string {
	if s == nil {
		return ""
	}
	status := s.Status
	if status == "completed" && s.Completeness == database.CompletenessPartial {
		return terminal.Yellow("completed (partial)")
	}
	switch status {
	case "completed":
		return terminal.Green(status)
	case "running":
		return terminal.Cyan(status)
	case "failed":
		return terminal.Red(status)
	case "cancelled":
		return terminal.Yellow(status)
	}
	return status
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
func runListGenericTable(ctx context.Context, cmd *cobra.Command, db *database.DB, tableName string) error {
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
		// This path used to accept --fields and ignore it, which is the same
		// "parses and does nothing" defect the scans path was just fixed for.
		// The vocabulary here is the table's own column set, already in hand.
		fields := normalizeFieldList(jsonFields)
		if err := validateFieldSelection(fields, headers); err != nil {
			return err
		}
		projected := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			projected = append(projected, projectFields(r, fields))
		}
		env := newMachineEnvelope(cmd, kindRead, "rows", projected, total, listOffset, listLimit)
		env.DBPath = resolvedReadDBPath()
		env.With("table", tableName).With("columns", headers)
		return writeAgentJSON(env)
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

func displayJSON(ctx context.Context, cmd *cobra.Command, db *database.DB, records []*database.HTTPRecord, total int64, offset, limit int, extra ...envOpt) error {
	// effectiveProjectUUID, not resolveProjectUUID: under -S scoping is off and
	// the rows span every project, so naming one here was a false claim.
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	// No scan is named: this is a project-scoped read, so the most recent stored
	// observation per endpoint is the right answer. Without it the DNS/TLS keys
	// appeared only when THIS process happened to have probed the host and not
	// yet evicted it - so reading a database back showed nothing, and reading a
	// large sweep back showed facts for its last hosts only.
	opts := agentViewOptionsFromFlags().withHostFacts(ctx, db, projectUUID, "").withNotFound(ctx, db, projectUUID)
	env := newMachineEnvelope(cmd, kindRead, "records",
		recordViews(records, opts), total, offset, limit)
	env.WithProjectScope(projectUUID)
	env.DBPath = resolvedReadDBPath()
	// The hint from a READ is another read. It used to be `replay -u <uuid>`,
	// which re-sends the request to the target: a follow-up that a caller may be
	// running unattended, out of scope, or under a read-only remit must never be
	// one that puts traffic on the wire. Inspecting the record whole is the
	// actual next step, and --uuid now exists to express it.
	if len(records) > 0 {
		env.WithQuery("traffic", "--uuid", records[0].UUID, "--json", "--full-body")
	}
	return writeAgentJSON(applyEnvOpts(env, extra))
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
func displayTree(ctx context.Context, db *database.DB, records []*database.HTTPRecord) error {
	for _, root := range splitRecordsBySource(ctx, db, records) {
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
func splitRecordsBySource(ctx context.Context, db *database.DB, records []*database.HTTPRecord) []recordRoot {
	if globDBMergedCount() == 0 {
		return []recordRoot{{label: displayDBPath(), records: records}}
	}
	// Attribution is resolved for the rows about to be printed, not for the whole
	// merged corpus. Idempotent, so the tree's earlier redirect hydration may
	// already have covered these.
	resolveGlobRecordSources(ctx, db, records)
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
// the tree (status, timing/size, content-type, title, redirect target, scores).
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

	// Where a 3xx actually points. Without it every redirect in the tree renders
	// as an identical bodyless line and the one fact that distinguishes them —
	// the destination — is the one the reader has to re-query for.
	if loc := redirectLocation(rec); loc != "" {
		suffix += " " + terminal.BoldMagenta("↪") + " " + terminal.Blue(loc)
	}

	if rec.RiskScore > 0 {
		suffix += " " + terminal.BoldYellow(fmt.Sprintf("[risk_score:%d]", rec.RiskScore))
	}

	if rec.SurfaceScore > 0 {
		suffix += " " + terminal.BoldCyan(fmt.Sprintf("[surface:%d]", rec.SurfaceScore))
	}

	return suffix
}

func displayTable(records []*database.HTTPRecord, total int64, offset, _ int) error {
	fmt.Printf("Showing %d-%d of %d records\n\n",
		offset+1,
		min(offset+len(records), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "HOST", "METHOD", "PATH", "STATUS", "TIME", "SIZE", "WORDS", "CONTENT_TYPE", "TITLE", "RISK", "SURFACE")

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

		surface := ""
		if rec.SurfaceScore > 0 {
			surface = fmt.Sprintf("%d", rec.SurfaceScore)
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
			surface,
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
