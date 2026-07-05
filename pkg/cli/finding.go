package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	// Shared filter flags for finding command
	findingHost          string
	findingMethods       []string
	findingStatus        []int
	findingPath          string
	findingFrom          string
	findingTo            string
	findingSearch        []string
	findingHeader        string
	findingBody          string
	findingSource        string
	findingSort          string
	findingAsc           bool
	findingLimit         int
	findingOffset        int
	findingSeverity      string
	findingMinSeverity   string
	findingConfidence    string
	findingScanUUID      string
	findingAgenticScan   string
	findingModuleType    string
	findingFindingSource string
	findingID            int

	// Display-only flags
	findingRaw         bool
	findingBurp        bool
	findingTree        bool
	findingMarkdown    bool
	findingWithRecords bool
	findingColumns     []string
	findingExclude     []string
	findingPick        string
)

// findingColumnDef defines a displayable column for the findings table.
type findingColumnDef struct {
	name    string // key used by --columns/--exclude-columns
	header  string // optional display header; falls back to name when empty
	extract func(*database.Finding) string
	maxLen  int
}

var allFindingColumns = []findingColumnDef{
	{"ID", "", func(f *database.Finding) string { return fmt.Sprintf("%d", f.ID) }, 6},
	{"SEVERITY", "", func(f *database.Finding) string { return clicommon.ColorSeverity(f.Severity) }, 10},
	{"CONFIDENCE", "", func(f *database.Finding) string { return clicommon.ColorConfidence(f.Confidence) }, 10},
	{"MODULE", "", func(f *database.Finding) string { return clicommon.Truncate(f.ModuleName, 30) }, 30},
	{"MODULE_ID", "", func(f *database.Finding) string { return clicommon.Truncate(f.ModuleID, 30) }, 30},
	{"SHORT_DESC", "", func(f *database.Finding) string { return clicommon.Truncate(f.ModuleShort, 40) }, 40},
	{"DESCRIPTION", "", func(f *database.Finding) string { return clicommon.Truncate(f.Description, 50) }, 50},
	{"TYPE", "", func(f *database.Finding) string { return colorModuleType(f.ModuleType) }, 12},
	{"SOURCE", "", func(f *database.Finding) string { return f.FindingSource }, 20},
	{"HOST_REPO", "URL / REPO NAME", func(f *database.Finding) string {
		if f.RepoName != "" {
			return clicommon.Truncate(f.RepoName, 60)
		}
		return clicommon.Truncate(findingURLValue(f), 60)
	}, 60},
	{"MATCHED_AT", "", func(f *database.Finding) string {
		return clicommon.Truncate(strings.Join(f.MatchedAt, ", "), 50)
	}, 50},
	{"FOUND_AT", "", func(f *database.Finding) string {
		return f.FoundAt.Format("2006-01-02 15:04")
	}, 16},
	{"SCAN_UUID", "", func(f *database.Finding) string {
		if len(f.ScanUUID) > 8 {
			return f.ScanUUID[:8]
		}
		return f.ScanUUID
	}, 8},
	{"TAGS", "", func(f *database.Finding) string {
		return clicommon.Truncate(strings.Join(f.Tags, ", "), 30)
	}, 30},
}

var defaultFindingColumnNames = []string{"ID", "SEVERITY", "CONFIDENCE", "MODULE", "SHORT_DESC", "TYPE", "SOURCE", "HOST_REPO", "MATCHED_AT"}

var findingCmd = &cobra.Command{
	Use:     "finding [search-term]",
	Aliases: []string{"findings"},
	Short:   "Browse vulnerability findings with fuzzy search and filtering",
	Long:    "Browse stored vulnerability findings with fuzzy search, raw display, tree view, and column selection.",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runFinding,
}

func init() {
	rootCmd.AddCommand(findingCmd)
	findingCmd.AddCommand(findingLoadCmd)

	// Filter flags
	pf := findingCmd.PersistentFlags()
	pf.StringVar(&findingHost, "host", "", "Filter by hostname pattern (wildcard supported)")
	pf.StringSliceVar(&findingMethods, "method", nil, "Filter by HTTP method (repeatable)")
	pf.IntSliceVar(&findingStatus, "status", nil, "Filter by HTTP status code (repeatable)")
	pf.StringVar(&findingPath, "path", "", "Filter by URL path pattern")
	pf.StringVar(&findingFrom, "from", "", "Show findings after this date (YYYY-MM-DD or RFC3339)")
	pf.StringVar(&findingTo, "to", "", "Show findings before this date (YYYY-MM-DD or RFC3339)")
	pf.StringArrayVar(&findingSearch, "search", nil, "Search across module name, short description, description, module ID, and matched_at (repeatable; each term further narrows, AND-combined)")
	pf.StringVar(&findingHeader, "header", "", "Search within HTTP header names and values")
	pf.StringVar(&findingBody, "body", "", "Search within HTTP request/response body content")
	pf.StringVar(&findingSource, "source", "", "Filter by record source (e.g. scanner, ingest-cli)")
	pf.StringVar(&findingSort, "sort", "found_at", "Sort by: found_at, created_at, severity, module, confidence")
	pf.BoolVar(&findingAsc, "asc", false, "Sort in ascending order (default: descending)")
	pf.IntVarP(&findingLimit, "limit", "n", 100, "Maximum findings to display")
	pf.IntVar(&findingOffset, "offset", 0, "Number of findings to skip (for pagination)")

	// Finding-specific filter flags
	pf.StringVar(&findingSeverity, "severity", "", "Filter by severity: critical,high,medium,low,info (comma-separated)")
	pf.StringVar(&findingMinSeverity, "min-severity", "", "Filter by minimum severity (e.g. high → high+critical); ignored when --severity is set")
	pf.StringVar(&findingConfidence, "confidence", "", "Filter by confidence: certain,firm,tentative (comma-separated)")
	pf.StringVar(&findingScanUUID, "scan-uuid", "", "Filter by scan UUID")
	pf.StringVar(&findingAgenticScan, "agentic-scan", "", "Filter by agentic-scan UUID (findings produced by an agent autopilot/swarm/audit run)")
	pf.StringVar(&findingModuleType, "module-type", "", "Filter by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension)")
	pf.StringVar(&findingFindingSource, "finding-source", "", "Filter by finding source (dynamic-assessment, spa, agent, oast, source-tools, extension)")
	pf.IntVar(&findingID, "id", 0, "Filter by finding ID")

	// Display-only flags
	f := findingCmd.Flags()
	f.BoolVar(&findingRaw, "raw", false, "Show full raw HTTP request and response for each finding")
	f.BoolVar(&findingBurp, "burp", false, "Display in Burp Suite-style format (colored request/response)")
	f.BoolVar(&findingTree, "tree", false, "Display as a host/path hierarchy tree; repeated titles collapse into one node with each affected URL listed below")
	f.BoolVar(&findingMarkdown, "markdown", false, "Render the matched findings as Markdown (evidence + request/response in fenced http blocks) to stdout; response bodies are compacted to a preview by default (use --full-body for whole bodies)")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
	f.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
	f.BoolVar(&findingWithRecords, "with-records", false, "With --json: resolve and embed the linked HTTP records (self-contained triage bundle)")
	f.StringSliceVar(&findingColumns, "columns", nil, "Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE)")
	f.StringSliceVar(&findingExclude, "exclude-columns", nil, "Columns to hide (comma-separated)")
	f.StringVar(&findingPick, "pick", "", "Select finding(s) by 1-based position in the result list (e.g. 2, 1,3, 2-4); applied after --search/filters and sort")
	registerAgentJSONFlags(f)
	tui.AddFlags(findingCmd, &findingTUIFlag, &findingNoTUIFlag)
}

func runFinding(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := openReadDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	var fuzzyTerm string
	// Argument routing mirrors traffic: "tree" activates tree mode, "ls"/"list"
	// are no-ops (default table view), anything else is a fuzzy search term.
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "tree":
			findingTree = true
		case "ls", "list":
			// no-op — default table view
		default:
			fuzzyTerm = args[0]
		}
	}

	return runWithWatch(func() error {
		filters, err := buildFindingFilters(fuzzyTerm)
		if err != nil {
			return err
		}

		ctx := context.Background()

		// --agentic-scan expands to the whole scan tree (parent + nested audit
		// driver legs / swarm sub-runs) so one UUID returns every linked finding.
		if findingAgenticScan != "" {
			filters.AgenticScanUUIDs = resolveAgenticScanTree(ctx, db, findingAgenticScan)
		}
		fqb := database.NewFindingsQueryBuilder(db, filters)
		findings, total, err := fqb.ExecuteWithCount(ctx)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}

		// --pick narrows the fetched page to specific 1-based positions (after
		// filters + sort). Applied here — before any display path — so it composes
		// with --raw/--burp/--markdown/--json/--tui alike. The picked findings
		// become the result set: total and offset are normalized together so the
		// "Showing X of Y" summary and JSON stay internally consistent (otherwise
		// a leftover non-zero --offset would desync into e.g. "Showing 11-1 of 1").
		if findingPick != "" {
			picked, perr := selectFindingsByPosition(findings, findingPick)
			if perr != nil {
				return perr
			}
			findings = picked
			total = int64(len(findings))
			findingOffset = 0
		}

		if active, tuiErr := tui.Active(findingTUIFlag, findingNoTUIFlag, globalJSON); tuiErr != nil {
			return tuiErr
		} else if active {
			if len(findings) == 0 {
				fmt.Printf("%s No findings found.\n", terminal.InfoSymbol())
				return nil
			}
			return pickFindingTUI(ctx, db, findings, total)
		}

		if globalJSON {
			return displayFindingsJSON(ctx, db, findings, total, filters.ProjectUUID)
		} else if findingMarkdown {
			return displayFindingsMarkdown(ctx, db, findings)
		} else if findingBurp {
			return displayFindingsBurp(db, ctx, findings)
		} else if findingRaw {
			return displayFindingsRaw(db, ctx, findings)
		} else if findingTree {
			return displayFindingTree(db, ctx, findings, total)
		}
		return findingDisplayTable(db, ctx, findings, total)
	})
}

// selectFindingsByPosition narrows findings to the 1-based positions named by
// spec — a comma list of single indices and A-B ranges (e.g. "2", "1,3",
// "2-4"). Positions index into the already-filtered, already-sorted result
// list; input order is preserved as written and duplicates are collapsed.
// Out-of-range positions are warned about on stderr and skipped; a spec that
// selects nothing from a non-empty list is an error naming the valid range.
func selectFindingsByPosition(findings []*database.Finding, spec string) ([]*database.Finding, error) {
	n := len(findings)
	if n == 0 {
		return findings, nil
	}

	positions, err := parsePositionSpec(spec)
	if err != nil {
		return nil, err
	}

	// Both collections hold at most one entry per distinct in-range position, so
	// they can never exceed n — size to that, not to len(positions), which the
	// spec can inflate well past the page size.
	sizeHint := min(len(positions), n)
	seen := make(map[int]bool, sizeHint)
	picked := make([]*database.Finding, 0, sizeHint)
	var outOfRange []int
	for _, p := range positions {
		if p < 1 || p > n {
			outOfRange = append(outOfRange, p)
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		picked = append(picked, findings[p-1])
	}

	if len(outOfRange) > 0 {
		fmt.Fprintf(os.Stderr, "%s --pick: position(s) %s out of range (valid: 1-%d)\n",
			terminal.WarningSymbol(), summarizeInts(outOfRange, 10), n)
	}
	if len(picked) == 0 {
		return nil, fmt.Errorf("--pick %q selected no findings (valid range: 1-%d)", spec, n)
	}
	return picked, nil
}

// maxPickPositions caps how many positions a --pick spec may expand to. A
// selection can never usefully exceed the result page (bounded by --limit), so
// this rejects a fat-fingered range like "1-1000000" up front instead of
// eagerly allocating millions of throwaway ints.
const maxPickPositions = 10000

// parsePositionSpec parses a comma list of 1-based positions and A-B ranges
// (e.g. "2", "1,3", "2-4") into a flat, ordered slice. It validates syntax and
// 1-based positivity but not against any result-set length, and bounds the
// total expansion at maxPickPositions.
func parsePositionSpec(spec string) ([]int, error) {
	// parsePos parses one 1-based index; the caller wraps the error with the
	// offending token so the single-index and range paths share one validation.
	parsePos := func(s string) (int, error) {
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return 0, err
		}
		if v < 1 {
			return 0, fmt.Errorf("positions are 1-based")
		}
		return v, nil
	}

	var positions []int
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if lo, hi, isRange := strings.Cut(tok, "-"); isRange {
			a, err := parsePos(lo)
			if err != nil {
				return nil, fmt.Errorf("invalid --pick range %q: %v", tok, err)
			}
			b, err := parsePos(hi)
			if err != nil {
				return nil, fmt.Errorf("invalid --pick range %q: %v", tok, err)
			}
			if a > b {
				return nil, fmt.Errorf("invalid --pick range %q: start must be <= end", tok)
			}
			if b-a+1 > maxPickPositions {
				return nil, fmt.Errorf("invalid --pick range %q: spans more than %d positions", tok, maxPickPositions)
			}
			for i := a; i <= b; i++ {
				positions = append(positions, i)
			}
		} else {
			v, err := parsePos(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid --pick position %q: %v", tok, err)
			}
			positions = append(positions, v)
		}
		if len(positions) > maxPickPositions {
			return nil, fmt.Errorf("--pick: too many positions (max %d)", maxPickPositions)
		}
	}
	if len(positions) == 0 {
		return nil, fmt.Errorf("--pick: no positions given")
	}
	return positions, nil
}

// summarizeInts renders nums as a comma-separated string, truncating to the
// first max entries with a "(+N more)" suffix so an oversized spec can't dump a
// huge warning line.
func summarizeInts(nums []int, max int) string {
	shown := nums
	suffix := ""
	if len(nums) > max {
		shown = nums[:max]
		suffix = fmt.Sprintf(" (+%d more)", len(nums)-max)
	}
	parts := make([]string, len(shown))
	for i, v := range shown {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ") + suffix
}

func buildFindingFilters(fuzzyTerm string) (database.QueryFilters, error) {
	var dateFrom, dateTo *time.Time
	if findingFrom != "" {
		t, err := clicommon.ParseDate(findingFrom)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if findingTo != "" {
		t, err := clicommon.ParseDate(findingTo)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if findingSeverity != "" {
		severities = strings.Split(findingSeverity, ",")
	} else if findingMinSeverity != "" {
		severities = severitiesAtOrAbove(findingMinSeverity)
		if severities == nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --min-severity %q (want one of: %s)", findingMinSeverity, strings.Join(severityOrder, ", "))
		}
	}

	var confidences []string
	if findingConfidence != "" {
		for _, c := range strings.Split(findingConfidence, ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
				confidences = append(confidences, c)
			}
		}
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}

	return database.QueryFilters{
		ProjectUUID:   projectUUID,
		FindingID:     findingID,
		HostPattern:   findingHost,
		Methods:       findingMethods,
		StatusCodes:   findingStatus,
		PathPattern:   findingPath,
		Source:        findingSource,
		ScanUUID:      findingScanUUID,
		Severity:      severities,
		Confidence:    confidences,
		ModuleType:    findingModuleType,
		FindingSource: findingFindingSource,
		DateFrom:      dateFrom,
		DateTo:        dateTo,
		FuzzyTerm:     fuzzyTerm,
		SearchTerms:   findingSearch,
		HeaderSearch:  findingHeader,
		BodySearch:    findingBody,
		Limit:         findingLimit,
		Offset:        findingOffset,
		SortBy:        findingSort,
		SortAsc:       findingAsc,
	}, nil
}

func displayFindingsJSON(ctx context.Context, db *database.DB, findings []*database.Finding, total int64, projectUUID string) error {
	opts := agentViewOptionsFromFlags()
	return writeAgentJSON(map[string]any{
		"project_uuid": projectUUID,
		"total":        total,
		"offset":       findingOffset,
		"limit":        findingLimit,
		"findings":     findingViews(ctx, db, findings, opts, findingWithRecords),
	})
}

// displayFindingsBurp shows findings with their associated HTTP records in Burp-style format.
func displayFindingsBurp(db *database.DB, ctx context.Context, findings []*database.Finding) error {
	// Fetch every referenced record in one query instead of one per finding.
	byUUID := batchLoadFindingRecords(ctx, db, findings)
	for i, f := range findings {
		if i > 0 {
			fmt.Println(terminal.Gray(burpDivider))
		}

		// Finding header
		fmt.Printf("%s %s [%s] %s\n",
			terminal.InfoSymbol(),
			clicommon.ColorSeverity(f.Severity),
			terminal.Cyan(f.ModuleName),
			f.ModuleShort)
		if len(f.MatchedAt) > 0 {
			fmt.Printf("  Matched at: %s\n", terminal.Gray(strings.Join(f.MatchedAt, ", ")))
		}
		fmt.Println()

		// Show associated HTTP records
		records := recordsForFinding(byUUID, f)
		for _, rec := range records {
			printBurpRequest(rec.RawRequest)
			fmt.Println(terminal.Gray("---"))
			if rec.HasResponse && len(rec.RawResponse) > 0 {
				printBurpResponse(rec.RawResponse, rec.StatusCode)
			} else {
				fmt.Println(terminal.Gray("(no response)"))
			}
		}
		if len(records) == 0 {
			fmt.Println(terminal.Gray("(no associated HTTP records)"))
		}
	}
	return nil
}

// displayFindingsRaw shows findings with their associated HTTP records in raw format.
func displayFindingsRaw(db *database.DB, ctx context.Context, findings []*database.Finding) error {
	// Fetch every referenced record in one query instead of one per finding.
	byUUID := batchLoadFindingRecords(ctx, db, findings)
	for _, f := range findings {
		fmt.Println("──────────────────────────────────────────────────────────────────")
		fmt.Printf("Finding #%d - %s [%s] %s\n", f.ID, clicommon.ColorSeverity(f.Severity), f.ModuleName, f.ModuleShort)
		if f.Description != "" {
			fmt.Printf("Description: %s\n", f.Description)
		}
		if len(f.MatchedAt) > 0 {
			fmt.Printf("Matched at:  %s\n", strings.Join(f.MatchedAt, ", "))
		}
		fmt.Printf("Confidence:  %s  |  Source: %s  |  Found: %s\n",
			f.Confidence, f.FindingSource, f.FoundAt.Format("2006-01-02 15:04:05"))
		fmt.Println("──────────────────────────────────────────────────────────────────")

		records := recordsForFinding(byUUID, f)
		for _, rec := range records {
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
		}
		if len(records) == 0 {
			// Fall back to inline request/response stored on the finding itself
			if f.Request != "" {
				fmt.Println()
				fmt.Println(f.Request)
			}
			if f.Response != "" {
				fmt.Println()
				fmt.Println("──────────────────────────────────────────────────────────────────")
				fmt.Println("Response")
				fmt.Println("──────────────────────────────────────────────────────────────────")
				fmt.Println()
				fmt.Println(f.Response)
			}
		}
		fmt.Println()
	}
	return nil
}

// loadFindingRecords fetches the HTTP records associated with a single finding.
// Prefer batchLoadFindingRecords + recordsForFinding when rendering many
// findings to avoid an N+1 round-trip; this single-finding form is for callers
// that already operate on one finding at a time.
func loadFindingRecords(ctx context.Context, repo *database.Repository, f *database.Finding) []*database.HTTPRecord {
	if len(f.HTTPRecordUUIDs) == 0 {
		return nil
	}
	records, err := repo.GetRecordsByUUIDs(ctx, f.HTTPRecordUUIDs)
	if err != nil {
		return nil
	}
	return records
}

// recordsForFinding resolves a finding's linked records from a pre-fetched
// byUUID map (see batchLoadFindingRecords), preserving the finding's UUID order
// and skipping any that weren't loaded.
func recordsForFinding(byUUID map[string]*database.HTTPRecord, f *database.Finding) []*database.HTTPRecord {
	if len(f.HTTPRecordUUIDs) == 0 {
		return nil
	}
	records := make([]*database.HTTPRecord, 0, len(f.HTTPRecordUUIDs))
	for _, u := range f.HTTPRecordUUIDs {
		if r := byUUID[u]; r != nil {
			records = append(records, r)
		}
	}
	return records
}

// printFindingsSummary prints the "Showing X-Y of Z findings" line plus the
// project-wide severity and confidence breakdown. Shared by the default table
// view and the tree view so both surface the same totals.
func printFindingsSummary(db *database.DB, ctx context.Context, shown int, total int64) {
	// Stateless counts across the whole file (effectiveProjectUUID returns "").
	projectUUID, _ := effectiveProjectUUID()

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
		findingOffset+1,
		min(findingOffset+shown, int(total)),
		total)
	if sevLine != "" {
		fmt.Printf("  %s Severity:  %s\n", terminal.Cyan(terminal.SymbolSparkle), sevLine)
	}
	if confLine != "" {
		fmt.Printf("  %s Confidence:%s\n", terminal.Cyan(terminal.SymbolSparkle2), confLine)
	}
	fmt.Println()
}

func findingDisplayTable(db *database.DB, ctx context.Context, findings []*database.Finding, total int64) error {
	printFindingsSummary(db, ctx, len(findings), total)

	cols := resolveFindingColumns(findingColumns, findingExclude)
	if len(cols) == 0 {
		return fmt.Errorf("no columns selected")
	}

	headers := make([]string, len(cols))
	weights := make([]int, len(cols))
	for i, c := range cols {
		if c.header != "" {
			headers[i] = c.header
		} else {
			headers[i] = c.name
		}
		weights[i] = c.maxLen
	}

	tbl := terminal.NewTableFullWidthWeighted(terminal.TerminalWidth(), weights, headers...)
	for _, f := range findings {
		vals := make([]any, len(cols))
		for i, c := range cols {
			vals[i] = c.extract(f)
		}
		tbl.AddRow(vals...)
	}
	tbl.Print()
	fmt.Println()
	return nil
}

// findingURLValue returns the best URL for a finding, preferring the
// denormalized URL and falling back to the first MatchedAt entry so legacy
// rows without a URL still render.
func findingURLValue(f *database.Finding) string {
	if f.URL != "" {
		return f.URL
	}
	if len(f.MatchedAt) > 0 {
		return f.MatchedAt[0]
	}
	return f.Hostname
}

// resolveFindingColumns selects columns based on --columns and --exclude-columns flags.
func resolveFindingColumns(include, exclude []string) []findingColumnDef {
	colMap := make(map[string]findingColumnDef, len(allFindingColumns))
	for _, c := range allFindingColumns {
		colMap[c.name] = c
	}

	if len(include) > 0 {
		var cols []findingColumnDef
		for _, name := range include {
			name = strings.ToUpper(strings.TrimSpace(name))
			if c, ok := colMap[name]; ok {
				cols = append(cols, c)
			}
		}
		if len(cols) > 0 {
			return cols
		}
	}

	var cols []findingColumnDef
	for _, name := range defaultFindingColumnNames {
		if c, ok := colMap[name]; ok {
			cols = append(cols, c)
		}
	}

	if len(exclude) > 0 {
		excludeSet := make(map[string]bool, len(exclude))
		for _, name := range exclude {
			excludeSet[strings.ToUpper(strings.TrimSpace(name))] = true
		}
		var filtered []findingColumnDef
		for _, c := range cols {
			if !excludeSet[c.name] {
				filtered = append(filtered, c)
			}
		}
		return filtered
	}

	return cols
}
