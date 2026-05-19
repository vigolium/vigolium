package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
	findingSearch        string
	findingHeader        string
	findingBody          string
	findingSource        string
	findingSort          string
	findingAsc           bool
	findingLimit         int
	findingOffset        int
	findingSeverity      string
	findingScanUUID      string
	findingModuleType    string
	findingFindingSource string
	findingID            int

	// Display-only flags
	findingRaw     bool
	findingBurp    bool
	findingColumns []string
	findingExclude []string
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
	{"SEVERITY", "", func(f *database.Finding) string { return colorSeverity(f.Severity) }, 10},
	{"CONFIDENCE", "", func(f *database.Finding) string { return f.Confidence }, 10},
	{"MODULE", "", func(f *database.Finding) string { return truncate(f.ModuleName, 30) }, 30},
	{"MODULE_ID", "", func(f *database.Finding) string { return truncate(f.ModuleID, 30) }, 30},
	{"SHORT_DESC", "", func(f *database.Finding) string { return truncate(f.ModuleShort, 40) }, 40},
	{"DESCRIPTION", "", func(f *database.Finding) string { return truncate(f.Description, 50) }, 50},
	{"TYPE", "", func(f *database.Finding) string { return colorModuleType(f.ModuleType) }, 12},
	{"SOURCE", "", func(f *database.Finding) string { return f.FindingSource }, 20},
	{"HOST_REPO", "URL / REPO NAME", func(f *database.Finding) string {
		if f.RepoName != "" {
			return truncate(f.RepoName, 60)
		}
		return truncate(findingURLValue(f), 60)
	}, 60},
	{"MATCHED_AT", "", func(f *database.Finding) string {
		return truncate(strings.Join(f.MatchedAt, ", "), 50)
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
		return truncate(strings.Join(f.Tags, ", "), 30)
	}, 30},
}

var defaultFindingColumnNames = []string{"ID", "SEVERITY", "MODULE", "SHORT_DESC", "TYPE", "SOURCE", "HOST_REPO", "MATCHED_AT"}

var findingCmd = &cobra.Command{
	Use:     "finding [search-term]",
	Aliases: []string{"findings"},
	Short:   "Browse vulnerability findings with fuzzy search and filtering",
	Long:    "Browse stored vulnerability findings with fuzzy search, raw display, and column selection.",
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
	pf.StringVar(&findingSearch, "search", "", "Search across descriptions, module IDs, and matched_at")
	pf.StringVar(&findingHeader, "header", "", "Search within HTTP header names and values")
	pf.StringVar(&findingBody, "body", "", "Search within HTTP request/response body content")
	pf.StringVar(&findingSource, "source", "", "Filter by record source (e.g. scanner, ingest-cli)")
	pf.StringVar(&findingSort, "sort", "found_at", "Sort by: found_at, created_at, severity, module, confidence")
	pf.BoolVar(&findingAsc, "asc", false, "Sort in ascending order (default: descending)")
	pf.IntVarP(&findingLimit, "limit", "n", 100, "Maximum findings to display")
	pf.IntVarP(&findingOffset, "offset", "o", 0, "Number of findings to skip (for pagination)")

	// Finding-specific filter flags
	pf.StringVar(&findingSeverity, "severity", "", "Filter by severity: critical,high,medium,low,info (comma-separated)")
	pf.StringVar(&findingScanUUID, "scan-uuid", "", "Filter by scan UUID")
	pf.StringVar(&findingModuleType, "module-type", "", "Filter by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension)")
	pf.StringVar(&findingFindingSource, "finding-source", "", "Filter by finding source (dynamic-assessment, spa, agent, oast, source-tools, extension)")
	pf.IntVar(&findingID, "id", 0, "Filter by finding ID")

	// Display-only flags
	f := findingCmd.Flags()
	f.BoolVar(&findingRaw, "raw", false, "Show full raw HTTP request and response for each finding")
	f.BoolVar(&findingBurp, "burp", false, "Display in Burp Suite-style format (colored request/response)")
	f.StringSliceVar(&findingColumns, "columns", nil, "Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE)")
	f.StringSliceVar(&findingExclude, "exclude-columns", nil, "Columns to hide (comma-separated)")
	tui.AddFlags(findingCmd, &findingTUIFlag, &findingNoTUIFlag)
}

func runFinding(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	var fuzzyTerm string
	if len(args) == 1 {
		fuzzyTerm = args[0]
	}

	return runWithWatch(func() error {
		filters, err := buildFindingFilters(fuzzyTerm)
		if err != nil {
			return err
		}

		ctx := context.Background()
		fqb := database.NewFindingsQueryBuilder(db, filters)
		findings, err := fqb.Execute(ctx)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}

		total, err := fqb.Count(ctx)
		if err != nil {
			return fmt.Errorf("failed to count findings: %w", err)
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
			return displayFindingsJSON(findings, total, filters.ProjectUUID)
		} else if findingBurp {
			return displayFindingsBurp(db, ctx, findings)
		} else if findingRaw {
			return displayFindingsRaw(db, ctx, findings)
		}
		return findingDisplayTable(db, ctx, findings, total)
	})
}

func buildFindingFilters(fuzzyTerm string) (database.QueryFilters, error) {
	var dateFrom, dateTo *time.Time
	if findingFrom != "" {
		t, err := parseDate(findingFrom)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if findingTo != "" {
		t, err := parseDate(findingTo)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	var severities []string
	if findingSeverity != "" {
		severities = strings.Split(findingSeverity, ",")
	}

	projectUUID, err := resolveProjectUUID()
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
		ModuleType:    findingModuleType,
		FindingSource: findingFindingSource,
		DateFrom:      dateFrom,
		DateTo:        dateTo,
		FuzzyTerm:     fuzzyTerm,
		SearchTerm:    findingSearch,
		HeaderSearch:  findingHeader,
		BodySearch:    findingBody,
		Limit:         findingLimit,
		Offset:        findingOffset,
		SortBy:        findingSort,
		SortAsc:       findingAsc,
	}, nil
}

func displayFindingsJSON(findings []*database.Finding, total int64, projectUUID string) error {
	output := map[string]interface{}{
		"project_uuid": projectUUID,
		"total":        total,
		"offset":       findingOffset,
		"limit":        findingLimit,
		"findings":     findings,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// displayFindingsBurp shows findings with their associated HTTP records in Burp-style format.
func displayFindingsBurp(db *database.DB, ctx context.Context, findings []*database.Finding) error {
	repo := database.NewRepository(db)
	for i, f := range findings {
		if i > 0 {
			fmt.Println(terminal.Gray(burpDivider))
		}

		// Finding header
		fmt.Printf("%s %s [%s] %s\n",
			terminal.InfoSymbol(),
			colorSeverity(f.Severity),
			terminal.Cyan(f.ModuleName),
			f.ModuleShort)
		if len(f.MatchedAt) > 0 {
			fmt.Printf("  Matched at: %s\n", terminal.Gray(strings.Join(f.MatchedAt, ", ")))
		}
		fmt.Println()

		// Show associated HTTP records
		records := loadFindingRecords(ctx, repo, f)
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
	repo := database.NewRepository(db)
	for _, f := range findings {
		fmt.Println("──────────────────────────────────────────────────────────────────")
		fmt.Printf("Finding #%d - %s [%s] %s\n", f.ID, colorSeverity(f.Severity), f.ModuleName, f.ModuleShort)
		if f.Description != "" {
			fmt.Printf("Description: %s\n", f.Description)
		}
		if len(f.MatchedAt) > 0 {
			fmt.Printf("Matched at:  %s\n", strings.Join(f.MatchedAt, ", "))
		}
		fmt.Printf("Confidence:  %s  |  Source: %s  |  Found: %s\n",
			f.Confidence, f.FindingSource, f.FoundAt.Format("2006-01-02 15:04:05"))
		fmt.Println("──────────────────────────────────────────────────────────────────")

		records := loadFindingRecords(ctx, repo, f)
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

// loadFindingRecords fetches the HTTP records associated with a finding.
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

func findingDisplayTable(db *database.DB, ctx context.Context, findings []*database.Finding, total int64) error {
	projectUUID, _ := resolveProjectUUID()

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
		min(findingOffset+len(findings), int(total)),
		total)
	if sevLine != "" {
		fmt.Printf("  %s Severity:  %s\n", terminal.Cyan(terminal.SymbolSparkle), sevLine)
	}
	if confLine != "" {
		fmt.Printf("  %s Confidence:%s\n", terminal.Cyan(terminal.SymbolSparkle2), confLine)
	}
	fmt.Println()

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
