package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// columnDef defines a displayable column for the traffic table.
type columnDef struct {
	name    string
	extract func(*database.HTTPRecord) string
	maxLen  int
	// needsRawBodies marks a column whose extract parses the record's raw
	// request/response rather than reading a metadata field. Selecting one forces
	// the query to fetch those blobs (see trafficColumnsUseRawBodies); every other
	// column is served from metadata alone. It is a positional field so a new
	// column cannot be added without answering the question.
	needsRawBodies bool
}

// allTrafficColumns is the registry of every available column.
var allTrafficColumns = []columnDef{
	{"UUID", func(r *database.HTTPRecord) string { return r.UUID[:min(8, len(r.UUID))] }, 8, false},
	{"HOST", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(fmt.Sprintf("%s://%s:%d", r.Scheme, r.Hostname, r.Port), 30)
	}, 30, false},
	{"METHOD", func(r *database.HTTPRecord) string { return r.Method }, 7, false},
	{"PATH", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.Path, 40) }, 40, false},
	{"STATUS", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			s := fmt.Sprintf("%d", r.StatusCode)
			return colorStatus(s, r.StatusCode)
		}
		return ""
	}, 6, false},
	{"TIME", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%dms", r.ResponseTimeMs)
		}
		return ""
	}, 8, false},
	{"SIZE", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%d", r.ResponseContentLength)
		}
		return ""
	}, 10, false},
	{"WORDS", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%d", r.ResponseWords)
		}
		return ""
	}, 7, false},
	{"CONTENT_TYPE", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(r.ResponseContentType, 25)
	}, 25, false},
	{"SENT_AT", func(r *database.HTTPRecord) string {
		return r.SentAt.Format("2006-01-02 15:04:05")
	}, 19, false},
	{"TITLE", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.ResponseTitle, 30) }, 30, false},
	{"AUTH", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.RequestAuthorization, 30) }, 30, false},
	{"STATUS_PHRASE", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.StatusPhrase, 20) }, 20, false},
	{"REQ_HEADERS", func(r *database.HTTPRecord) string { return formatHeaders(r.RequestHeadersMap(), 40) }, 40, true},
	{"RESP_HEADERS", func(r *database.HTTPRecord) string { return formatHeaders(r.ResponseHeadersMap(), 40) }, 40, true},
	{"SOURCE", func(r *database.HTTPRecord) string { return r.Source }, 20, false},
	{"REMARKS", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(strings.Join(r.Remarks, ", "), 40)
	}, 40, false},
}

// defaultTrafficColumns are shown when no --columns flag is provided.
var defaultTrafficColumnNames = []string{"HOST", "METHOD", "PATH", "STATUS", "CONTENT_TYPE", "SIZE", "WORDS", "TITLE", "SOURCE"}

var (
	// Shared filter flags (PersistentFlags)
	trafficHost    string
	trafficMethods []string
	trafficStatus  []int
	trafficPath    string
	trafficFrom    string
	trafficTo      string
	trafficSearch  []string
	trafficHeader  string
	trafficBody    string

	trafficExcludeSearch []string
	trafficExcludeHeader string
	trafficExcludeBody   string

	trafficSource string
	trafficSort   string
	trafficAsc    bool
	trafficLimit  int
	trafficOffset int

	// Display-only flags (trafficCmd.Flags only)
	trafficTree     bool
	trafficRaw      bool
	trafficBurp     bool
	trafficMarkdown bool
	trafficColumns  []string
	trafficExclude  []string

	// Replay flags (trafficCmd.Flags only; only active with --replay)
	trafficReplay            bool
	trafficReplayConcurrency int
	trafficReplayBrowser     bool

	// trafficAll lifts the -n/--limit cap so every matched record is
	// listed/replayed. Most useful with --replay to re-send all stored traffic.
	trafficAll bool

	// trafficBurpBridgeURL enables live Burp records as an additional source.
	trafficBurpBridgeURL    string
	trafficSaveToVigoliumDB bool
	trafficSaveToBurp       bool
)

var trafficCmd = &cobra.Command{
	Use:     "traffic [search-term]",
	Aliases: []string{"traffics", "tf"},
	Short:   "Browse or replay HTTP traffic (alias: db ls --table http_records)",
	Long: "Alias for 'vigolium db ls --table http_records'. Browse stored HTTP traffic with fuzzy search, " +
		"tree view, and column selection.\n\n" +
		"With --replay, the matched records are re-sent instead of listed, showing an original-vs-replay " +
		"comparison. Use --concurrency to throttle load on an intercepting proxy, --proxy to route through " +
		"Burp, --with-browser to replay each URL in a real browser so the proxy sees browser-driven traffic, " +
		"and --all to replay every matched record instead of just the most recent --limit (default 100).",
	Args: cobra.MaximumNArgs(1),
	RunE: runTraffic,
}

func init() {
	rootCmd.AddCommand(trafficCmd)

	// Shared filter flags on PersistentFlags (apply to both the listing and --replay)
	pf := trafficCmd.PersistentFlags()
	pf.StringVar(&trafficHost, "host", "", "Filter by hostname pattern (wildcard supported)")
	pf.StringSliceVar(&trafficMethods, "method", nil, "Filter by HTTP method (repeatable, e.g. --method GET --method POST)")
	pf.IntSliceVar(&trafficStatus, "status", nil, "Filter by HTTP status code (repeatable, e.g. --status 200 --status 404)")
	pf.StringVar(&trafficPath, "path", "", "Filter by URL path pattern")
	pf.StringVar(&trafficFrom, "from", "", "Show records after this date (YYYY-MM-DD or RFC3339)")
	pf.StringVar(&trafficTo, "to", "", "Show records before this date (YYYY-MM-DD or RFC3339)")
	pf.StringArrayVar(&trafficSearch, "search", nil, "Search across URL, path, and the raw request/response (headers + body); repeatable, AND-combined (each term further narrows)")
	pf.StringVar(&trafficHeader, "header", "", "Search within HTTP header names and values")
	pf.StringVar(&trafficBody, "body", "", "Search within HTTP request/response body content")
	pf.StringArrayVar(&trafficExcludeSearch, "exclude-search", nil, "Exclude records where the term appears in the URL, path, or raw request/response (repeatable; dropped if ANY term matches — the inverse of --search)")
	pf.StringVar(&trafficExcludeHeader, "exclude-header", "", "Exclude records whose HTTP header names/values contain the term (inverse of --header)")
	pf.StringVar(&trafficExcludeBody, "exclude-body", "", "Exclude records whose request/response body contains the term (inverse of --body)")
	pf.StringVar(&trafficSource, "source", "", "Filter by record source (e.g. burp, scanner, ingest-cli, ingest-server, ingest-proxy, seed)")
	pf.StringVar(&trafficSort, "sort", "created_at", "Sort by: uuid, created_at, sent_at, method, status, time")
	pf.BoolVar(&trafficAsc, "asc", false, "Sort in ascending order (default: descending)")
	pf.IntVarP(&trafficLimit, "limit", "n", 100, "Maximum records to display")
	pf.IntVar(&trafficOffset, "offset", 0, "Number of records to skip (for pagination)")

	// Display-only flags
	f := trafficCmd.Flags()
	f.BoolVar(&trafficTree, "tree", false, "Display as host/path hierarchy tree")
	f.BoolVar(&trafficRaw, "raw", false, "Show full raw HTTP request and response")
	f.BoolVar(&trafficBurp, "burp", false, "Display in Burp Suite-style format (colored request/response)")
	f.BoolVar(&trafficMarkdown, "markdown", false, "Render the matched records as Markdown (request/response in fenced http blocks) to stdout; response bodies are compacted to a preview by default (use --full-body for whole bodies)")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
	f.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
	f.StringSliceVar(&trafficColumns, "columns", nil, "Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS)")
	f.StringSliceVar(&trafficExclude, "exclude-columns", nil, "Columns to hide (comma-separated)")
	registerAgentJSONFlags(f)

	// Replay flags
	f.BoolVar(&trafficReplay, "replay", false, "Re-send the matched requests and compare original vs new response (instead of listing)")
	f.BoolVarP(&trafficAll, "all", "a", false, "List/replay every matched record (ignore the -n/--limit cap); pair with --replay to re-send all stored traffic")
	f.IntVarP(&trafficReplayConcurrency, "concurrency", "c", 10, "Concurrent replays (--replay); keep low to avoid overwhelming an intercepting proxy like Burp")
	f.BoolVar(&trafficReplayBrowser, "with-browser", false, "Replay each URL through a real browser routed via --proxy (--replay), so Burp captures browser-driven traffic")
	f.StringVar(
		&trafficBurpBridgeURL,
		"burp-bridge-url",
		burpbridge.URLFromEnvironment(),
		"Merge live traffic from this loopback Burp bridge URL with local database records")
	f.BoolVar(
		&trafficSaveToVigoliumDB,
		"save-to-vigolium-db",
		false,
		"Persist the live Burp records selected by the active filters into the database")
	f.BoolVar(
		&trafficSaveToBurp,
		"save-to-burp",
		false,
		"Copy the database records selected by the active filters into Burp's Target Site map")
	f.BoolVar(&replayInReplace, "in-replace", false, "With --replay: overwrite each stored response with the new replay response")
	f.DurationVar(&globalTimeout, "timeout", 15*time.Second, "Per-request timeout for --replay (e.g. 30s, 1m)")

	tui.AddFlags(trafficCmd, &trafficTUI, &trafficNoTUI)
}

func runTraffic(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	if trafficSaveToVigoliumDB && strings.TrimSpace(trafficBurpBridgeURL) == "" {
		return fmt.Errorf("--save-to-vigolium-db requires --burp-bridge-url")
	}
	if trafficSaveToBurp && strings.TrimSpace(trafficBurpBridgeURL) == "" {
		return fmt.Errorf("--save-to-burp requires --burp-bridge-url")
	}
	if trafficSaveToBurp && trafficSaveToVigoliumDB {
		return fmt.Errorf("--save-to-burp and --save-to-vigolium-db cannot be combined")
	}
	if trafficSaveToVigoliumDB && statelessReadRequested() {
		return fmt.Errorf("--save-to-vigolium-db cannot be used with --stateless or --glob-db")
	}
	if trafficSaveToVigoliumDB && trafficReplay {
		return fmt.Errorf("--save-to-vigolium-db cannot be combined with --replay")
	}
	if trafficSaveToBurp && trafficReplay {
		return fmt.Errorf("--save-to-burp cannot be combined with --replay")
	}
	if trafficBurpBridgeURL != "" {
		validated, err := burpbridge.ValidateURL(trafficBurpBridgeURL)
		if err != nil {
			return fmt.Errorf("--burp-bridge-url: %w", err)
		}
		trafficBurpBridgeURL = validated
	}

	var fuzzyTerm string

	// Argument routing: "tree" activates tree mode, "ls"/"list" are no-ops, anything else is a fuzzy search term
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "tree":
			trafficTree = true
		case "ls", "list":
			// no-op — default table view
		default:
			fuzzyTerm = args[0]
		}
	}

	// Built once, up front: the filters are a pure function of the flags and the
	// positional term, so they cannot change between --watch ticks, and the
	// --glob-db merge below needs them to know whether any filter reads the raw
	// corpus.
	filters, err := buildTrafficFilters(fuzzyTerm)
	if err != nil {
		return err
	}
	rendersRaw := trafficRendersRawBodies()

	// What the --glob-db merge can skip. traffic always needs the record rows
	// themselves — they are its data — but the bodies can go unless something
	// renders them or a filter LIKEs over them. Dropping the columns from the
	// merge would break such a filter, since it would match against absent data;
	// a query-level projection would not, which is why this is stricter than
	// rendersRaw alone.
	db, err := openReadDB(globDBSkipSet{
		RecordBodies:  !rendersRaw && !filters.UsesRawCorpus(),
		RecordFileMap: !trafficTree,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	if trafficSaveToVigoliumDB {
		ctx := context.Background()
		if err := db.CreateSchema(ctx); err != nil {
			return fmt.Errorf("failed to create database schema: %w", err)
		}
		if err := db.SeedDefaults(ctx); err != nil {
			return fmt.Errorf("failed to seed default data: %w", err)
		}
	}

	// --replay re-sends matched records instead of listing them. Run it
	// directly (not under --watch, which would re-fire the traffic each tick).
	if trafficReplay {
		return runTrafficReplayFlow(context.Background(), db, fuzzyTerm)
	}

	return runWithWatch(func() error {
		ctx := context.Background()
		if trafficSaveToBurp {
			records, err := database.NewQueryBuilder(db, filters).Execute(ctx)
			if err != nil {
				return fmt.Errorf("query records to save to Burp: %w", err)
			}
			client, err := burpbridge.New(trafficBurpBridgeURL)
			if err != nil {
				return err
			}
			result := client.SaveRecordsToSiteMap(ctx, records)
			writeBurpSiteMapSaveResult(os.Stderr, result)
			if result.Added == 0 && result.Skipped > 0 {
				return fmt.Errorf("no selected records could be saved to Burp")
			}
		}
		if trafficSaveToVigoliumDB {
			if !burpbridge.Eligible(filters) {
				return fmt.Errorf("the active source/risk/remark filters exclude live Burp traffic")
			}
			result, err := importBurpTrafficToDB(
				ctx,
				database.NewRepository(db),
				trafficBurpBridgeURL,
				burpbridge.QueryFromFilters(filters, false),
				filters.ProjectUUID,
			)
			if err != nil {
				return fmt.Errorf("import Burp traffic: %w", err)
			}
			writeBurpImportResult(os.Stderr, trafficBurpBridgeURL, result, false)
		}
		tuiActive, tuiErr := tui.Active(trafficTUI, trafficNoTUI, globalJSON)
		if tuiErr != nil {
			return tuiErr
		}
		records, total, err := queryTrafficRecords(ctx, db, filters, rendersRaw)
		if err != nil {
			return fmt.Errorf("failed to query database: %w", err)
		}

		if tuiActive {
			if len(records) == 0 {
				fmt.Printf("%s No HTTP records found.\n", terminal.InfoSymbol())
				return nil
			}
			return pickTrafficTUI(records, total)
		}

		if globalJSON {
			return displayJSON(records, total, trafficOffset, trafficLimit)
		}

		// Echo the active filter conditions (search, host, method, status, …) so
		// it's clear the result set was narrowed and by what. Text modes only; JSON
		// already carries the filters implicitly and must stay clean on stdout.
		printActiveTrafficFilters(filters, fuzzyTerm)

		var renderErr error
		switch {
		case trafficMarkdown:
			renderErr = displayTrafficMarkdown(records)
		case trafficBurp:
			renderErr = displayBurp(records)
		case trafficRaw:
			renderErr = displayRaw(records)
		case trafficTree:
			warnIfCapped(len(records), total) // top, so it's seen before a long tree
			printTrafficSummary(ctx, db, records, total)
			renderErr = displayTree(records)
		default:
			warnIfCapped(len(records), total)
			printTrafficSummary(ctx, db, records, total)
			renderErr = trafficDisplayTable(records, total, trafficOffset)
		}
		if renderErr != nil {
			return renderErr
		}
		// Repeat at the bottom so it's also visible after scrolling a long list.
		warnIfCapped(len(records), total)
		return nil
	})
}

// buildTrafficFilters constructs QueryFilters from traffic flags and an optional fuzzy term.
func buildTrafficFilters(fuzzyTerm string) (database.QueryFilters, error) {
	var dateFrom, dateTo *time.Time
	if trafficFrom != "" {
		t, err := clicommon.ParseDate(trafficFrom)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --from date: %w", err)
		}
		dateFrom = &t
	}
	if trafficTo != "" {
		t, err := clicommon.ParseDate(trafficTo)
		if err != nil {
			return database.QueryFilters{}, fmt.Errorf("invalid --to date: %w", err)
		}
		dateTo = &t
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}

	// --all lifts the cap: a zero Limit means "no LIMIT clause" in the query.
	limit := trafficLimit
	if trafficAll {
		limit = 0
	}

	return database.QueryFilters{
		ProjectUUID:         projectUUID,
		HostPattern:         trafficHost,
		Methods:             trafficMethods,
		StatusCodes:         trafficStatus,
		PathPattern:         trafficPath,
		Source:              trafficSource,
		DateFrom:            dateFrom,
		DateTo:              dateTo,
		FuzzyTerm:           fuzzyTerm,
		SearchTerms:         trafficSearch,
		HeaderSearch:        trafficHeader,
		BodySearch:          trafficBody,
		ExcludeTerms:        trafficExcludeSearch,
		ExcludeHeaderSearch: trafficExcludeHeader,
		ExcludeBodySearch:   trafficExcludeBody,
		Limit:               limit,
		Offset:              trafficOffset,
		SortBy:              trafficSort,
		SortAsc:             trafficAsc,
	}, nil
}

// trafficRendersRawBodies reports whether any part of this invocation reads
// HTTPRecord.RawRequest/RawResponse off the records it fetches: --raw/--burp/
// --markdown and the TUI's detail view print them, --replay re-sends them, the
// Burp bridge and --save-to-burp ship them to Burp, --json embeds them, and a
// --columns selection carrying a needsRawBodies column parses them. Everything
// else — the table and tree — renders metadata only.
//
// A new output mode MUST be added here. This list is exhaustive by construction,
// not safe by default: an unlisted mode reports false, its bodies are never
// fetched, and it renders them empty with no error. Column-driven modes are
// covered automatically via columnDef.needsRawBodies; flag-driven ones are not.
func trafficRendersRawBodies() bool {
	// --tui is tested rather than tui.Active, which can only return true when the
	// flag is set: that errs toward keeping the bodies, and covers the non-TTY
	// case where Active errors out before rendering. The TUI's selection handler
	// renders a full raw view.
	return trafficRaw || trafficBurp || trafficMarkdown || trafficReplay ||
		trafficSaveToBurp || trafficSaveToVigoliumDB || globalJSON ||
		trafficTUI || trafficBurpBridgeURL != "" || trafficColumnsUseRawBodies()
}

// trafficColumnsUseRawBodies reports whether the resolved --columns selection
// includes a column parsed out of the raw request/response. The default set
// (defaultTrafficColumnNames) contains none, so this is only true when asked for
// explicitly.
func trafficColumnsUseRawBodies() bool {
	for _, c := range resolveColumns(trafficColumns, trafficExclude) {
		if c.needsRawBodies {
			return true
		}
	}
	return false
}

// printActiveTrafficFilters prints a one-line summary of the filter conditions
// actually in effect (e.g. "search=\"admin\" · host=*.acme.com · status=200"),
// or nothing when no narrowing filter is set. Traffic lists HTTP records, so it
// has no severity/confidence filters — only the request/response conditions.
func printActiveTrafficFilters(filters database.QueryFilters, fuzzyTerm string) {
	var s filterSummary
	s.addQuoted("search", fuzzyTerm)
	if len(filters.SearchTerms) > 0 {
		s.addQuoted("search", strings.Join(filters.SearchTerms, " "))
	}
	s.add("host", filters.HostPattern)
	s.add("path", filters.PathPattern)
	s.add("method", strings.Join(filters.Methods, ","))
	s.addInts("status", filters.StatusCodes)
	s.add("header", filters.HeaderSearch)
	s.add("body", filters.BodySearch)
	if len(filters.ExcludeTerms) > 0 {
		s.addQuoted("exclude-search", strings.Join(filters.ExcludeTerms, " "))
	}
	s.add("exclude-header", filters.ExcludeHeaderSearch)
	s.add("exclude-body", filters.ExcludeBodySearch)
	s.add("source", filters.Source)
	if filters.DateFrom != nil {
		s.add("from", filters.DateFrom.Format("2006-01-02"))
	}
	if filters.DateTo != nil {
		s.add("to", filters.DateTo.Format("2006-01-02"))
	}
	s.print()
}

// resolveColumns selects columns based on --columns and --exclude-columns flags.
func resolveColumns(include, exclude []string) []columnDef {
	// Build lookup for all available columns
	colMap := make(map[string]columnDef, len(allTrafficColumns))
	for _, c := range allTrafficColumns {
		colMap[c.name] = c
	}

	// If explicit include list, use only those
	if len(include) > 0 {
		var cols []columnDef
		for _, name := range include {
			name = strings.ToUpper(strings.TrimSpace(name))
			if c, ok := colMap[name]; ok {
				cols = append(cols, c)
			}
		}
		if len(cols) > 0 {
			return cols
		}
		// Fall through to defaults if none matched
	}

	// Start with defaults
	var cols []columnDef
	for _, name := range defaultTrafficColumnNames {
		if c, ok := colMap[name]; ok {
			cols = append(cols, c)
		}
	}

	// Apply excludes
	if len(exclude) > 0 {
		excludeSet := make(map[string]bool, len(exclude))
		for _, name := range exclude {
			excludeSet[strings.ToUpper(strings.TrimSpace(name))] = true
		}
		var filtered []columnDef
		for _, c := range cols {
			if !excludeSet[c.name] {
				filtered = append(filtered, c)
			}
		}
		return filtered
	}

	return cols
}

// statusBucket maps a numeric HTTP status to its class label (1xx…5xx), or
// "none" for a missing/zero code.
func statusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	case code >= 100:
		return "1xx"
	default:
		return "none"
	}
}

// statusClassOrder is the canonical display order + color for HTTP status-class
// buckets, shared by the traffic listing and the scan-completion summary so both
// render 2xx/3xx/4xx/5xx the same way.
var statusClassOrder = []struct {
	key   string
	color func(string) string
}{
	{"2xx", terminal.Green}, {"3xx", terminal.Cyan}, {"4xx", terminal.Yellow},
	{"5xx", terminal.Red}, {"1xx", terminal.Gray}, {"none", terminal.Gray},
}

// bucketStatusCounts folds raw status_code→count pairs into class buckets
// (2xx/3xx/4xx/5xx/1xx/none) keyed by statusBucket.
func bucketStatusCounts(byCode map[int]int64) map[string]int64 {
	buckets := make(map[string]int64, len(statusClassOrder))
	for code, n := range byCode {
		buckets[statusBucket(code)] += n
	}
	return buckets
}

// formatStatusClassLine renders status-class buckets in canonical order as a
// single colored "2xx:40 3xx:5 …" string, empty when every bucket is zero.
func formatStatusClassLine(buckets map[string]int64) string {
	var parts []string
	for _, b := range statusClassOrder {
		if n := buckets[b.key]; n > 0 {
			parts = append(parts, b.color(fmt.Sprintf("%s:%d", b.key, n)))
		}
	}
	return strings.Join(parts, " ")
}

// printTrafficSummary prints the "Showing X-Y of Z records" line plus a
// status-class / method / content-type breakdown, mirroring printFindingsSummary.
// Counts are DB-wide (project scope, filter-independent like the finding summary)
// so a --glob-db read shows the whole merged corpus at a glance.
func printTrafficSummary(ctx context.Context, db *database.DB, records []*database.HTTPRecord, total int64) {
	projectUUID, _ := effectiveProjectUUID()
	shown := len(records)

	fmt.Printf("%s Showing %d-%d of %d records\n",
		terminal.InfoSymbol(),
		trafficOffset+1,
		min(trafficOffset+shown, int(total)),
		total)
	if trafficBurpBridgeURL != "" {
		printVisibleTrafficBreakdown(records)
		fmt.Println()
		return
	}

	// Status classes, ordered and colored like the tree/table status column.
	if statusCounts, err := database.CountRecordsByColumn(ctx, db, projectUUID, "status_code"); err == nil {
		buckets := make(map[string]int64)
		for code, n := range statusCounts {
			c, _ := strconv.Atoi(code)
			buckets[statusBucket(c)] += n
		}
		if line := formatStatusClassLine(buckets); line != "" {
			fmt.Printf("  %s Status:   %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
		}
	}

	// Methods, most frequent first.
	if methodCounts, err := database.CountRecordsByColumn(ctx, db, projectUUID, "method"); err == nil {
		if line := formatCountLine(methodCounts, 0, terminal.Cyan); line != "" {
			fmt.Printf("  %s Method:   %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
		}
	}

	// Content types, params stripped and merged, top 6 with a "+N more" tail.
	if ctCounts, err := database.CountRecordsByColumn(ctx, db, projectUUID, "response_content_type"); err == nil {
		merged := make(map[string]int64)
		for ct, n := range ctCounts {
			key := shortContentType(ct)
			if key == "" || key == "-" {
				key = "(none)"
			}
			merged[key] += n
		}
		if line := formatCountLine(merged, 6, terminal.Orange); line != "" {
			fmt.Printf("  %s Type:     %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
		}
	}

	fmt.Println()
}

// printVisibleTrafficBreakdown keeps summary counts honest when the result page
// combines database and ephemeral Burp records. Database-wide GROUP BY queries
// cannot see the Burp source, so this branch summarizes the current merged page.
func printVisibleTrafficBreakdown(records []*database.HTTPRecord) {
	statusCounts := make(map[string]int64)
	methodCounts := make(map[string]int64)
	contentTypeCounts := make(map[string]int64)
	sourceCounts := make(map[string]int64)
	for _, record := range records {
		statusCounts[statusBucket(record.StatusCode)]++
		methodCounts[record.Method]++
		contentTypeCounts[shortContentType(record.ResponseContentType)]++
		sourceCounts[record.Source]++
	}
	if line := formatCountLine(statusCounts, 0, terminal.Green); line != "" {
		fmt.Printf("  %s Status:   %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
	}
	if line := formatCountLine(methodCounts, 0, terminal.Cyan); line != "" {
		fmt.Printf("  %s Method:   %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
	}
	if line := formatCountLine(contentTypeCounts, 6, terminal.Orange); line != "" {
		fmt.Printf("  %s Type:     %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
	}
	if line := formatCountLine(sourceCounts, 0, terminal.Cyan); line != "" {
		fmt.Printf("  %s Source:   %s\n", terminal.Cyan(terminal.SymbolSparkle), line)
	}
}

// formatCountLine renders a "key:count" list ordered by count desc (ties broken
// by key), coloring each token. When topN > 0 and more entries exist, it keeps
// the top N and appends a gray "+K more".
func formatCountLine(counts map[string]int64, topN int, color func(string) string) string {
	type kv struct {
		k string
		n int64
	}
	items := make([]kv, 0, len(counts))
	for k, n := range counts {
		items = append(items, kv{k, n})
	}
	if len(items) == 0 {
		return ""
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].k < items[j].k
	})
	more := 0
	if topN > 0 && len(items) > topN {
		more = len(items) - topN
		items = items[:topN]
	}
	parts := make([]string, 0, len(items)+1)
	for _, it := range items {
		parts = append(parts, color(fmt.Sprintf("%s:%d", it.k, it.n)))
	}
	if more > 0 {
		parts = append(parts, terminal.Gray(fmt.Sprintf("+%d more", more)))
	}
	return strings.Join(parts, " ")
}

// trafficDisplayTable builds and prints a table dynamically from resolved columns.
func trafficDisplayTable(records []*database.HTTPRecord, total int64, offset int) error {
	cols := resolveColumns(trafficColumns, trafficExclude)
	if len(cols) == 0 {
		return fmt.Errorf("no columns selected")
	}

	// Build header names
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.name
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, headers...)

	for _, rec := range records {
		vals := make([]any, len(cols))
		for i, c := range cols {
			vals[i] = c.extract(rec)
		}
		tbl.AddRow(vals...)
	}

	tbl.Print()
	fmt.Println()
	return nil
}

// Burp-style display constants
const (
	burpMaxLineWidth = 120
	burpMaxBodyLines = 50
)

const burpDivider = "───────────────────────────────────────────────────────────────────"

func displayBurp(records []*database.HTTPRecord) error {
	for i, rec := range records {
		if i > 0 {
			fmt.Println(terminal.Gray(burpDivider))
		}

		// Prefix line
		uuid := rec.UUID
		if len(uuid) > 8 {
			uuid = uuid[:8]
		}
		sourceStr := terminal.Gray("–")
		if rec.Source != "" {
			sourceStr = terminal.Cyan(rec.Source)
		}
		fmt.Printf("%s UUID: %s / Source: %s\n",
			terminal.InfoSymbol(), terminal.BoldCyan(uuid), sourceStr)

		// Request
		printBurpRequest(rec.RawRequest)

		fmt.Println(terminal.Gray("---"))

		// Response
		if rec.HasResponse && len(rec.RawResponse) > 0 {
			printBurpResponse(rec.RawResponse, rec.StatusCode)
		} else {
			fmt.Println(terminal.Gray("(no response)"))
		}
	}
	return nil
}

func printBurpRequest(raw []byte) {
	if len(raw) == 0 {
		return
	}

	lines := splitHTTPLines(raw)
	inBody := false

	for i, line := range lines {
		if i == 0 {
			// Request line: e.g. GET /path HTTP/1.1
			fmt.Println(terminal.BoldCyan(line))
			continue
		}
		if !inBody && line == "" {
			inBody = true
			fmt.Println()
			continue
		}
		if inBody {
			fmt.Println(line)
		} else {
			// Header line
			if idx := strings.Index(line, ":"); idx > 0 {
				fmt.Printf("%s%s\n", terminal.Cyan(line[:idx]), line[idx:])
			} else {
				fmt.Println(line)
			}
		}
	}
}

const burpBodyPreviewLines = 4

func printBurpResponse(raw []byte, statusCode int) {
	if len(raw) == 0 {
		return
	}

	lines := splitHTTPLines(raw)
	inBody := false
	bodyLineCount := 0

	for i, line := range lines {
		if i == 0 {
			// Status line: color by status code
			fmt.Println(colorStatusLine(line, statusCode))
			continue
		}
		if !inBody && line == "" {
			inBody = true
			fmt.Println()
			continue
		}
		if inBody {
			bodyLineCount++
			if bodyLineCount > burpBodyPreviewLines {
				remaining := len(lines) - i
				if remaining > 0 {
					fmt.Println(terminal.Gray(fmt.Sprintf("... (%d more lines)", remaining)))
				}
				break
			}
			if len(line) > burpMaxLineWidth {
				fmt.Println(terminal.Gray(line[:burpMaxLineWidth] + "..."))
			} else {
				fmt.Println(terminal.Gray(line))
			}
		} else {
			// Header line
			if idx := strings.Index(line, ":"); idx > 0 {
				fmt.Printf("%s%s\n", terminal.Yellow(line[:idx]), line[idx:])
			} else {
				fmt.Println(line)
			}
		}
	}
}

func colorStatusLine(line string, code int) string {
	switch {
	case code >= 200 && code < 300:
		return terminal.BoldGreen(line)
	case code >= 300 && code < 400:
		return terminal.BoldCyan(line)
	case code >= 400 && code < 500:
		return terminal.BoldYellow(line)
	case code >= 500:
		return terminal.BoldRed(line)
	default:
		return line
	}
}

// splitHTTPLines splits raw HTTP bytes by \r\n, falling back to \n.
func splitHTTPLines(raw []byte) []string {
	s := string(raw)
	if strings.Contains(s, "\r\n") {
		return strings.Split(s, "\r\n")
	}
	return strings.Split(s, "\n")
}

// formatHeaders formats a header map into a truncated single-line string like "Host: example.com, Content-Type: app...".
func formatHeaders(h map[string][]string, maxLen int) string {
	if len(h) == 0 {
		return ""
	}
	var parts []string
	for k, vals := range h {
		if len(vals) > 0 {
			parts = append(parts, k+": "+vals[0])
		}
	}
	return clicommon.Truncate(strings.Join(parts, ", "), maxLen)
}
