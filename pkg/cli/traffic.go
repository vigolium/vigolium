package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
}

// allTrafficColumns is the registry of every available column.
var allTrafficColumns = []columnDef{
	{"UUID", func(r *database.HTTPRecord) string { return r.UUID[:min(8, len(r.UUID))] }, 8},
	{"HOST", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(fmt.Sprintf("%s://%s:%d", r.Scheme, r.Hostname, r.Port), 30)
	}, 30},
	{"METHOD", func(r *database.HTTPRecord) string { return r.Method }, 7},
	{"PATH", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.Path, 40) }, 40},
	{"STATUS", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			s := fmt.Sprintf("%d", r.StatusCode)
			return colorStatus(s, r.StatusCode)
		}
		return ""
	}, 6},
	{"TIME", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%dms", r.ResponseTimeMs)
		}
		return ""
	}, 8},
	{"SIZE", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%d", r.ResponseContentLength)
		}
		return ""
	}, 10},
	{"WORDS", func(r *database.HTTPRecord) string {
		if r.HasResponse {
			return fmt.Sprintf("%d", r.ResponseWords)
		}
		return ""
	}, 7},
	{"CONTENT_TYPE", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(r.ResponseContentType, 25)
	}, 25},
	{"SENT_AT", func(r *database.HTTPRecord) string {
		return r.SentAt.Format("2006-01-02 15:04:05")
	}, 19},
	{"TITLE", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.ResponseTitle, 30) }, 30},
	{"AUTH", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.RequestAuthorization, 30) }, 30},
	{"STATUS_PHRASE", func(r *database.HTTPRecord) string { return clicommon.Truncate(r.StatusPhrase, 20) }, 20},
	{"REQ_HEADERS", func(r *database.HTTPRecord) string { return formatHeaders(r.RequestHeadersMap(), 40) }, 40},
	{"RESP_HEADERS", func(r *database.HTTPRecord) string { return formatHeaders(r.ResponseHeadersMap(), 40) }, 40},
	{"SOURCE", func(r *database.HTTPRecord) string { return r.Source }, 20},
	{"REMARKS", func(r *database.HTTPRecord) string {
		return clicommon.Truncate(strings.Join(r.Remarks, ", "), 40)
	}, 40},
}

// defaultTrafficColumns are shown when no --columns flag is provided.
var defaultTrafficColumnNames = []string{"HOST", "METHOD", "PATH", "STATUS", "CONTENT_TYPE", "SIZE", "WORDS", "TITLE", "SOURCE"}

var (
	// Shared filter flags (PersistentFlags — inherited by replay subcommand)
	trafficHost    string
	trafficMethods []string
	trafficStatus  []int
	trafficPath    string
	trafficFrom    string
	trafficTo      string
	trafficSearch  string
	trafficHeader  string
	trafficBody    string
	trafficSource  string
	trafficSort    string
	trafficAsc     bool
	trafficLimit   int
	trafficOffset  int

	// Display-only flags (trafficCmd.Flags only)
	trafficTree    bool
	trafficRaw     bool
	trafficBurp    bool
	trafficColumns []string
	trafficExclude []string
)

var trafficCmd = &cobra.Command{
	Use:     "traffic [search-term]",
	Aliases: []string{"traffics", "tf"},
	Short:   "Browse HTTP traffic (alias: db ls --table http_records)",
	Long:    "Alias for 'vigolium db ls --table http_records'. Browse stored HTTP traffic with fuzzy search, tree view, and column selection.",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runTraffic,
}

func init() {
	rootCmd.AddCommand(trafficCmd)

	// Shared filter flags on PersistentFlags so replay inherits them
	pf := trafficCmd.PersistentFlags()
	pf.StringVar(&trafficHost, "host", "", "Filter by hostname pattern (wildcard supported)")
	pf.StringSliceVar(&trafficMethods, "method", nil, "Filter by HTTP method (repeatable, e.g. --method GET --method POST)")
	pf.IntSliceVar(&trafficStatus, "status", nil, "Filter by HTTP status code (repeatable, e.g. --status 200 --status 404)")
	pf.StringVar(&trafficPath, "path", "", "Filter by URL path pattern")
	pf.StringVar(&trafficFrom, "from", "", "Show records after this date (YYYY-MM-DD or RFC3339)")
	pf.StringVar(&trafficTo, "to", "", "Show records before this date (YYYY-MM-DD or RFC3339)")
	pf.StringVar(&trafficSearch, "search", "", "Fuzzy search across URLs, paths, and hostnames")
	pf.StringVar(&trafficHeader, "header", "", "Search within HTTP header names and values")
	pf.StringVar(&trafficBody, "body", "", "Search within HTTP request/response body content")
	pf.StringVar(&trafficSource, "source", "", "Filter by record source (e.g. scanner, ingest-cli, ingest-server, ingest-proxy, seed)")
	pf.StringVar(&trafficSort, "sort", "created_at", "Sort by: uuid, created_at, sent_at, method, status, time")
	pf.BoolVar(&trafficAsc, "asc", false, "Sort in ascending order (default: descending)")
	pf.IntVarP(&trafficLimit, "limit", "n", 100, "Maximum records to display")
	pf.IntVar(&trafficOffset, "offset", 0, "Number of records to skip (for pagination)")

	// Display-only flags
	f := trafficCmd.Flags()
	f.BoolVar(&trafficTree, "tree", false, "Display as host/path hierarchy tree")
	f.BoolVar(&trafficRaw, "raw", false, "Show full raw HTTP request and response")
	f.BoolVar(&trafficBurp, "burp", false, "Display in Burp Suite-style format (colored request/response)")
	f.StringSliceVar(&trafficColumns, "columns", nil, "Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS)")
	f.StringSliceVar(&trafficExclude, "exclude-columns", nil, "Columns to hide (comma-separated)")
	tui.AddFlags(trafficCmd, &trafficTUI, &trafficNoTUI)
}

func runTraffic(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
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

	return runWithWatch(func() error {
		filters, err := buildTrafficFilters(fuzzyTerm)
		if err != nil {
			return err
		}

		ctx := context.Background()
		qb := database.NewQueryBuilder(db, filters)
		records, err := qb.Execute(ctx)
		if err != nil {
			return fmt.Errorf("failed to query database: %w", err)
		}

		total, err := qb.Count(ctx)
		if err != nil {
			return fmt.Errorf("failed to count records: %w", err)
		}

		if active, tuiErr := tui.Active(trafficTUI, trafficNoTUI, globalJSON); tuiErr != nil {
			return tuiErr
		} else if active {
			if len(records) == 0 {
				fmt.Printf("%s No HTTP records found.\n", terminal.InfoSymbol())
				return nil
			}
			return pickTrafficTUI(records, total)
		}

		if globalJSON {
			return displayJSON(records, total, trafficOffset, trafficLimit)
		} else if trafficBurp {
			return displayBurp(records)
		} else if trafficRaw {
			return displayRaw(records)
		} else if trafficTree {
			return displayTree(records)
		}
		return trafficDisplayTable(records, total, trafficOffset)
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

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}

	return database.QueryFilters{
		ProjectUUID:  projectUUID,
		HostPattern:  trafficHost,
		Methods:      trafficMethods,
		StatusCodes:  trafficStatus,
		PathPattern:  trafficPath,
		Source:       trafficSource,
		DateFrom:     dateFrom,
		DateTo:       dateTo,
		FuzzyTerm:    fuzzyTerm,
		SearchTerm:   trafficSearch,
		HeaderSearch: trafficHeader,
		BodySearch:   trafficBody,
		Limit:        trafficLimit,
		Offset:       trafficOffset,
		SortBy:       trafficSort,
		SortAsc:      trafficAsc,
	}, nil
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

// trafficDisplayTable builds and prints a table dynamically from resolved columns.
func trafficDisplayTable(records []*database.HTTPRecord, total int64, offset int) error {
	cols := resolveColumns(trafficColumns, trafficExclude)
	if len(cols) == 0 {
		return fmt.Errorf("no columns selected")
	}

	fmt.Printf("Showing %d-%d of %d records\n\n",
		offset+1,
		min(offset+len(records), int(total)),
		total)

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
