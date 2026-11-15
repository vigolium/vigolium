package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium endpoints` lists the application's endpoints — an origin plus a
// path template (/users/{int}/orders) with every method seen on it — built
// from stored traffic by one streaming pass over light record columns. It is
// the inventory a caller used to reconstruct by dumping `traffic -j` and
// grouping paths by hand. See pkg/database/endpoints.go.

var (
	endpointsFlags      inventoryFlags
	endpointsMinRecords int64
	endpointsSort       string
	endpointsCollapse   int
)

var endpointsCmd = &cobra.Command{
	Use:     "endpoints [search-term]",
	Aliases: []string{"endpoint"},
	Short:   "List endpoints (origin + path template) aggregated from stored traffic",
	Long: "List the endpoints seen in stored traffic: one row per origin and path template, with the methods, " +
		"record and distinct-path counts, parameter names by location, status mix, auth split, sources, " +
		"JS-derived (jstangle) outcomes and live finding counts.\n\n" +
		"Paths are grouped by structural template: /users/42 and /users/7 are /users/{int}; /users/me and " +
		"/about stay distinct. --collapse N additionally merges N or more sibling literal segments with the " +
		"same child shape (blog slugs) into {var}; it is off by default because it can merge real routes.\n\n" +
		"The filters are traffic's, so `endpoints --host x --status 200` aggregates exactly the records " +
		"`traffic --host x --status 200` lists. Bodies are never read.",
	Example: "  vigolium endpoints\n" +
		"  vigolium endpoints --host api.example.com -j\n" +
		"  vigolium endpoints --source jstangle --sort findings\n" +
		"  vigolium endpoints --scan-uuid <uuid> --min-records 2\n" +
		"  vigolium endpoints --collapse 5 -n 0",
	Args: cobra.MaximumNArgs(1),
	RunE: runEndpoints,
}

func init() {
	rootCmd.AddCommand(endpointsCmd)
	endpointsFlags.register(endpointsCmd, "endpoints")
	f := endpointsCmd.Flags()
	f.Int64Var(&endpointsMinRecords, "min-records", 0, "Only endpoints seen in at least this many records")
	f.StringVar(&endpointsSort, "sort", "records", "Sort by: "+strings.Join(database.EndpointSorts, ", "))
	f.IntVar(&endpointsCollapse, "collapse", 0, "Merge N or more sibling literal segments sharing the same child templates into {var} (0 = off; >= 2)")
	registerRowShapingFlags(f)
	registerTSVFlags(f)
}

// endpointsShaping is endpoints' --fields vocabulary and the keys --compact
// drops: the per-endpoint lists, which dominate a row's size.
var endpointsShaping = rowShaping{path: "endpoints", defaultTSV: []string{"id", "records", "top_status", "methods", "origin", "template"}}

func validateEndpointsFlags() error {
	if err := endpointsFlags.validate(); err != nil {
		return err
	}
	if err := database.ValidateEndpointSort(endpointsSort); err != nil {
		return usageErrorf("--sort: %v", err)
	}
	if endpointsCollapse < 0 || endpointsCollapse == 1 {
		return usageErrorf("--collapse must be 0 (off) or >= 2, got %d", endpointsCollapse)
	}
	if endpointsMinRecords < 0 {
		return usageErrorf("--min-records must be >= 0, got %d", endpointsMinRecords)
	}
	return nil
}

func runEndpoints(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	if err := validateJSONOutputFlag(cmd); err != nil {
		return err
	}
	if err := validateEndpointsFlags(); err != nil {
		return err
	}
	format, err := endpointsShaping.prepare(cmd)
	if err != nil {
		return err
	}
	filters, err := endpointsFlags.filters(inventoryPositional(args))
	if err != nil {
		return err
	}
	db, err := openReadDB(inventorySkipSet(filters))
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	return runWithWatch(func() error {
		return renderEndpoints(context.Background(), cmd, db, filters, format)
	})
}

// renderEndpoints runs the aggregate and writes it (envelope under -j, a table
// otherwise).
func renderEndpoints(ctx context.Context, cmd *cobra.Command, db *database.DB, filters database.QueryFilters, format string) error {
	res, err := database.NewQueryBuilder(db, filters).Endpoints(ctx, database.EndpointOptions{
		MinRecords: endpointsMinRecords,
		Sort:       endpointsSort,
		Collapse:   endpointsCollapse,
		Limit:      endpointsFlags.limit,
		Offset:     endpointsFlags.offset,
	})
	if err != nil {
		return fmt.Errorf("failed to aggregate endpoints: %w", err)
	}
	var provenance []envOpt
	if res.RecordsScanned == 0 && filters.ScanUUID != "" {
		provenance = noteProvenance(scanProvenanceWarning(ctx, db, filters.ProjectUUID, filters.ScanUUID))
	}
	if res.Capped {
		fmt.Fprintf(os.Stderr, "%s endpoint cap reached (%d): %d record(s) were not attributed to an endpoint; narrow with --host/--path\n",
			terminal.WarningSymbol(), database.DefaultMaxEndpoints, res.UnbucketedRecords)
	}

	if globalJSON {
		opts := []envOpt{
			withProjectScope(filters.ProjectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("records_scanned", res.RecordsScanned),
			withExtra("capped", res.Capped),
			withExtra("unbucketed_records", res.UnbucketedRecords),
		}
		if endpointsCollapse > 0 {
			opts = append(opts, withExtra("collapse", endpointsCollapse))
		}
		if len(res.Endpoints) > 0 {
			opts = append(opts, withQuery(endpointFollowUp(res.Endpoints[0])...))
		}
		opts = append(opts, provenance...)
		items, err := endpointsShaping.apply(res.Endpoints)
		if err != nil {
			return err
		}
		return emitRead(cmd, "", items, res.Total, endpointsFlags.offset, endpointsFlags.limit, opts...)
	}

	if format == "tsv" {
		return endpointsShaping.emitTSV(res.Endpoints)
	}

	printEndpointsTable(res, endpointsFlags.offset)
	return nil
}

// endpointFollowUp is the read that shows an endpoint's records: traffic over
// its host and a path glob of its template.
func endpointFollowUp(e database.EndpointView) []string {
	return []string{"traffic", "--host", e.Host,
		"--path", templatePathGlob(e.Template, len(e.Params["query"]) > 0), "--json", "--compact"}
}

func printEndpointsTable(res database.EndpointResult, offset int) {
	if len(res.Endpoints) == 0 {
		fmt.Printf("%s No endpoints found (%d records matched).\n", terminal.InfoSymbol(), res.RecordsScanned)
		return
	}
	fmt.Printf("%s Showing %d-%d of %d endpoints (%d records)\n\n", terminal.InfoSymbol(),
		offset+1, offset+len(res.Endpoints), res.Total, res.RecordsScanned)
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "ORIGIN", "METHODS", "TEMPLATE", "RECORDS", "PARAMS", "STATUS", "AUTH", "FINDINGS")
	for _, e := range res.Endpoints {
		findings := ""
		if e.Findings > 0 {
			findings = fmt.Sprintf("%d %s", e.Findings, clicommon.ColorSeverity(e.MaxSeverity))
		}
		template := e.Template
		if len(e.JSOutcomes) > 0 && len(e.Sources) == 1 && e.Sources[0] == "jstangle" {
			template += terminal.Gray(" (js)")
		}
		tbl.AddRow(
			clicommon.Truncate(e.Origin, 32),
			strings.Join(e.Methods, ","),
			clicommon.Truncate(template, 60),
			strconv.FormatInt(e.Records, 10),
			strconv.Itoa(e.ParamCount),
			formatEndpointStatus(e.Status),
			fmt.Sprintf("%d/%d", e.Auth.Authenticated, e.Auth.Anonymous),
			findings,
		)
	}
	tbl.Print()
	fmt.Println()
	if res.Total > int64(len(res.Endpoints)) {
		warnIfCapped(len(res.Endpoints), res.Total)
	}
}

// formatEndpointStatus renders the top three status codes as "200:40 404:2".
func formatEndpointStatus(status map[string]int64) string {
	type kv struct {
		code string
		n    int64
	}
	items := make([]kv, 0, len(status))
	for c, n := range status {
		items = append(items, kv{c, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].code < items[j].code
	})
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, len(items))
	for i, it := range items {
		code, _ := strconv.Atoi(it.code)
		parts[i] = colorStatus(fmt.Sprintf("%s:%d", it.code, it.n), code)
	}
	return strings.Join(parts, " ")
}
