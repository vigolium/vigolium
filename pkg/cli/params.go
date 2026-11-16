package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium params` lists every parameter of every endpoint with a value-type
// histogram (mutation.Classify): the input an IDOR or param-mining pass starts
// from (dominant_type integer / uuid / sequential_id). It shares the endpoint
// inventory's record stream, filters and endpoint ids. See
// pkg/database/params.go.

var (
	paramsFlags          inventoryFlags
	paramsEndpoint       string
	paramsLocations      []string
	paramsTypes          []string
	paramsMinOccurrences int64
	paramsShowValues     bool
	paramsPaths          bool
)

// paramLocations is the location vocabulary --location accepts.
var paramLocations = []string{"query", "body", "json", "xml", "cookie", "multipart", "header", "path", "other"}

var paramsCmd = &cobra.Command{
	Use:     "params [search-term]",
	Aliases: []string{"param", "parameters"},
	Short:   "List parameters per endpoint with value-type histograms, from stored traffic",
	Long: "List the parameters seen in stored traffic: one row per endpoint, location and name, with occurrence " +
		"and distinct-value counts and a histogram of value types (integer, uuid, email, jwt, …) over at most " +
		"200 values per parameter. Dynamic path segments are parameters too (location path, named {kind}@index).\n\n" +
		"Sample values are redacted by default for cookies, headers and secret-looking names (token, session, " +
		"key, …); --show-values prints them. The filters and endpoint ids are those of `vigolium endpoints`.\n\n" +
		"--paths lists JSON request-body shapes instead: one row per operation (method + path template) and JSON " +
		"key path (user.address.city; array elements share their array's path), with the JSON types seen, how " +
		"many records carried the path (sample_count) and how many JSON-body records the operation has " +
		"(operation_records). Values are never printed.",
	Example: "  vigolium params --host api.example.com\n" +
		"  vigolium params --type integer,uuid,sequential_id -j   # IDOR candidates\n" +
		"  vigolium params --endpoint <endpoint-id> --show-values\n" +
		"  vigolium params --location query,json --min-occurrences 3\n" +
		"  vigolium params --paths --method POST,PUT -j               # JSON body shapes per operation",
	Args: cobra.MaximumNArgs(1),
	RunE: runParams,
}

func init() {
	rootCmd.AddCommand(paramsCmd)
	paramsFlags.register(paramsCmd, "parameters")
	f := paramsCmd.Flags()
	f.StringVar(&paramsEndpoint, "endpoint", "", "Only this endpoint: an id from 'vigolium endpoints' or a path template (/users/{int})")
	f.StringSliceVar(&paramsLocations, "location", nil, "Only these locations (comma-separated): "+strings.Join(paramLocations, ", "))
	f.StringSliceVar(&paramsTypes, "type", nil, "Only parameters whose dominant value type is one of these (comma-separated, e.g. integer,uuid,sequential_id)")
	f.Int64Var(&paramsMinOccurrences, "min-occurrences", 0, "Only parameters seen at least this many times")
	f.BoolVar(&paramsShowValues, "show-values", false, "Print sample values unredacted (cookies, headers and secret-looking names are redacted by default)")
	f.BoolVar(&paramsPaths, "paths", false, "List JSON request-body key paths per operation (method + template) with their JSON types and sample counts, never values; --min-occurrences applies to sample_count")
	registerRowShapingFlags(f)
	registerTSVFlags(f)
}

// paramsShaping is params' --fields vocabulary; --compact drops the sample
// values and the per-type histogram.
var paramsShaping = rowShaping{path: "params", defaultTSV: []string{"endpoint_id", "location", "name", "occurrences", "dominant_type", "template"}}

func validateParamsFlags() error {
	if err := paramsFlags.validate(); err != nil {
		return err
	}
	for _, l := range paramsLocations {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" && !slices.Contains(paramLocations, l) {
			return usageErrorf("--location %q is not a location; use one of: %s", l, strings.Join(paramLocations, ", "))
		}
	}
	known := database.ParamValueTypes()
	for _, t := range paramsTypes {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" && !slices.Contains(known, t) {
			return usageErrorf("--type %q is not a value type; use one of: %s", t, strings.Join(known, ", "))
		}
	}
	if paramsMinOccurrences < 0 {
		return usageErrorf("--min-occurrences must be >= 0, got %d", paramsMinOccurrences)
	}
	if paramsPaths {
		// The shape view has no per-location or value-type rows to filter,
		// and no values to show; a filter that would do nothing is refused.
		for flag, set := range map[string]bool{
			"--location": len(paramsLocations) > 0, "--type": len(paramsTypes) > 0, "--show-values": paramsShowValues,
		} {
			if set {
				return usageErrorf("%s does not apply to --paths (JSON body key paths carry no values or value types)", flag)
			}
		}
	}
	return nil
}

func runParams(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	if err := validateJSONOutputFlag(cmd); err != nil {
		return err
	}
	if err := validateParamsFlags(); err != nil {
		return err
	}
	format, err := paramsShaping.prepare(cmd)
	if err != nil {
		return err
	}
	filters, err := paramsFlags.filters(inventoryPositional(args))
	if err != nil {
		return err
	}
	skip := inventorySkipSet(filters)
	skip.Findings = !filters.UsesLinkedFindings() // params never count findings
	db, err := openReadDB(skip)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	return runWithWatch(func() error {
		return renderParams(context.Background(), cmd, db, filters, format)
	})
}

func renderParams(ctx context.Context, cmd *cobra.Command, db *database.DB, filters database.QueryFilters, format string) error {
	if paramsPaths {
		return renderParamPaths(ctx, cmd, db, filters, format)
	}
	res, err := database.NewQueryBuilder(db, filters).Params(ctx, database.ParamOptions{
		Endpoint:       strings.TrimSpace(paramsEndpoint),
		Locations:      paramsLocations,
		Types:          paramsTypes,
		MinOccurrences: paramsMinOccurrences,
		ShowValues:     paramsShowValues,
		Limit:          paramsFlags.limit,
		Offset:         paramsFlags.offset,
	})
	if err != nil {
		return fmt.Errorf("failed to aggregate parameters: %w", err)
	}
	var provenance []envOpt
	if res.RecordsScanned == 0 && filters.ScanUUID != "" {
		provenance = noteProvenance(scanProvenanceWarning(ctx, db, filters.ProjectUUID, filters.ScanUUID))
	}
	if res.Capped {
		fmt.Fprintf(os.Stderr, "%s parameter cap reached (%d): %d record(s) were only partly attributed; narrow with --host/--path/--endpoint\n",
			terminal.WarningSymbol(), database.DefaultMaxParams, res.UnbucketedRecords)
	}

	if globalJSON {
		opts := []envOpt{
			withProjectScope(filters.ProjectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("records_scanned", res.RecordsScanned),
			withExtra("capped", res.Capped),
			withExtra("values_redacted", !paramsShowValues),
			withRedacted(paramsAnyRedacted(res.Params)),
		}
		if len(res.Params) > 0 {
			p := res.Params[0]
			opts = append(opts, withQuery("endpoints", "--host", hostOfOrigin(p.Origin),
				"--path", templatePathGlob(p.Template, false), "--json"))
		}
		opts = append(opts, provenance...)
		items, err := paramsShaping.apply(res.Params)
		if err != nil {
			return err
		}
		return emitRead(cmd, "", items, res.Total, paramsFlags.offset, paramsFlags.limit, opts...)
	}

	if format == "tsv" {
		return paramsShaping.emitTSV(res.Params)
	}
	printParamsTable(res, paramsFlags.offset)
	return nil
}

// hostOfOrigin strips the scheme and port from an origin.
func hostOfOrigin(origin string) string {
	_, rest, ok := strings.Cut(origin, "://")
	if !ok {
		rest = origin
	}
	if strings.HasPrefix(rest, "[") {
		if i := strings.Index(rest, "]"); i > 0 {
			return rest[1:i]
		}
	}
	host, _, _ := strings.Cut(rest, ":")
	return host
}

func printParamsTable(res database.ParamResult, offset int) {
	if len(res.Params) == 0 {
		fmt.Printf("%s No parameters found (%d records matched).\n", terminal.InfoSymbol(), res.RecordsScanned)
		return
	}
	fmt.Printf("%s Showing %d-%d of %d parameters (%d records)\n\n", terminal.InfoSymbol(),
		offset+1, offset+len(res.Params), res.Total, res.RecordsScanned)
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "ENDPOINT", "LOCATION", "NAME", "SEEN", "DISTINCT", "TYPE", "SAMPLES")
	for _, p := range res.Params {
		distinct := strconv.FormatInt(p.DistinctValues, 10)
		if p.DistinctCapped {
			distinct += "+"
		}
		tbl.AddRow(
			clicommon.Truncate(p.Origin+p.Template, 50),
			p.Location,
			clicommon.Truncate(p.Name, 30),
			strconv.FormatInt(p.Occurrences, 10),
			distinct,
			p.DominantType,
			clicommon.Truncate(strings.Join(p.Samples, ", "), 40),
		)
	}
	tbl.Print()
	fmt.Println()
	if res.Total > int64(len(res.Params)) {
		warnIfCapped(len(res.Params), res.Total)
	}
}

// paramsAnyRedacted reports whether a credential-bearing sample in the rows was
// masked, for the envelope's `redacted`.
func paramsAnyRedacted(params []database.ParamView) bool {
	for _, p := range params {
		if p.Redacted {
			return true
		}
	}
	return false
}

// paramPathsShaping is --paths' --fields/--format tsv vocabulary.
var paramPathsShaping = rowShaping{path: "params", defaultTSV: []string{"method", "template", "key_path", "json_type", "sample_count"}}

// renderParamPaths prints the JSON body shapes (`params --paths`).
func renderParamPaths(ctx context.Context, cmd *cobra.Command, db *database.DB, filters database.QueryFilters, format string) error {
	res, err := database.NewQueryBuilder(db, filters).ParamPaths(ctx, database.ParamPathOptions{
		Endpoint:   strings.TrimSpace(paramsEndpoint),
		MinSamples: paramsMinOccurrences,
		Limit:      paramsFlags.limit,
		Offset:     paramsFlags.offset,
	})
	if err != nil {
		return fmt.Errorf("failed to aggregate JSON body paths: %w", err)
	}
	var provenance []envOpt
	if res.RecordsScanned == 0 && filters.ScanUUID != "" {
		provenance = noteProvenance(scanProvenanceWarning(ctx, db, filters.ProjectUUID, filters.ScanUUID))
	}
	if res.Capped {
		fmt.Fprintf(os.Stderr, "%s key path cap reached (%d); narrow with --host/--path/--endpoint\n",
			terminal.WarningSymbol(), database.DefaultMaxParams)
	}
	if res.RecordsWithoutPaths > 0 {
		fmt.Fprintf(os.Stderr, "%s %d record(s) with JSON bodies were stored without key paths; their keys are in `vigolium params --location json`\n",
			terminal.InfoSymbol(), res.RecordsWithoutPaths)
	}

	if globalJSON {
		opts := []envOpt{
			withProjectScope(filters.ProjectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("records_scanned", res.RecordsScanned),
			withExtra("records_without_paths", res.RecordsWithoutPaths),
			withExtra("capped", res.Capped),
			// No value is ever printed under --paths.
			withExtra("values_redacted", true),
			withRedacted(false),
		}
		opts = append(opts, provenance...)
		items, err := paramPathsShaping.apply(res.Paths)
		if err != nil {
			return err
		}
		return emitRead(cmd, "", items, res.Total, paramsFlags.offset, paramsFlags.limit, opts...)
	}

	if format == "tsv" {
		return paramPathsShaping.emitTSV(res.Paths)
	}
	if len(res.Paths) == 0 {
		fmt.Printf("%s No JSON body key paths found (%d records matched).\n", terminal.InfoSymbol(), res.RecordsScanned)
		return nil
	}
	fmt.Printf("%s Showing %d-%d of %d JSON body key paths (%d records)\n\n", terminal.InfoSymbol(),
		paramsFlags.offset+1, paramsFlags.offset+len(res.Paths), res.Total, res.RecordsScanned)
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "METHOD", "ENDPOINT", "KEY PATH", "TYPE", "SEEN")
	for _, p := range res.Paths {
		tbl.AddRow(
			p.Method,
			clicommon.Truncate(p.Origin+p.Template, 50),
			clicommon.Truncate(p.KeyPath, 40),
			p.JSONType,
			strconv.FormatInt(p.SampleCount, 10)+"/"+strconv.FormatInt(p.OperationRecords, 10),
		)
	}
	tbl.Print()
	fmt.Println()
	if res.Total > int64(len(res.Paths)) {
		warnIfCapped(len(res.Paths), res.Total)
	}
	return nil
}
