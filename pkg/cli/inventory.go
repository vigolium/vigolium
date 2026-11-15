package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// inventory.go holds what `vigolium endpoints` and `vigolium params` share:
// the record filter flags (the same predicate set `traffic` uses, so a filter
// means the same thing on all three) and the --scan-uuid provenance check.

// inventoryFlags is one inventory command's filter flags. Each command owns an
// instance, so the two never share state.
type inventoryFlags struct {
	host     string
	methods  []string
	status   []int
	path     string
	source   string
	remarks  []string
	scanUUID string
	from, to string
	limit    int
	offset   int
}

// register adds the filter, paging and read-source flags. noun names what -n
// counts ("endpoints", "parameters").
func (f *inventoryFlags) register(cmd *cobra.Command, noun string) {
	fl := cmd.Flags()
	fl.StringVar(&f.host, "host", "", "Filter by host: hostname, host:port, origin (https://host[:port]) or bracketed IPv6; * wildcards")
	fl.StringSliceVar(&f.methods, "method", nil, "Filter by HTTP method (repeatable)")
	fl.IntSliceVar(&f.status, "status", nil, "Filter by HTTP status code (repeatable)")
	fl.StringVar(&f.path, "path", "", "Filter by URL path pattern (wildcard supported)")
	fl.StringVar(&f.source, "source", "", "Filter by record source (e.g. scanner, deparos, jstangle, html-form, api-spec, ingest-cli, ingest-proxy)")
	fl.StringArrayVar(&f.remarks, "remark", nil, "Keep records carrying a remark containing this text (repeatable, AND-combined; e.g. --remark jstangle: for JS-derived records, --remark jstangle:not_found)")
	fl.StringVar(&f.scanUUID, "scan-uuid", "", "Only records first stored by this scan (http_records.scan_uuid; records deduplicated against an earlier scan keep that scan's uuid)")
	fl.StringVar(&f.from, "from", "", fmt.Sprintf(
		"Only records sent at or after this time — %s (alias: --since)", clicommon.TimeFilterSyntax))
	fl.StringVar(&f.to, "to", "", fmt.Sprintf(
		"Only records sent at or before this time — %s; %s (alias: --until)",
		clicommon.TimeFilterSyntax, clicommon.TimeFilterUpperBoundNote))
	fl.IntVarP(&f.limit, "limit", "n", 100, fmt.Sprintf("Maximum %s to list (0 = all); the aggregate always covers every matched record", noun))
	fl.IntVar(&f.offset, "offset", 0, fmt.Sprintf("Number of %s to skip (for pagination)", noun))
	fl.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
	fl.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
	fl.BoolVar(&globalGlobStrict, "glob-strict", false, "Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning")
	registerJSONOutputFlag(cmd)
	addFlagAliases(cmd, timeFilterAliases)
}

// validate rejects what the flags alone make impossible, before any open.
func (f *inventoryFlags) validate() error {
	if f.limit < 0 {
		return usageErrorf("-n/--limit must be >= 0 (0 = all), got %d", f.limit)
	}
	if f.offset < 0 {
		return usageErrorf("--offset must be >= 0, got %d", f.offset)
	}
	return nil
}

// filters builds the record filters. Limit/Offset page the inventory, not the
// records, so they are not set here.
func (f *inventoryFlags) filters(fuzzyTerm string) (database.QueryFilters, error) {
	dateFrom, dateTo, err := parseDateRangeFlags(f.from, f.to, timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return database.QueryFilters{}, err
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}
	return database.QueryFilters{
		ProjectUUID: projectUUID,
		HostPattern: f.host,
		Methods:     f.methods,
		StatusCodes: f.status,
		PathPattern: f.path,
		Source:      f.source,
		Remarks:     nonBlankStrings(f.remarks),
		ScanUUID:    strings.TrimSpace(f.scanUUID),
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		FuzzyTerm:   fuzzyTerm,
	}, nil
}

func nonBlankStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// inventorySkipSet: an inventory reads light record columns and the findings
// table (endpoint finding counts), so a --glob-db merge may drop the record
// bodies unless a filter LIKEs over them.
func inventorySkipSet(filters database.QueryFilters) globDBSkipSet {
	return globDBSkipSet{
		RecordBodies:  !filters.UsesRawCorpus(),
		RecordFileMap: true,
	}
}

// inventoryPositional routes the optional positional argument: "ls"/"list" are
// no-ops, anything else is the fuzzy search term traffic uses.
func inventoryPositional(args []string) string {
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "ls", "list":
			return ""
		default:
			return args[0]
		}
	}
	return ""
}

// Provenance warning codes for an empty --scan-uuid read.
const (
	provenanceScanNotFound   = "scan_not_found"
	provenanceScanNotStamped = "scan_uuid_not_stamped"
)

// scanProvenanceWarning explains a --scan-uuid read that matched nothing,
// instead of letting it read as "this scan saw no traffic". It returns "" when
// the scan does have stamped records (the other filters excluded them).
//
// Records are stamped with the scan that first stored them, on insert only.
// A scan from before stamping, or one whose every exchange was already stored
// by an earlier scan, has none; a time window is then the only selector.
func scanProvenanceWarning(ctx context.Context, db *database.DB, projectUUID, scanUUID string) (code, detail string) {
	if scanUUID == "" || db == nil {
		return "", ""
	}
	repo := database.NewRepository(db)
	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return provenanceScanNotFound, fmt.Sprintf("no scan %s in this database", scanUUID)
		}
		return "", ""
	}
	n, err := repo.CountRecordsForScan(ctx, projectUUID, scanUUID)
	if err != nil || n > 0 {
		return "", ""
	}
	window := "--from <scan start> --to <scan end>"
	if !scan.StartedAt.IsZero() {
		end := scan.FinishedAt
		if end.IsZero() {
			end = time.Now()
		}
		window = "--from " + scan.StartedAt.UTC().Format(time.RFC3339) + " --to " + end.UTC().Format(time.RFC3339)
	}
	return provenanceScanNotStamped, fmt.Sprintf(
		"scan %s exists but no record carries its scan_uuid: it predates record stamping, or every exchange it made was already stored by an earlier scan. Select its time window instead: %s",
		scanUUID, window)
}

// noteProvenance prints the provenance warning to stderr (never stdout, so a
// -j document stays clean) and returns the envelope option carrying it.
func noteProvenance(code, detail string) []envOpt {
	if code == "" {
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(), detail)
	return []envOpt{withExtra("provenance_warning", code), withExtra("provenance_detail", detail)}
}

// templatePlaceholder matches a pathshape / collapse placeholder segment.
var templatePlaceholder = regexp.MustCompile(`\{[^/{}]*\}`)

// templatePathGlob turns an endpoint template into a `traffic --path` glob:
// every placeholder becomes *, and a trailing * keeps stored paths that carry
// a query string. The glob over-matches by design (a * also matches /users/me);
// it is a follow-up, not a definition.
func templatePathGlob(template string, withQuery bool) string {
	glob := templatePlaceholder.ReplaceAllString(template, "*")
	if withQuery && !strings.HasSuffix(glob, "*") {
		glob += "*"
	}
	return glob
}
