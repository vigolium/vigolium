package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium import -B` used to build its bridge query as {Location:
// "proxy_history"} with no filters at all — the CLI exposed none — so it copied
// every host the operator had ever browsed, carrying those hosts' cookies and
// tokens, into the destination database. Where that database is shared with an
// autonomous agent, that is a cross-engagement data leak (banking sessions,
// internal tools, an unrelated client's engagement) with nothing in front of it.
//
// `traffic -B` already had the whole filter set, so consumers routed around
// `import -B` entirely and used `traffic -B --host <h> --save-to-vigolium-db`
// instead. Three changes make the direct path safe to use:
//
//  1. The same filters `traffic -B` has, spelled the same way.
//  2. An unfiltered pull requires --all-hosts. Silence no longer means "all".
//  3. A pre-flight that says how many hosts and records are about to cross,
//     and on a TTY asks. Under --events it is emitted as an import.summary
//     event instead, so a driver reads the same fact without a prompt.
var (
	importBridgeHost     string
	importBridgePath     string
	importBridgeMethods  []string
	importBridgeStatus   []int
	importBridgeExclude  []string
	importBridgeFrom     string
	importBridgeTo       string
	importBridgeAllHosts bool
	importBridgeYes      bool
	importBridgeLimit    int
)

func registerImportBridgeFilterFlags(flags *pflag.FlagSet) {
	// --host is the one filter here that a path source honours too: a vigolium
	// SQLite source is merged narrowed to the host (importPathHosts). It stays a
	// single pattern because the bridge sends it to the listener as one string.
	flags.StringVar(&importBridgeHost, "host", "", "Import only records for this host (supports * wildcards, e.g. '*.example.com'): applies to a bridge pull and to a vigolium SQLite source, where findings are narrowed to the host too; one pattern per import")
	flags.StringVar(&importBridgePath, "path", "", "Import only records whose path matches this pattern")
	flags.StringSliceVar(&importBridgeMethods, "method", nil, "Import only these HTTP methods (comma-separated)")
	flags.IntSliceVar(&importBridgeStatus, "status", nil, "Import only these response status codes (comma-separated)")
	// --search is NOT declared here: `import` already owns that name for its
	// post-import report filter. The two cannot both exist, and they cannot
	// collide either — --format (and therefore the report) is rejected alongside
	// -B — so the bridge path reads the same flag's value instead of adding a
	// second spelling for one concept.
	flags.StringArrayVar(&importBridgeExclude, "exclude-search", nil, "Skip records matching this term (repeatable)")
	flags.StringVar(&importBridgeFrom, "from", "", "Import only records from this time onward (2d, 12h, today, YYYY-MM-DD, RFC3339)")
	flags.StringVar(&importBridgeTo, "to", "", "Import only records up to this time")
	flags.IntVarP(&importBridgeLimit, "limit", "n", 0, "Import at most N records (0 = no limit)")
	flags.BoolVar(&importBridgeAllHosts, "all-hosts", false,
		"Import the operator's ENTIRE proxy history, unfiltered. Required when no filter is given — an unfiltered pull copies every host ever browsed, with its cookies and tokens, into this database.")
	flags.BoolVar(&importBridgeYes, "yes", false, "Skip the pre-flight confirmation for a bridge import (the global --force does too)")
	addFlagAliases(importCmd, timeFilterAliases)
}

// importBridgeSearchTerm reads the shared --search flag. It is registered by
// runImport's report-filter block; under -B that block is unreachable (--format
// is rejected with a bridge source), so the value can only have been meant for
// the bridge query.
func importBridgeSearchTerm() string { return strings.TrimSpace(importSearchFilter) }

func importBridgeSearchTerms() []string {
	if term := importBridgeSearchTerm(); term != "" {
		return []string{term}
	}
	return nil
}

// importBridgeFiltersActive reports whether any narrowing filter was given.
func importBridgeFiltersActive() bool {
	return importBridgeHost != "" || importBridgePath != "" ||
		len(importBridgeMethods) > 0 || len(importBridgeStatus) > 0 ||
		importBridgeSearchTerm() != "" || len(importBridgeExclude) > 0 ||
		importBridgeFrom != "" || importBridgeTo != "" || importBridgeLimit > 0
}

// importBridgeFilterNames lists the filter flags, for the refusal message. A
// refusal that does not name the way out is a refusal the operator answers with
// --all-hosts, which is the one thing it exists to discourage.
//
// Written in the order it prints — grouping the record selectors before the time
// window before the budget reads better than alphabetical, and a runtime sort of
// a constant just makes the reader work out what the message says.
var importBridgeFilterNames = []string{
	"--host", "--path", "--method", "--status",
	"--search", "--exclude-search",
	"--from", "--to", "-n/--limit",
}

// buildImportBridgeQuery turns the filter flags into a bridge query, refusing an
// unfiltered pull that did not opt in with --all-hosts.
func buildImportBridgeQuery(projectUUID string) (burpbridge.Query, error) {
	if !importBridgeFiltersActive() && !importBridgeAllHosts {
		return burpbridge.Query{}, asUsageError(fmt.Errorf(
			"refusing to import the entire proxy history: it copies every host you have browsed — with those hosts' cookies and tokens — into this database.\n"+
				"Narrow it with %s, or pass %s to import everything on purpose",
			strings.Join(importBridgeFilterNames, " / "), "--all-hosts"))
	}

	dateFrom, dateTo, err := parseDateRangeFlags(importBridgeFrom, importBridgeTo,
		timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return burpbridge.Query{}, asUsageError(err)
	}

	// Built through QueryFromFilters — the same translation traffic -B uses —
	// rather than by hand, so a filter added to one path cannot silently go
	// missing on the other. That divergence is the whole reason this command was
	// unfiltered in the first place.
	filters := database.QueryFilters{
		ProjectUUID:  projectUUID,
		HostPattern:  importBridgeHost,
		PathPattern:  importBridgePath,
		Methods:      importBridgeMethods,
		StatusCodes:  importBridgeStatus,
		SearchTerms:  importBridgeSearchTerms(),
		ExcludeTerms: importBridgeExclude,
		DateFrom:     dateFrom,
		DateTo:       dateTo,
		Limit:        importBridgeLimit,
	}
	return burpbridge.QueryFromFilters(filters, false), nil
}

// preflightImportBridge reports what is about to cross into the database and,
// on an interactive terminal, asks. Returns false when the operator declines.
//
// It counts by asking the listener for one page and reading its total, so the
// count is the listener's own rather than an estimate — and it happens before
// any write, which is the point: an operator who sees "12,400 records across 380
// hosts" when they expected one host stops there.
func preflightImportBridge(ctx context.Context, client *burpbridge.Client, query burpbridge.Query) (bool, error) {
	probe := query
	probe.Limit = 1
	probe.Offset = 0
	probe.IncludeRaw = false
	page, err := client.Query(ctx, probe)
	if err != nil {
		return false, fmt.Errorf("bridge pre-flight: %w", err)
	}

	total := page.Total
	if query.Limit > 0 && total > int64(query.Limit) {
		total = int64(query.Limit)
	}

	if scanevents.On() {
		scanevents.Emit(scanevents.Event{
			Type:    scanevents.TypeImportSummary,
			Source:  page.Source,
			Matched: page.Total,
			Total:   scanevents.Int64(total),
		})
	}

	if total == 0 {
		fmt.Fprintf(os.Stderr, "%s no records match — nothing to import\n", terminal.InfoSymbol())
		return false, nil
	}

	scope := "filtered"
	if importBridgeAllHosts && !importBridgeFiltersActive() {
		scope = terminal.BoldRed("ENTIRE proxy history (every host you have browsed)")
	}
	fmt.Fprintf(os.Stderr, "%s about to import %s record(s) from %s — %s\n",
		terminal.InfoSymbol(), terminal.BoldYellow(fmt.Sprintf("%d", total)), page.Source, scope)

	// --yes, --force, and the machine output modes proceed without asking; the
	// refusal in buildImportBridgeQuery is the guard that survives all of them,
	// and this prompt is the second, interactive-only layer.
	//
	// Routed through the shared gate so this import is classified like every
	// other confirmation (a decline is a clean exit, a missing terminal is exit
	// 2 naming --force) rather than being the one prompt left outside it. The
	// force argument folds the pre-existing opt-outs in: a non-TTY still needs
	// no special case here, because Confirm checks for a terminal itself.
	if err := clicommon.Confirm("importing this traffic", importBridgeYes || globalForce || machineOutputMode()); err != nil {
		if errors.Is(err, clicommon.ErrAborted) || errors.Is(err, clicommon.ErrConfirmationRequired) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
