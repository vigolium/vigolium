package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `traffic --group-by <field>` answers "how many records share this value"
// without shipping the records.
//
// The workaround it replaces was recorded repeatedly: dump the matching rows —
// as JSON through a pipe, or as an export read back by a script — and count them
// in the caller. One such chain spilled 235 KB to answer a question whose answer
// was a dozen integers; another grouped by hand in SQL against physical column
// names and got the column name wrong first. The counting is the cheap part; the
// materialization is the whole cost, and it is paid to learn a shape.
//
// The aggregate runs through the same QueryBuilder filters as the listing, so
// `--host x --status 200 --group-by method` describes exactly the rows
// `--host x --status 200` would have listed. See pkg/database/query_group.go.

var (
	trafficGroupBy    string
	trafficGroupLimit int
)

// defaultTrafficGroupLimit bounds the bucket list. A grouping is not
// automatically a summary — one recorded case turned 56 rows into 54 buckets —
// and the tail beyond this cap is reported as a count rather than dropped.
const defaultTrafficGroupLimit = 20

// trafficGroupConflicts are the flags that render records. --group-by replaces
// the rows with their shape, so pairing it with one of these is a request for
// two different outputs; saying so beats silently honoring whichever branch the
// control flow reaches first.
var trafficGroupConflicts = []string{
	"replay", "raw", "burp", "markdown", "tree", "tui",
	"save-to-burp", "save-to-vigolium-db",
}

// validateTrafficGroupFlags rejects what is knowable from the flags alone.
//
// `on` answers "did the operator ask for this behaviour", not "did they mention
// the flag": `--group-by host --raw=false` is a caller explicitly turning the
// conflicting renderer OFF, and rejecting it as a conflict told them to remove
// the very flag that resolved it.
func validateTrafficGroupFlags(on func(string) bool) error {
	if strings.TrimSpace(trafficGroupBy) == "" {
		return nil
	}
	if _, err := database.GroupRecordsByField(trafficGroupBy); err != nil {
		return usageErrorf("%v", err)
	}
	if trafficGroupLimit < 0 {
		return usageErrorf("--group-limit must be >= 0 (0 = every group), got %d", trafficGroupLimit)
	}
	for _, name := range trafficGroupConflicts {
		if on(name) {
			return usageErrorf("--group-by cannot be combined with --%s: one counts records, the other renders them", name)
		}
	}
	return nil
}

// runTrafficGroupBy executes the aggregate and renders it.
func runTrafficGroupBy(ctx context.Context, cmd *cobra.Command, db *database.DB, filters database.QueryFilters) error {
	grouping, err := database.NewQueryBuilder(db, filters).
		GroupRecordsBy(ctx, trafficGroupBy, trafficGroupLimit)
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}
	if globalJSON {
		// The project scope comes from the filters the query actually ran with,
		// not from a second resolve: two sources for "which project was this" can
		// disagree, and the envelope exists to be asserted against.
		return emitTrafficGroupJSON(cmd, grouping, filters.ProjectUUID)
	}
	printTrafficGrouping(grouping)
	return nil
}

// emitTrafficGroupJSON puts the buckets in the standard envelope.
//
// `items` is the bucket list, so `total` is the number of BUCKETS — the same
// relationship `items`/`total` has on every other command. The record count is a
// separate named field rather than an overloaded `total`, because a consumer
// dividing one by the other is asking a real question and must not be handed two
// different denominators under one name.
func emitTrafficGroupJSON(cmd *cobra.Command, g database.RecordGrouping, projectUUID string) error {
	env := newMachineEnvelope(cmd, "", g.Groups, g.DistinctGroups, 0, trafficGroupLimit)
	env.WithProjectScope(projectUUID)
	env.DBPath = resolvedReadDBPath()
	env.With("group_by", g.Field).
		With("total_records", g.TotalRecords).
		With("other_groups", g.OtherGroups).
		With("other_records", g.OtherRecords)
	// The follow-up is the listing this grouping summarizes, narrowed to the
	// largest bucket — a read, never a re-send.
	if len(g.Groups) > 0 {
		if flag := trafficFilterFlagFor[g.Field]; flag != "" {
			env.WithQuery("traffic", flag, g.Groups[0].Value, "--json", "--compact")
		}
	}
	return writeAgentJSON(env)
}

// trafficFilterFlagFor names the listing flag that selects one bucket, for the
// query hint. Every groupable field has an entry; the ones with no such flag map
// to "" on purpose, because a hint that cannot be run is worse than no hint and
// an ABSENT key is indistinguishable from a forgotten one.
// TestTrafficFilterFlagCoversEveryGroupableField holds the two tables together.
var trafficFilterFlagFor = map[string]string{
	"method":                "--method",
	"status_code":           "--status",
	"host":                  "--host",
	"source":                "--source",
	"scan_uuid":             "--scan-uuid",
	"response_content_type": "", // no listing filter for it
	"ip":                    "",
	"is_authenticated":      "",
}

func printTrafficGrouping(g database.RecordGrouping) {
	if len(g.Groups) == 0 {
		fmt.Printf("%s No HTTP records matched.\n", terminal.InfoSymbol())
		return
	}
	// Width is measured over the RENDERED label, not the raw value: the empty
	// bucket prints as "(none)", which is wider than the "" it stands for.
	labels := make([]string, len(g.Groups))
	width := 0
	for i, b := range g.Groups {
		labels[i] = clicommon.ValueOrNone(b.Value)
		if n := len(labels[i]); n > width {
			width = n
		}
	}
	width = min(width, 48)
	fmt.Printf("%s %d records in %d %s groups\n\n",
		terminal.InfoSymbol(), g.TotalRecords, g.DistinctGroups, g.Field)
	for i, b := range g.Groups {
		fmt.Printf("  %-*s  %6d\n", width, terminal.Truncate(labels[i], width), b.Count)
	}
	// The tail is stated, never dropped: a capped list that looks complete is the
	// failure mode this whole view exists to avoid.
	if g.OtherGroups > 0 {
		fmt.Printf("  %-*s  %6d  (in %d more groups; raise --group-limit)\n",
			width, "…", g.OtherRecords, g.OtherGroups)
	}
}
