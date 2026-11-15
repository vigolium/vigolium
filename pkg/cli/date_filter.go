package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// timeFilterAliases are the alternate spellings every command carrying a
// --from/--to pair accepts.
var timeFilterAliases = map[string]string{"since": "from", "until": "to"}

// Error-message labels for the two bounds, derived from timeFilterAliases so a
// new alias can't leave a hand-written label stale — a wrong error string fails
// no test and crashes nothing.
var (
	timeFilterFromLabel = flagAliasLabel(timeFilterAliases, "from")
	timeFilterToLabel   = flagAliasLabel(timeFilterAliases, "to")
)

// registerTimeRangeFlags registers the standard --from/--to pair (with the
// --since/--until aliases) on cmd; what names the rows being bounded.
func registerTimeRangeFlags(cmd *cobra.Command, from, to *string, what string) {
	cmd.Flags().StringVar(from, "from", "", fmt.Sprintf("Only %s at or after this time — %s (alias: --since)", what, clicommon.TimeFilterSyntax))
	cmd.Flags().StringVar(to, "to", "", fmt.Sprintf("Only %s at or before this time — %s; %s (alias: --until)",
		what, clicommon.TimeFilterSyntax, clicommon.TimeFilterUpperBoundNote))
	addFlagAliases(cmd, timeFilterAliases)
}

// parseDateRangeFlags resolves a --from/--to (--since/--until) pair into query
// bounds. Either side may be empty, yielding a nil (unbounded) end. fromFlag and
// toFlag are display labels for the error message — pass flagAliasLabel's output
// so a command that accepts aliases names all of them.
func parseDateRangeFlags(from, to, fromFlag, toFlag string) (*time.Time, *time.Time, error) {
	var dateFrom, dateTo *time.Time
	if from != "" {
		t, err := clicommon.ParseSince(from)
		if err != nil {
			return nil, nil, usageErrorf("invalid %s: %w", fromFlag, err)
		}
		dateFrom = &t
	}
	if to != "" {
		t, err := clicommon.ParseUntil(to)
		if err != nil {
			return nil, nil, usageErrorf("invalid %s: %w", toFlag, err)
		}
		dateTo = &t
	}
	if dateFrom != nil && dateTo != nil && dateTo.Before(*dateFrom) {
		return nil, nil, usageErrorf(
			"%s (%s) is before %s (%s) — the range matches nothing",
			toFlag, clicommon.FormatTimeFilter(*dateTo),
			fromFlag, clicommon.FormatTimeFilter(*dateFrom))
	}
	return dateFrom, dateTo, nil
}

// flagAliases records each command's alias→canonical mapping. Keeping the
// aliases as data (rather than chained closures) is what lets repeated
// addFlagAliases calls compose: cobra's SetGlobalNormalizationFunc is an
// overwriting setter, so two independent closures racing for that one slot would
// leave whichever registered first silently dead.
var flagAliases = map[*cobra.Command]map[string]string{}

// addFlagAliases makes each alias resolve to its canonical flag name. A
// normalize func routes the spellings onto one flag; registering a second flag
// bound to the same variable would instead let one spelling silently overwrite
// the other. Installed globally so it reaches the merged parse-time set —
// --severity/--from/--to are persistent flags, which a func on
// PersistentFlags() alone would miss.
//
// Calls accumulate and are order-independent: the normalize func closes over the
// command's map, which later calls extend in place.
func addFlagAliases(cmd *cobra.Command, aliases map[string]string) {
	merged, installed := flagAliases[cmd]
	if !installed {
		merged = make(map[string]string, len(aliases))
		flagAliases[cmd] = merged
	}
	for alias, canonical := range aliases {
		merged[alias] = canonical
	}
	if installed {
		return
	}
	cmd.SetGlobalNormalizationFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if canonical, ok := merged[name]; ok {
			name = canonical
		}
		return pflag.NormalizedName(name)
	})
}

// flagAliasSpellings returns every alias that resolves to canonical, each
// already "--"-prefixed and sorted. It is the one place the alias table is
// walked for display, so a label and a usage-string note can never disagree
// about which spellings exist.
//
// Filtering on target matters: a table may carry aliases for several canonical
// flags, and an unfiltered walk would advertise another flag's spelling as this
// one's.
func flagAliasSpellings(aliases map[string]string, canonical string) []string {
	var spellings []string
	for alias, target := range aliases {
		if target == canonical {
			spellings = append(spellings, "--"+alias)
		}
	}
	sort.Strings(spellings) // map iteration order is random; the rendering must not be
	return spellings
}

// flagAliasLabel renders a flag and every alias that resolves to it, e.g.
// "--from/--since". Reading the same table the normalize func uses is what keeps
// the label honest; taking the alias map (rather than the command) also keeps it
// callable from the run path, which a *cobra.Command argument would not be —
// package-level command vars reference their own RunE.
func flagAliasLabel(aliases map[string]string, canonical string) string {
	return strings.Join(
		append([]string{"--" + canonical}, flagAliasSpellings(aliases, canonical)...), "/")
}
