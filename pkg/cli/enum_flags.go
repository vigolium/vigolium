package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/olium"
)

// closedValueFlag declares one flag whose values form a closed set. Applied by
// applyClosedValueFlags from prepareCommandTree, once every init() has
// registered its flags, so the table can name flags from any file.
type closedValueFlag struct {
	path, flag string
	values     func() []string
	opts       []enumOpt
}

// closedValueFlags is every flag with a closed value set outside the ones a
// command validates itself. Unchecked, a typo answers "total: 0" (a filter
// that matched nothing) or is ignored (a sort key), both indistinguishable from
// a real empty result.
var closedValueFlags = []closedValueFlag{
	// Severity filters that normalise shorthands and prefixes ('h,c', 'me').
	{"finding", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumAccept(isSeverityToken)}},
	{"db list", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumAccept(isSeverityToken)}},
	// Severity filters compared verbatim against the stored value.
	{"db export", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumCaseSensitive()}},
	{"db clean", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumCaseSensitive()}},
	{"export", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumCaseSensitive()}},
	{"import", "severity", severityValues, []enumOpt{enumAllowEmpty(), enumCommaList(), enumCaseSensitive()}},

	{"finding", "sort", func() []string { return database.FindingSortKeys }, []enumOpt{enumAllowEmpty()}},
	{"traffic", "sort", func() []string { return database.RecordSortKeys }, []enumOpt{enumAllowEmpty()}},
	{"replay", "sort", func() []string { return database.RecordSortKeys }, []enumOpt{enumAllowEmpty()}},
	// db list sorts records or findings, depending on what it lists.
	{"db list", "sort", dbListSortKeys, []enumOpt{enumAllowEmpty()}},

	{"module", "type", moduleTypeValues, nil},
	{"module ls", "type", moduleTypeValues, nil},

	{"fuzz", "mode", func() []string { return []string{"sniper", "batteringram", "pitchfork", "clusterbomb"} },
		[]enumOpt{enumAccept(func(v string) bool { _, err := fuzz.ParseAttackMode(v); return err == nil })}},
}

func severityValues() []string { return severityOrder }

// isSeverityToken reports whether v names a severity, by its full name, a
// single-letter shorthand or an unambiguous prefix.
func isSeverityToken(v string) bool {
	return severityRank(normalizeSeverity(v)) > 0
}

func moduleTypeValues() []string { return []string{"all", "active", "passive"} }

func dbListSortKeys() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range append(append([]string(nil), database.RecordSortKeys...), database.FindingSortKeys...) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// registerOliumProviderFlag registers the olium --provider override as a
// closed-set flag over the providers the runtime accepts.
func registerOliumProviderFlag(fs *pflag.FlagSet, p *string, usage string) {
	fs.StringVar(p, "provider", "", usage)
	enumFlag(fs, "provider", olium.ProviderNames, enumAllowEmpty(),
		enumAccept(func(v string) bool { return olium.IsKnownProvider(v) }))
}

// applyClosedValueFlags converts every flag in closedValueFlags into an enum
// flag.
func applyClosedValueFlags(root *cobra.Command) {
	byPath := map[string][]closedValueFlag{}
	for _, cv := range closedValueFlags {
		byPath[cv.path] = append(byPath[cv.path], cv)
	}
	walkTree(root, func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		for _, cv := range byPath[path] {
			fs := c.Flags()
			if c.PersistentFlags().Lookup(cv.flag) != nil {
				fs = c.PersistentFlags()
			}
			enumFlag(fs, cv.flag, cv.values(), cv.opts...)
		}
	})
}
