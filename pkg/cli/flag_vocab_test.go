package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// flagVocabViolations walks the prepared command tree and returns every
// breach of the flag vocabulary, keyed for the allow-list:
//
//   - "type:<name>": one long flag name has more than one Value.Type();
//   - "short:<letter>": one shorthand stands for more than one long name;
//   - "alias:<command>:<alias>": an alias (addFlagAliases) shadows a real
//     flag of the command or of a descendant.
func flagVocabViolations(root *cobra.Command) map[string]string {
	types := map[string]map[string][]string{}  // name -> type -> commands
	shorts := map[string]map[string][]string{} // letter -> name -> commands
	walkTree(root, func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		visit := func(f *pflag.Flag) {
			if types[f.Name] == nil {
				types[f.Name] = map[string][]string{}
			}
			types[f.Name][f.Value.Type()] = append(types[f.Name][f.Value.Type()], path)
			if f.Shorthand != "" {
				if shorts[f.Shorthand] == nil {
					shorts[f.Shorthand] = map[string][]string{}
				}
				shorts[f.Shorthand][f.Name] = append(shorts[f.Shorthand][f.Name], path)
			}
		}
		c.Flags().VisitAll(visit)
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			if c.Flags().Lookup(f.Name) == nil {
				visit(f)
			}
		})
	})
	out := map[string]string{}
	for name, byType := range types {
		if len(byType) > 1 {
			out["type:"+name] = describeSpread(byType)
		}
	}
	for letter, byName := range shorts {
		if len(byName) > 1 {
			out["short:"+letter] = describeSpread(byName)
		}
	}
	for key, where := range flagAliasShadows {
		out["alias:"+key] = "shadows a real flag on " + where
	}
	for c, aliases := range flagAliases {
		for alias := range aliases {
			walkTree(c, func(d *cobra.Command) {
				if hasRealFlagNamed(d, alias) {
					out["alias:"+commandPathWithoutRoot(c)+":"+alias] = "is a real flag on " + commandPathWithoutRoot(d)
				}
			})
		}
	}
	return out
}

func describeSpread(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		cmds := m[k]
		sort.Strings(cmds)
		if len(cmds) > 3 {
			cmds = append(cmds[:3:3], fmt.Sprintf("+%d", len(m[k])-3))
		}
		parts = append(parts, k+" ("+strings.Join(cmds, ", ")+")")
	}
	return strings.Join(parts, " | ")
}

// flagVocabAllowed are the vocabulary breaches that ship today, each with why
// it is not fixed by a rename (renames are out: they break every script). The
// list may only shrink: an entry that no longer breaches fails the test.
var flagVocabAllowed = map[string]string{
	// Shorthands.
	"short:S": "-S is --stateless everywhere; stateless-shorthand and scan-on-receive-shorthand are hidden tombstones carrying the letter (one injected, one retired)",
	"short:X": "-X is the method on kit param-mine (--method) and fuzz (--request, curl's spelling); fuzz also accepts --method",
	"short:a": "--advanced-options on scans, --all on traffic/replay, --anomaly on fuzz; each is the command's documented spelling",
	"short:c": "kit payload --class predates --concurrency's -c and is an offline listing with no concurrency",
	"short:f": "log --follow (tail -f) and db export --format; neither command has the other flag",
	"short:i": "audit --interactive (-i) predates --input; audit takes its source as a positional",
	"short:n": "-n is a count everywhere: rows (--limit), log lines (--tail), kit oast new --count",
	"short:o": "skills gen-flags --out is a hidden developer generator; --output elsewhere",
	"short:p": "fuzz --payload, the olium --prompt and kit jwt-crack --secret are each that tool's established spelling",

	// One long name, several types. Mostly a single value vs a repeatable list
	// of the same idea, which a caller types identically.
	"type:baseline":       "scan --baseline is a stored scan reference; replay --baseline is the switch to send the un-mutated request first",
	"type:concurrency":    "the scan family's --concurrency takes a phase qualifier (int|phase=int); single-phase commands take a plain int",
	"type:cookie":         "fuzz --cookie is one Cookie header (curl's -b); agent swarm --cookie is repeatable",
	"type:exclude":        "scope add/rm --exclude switches the rule to an exclude rule; export --exclude lists record types",
	"type:exclude-header": "repeatable on fuzz (headers dropped from the request), a single search term on the read filters",
	"type:header":         "-H/--header sends a header (repeatable); the read filters' --header is a search term (alias --header-search)",
	"type:id":             "finding --id selects a finding; module enable/disable --id switches the positional to module ids",
	"type:location":       "fuzz --location follows redirects (curl's -L); param-mine and params name a parameter location",
	"type:method":         "a list on the read filters, one method on a command that sends one request",
	"type:modules":        "kit js-beautify --modules is the bundle-module output selector; a module list on the scans",
	"type:only":           "--only is phases on the scans, record types on export and check names on doctor",
	"type:rate-limit":     "the scan family's dial takes a phase qualifier; fuzz and finding verify accept fractions; param-mine an int",
	"type:record-uuid":    "one record on the commands that send or read one; repeatable where a scan or swarm takes several",
	"type:remark":         "db list --remark is one filter term; endpoints/params take a repeatable list",
	"type:request":        "traffic body/headers --request selects the request side; fuzz --request is the method (-X)",
	"type:resume":         "scan --resume continues the last run; agent autopilot --resume names the session to continue",
	"type:save":           "replay --save is a switch; fuzz --save[=all] says which exchanges to keep",
	"type:scan-uuid":      "one scan on every read; export takes a list",
	"type:search":         "repeatable search terms on the reads; db/export/import take one",
	"type:secret":         "auth totp --secret is one seed; kit jwt-crack --secret is a repeatable candidate list",
	"type:source":         "a code path or record-source label (one value); kit harvest --source names harvest providers (a list)",
	"type:target":         "one target where a command takes one, repeatable where it takes several",
	"type:type":           "one type on module/extensions listings; a list on dns record types and params locations",
	"type:url":            "auth check --url is the one URL to probe; the read filters take a list",
	"type:uuid":           "one record on db export and traffic body/headers; a list on the listing reads",
	"type:wait":           "scan stop/agent cancel --wait is a switch; the oast pollers' --wait is how long to wait",
	"type:wordlist":       "kit jwt-crack --wordlist is one file; fuzz and param-mine take several",
}

// TestFlagVocabulary is the vocabulary guardrail: one long name has one type,
// one shorthand one long name, and no alias shadows a real flag on its command
// or a descendant — except the reasoned allow-list, which may only shrink.
func TestFlagVocabulary(t *testing.T) {
	prepareCommandTree(rootCmd)
	got := flagVocabViolations(rootCmd)
	for key, detail := range got {
		if _, ok := flagVocabAllowed[key]; !ok {
			t.Errorf("flag vocabulary breach %s: %s\n(rename the new flag, reuse the existing spelling, or add a reasoned entry to flagVocabAllowed)", key, detail)
		}
	}
	for key, reason := range flagVocabAllowed {
		if reason == "" {
			t.Errorf("flagVocabAllowed[%q] has no reason", key)
		}
		if _, ok := got[key]; !ok {
			t.Errorf("flagVocabAllowed lists %q, which no longer breaches: delete the entry", key)
		}
	}
}

// TestFlagVocabularyAliasRule: the alias check sees a real flag an alias
// would shadow on a descendant (Lookup alone normalises it away).
func TestFlagVocabularyAliasRule(t *testing.T) {
	root := &cobra.Command{Use: "vigolium"}
	parent := &cobra.Command{Use: "p"}
	child := &cobra.Command{Use: "c", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(parent)
	parent.AddCommand(child)
	parent.Flags().String("canonical", "", "")
	child.Flags().String("shadowed", "", "")
	addFlagAliases(parent, map[string]string{"shadowed": "canonical"})
	t.Cleanup(func() {
		delete(flagAliases, parent)
		delete(flagAliasShadows, "p:shadowed")
	})
	require.Contains(t, flagVocabViolations(parent), "alias:p:shadowed")
}

// literalPaceDefault matches a speed-dial flag registered with a numeric
// literal default.
var literalPaceDefault = regexp.MustCompile(`"(rate-limit|concurrency|max-per-host)",\s*("[A-Za-z]",\s*)?-?[0-9]`)

// TestPaceDefaultsAreNamedConstants: a rate or concurrency default is a named
// constant, so one place says what each command sends at.
func TestPaceDefaultsAreNamedConstants(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for i, line := range strings.Split(string(src), "\n") {
			if literalPaceDefault.MatchString(line) {
				t.Errorf("%s:%d registers a speed dial with a literal default; name it (pace_flag.go): %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A child no longer inherits the listing's filters, which it ignored: a filter
// given to a subcommand is an unknown flag (a usage error), not a silent no-op.
func TestListingFiltersAreLocal(t *testing.T) {
	prepareCommandTree(rootCmd)
	for _, argv := range [][]string{
		{"finding", "--severity", "high", "mark", "4", "confirmed"},
		{"finding", "mark", "4", "confirmed", "--severity", "high"},
		{"finding", "show", "4", "--limit", "5"},
		{"finding", "load", "x.json", "--host", "a"},
		{"traffic", "body", "rec", "--host", "a"},
		{"traffic", "headers", "rec", "--status", "200"},
		{"db", "compact", "--search", "x"},
		{"db", "stats", "--table", "findings"},
		{"db", "migrate", "--watch", "5s"},
	} {
		c, rest, err := rootCmd.Find(argv)
		require.NoError(t, err, argv)
		perr := c.ParseFlags(rest)
		require.Error(t, perr, "%v must reject the listing's filter", argv)
		require.Contains(t, perr.Error(), "unknown flag", argv)
		c.Flags().VisitAll(resetFlagToDefault)
	}
	// What the children do read is theirs.
	for _, argv := range [][]string{
		{"finding", "verify", "--scan-uuid", "latest"},
		{"db", "list", "--search", "x", "--table", "findings", "--watch", "5s"},
		{"db", "export", "--search", "x"},
		{"db", "clean", "--search", "x"},
		{"db", "stats", "--watch", "5s"},
	} {
		c, rest, err := rootCmd.Find(argv)
		require.NoError(t, err, argv)
		require.NoError(t, c.ParseFlags(rest), argv)
		c.Flags().VisitAll(resetFlagToDefault)
	}
	findingScanUUID, dbSearch, globalTable, globalWatchRaw = "", "", "", ""
}
