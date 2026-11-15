package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// vocabularyAliases gives an idea the spelling it has elsewhere on the
// commands that name it differently: command path -> alias -> the command's
// own flag. Aliases only (renames would break scripts), routed through
// addFlagAliases so both spellings drive one flag. Deliberately absent:
//
//   - --yes for --force: an alias on the persistent --force would reach every
//     child and rewrite the local --yes on import, server ca and kit cookies,
//     which mean something else there (import honours --force as it is);
//   - --max-time on fuzz, where it is already the per-request budget;
//   - --to for db clean --before (--to snaps to the end of the day, which
//     would widen a DELETE), and --older-than/--new-since, which are not
//     ranges.
var vocabularyAliases = map[string]map[string]string{
	// The read filters' header/body search terms. -H/--header and -d/--data
	// send a header or a body; on the reads --header-search/--body-search say
	// what these flags do (replay already ships --header-search).
	"traffic": {
		"header-search": "header", "exclude-header-search": "exclude-header",
		"body-search": "body", "exclude-body-search": "exclude-body",
		"record-uuid": "uuid",
	},
	"finding": {
		"header-search": "header", "exclude-header-search": "exclude-header",
		"body-search": "body", "exclude-body-search": "exclude-body",
	},
	"db list": {"header-search": "header", "body-search": "body", "record-uuid": "uuid"},
	"replay":  {"body-search": "body", "exclude-body-search": "exclude-body"},

	// A stored record is --record-uuid where a command takes one.
	"db export":       {"record-uuid": "uuid"},
	"traffic body":    {"record-uuid": "uuid"},
	"traffic headers": {"record-uuid": "uuid"},

	// The body to send is -d/--data (fuzz, kit param-mine).
	"scan-url": {"data": "body"},
	// The method is -X/--method (kit param-mine, scan-url).
	"fuzz": {"method": "request"},

	// A whole-run budget is --max-time (the scan family's spelling).
	"agent query":     {"max-time": "max-duration"},
	"agent autopilot": {"max-time": "max-duration"},
	"agent swarm":     {"max-time": "max-duration"},
	"agent triage":    {"max-time": "max-duration"},
	"agent audit":     {"max-time": "max-duration"},
	"audit":           {"max-time": "max-duration"},
	"kit js-beautify": {"max-time": "deadline"},
	"scan wait":       {"max-time": "timeout"},

	// An output file is -o/--output.
	"server ca print":  {"output": "out"},
	"skills gen-flags": {"output": "out"},
}

// applyVocabularyAliases installs vocabularyAliases and names each alias in
// its flag's help. Called from prepareCommandTree; safe to call again.
func applyVocabularyAliases(root *cobra.Command) {
	walkTree(root, func(c *cobra.Command) {
		aliases, ok := vocabularyAliases[commandPathWithoutRoot(c)]
		if !ok {
			return
		}
		addFlagAliases(c, aliases)
		for alias, canonical := range aliases {
			f := c.Flags().Lookup(canonical)
			if f == nil || f.Name != canonical {
				continue
			}
			note := "--" + alias
			if !strings.Contains(f.Usage, note) {
				f.Usage += " (alias: " + note + ")"
			}
		}
	})
}
