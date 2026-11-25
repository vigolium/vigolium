package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `skills get vigolium-scanner --profile embedded` is the skill an agent
// embedded in another tool's session reads instead of the whole bundle: the
// safe verb set, each with its one-line purpose and examples, and the pointer
// to the machine contract `vigolium schema` already prints. It is generated
// from the command tree on every call — Short, Example and flags are the same
// data --help renders — so it names this build's verbs and nothing it does not
// have, and under VIGOLIUM_PINNED=1 it drops what the pin refuses as every
// other help surface does.

// skillProfileEmbedded is the --profile value.
const skillProfileEmbedded = "embedded"

// embeddedProfileMaxBytes bounds the profile; TestEmbeddedProfileSize holds it.
const embeddedProfileMaxBytes = 15 * 1024

// embeddedProfileMaxExamples caps the examples shown per verb.
const embeddedProfileMaxExamples = 3

// embeddedVerb is one verb of the profile. Prefer, when set, lists the
// examples naming it first (scan is taught through --only).
type embeddedVerb struct {
	Path   string
	Prefer string
}

// embeddedProfileVerbs is the safe verb set: send one request or a bounded
// phase, read the store, and inspect the contract. A path this build does not
// have is skipped, so a verb lands in the profile the release it lands in the
// tree.
var embeddedProfileVerbs = []embeddedVerb{
	{Path: "scan-url"},
	{Path: "scan", Prefer: "--only"},
	{Path: "scan status"},
	{Path: "scan wait"},
	{Path: "fuzz"},
	{Path: "replay"},
	{Path: "traffic"},
	{Path: "finding"},
	{Path: "finding verify"},
	{Path: "endpoints"},
	{Path: "kit param-mine"},
	{Path: "kit unlock-walk"},
	{Path: "ingest"},
	{Path: "auth lint"},
	{Path: "explain-argv"},
	{Path: "schema"},
}

// embeddedSkillProfile renders the profile for root.
func embeddedSkillProfile(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("---\nname: vigolium-scanner\n")
	b.WriteString("description: >-\n  Drive the vigolium CLI from an embedded agent session: send one request or\n" +
		"  one bounded phase, read findings and traffic back from the store, and read\n" +
		"  the machine contract. The safe verb set only.\n---\n\n")
	b.WriteString("# vigolium (embedded profile)\n\n")
	fmt.Fprintf(&b, "Generated from vigolium %s (commit %s) by `vigolium skills get vigolium-scanner --profile embedded`. "+
		"Regenerate it from the binary you run; do not edit it.\n\n", Version, embeddedProfileCommit())

	b.WriteString("## Contract\n\n")
	b.WriteString("- Add `-j` to any verb: one JSON document on stdout, logs on stderr. `vigolium schema` lists every " +
		"document; `vigolium schema command <name>` prints one; `vigolium schema error` prints the error envelope " +
		"and its closed `error.code` set. Branch on `error.code`, never on prose.\n")
	fmt.Fprintf(&b, "- Exit codes: `%d` ok, `%d` error, `%d` usage or policy refusal (`error.hint` carries the "+
		"command line that runs), `%d` fuzz match, `%d` gate tripped, `%d` ran but incomplete.\n",
		apicontract.ExitSuccess, apicontract.ExitError, apicontract.ExitUsageError, apicontract.ExitFuzzMatch,
		apicontract.ExitFailOnGate, apicontract.ExitIncomplete)
	b.WriteString("- `vigolium <verb> --usage` prints a verb's flags one per line; `--usage -j` is the same list as data.\n")
	b.WriteString("- A finding's `proof` (when its module states one) is a replayable recipe: `vigolium schema proof`.\n\n")

	b.WriteString("## Verbs\n")
	for _, v := range embeddedProfileVerbs {
		cmd, _, err := root.Find(strings.Fields(v.Path))
		if err != nil || cmd == nil || cmd == root || commandPathWithoutRoot(cmd) != v.Path || !cmd.IsAvailableCommand() {
			continue
		}
		fmt.Fprintf(&b, "\n### `vigolium %s`\n\n%s.\n\n```bash\n", v.Path, strings.TrimSuffix(cmd.Short, "."))
		for _, ex := range embeddedExamples(root, cmd, v) {
			b.WriteString(ex + "\n")
		}
		fmt.Fprintf(&b, "vigolium %s --usage\n```\n", v.Path)
	}
	if pinnedEnv() {
		b.WriteString("\n> " + pinnedHelpNote + "\n")
	}
	return b.String()
}

// embeddedExamples picks up to embeddedProfileMaxExamples of the example
// lines cmd's help carries (Example, then the Long text): single-line
// `vigolium …` commands that resolve to cmd or a visible subcommand of it and
// name only flags that command has and shows. Prefer-matching lines come
// first, then lines asking for -j, then the rest, each in help order.
func embeddedExamples(root, cmd *cobra.Command, v embeddedVerb) []string {
	var preferred, machine, rest []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(terminal.StripANSI(cmd.Example+"\n"+cmd.Long), "\n") {
		line := strings.TrimPrefix(strings.TrimSpace(raw), "$ ")
		if seen[line] || !strings.HasPrefix(line, "vigolium ") || strings.HasSuffix(line, `\`) ||
			!embeddedExampleFits(root, cmd, line) {
			continue
		}
		seen[line] = true
		switch {
		case v.Prefer != "" && strings.Contains(line, v.Prefer):
			preferred = append(preferred, line)
		case slices.Contains(strings.Fields(line), "-j"):
			machine = append(machine, line)
		default:
			rest = append(rest, line)
		}
	}
	out := append(append(preferred, machine...), rest...)
	if len(out) > embeddedProfileMaxExamples {
		out = out[:embeddedProfileMaxExamples]
	}
	return out
}

// embeddedExampleFits reports whether one example line is a single command
// that resolves to cmd or a visible subcommand of it and names only flags
// that command has and shows.
func embeddedExampleFits(root, cmd *cobra.Command, line string) bool {
	for _, op := range []string{"|", "&&", ";", ">", "<", "$(", "`", "…"} {
		if strings.Contains(line, op) {
			return false
		}
	}
	words := strings.Fields(strings.TrimPrefix(line, "vigolium "))
	found, _, err := root.Find(words)
	if err != nil || found == nil || !found.IsAvailableCommand() {
		return false
	}
	if found != cmd {
		if !strings.HasPrefix(commandPathWithoutRoot(found), commandPathWithoutRoot(cmd)+" ") {
			return false
		}
		cmd = found
	}
	for _, w := range words {
		if !strings.HasPrefix(w, "-") || w == "-" || w == "--" {
			continue
		}
		name := strings.TrimLeft(w, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		f := cmd.Flags().Lookup(name)
		if f == nil {
			f = cmd.InheritedFlags().Lookup(name)
		}
		if !strings.HasPrefix(w, "--") && len(name) == 1 {
			f = cmd.Flags().ShorthandLookup(name)
			if f == nil {
				f = cmd.InheritedFlags().ShorthandLookup(name)
			}
		}
		if f == nil || f.Hidden {
			return false
		}
	}
	return true
}

// embeddedProfileCommit is the build's commit, "unknown" for a build without
// one (a plain `go build`; `make build` stamps it).
func embeddedProfileCommit() string {
	if strings.TrimSpace(Commit) == "" {
		return "unknown"
	}
	return Commit
}
