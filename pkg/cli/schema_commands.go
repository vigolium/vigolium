package cli

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium schema commands` publishes commandTraits: for every command, what
// it does to the store, to user-global state and to targets, and which of its
// flags take a value. A driver that guards vigolium invocations (which may
// send traffic, which may change shared state, which argv token is a flag's
// value rather than a target) generates its tables from this document instead
// of maintaining a copy that drifts every release.

var schemaCommandsCmd = &cobra.Command{
	Use:   "commands [command]",
	Short: "List every command's traits: store use, global writes, traffic, value-taking flags",
	Long: "List every command with the traits the machine contract declares for it (command_traits.go): " +
		"its -j kind, what it does with the store (db: none, read, write), whether it may change persistent " +
		"state (mutates), whether it writes user-global state shared across engagements (writes_global: the " +
		"config file and scope, skills installs, the binary, another run's session), whether its job is to send " +
		"requests to a target (sends_traffic), and the flags that take a value. Value flags inherited from the " +
		"root are listed once, as global_value_flags. Each row also names every other spelling of the command " +
		"(aliases, `run <phase>` included), the argv words that name a target and their kind (targets), and how far " +
		"it reaches (reach: none, line, store, unbounded) with the flags that change that (reach_flags; each set flag " +
		"replaces the reach, in order), the scan pipeline it runs (pipeline: full or single-request) and, for a tool " +
		"shim or a phase front door, the native lines it runs as (translates_to). `vigolium explain-argv -j -- <argv...>` answers the same for one command " +
		"line. Name a command to get its row alone.",
	Example: "  vigolium schema commands -j\n  vigolium schema commands scan stop -j",
	Args:    cobra.ArbitraryArgs,
	RunE:    runSchemaCommands,
}

func init() {
	schemaCmd.AddCommand(schemaCommandsCmd)
	registerCommandSchema(contract.Command{Name: "schema commands", Item: commandTraitView{}, Extras: schemaCommandsExtras{},
		Description: "One row per command: kind, db (none/read/write), reads_store, mutates, writes_global, sends_traffic, read_only_flag, value_flags, aliases (every other spelling, `run <phase>` included), targets (the flag or positional naming a target, and its kind: url, host, file, input, record_uuid, scan_uuid, finding_id), reach (none, line, store, unbounded), reach_flags (each set flag replaces the reach, in order), pipeline (full or single-request, on the commands that run the scan pipeline) and translates_to (the native lines a shim or phase front door runs as); global_value_flags are the root's, global_reach_flags apply to every command."})
}

// commandTraitView is one command's row of `schema commands -j`.
type commandTraitView struct {
	// Command is the cobra path without `vigolium`.
	Command string `json:"command"`
	// Kind is the -j output it owes: read, mutation, scan, stream or
	// interactive.
	Kind string `json:"kind"`
	// DB is what it does with the store: none, read (the read-only pool) or
	// write (the read-write store).
	DB string `json:"db"`
	// ReadsStore: it opens the store (db read or write).
	ReadsStore bool `json:"reads_store"`
	// Mutates: it may change persistent state — a mutation document, the
	// read-write store, or user-global state. Conservative: a guard that
	// treats it as "may write" is never wrong.
	Mutates bool `json:"mutates"`
	// WritesGlobal: it changes user-global state shared by every engagement
	// on the machine (see commandTrait.WritesGlobal).
	WritesGlobal bool `json:"writes_global"`
	// SendsTraffic: its job is to send requests to a target.
	SendsTraffic bool `json:"sends_traffic"`
	// ReadOnlyFlag: it accepts --read-only.
	ReadOnlyFlag bool `json:"read_only_flag"`
	// ValueFlags are the flags that consume the next argv token as their value
	// (--name and -x forms; hidden flags included, since argv may carry them),
	// local and inherited from a parent group, without the root's
	// global_value_flags.
	ValueFlags []string `json:"value_flags"`
	// Aliases are every other spelling of the command path (each segment by
	// its name or an alias); `run` lists `run <phase>` for every phase
	// spelling it accepts.
	Aliases []string `json:"aliases"`
	// Targets are the argv words that name a target, and of what kind
	// (command_reach.go).
	Targets []targetSpec `json:"targets"`
	// Reach is how far the command reaches by default: none, line, store or
	// unbounded.
	Reach string `json:"reach"`
	// ReachFlags change Reach when set: applied in order, the last
	// applicable entry wins. global_reach_flags apply to every command.
	ReachFlags []reachFlag `json:"reach_flags"`
	// ReachNote says what the reach or a target means where the words alone
	// do not.
	ReachNote string `json:"reach_note,omitempty"`
	// Pipeline is the scan pipeline the command runs: full (the phase
	// pipeline --only, --skip and --strategy select from: scan, run,
	// fingerprint) or single-request (the one request the line names:
	// scan-url, scan-request). Absent on every other command.
	Pipeline string `json:"pipeline,omitempty" jsonschema:"enum=full,enum=single-request"`
	// TranslatesTo lists every native command line the command runs as,
	// whatever else its argv says (`<command>` or `run <canonical phase>`): a
	// tool shim's translations, and `run fingerprint` for `fingerprint`.
	TranslatesTo []string `json:"translates_to,omitempty"`
}

// schemaCommandsExtras are `schema commands -j`'s top-level keys.
type schemaCommandsExtras struct {
	// GlobalValueFlags are the root's persistent value-taking flags, which
	// every command accepts.
	GlobalValueFlags []string `json:"global_value_flags"`
	// GlobalReachFlags reach none on every command that accepts them
	// (--help, --usage, --dry-run): they print and exit.
	GlobalReachFlags []reachFlag `json:"global_reach_flags"`
}

func runSchemaCommands(cmd *cobra.Command, args []string) error {
	rows := commandTraitRows(rootCmd)
	if len(args) > 0 {
		want := strings.Join(strings.Fields(strings.Join(args, " ")), " ")
		var one []commandTraitView
		for _, r := range rows {
			if r.Command == want {
				one = append(one, r)
			}
		}
		if len(one) == 0 {
			return usageErrorf("no command %q (`vigolium schema commands` lists them)", want)
		}
		rows = one
	}
	global := valueFlagNames(rootCmd.PersistentFlags(), nil)
	if globalJSON {
		return emitRead(cmd, "", rows, int64(len(rows)), 0, len(rows), withExtra("global_value_flags", global),
			withExtra("global_reach_flags", publishedGlobalReachFlags()))
	}
	for _, r := range rows {
		var traits []string
		for _, t := range []struct {
			on   bool
			name string
		}{{r.Mutates, "mutates"}, {r.WritesGlobal, "writes-global"}, {r.SendsTraffic, "sends-traffic"}} {
			if t.on {
				traits = append(traits, t.name)
			}
		}
		fmt.Printf("%-28s %-12s db:%-6s reach:%-9s %s\n", terminal.Cyan(r.Command), r.Kind, r.DB, r.Reach, strings.Join(traits, ","))
	}
	fmt.Fprintf(os.Stderr, "\n%s %d commands; -j adds value_flags, aliases, targets and reach_flags\n", terminal.InfoSymbol(), len(rows))
	return nil
}

// commandTraitRows walks the command tree and returns one row per declared
// command, sorted by path. A command missing from commandTraits is skipped
// here; the coverage test fails on it.
func commandTraitRows(root *cobra.Command) []commandTraitView {
	rootFlags := root.PersistentFlags()
	var rows []commandTraitView
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		if t, ok := commandTraits[path]; ok && c != root {
			rows = append(rows, traitView(path, t, c, rootFlags))
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Command < rows[j].Command })
	return rows
}

func traitView(path string, t commandTrait, c *cobra.Command, rootFlags *pflag.FlagSet) commandTraitView {
	local := valueFlagNames(c.LocalFlags(), rootFlags)
	inherited := valueFlagNames(c.InheritedFlags(), rootFlags)
	flags := append(local, inherited...)
	sort.Strings(flags)
	flags = slices.Compact(flags)
	reach, targets, reachFlags, note := reachOf(path, c)
	return commandTraitView{
		Command:      path,
		Kind:         string(t.Kind),
		DB:           t.DB.String(),
		ReadsStore:   t.DB == dbRead || t.DB == dbWrite,
		Mutates:      t.Kind == kindMutation || t.DB == dbWrite || t.WritesGlobal,
		WritesGlobal: t.WritesGlobal,
		SendsTraffic: t.SendsTraffic,
		ReadOnlyFlag: t.ReadOnly,
		ValueFlags:   flags,
		Aliases:      commandAliases(c),
		Targets:      targets,
		Reach:        reach,
		ReachFlags:   reachFlags,
		ReachNote:    note,
		Pipeline:     pipelineOf(c),
		TranslatesTo: translatesTo(path),
	}
}

// publishedGlobalReachFlags is globalReachFlags as published, dashed.
func publishedGlobalReachFlags() []reachFlag {
	out := make([]reachFlag, 0, len(globalReachFlags))
	// cobra adds --help (-h) to each command's own flag set on first use.
	rootCmd.InitDefaultHelpFlag()
	for _, f := range globalReachFlags {
		pf := rootCmd.PersistentFlags().Lookup(f.Flag)
		if pf == nil {
			pf = rootCmd.Flags().Lookup(f.Flag)
		}
		if pf != nil && pf.Shorthand != "" {
			f.Short = "-" + pf.Shorthand
		}
		f.Flag = "--" + f.Flag
		out = append(out, f)
	}
	return out
}

// valueFlagNames lists the flags in fs that take a value, as "--name" and
// "-x", skipping those also defined in exclude (the root's, reported once).
// A flag takes a value unless it has a no-option default (bool and count
// flags do: `--flag` alone sets them).
func valueFlagNames(fs, exclude *pflag.FlagSet) []string {
	out := []string{}
	fs.VisitAll(func(f *pflag.Flag) {
		if f.NoOptDefVal != "" {
			return
		}
		if exclude != nil && exclude != fs && exclude.Lookup(f.Name) != nil {
			return
		}
		out = append(out, "--"+f.Name)
		if f.Shorthand != "" {
			out = append(out, "-"+f.Shorthand)
		}
	})
	sort.Strings(out)
	return out
}
