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
		"root are listed once, as global_value_flags. Name a command to get its row alone.",
	Example: "  vigolium schema commands -j\n  vigolium schema commands scan stop -j",
	Args:    cobra.ArbitraryArgs,
	RunE:    runSchemaCommands,
}

func init() {
	schemaCmd.AddCommand(schemaCommandsCmd)
	registerCommandSchema(contract.Command{Name: "schema commands", Item: commandTraitView{}, Extras: schemaCommandsExtras{},
		Description: "One row per command: kind, db (none/read/write), reads_store, mutates, writes_global, sends_traffic, read_only_flag and value_flags; global_value_flags are the root's."})
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
}

// schemaCommandsExtras are `schema commands -j`'s top-level keys.
type schemaCommandsExtras struct {
	// GlobalValueFlags are the root's persistent value-taking flags, which
	// every command accepts.
	GlobalValueFlags []string `json:"global_value_flags"`
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
		return emitRead(cmd, "", rows, int64(len(rows)), 0, len(rows), withExtra("global_value_flags", global))
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
		fmt.Printf("%-28s %-12s db:%-6s %s\n", terminal.Cyan(r.Command), r.Kind, r.DB, strings.Join(traits, ","))
	}
	fmt.Fprintf(os.Stderr, "\n%s %d commands; -j adds value_flags and global_value_flags\n", terminal.InfoSymbol(), len(rows))
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
	}
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
