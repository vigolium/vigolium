package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// --usage: one line per flag, read whole.
//
// A command's --help runs to 11-16 KB (fuzz, traffic) because it carries
// examples and long-form guidance. A caller that wants one flag's spelling
// piped it into grep or head and read a fragment; --usage prints every flag on
// one line — local flags first, then inherited — and nothing else, small
// enough to read in full. `vigolium schema flags <command>` is the same list as
// a -j document.

// globalUsage backs the persistent --usage flag. The flag is answered before
// cobra parses the command line (see runUsageIfRequested), so a command's
// required flags or arguments never stand between a caller and its flag list;
// it is registered so it is listed and so cobra never rejects it.
var globalUsage bool

// usageDescMax caps one flag's description on its line, after it is cut to its
// first clause.
const usageDescMax = 72

// flagUsageView is one flag, as `schema flags -j` lists it.
type flagUsageView struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
	Usage     string `json:"usage"`
	Inherited bool   `json:"inherited"`
	// Enum is the closed set of values the flag accepts; absent for an open
	// flag. A value outside it is a usage error.
	Enum []string `json:"enum,omitempty"`
}

// collectFlagUsage lists cmd's visible flags — local first, then inherited,
// each in name order — through collectFlags, the skill flag reference's
// walker, so both skip the same hidden and deprecated flags.
func collectFlagUsage(cmd *cobra.Command) []flagUsageView {
	var out []flagUsageView
	add := func(fs *pflag.FlagSet, inherited bool) {
		for _, f := range collectFlags(fs, nil) {
			if f.Name == "help" {
				continue
			}
			def := f.Default
			switch def {
			case "[]", "false", "0", `""`:
				def = ""
			}
			out = append(out, flagUsageView{
				Name: f.Name, Shorthand: f.Short, Type: f.Type, Default: def,
				Usage: f.Description, Inherited: inherited,
				Enum: flagEnumValues(fs.Lookup(f.Name)),
			})
		}
	}
	add(cmd.LocalFlags(), false)
	add(cmd.InheritedFlags(), true)
	return out
}

// writeCompactUsage prints the --usage view of cmd.
func writeCompactUsage(w io.Writer, cmd *cobra.Command) {
	var sb strings.Builder
	use := cmd.UseLine()
	fmt.Fprintf(&sb, "%s\n", use)
	if cmd.Short != "" {
		fmt.Fprintf(&sb, "%s\n", cmd.Short)
	}
	flags := collectFlagUsage(cmd)
	width := 0
	spell := func(f flagUsageView) string {
		s := "    --" + f.Name
		if f.Shorthand != "" {
			s = "-" + f.Shorthand + ", --" + f.Name
		}
		if f.Type != "bool" {
			s += " " + f.Type
		}
		return s
	}
	for _, f := range flags {
		if n := len(spell(f)); !f.Inherited && n > width {
			width = n
		}
	}
	// Global flags are the same on every command, so they are named on one
	// line rather than described again; `schema flags <command> -j` has them
	// in full.
	var globals []string
	fmt.Fprintln(&sb, "flags:")
	for _, f := range flags {
		if f.Inherited {
			globals = append(globals, "--"+f.Name)
			continue
		}
		desc := firstClause(f.Usage)
		desc = textutil.TruncateUTF8Ellipsis(desc, usageDescMax, "…")
		if f.Default != "" {
			desc += " (default " + f.Default + ")"
		}
		fmt.Fprintf(&sb, "  %-*s  %s\n", width, spell(f), desc)
	}
	if len(globals) > 0 {
		fmt.Fprintf(&sb, "global flags: %s\n", strings.Join(globals, " "))
	}
	if subs := visibleSubcommands(cmd); len(subs) > 0 {
		fmt.Fprintf(&sb, "subcommands: %s\n", strings.Join(subs, ", "))
	}
	_, _ = io.WriteString(w, sb.String())
}

// firstClause is a flag description up to its first sentence or clause break:
// enough to recognise the flag, which is what the usage view is for.
func firstClause(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	cut := len(s)
	for _, sep := range []string{". ", "; ", " — ", " - "} {
		if i := strings.Index(s, sep); i > 0 && i < cut {
			cut = i
		}
	}
	return strings.TrimSpace(s[:cut])
}

func visibleSubcommands(cmd *cobra.Command) []string {
	var out []string
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() {
			out = append(out, c.Name())
		}
	}
	return out
}

// runUsageIfRequested answers --usage before cobra parses the command line, and
// reports whether it did. -j/--json selects the `schema flags` document.
func runUsageIfRequested(root *cobra.Command, args []string) bool {
	var rest []string
	asked, asJSON := false, false
	for _, a := range args {
		if a == "--" {
			// Past "--" the tokens belong to someone else (a shim's tool argv).
			break
		}
		switch a {
		case "--usage":
			asked = true
			continue
		case "-j", "--json":
			asJSON = true
		}
		rest = append(rest, a)
	}
	if !asked {
		return false
	}
	cmd, _, err := root.Find(rest)
	if err != nil || cmd == nil {
		cmd = root
	}
	if asJSON {
		globalJSON = true
		if err := emitFlagUsageDocument(cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return true
	}
	writeCompactUsage(os.Stdout, cmd)
	return true
}

// emitFlagUsageDocument writes `schema flags <command> -j` for cmd.
func emitFlagUsageDocument(target *cobra.Command) error {
	flags := collectFlagUsage(target)
	return emitRead(schemaFlagsCmd, "", flags, int64(len(flags)), 0, len(flags),
		withExtra("for_command", commandPathWithoutRoot(target)))
}

var schemaFlagsCmd = &cobra.Command{
	Use:   "flags <command>",
	Short: "List one command's flags, one entry per flag (the --usage view as data)",
	Long: "List the flags of one command: name, shorthand, type, default, description, and whether it is " +
		"inherited from the root. The command is its path without `vigolium` (`schema flags traffic body`). " +
		"`vigolium <command> --usage` prints the same list as one line per flag.",
	Example: "  vigolium schema flags fuzz -j\n  vigolium fuzz --usage",
	Args:    cobra.MinimumNArgs(1),
}

func runSchemaFlags(_ *cobra.Command, args []string) error {
	target, _, err := rootCmd.Find(strings.Fields(strings.Join(args, " ")))
	if err != nil || target == nil || target == rootCmd {
		return usageErrorf("no command %q", strings.Join(args, " "))
	}
	if !globalJSON {
		writeCompactUsage(os.Stdout, target)
		return nil
	}
	return emitFlagUsageDocument(target)
}

func init() {
	// RunE is set here, not in the literal: it reaches back to schemaFlagsCmd
	// (the document's command) and rootCmd, which an initializer cannot.
	schemaFlagsCmd.RunE = runSchemaFlags
	schemaCmd.AddCommand(schemaFlagsCmd)
}
