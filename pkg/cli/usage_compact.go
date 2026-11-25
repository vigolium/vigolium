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
const usageDescMax = 100

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
	if pinnedEnv() {
		fmt.Fprintln(&sb, pinnedHelpNote)
	}
	_, _ = io.WriteString(w, sb.String())
}

// firstClause is a flag description up to its first sentence or clause break:
// enough to recognise the flag, which is what the usage view is for. A break
// inside parentheses does not count, so "(e.g. -H 'Auth: x')" survives whole,
// and neither does the full stop of an abbreviation (e.g., i.e., etc., vs.).
func firstClause(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
			continue
		case ')', ']':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth > 0 || i == 0 {
			continue
		}
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, ". ") && !endsWithAbbreviation(s[:i+1]):
			return strings.TrimSpace(s[:i])
		case strings.HasPrefix(rest, "; "), strings.HasPrefix(rest, " — "), strings.HasPrefix(rest, " - "):
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// usageAbbreviations end in a full stop that does not end a sentence.
var usageAbbreviations = []string{"e.g.", "i.e.", "etc.", "vs.", "approx.", "incl.", "no."}

// endsWithAbbreviation reports whether s (text up to and including a full
// stop) ends in an abbreviation rather than a sentence.
func endsWithAbbreviation(s string) bool {
	lower := strings.ToLower(s)
	for _, a := range usageAbbreviations {
		if strings.HasSuffix(lower, a) {
			before := len(lower) - len(a)
			if before == 0 || !isWordByte(lower[before-1]) {
				return true
			}
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || b == '-' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
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
//
// A command path that does not resolve (`vigolium bogus --usage`, `vigolium
// config bogus --usage`) is a usage error, returned for the caller to report:
// answering with the root's or the group's flags and exit 0 told the caller the
// command existed.
func runUsageIfRequested(root *cobra.Command, args []string) (bool, error) {
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
		return false, nil
	}
	if asJSON {
		globalJSON = true
	}
	cmd, err := resolveUsageTarget(root, rest)
	if err != nil {
		return true, err
	}
	if asJSON {
		if err := emitFlagUsageDocument(cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return true, nil
	}
	writeCompactUsage(os.Stdout, cmd)
	return true, nil
}

// resolveUsageTarget finds the command --usage describes, or the unknown
// command error for a path that names none.
func resolveUsageTarget(root *cobra.Command, args []string) (*cobra.Command, error) {
	cmd, rest, err := root.Find(args)
	if err != nil || cmd == nil {
		word := firstPositional(args)
		return nil, unknownSubcommandError(root, word, nearestSubcommand(root, word, true))
	}
	// A group given a word it does not know: the group's own Args say whether
	// the word is a filter it accepts or a subcommand that does not exist.
	if word := firstPositional(rest); word != "" && cmd.HasSubCommands() && cmd.Args != nil {
		if err := cmd.Args(cmd, []string{word}); err != nil {
			return nil, err
		}
	}
	return cmd, nil
}

// firstPositional is the first token that is not a flag, "" when there is none.
func firstPositional(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// emitFlagUsageDocument writes `schema flags <command> -j` for cmd.
func emitFlagUsageDocument(target *cobra.Command) error {
	flags := collectFlagUsage(target)
	opts := []envOpt{withExtra("for_command", commandPathWithoutRoot(target))}
	if pinnedEnv() {
		opts = append(opts, withExtra("policy", pinnedHelpNote))
	}
	return emitRead(schemaFlagsCmd, "", flags, int64(len(flags)), 0, len(flags), opts...)
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
