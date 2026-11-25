package cli

import (
	"bufio"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Under VIGOLIUM_PINNED=1 every help surface — --help, --usage, --usage -j
// (`schema flags`), `skills get vigolium-scanner` and its embedded profile —
// shows only what the pin admits, and says so in one line (pinnedHelpNote).
// The refusal tables in pinned_env.go are the source: a flag the pin refuses
// whatever its value is hidden, a refused command is hidden, and the flags
// the pin narrows by value (--redirect-mode, --intensity, --max-module-tier,
// --set) stay listed because most of their values are admitted. Hiding is
// display only: a hidden flag or command still parses and still exits 2
// refused_by_policy with its hint.

// pinnedHelpNote is the line a pinned help surface ends with.
const pinnedHelpNote = "pinned session: refused flags are hidden; see error.hint on a refusal"

// pinnedHiddenFlags are the flags a pinned session never needs to see: every
// switch the pin refuses when on, and --config, which can only name the file
// VIGOLIUM_CONFIG already pins.
func pinnedHiddenFlags() []string {
	out := append([]string{"config"}, pinnedBoolWideners...)
	sort.Strings(out)
	return out
}

// pinnedHiddenCommands are the refused commands, sorted.
func pinnedHiddenCommands() []string {
	out := make([]string, 0, len(pinnedRefusedCommands))
	for path := range pinnedRefusedCommands {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// applyPinnedHelpView marks the refused flags and commands hidden across the
// tree rooted at root, so every renderer that skips hidden entries (cobra's
// templates, pflag's FlagUsages, collectFlags) drops them, and returns the
// function that restores what it changed. Execute applies it once, after the
// tree is complete, when the variable is on.
func applyPinnedHelpView(root *cobra.Command) (restore func()) {
	var undo []func()
	hide := func(f *pflag.Flag) {
		if f != nil && !f.Hidden {
			f.Hidden = true
			undo = append(undo, func() { f.Hidden = false })
		}
	}
	names := pinnedHiddenFlags()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, fs := range []*pflag.FlagSet{c.LocalFlags(), c.PersistentFlags()} {
			for _, name := range names {
				hide(fs.Lookup(name))
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	for _, path := range pinnedHiddenCommands() {
		if c, _, err := root.Find(strings.Fields(path)); err == nil && c != nil && c != root && !c.Hidden {
			c.Hidden = true
			undo = append(undo, func() { c.Hidden = false })
		}
	}
	return func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
}

// pinnedHelpFooter is the help template's last line under the pin, "" off it.
func pinnedHelpFooter() string {
	if !pinnedEnv() {
		return ""
	}
	return "\n" + pinnedHelpNote + "\n"
}

// pinnedRefusedText matches a refused flag or command where help prose and
// the skill bundle name it: `--ignore-scope`, `--config <path>`, `scan stop`.
// Exact tokens from the refusal tables, so prose about something else never
// matches; a word boundary keeps --config from matching --config-dir.
var pinnedRefusedText = func() *regexp.Regexp {
	var alts []string
	for _, f := range pinnedHiddenFlags() {
		alts = append(alts, "--"+regexp.QuoteMeta(f)+`\b(?:[^-]|$)`)
	}
	for _, c := range pinnedHiddenCommands() {
		alts = append(alts, `\b`+regexp.QuoteMeta(c)+`\b`)
	}
	return regexp.MustCompile(strings.Join(alts, "|"))
}()

// pinnedSkillView is skill markdown as a pinned session reads it: every line
// naming a refused flag or command is dropped — a shell command continued with
// `\` inside a fence goes whole — and the note is appended.
func pinnedSkillView(md string) string {
	var out strings.Builder
	sc := bufio.NewScanner(strings.NewReader(md))
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	inFence := false
	var unit []string
	flush := func() {
		if !slices.ContainsFunc(unit, pinnedRefusedText.MatchString) {
			for _, l := range unit {
				out.WriteString(l)
				out.WriteByte('\n')
			}
		}
		unit = unit[:0]
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			flush()
			inFence = !inFence
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}
		unit = append(unit, line)
		if inFence && strings.HasSuffix(strings.TrimSpace(line), `\`) {
			continue // the command goes on; judge it whole
		}
		flush()
	}
	flush()
	out.WriteString("\n> " + pinnedHelpNote + "\n")
	return out.String()
}
