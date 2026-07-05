package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// globalsFixture returns the real root persistent (global) flags that every
// subcommand inherits, so the help renderers are exercised against the actual
// flag surface rather than a hand-copied duplicate that can silently drift.
func globalsFixture() *pflag.FlagSet {
	return rootCmd.PersistentFlags()
}

func TestGroupedFlagUsages_PipedIsTerse(t *testing.T) {
	defer terminal.SetIsTerminal(terminal.IsTerminal())
	terminal.SetIsTerminal(false) // simulate a pipe / agent / CI

	out := groupedFlagUsages(globalsFixture())

	// One logical line: heading, hint flags, and a pointer to the full list.
	if lines := strings.Count(strings.TrimRight(out, "\n"), "\n"); lines != 0 {
		t.Fatalf("terse output should be a single line, got %d newlines:\n%s", lines, out)
	}
	if !strings.Contains(out, "Global Flags:") {
		t.Errorf("terse output missing heading:\n%s", out)
	}
	if !strings.Contains(out, "run 'vigolium --help'") {
		t.Errorf("terse output missing pointer to full help:\n%s", out)
	}
	// Hint flags render with their shorthand when present.
	for _, want := range []string{"-v/--verbose", "-j/--json", "--proxy", "-F/--force"} {
		if !strings.Contains(out, want) {
			t.Errorf("terse output missing hint %q:\n%s", want, out)
		}
	}
}

func TestGroupedFlagUsages_TTYIsFull(t *testing.T) {
	defer terminal.SetIsTerminal(terminal.IsTerminal())
	terminal.SetIsTerminal(true) // simulate an interactive terminal

	out := groupedFlagUsages(globalsFixture())

	// The full grouped block keeps its section headings and flag descriptions.
	for _, want := range []string{"Global Flags:", "Network:", "Output:", "Route all requests through this proxy"} {
		if !strings.Contains(out, want) {
			t.Errorf("full output missing %q:\n%s", want, out)
		}
	}
	// A pointer stand-in has no place in the full block.
	if strings.Contains(out, "run 'vigolium --help'") {
		t.Errorf("full output should not contain the terse pointer:\n%s", out)
	}
}

// ungroupedVisibleFlags returns the non-hidden flag names in fs that no group in
// groups covers, ignoring cobra's auto-added --help (which is expected to land in
// the trailing "Other:" section). It reuses the same groupedFlagSet the renderer
// uses, so the test's notion of "grouped" can't drift from production.
func ungroupedVisibleFlags(fs *pflag.FlagSet, groups []flagGroup) []string {
	grouped := groupedFlagSet(groups)
	var missing []string
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == "help" {
			return
		}
		if !grouped[f.Name] {
			missing = append(missing, f.Name)
		}
	})
	return missing
}

// TestFlagGroups_CoverAllVisibleFlags guards that every command's visible flags
// are assigned to a group, so the "Other:" help section only ever holds cobra's
// --help. The four native-scan commands share scanFlagGroups (their local flags);
// the root's persistent flags feed the inherited "Global Flags:" block via
// globalFlagGroups. A new ungrouped flag fails here instead of silently appearing
// under "Other".
func TestFlagGroups_CoverAllVisibleFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flags  *pflag.FlagSet
		groups []flagGroup
	}{
		{"scan", scanCmd.Flags(), scanFlagGroups},
		{"run", runCmd.Flags(), scanFlagGroups},
		{"scan-url", scanURLCmd.Flags(), scanFlagGroups},
		{"scan-request", scanRequestCmd.Flags(), scanFlagGroups},
		{"root (global)", rootCmd.PersistentFlags(), globalFlagGroups},
	} {
		if missing := ungroupedVisibleFlags(tc.flags, tc.groups); len(missing) > 0 {
			t.Errorf("%s: visible flags missing from groups (would fall into \"Other:\"): %v", tc.name, missing)
		}
	}
}

// terseGlobalFlags only advertises hint flags the command actually inherits.
func TestTerseGlobalFlags_SkipsAbsentHints(t *testing.T) {
	fs := pflag.NewFlagSet("partial", pflag.ContinueOnError)
	var b bool
	fs.BoolVarP(&b, "verbose", "v", false, "Enable verbose logging output")
	// No --proxy / --db / --force etc. registered here.

	out := terseGlobalFlags(fs)

	if !strings.Contains(out, "-v/--verbose") {
		t.Errorf("expected inherited hint to appear:\n%s", out)
	}
	if strings.Contains(out, "--proxy") || strings.Contains(out, "--force") {
		t.Errorf("absent hints must not be advertised:\n%s", out)
	}
}
