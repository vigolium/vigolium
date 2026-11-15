package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// pflag's UnquoteUsage treats the first `backticked` span in a flag's usage as
// the value's name: "see `vigolium run --help`" rendered as
// "--only vigolium run --help   Run only these phases (... see vigolium run --help)".
// A backtick in usage text is only correct when it names the value, which is a
// short lowercase word.
var flagVarnamePattern = regexp.MustCompile(`^[a-z][a-z0-9|=-]*$`)

func TestFlagUsageHasNoBacktickVarname(t *testing.T) {
	prepareCommandTree(rootCmd)

	seen := map[*pflag.Flag]bool{}
	walkTree(rootCmd, func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			// Without a backtick the value name is the type name
			// ("stringArray"), which pflag picks itself.
			if seen[f] || !strings.Contains(f.Usage, "`") {
				return
			}
			seen[f] = true
			name, _ := pflag.UnquoteUsage(f)
			if f.Value.Type() == "bool" {
				// A bool takes no value, yet pflag still prints the
				// backticked span after the flag name.
				t.Errorf("%s --%s: bool flag help renders a value name %q; quote with '...' instead",
					c.CommandPath(), f.Name, name)
				return
			}
			if !flagVarnamePattern.MatchString(name) {
				t.Errorf("%s --%s: help renders the value name as %q; a backtick in usage text "+
					"becomes the value name, so quote with '...' instead", c.CommandPath(), f.Name, name)
			}
		}
		// LocalFlags includes the persistent flags this command declares
		// (root's globals), so every flag is visited once at its owner.
		c.LocalFlags().VisitAll(check)
	})
}

// --fail-on accepts every entry of severityOrder; the help must say so (a
// hand-written list omitted "suspect").
func TestFailOnHelpListsEverySeverity(t *testing.T) {
	want := "(" + strings.Join(severityOrder, "|") + ")"
	seen := 0
	walkTree(rootCmd, func(c *cobra.Command) {
		f := c.LocalFlags().Lookup("fail-on")
		if f == nil {
			return
		}
		seen++
		if !strings.Contains(f.Usage, want) {
			t.Errorf("%s --fail-on usage does not list %s:\n  %s", c.CommandPath(), want, f.Usage)
		}
	})
	if seen == 0 {
		t.Fatal("no command registers --fail-on; the walk is broken")
	}
}

// kit's one-line summary is what `vigolium --help` shows. It listed four of
// its eight tools; it is now derived from the registered subcommands.
func TestKitShortListsEverySubcommand(t *testing.T) {
	prepareCommandTree(rootCmd)

	subs := 0
	for _, sub := range kitCmd.Commands() {
		if !sub.IsAvailableCommand() {
			continue
		}
		subs++
		if !strings.Contains(kitCmd.Short, sub.Name()) {
			t.Errorf("kit Short %q does not mention %q", kitCmd.Short, sub.Name())
		}
		if !strings.Contains(kitCmd.Long, "vigolium kit "+sub.Name()) {
			t.Errorf("kit Long does not list %q", sub.Name())
		}
	}
	if subs < 8 {
		t.Errorf("kit has %d visible subcommands, want at least 8", subs)
	}
}

// --full-example is a curated tour an operator copies from; every line must
// name a real command and pass the shared doc-command validator
// (doc_commands_test.go): parse, unknown subcommands, enums, positionals.
func TestFullExamplesParse(t *testing.T) {
	prepareCommandTree(rootCmd)

	cmds := fullExampleDocCommands()
	if len(cmds) == 0 {
		t.Fatal("no full-example commands extracted")
	}
	checkDocCommands(t, cmds)
}

// The ext eval example must call vigolium.log as a namespace; calling it as a
// function throws at runtime.
func TestFullExamplesUseLogNamespace(t *testing.T) {
	for _, sec := range fullExampleSections() {
		for _, line := range sec.examples {
			if strings.Contains(line, "vigolium.log(") {
				t.Errorf("[%s] vigolium.log is a namespace (use vigolium.log.info): %s", sec.title, line)
			}
		}
	}
}
