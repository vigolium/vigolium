package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// flagErrorFunc augments cobra's flag-parse errors with a "did you mean" hint.
// Cobra suggests near-miss *subcommands* out of the box but says nothing for a
// mistyped *flag*, so `--module` (instead of `--modules`) dead-ends at a bare
// "unknown flag: --module". This closes that gap by pointing at the closest
// registered long flag on the command that actually failed to parse. It is
// installed once on rootCmd; cobra's FlagErrorFunc() walks up to the parent, so
// every subcommand inherits it.
func flagErrorFunc(cmd *cobra.Command, err error) error {
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		return err
	}
	// Only long-flag typos ("--module") get a suggestion. An unknown shorthand
	// carries a shortname group (GetSpecifiedShortnames) and rarely has a
	// meaningful near-match, so leave those untouched.
	typed := notExist.GetSpecifiedName()
	if notExist.GetSpecifiedShortnames() != "" || len(typed) < 2 {
		return err
	}
	// The remedies travel as fields (clicommon.CLIError): a human reads them
	// under the fact, the -j envelope carries them as hint/did_you_mean/
	// usage_argv with error.message left as the bare fact. With no confident
	// near-miss, the hint still says where the answer is.
	best := closestFlagName(cmd, typed)
	out := clicommon.CLIError{
		Err:       err,
		Hint:      fmt.Sprintf("Run '%s --help' for this command's flags", cmd.CommandPath()),
		UsageArgv: clicommon.UsageArgvFor(commandPathWithoutRoot(cmd)),
	}
	if best != "" {
		out.DidYouMean = "--" + best
	}
	return out
}

// closestFlagName returns the registered long flag on cmd nearest to typed by
// Levenshtein distance, or "" when nothing is close enough to be a confident
// suggestion. cmd.Flags() is the fully-merged set (local + inherited persistent)
// by the time flag parsing fails.
//
// The threshold used to be `max(2, len/3)`, which was too generous at the short
// end and produced the worst class of wrong answer. `vigolium traffic --url ...`
// was answered with "Did you mean --all?": three characters, edit distance two,
// so it cleared a floor of two — and --all is not a near-miss of --url, it is an
// unrelated flag that LIFTS the result cap. A suggestion that silently widens
// the query is worse than no suggestion, because a caller who takes it gets a
// plausible-looking answer to a question they did not ask.
//
// So the budget scales with the typed name throughout, and a distance that
// rewrites most of a short name no longer qualifies. Anything of five characters
// or fewer must match within one edit — a genuine typo (--modul for --module,
// --hosts for --host) still lands, while --url→--all does not.
func closestFlagName(cmd *cobra.Command, typed string) string {
	var names []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Hidden {
			names = append(names, f.Name)
		}
	})
	return closestName(typed, names)
}

// closestName is the candidate nearest typed within suggestionBudget, "" when
// none is. Ties go to the first candidate, so the hint is stable across builds
// (pflag visits flags in lexical order).
func closestName(typed string, candidates []string) string {
	best, bestDist := "", -1
	for _, c := range candidates {
		if d := textutil.Levenshtein(typed, c); bestDist == -1 || d < bestDist {
			best, bestDist = c, d
		}
	}
	if bestDist >= 0 && bestDist <= suggestionBudget(typed) {
		return best
	}
	return ""
}

// suggestionBudget is the largest edit distance still considered a typo of
// typed. One edit for a short name, widening to a third of the name's length for
// longer ones, where the same distance leaves far more of the word intact.
func suggestionBudget(typed string) int {
	if len(typed) <= 5 {
		return 1
	}
	return len(typed) / 3
}
