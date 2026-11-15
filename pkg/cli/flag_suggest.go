package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// flagErrorFunc makes every flag-parse error a usage error (exit 2) and
// augments the mistyped-flag ones with a "did you mean" hint. Cobra suggests
// near-miss *subcommands* out of the box but says nothing for a mistyped
// *flag*, so `--module` (instead of `--modules`) dead-ends at a bare
// "unknown flag: --module". This closes that gap by pointing at the closest
// registered long flag on the command that actually failed to parse. It is
// installed once on rootCmd; cobra's FlagErrorFunc() walks up to the parent, so
// every subcommand inherits it.
func flagErrorFunc(cmd *cobra.Command, err error) error {
	// A closed-set flag given a value outside its set: the valid values are in
	// the message, the nearest one is the suggestion.
	var invalid *pflag.InvalidValueError
	var enum *enumError
	if errors.As(err, &invalid) && errors.As(err, &enum) {
		return clicommon.CLIError{
			Err:        err,
			DidYouMean: enum.suggestion(),
			UsageArgv:  clicommon.UsageArgvFor(commandPathWithoutRoot(cmd)),
		}
	}
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		return asUsageError(err)
	}
	// Only long-flag typos ("--module") get a suggestion. An unknown shorthand
	// carries a shortname group (GetSpecifiedShortnames) and rarely has a
	// meaningful near-match, so leave those untouched.
	typed := notExist.GetSpecifiedName()
	if notExist.GetSpecifiedShortnames() != "" || len(typed) < 2 {
		return asUsageError(err)
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
	return textutil.Closest(typed, names)
}
