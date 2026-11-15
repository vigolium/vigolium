package cli

import (
	"io"
	"os"

	"github.com/spf13/pflag"
)

// Execute emits the structured error object only if globalJSON is set, and
// globalJSON is set by cobra's flag parsing. When parsing itself is what failed,
// it never ran — so the mode the caller asked for was unknown at exactly the
// moment it mattered most:
//
//	vigolium traffic --json --definitely-invalid   -> exit 2, one JSON usage_error
//	vigolium traffic --definitely-invalid --json   -> exit 2, EMPTY stdout
//
// Same two flags, same error, and whether the caller got a parseable answer
// depended on which one came first.
//
// resolvePresentationMode recovers the presentation flags from argv after a
// parse failure. It is deliberately NOT another hand-rolled argv scan of the
// kind that produced the banner bug: it is a real pflag.FlagSet that knows only
// the presentation flags, with unknown flags whitelisted. That means it honors
// --json=false, the -j shorthand, combined shorthands, the `--` terminator, and
// flag values, because pflag's own parser is doing the work.
//
// It is a best-effort recovery used only on the error path. With unknown flags
// whitelisted, pflag cannot know whether an unknown flag consumes the next
// argument, so an adversarial command line can still confuse it. Producing a
// structured error for the overwhelmingly common case beats producing nothing
// for half of them.
// Every recovered flag must be declared with the SAME type as its root
// counterpart. --ci-output-format was declared here as a String while the root
// declares it Bool, and pflag's parser consumes the next argument as the value
// of a string flag — so `traffic --bad --ci-output-format --json` swallowed
// --json, and the caller that asked for JSON got none. TestPresentationFlagsMatchRootTypes
// asserts the whole set against the root flagset, so a type can no longer drift
// in one place.
func resolvePresentationMode(args []string) {
	// No early return on machineOutputMode(): one presentation flag having
	// parsed before the error does not mean the rest did. `traffic --json --bad
	// --soft-fail` sets globalJSON during cobra's own parse, then fails — and
	// bailing here because "the mode is already known" left --soft-fail
	// unrecovered. Recovery only ever turns a flag ON, so re-running it over an
	// argv that already produced a mode cannot unset one.
	fs, bound := newPresentationFlagSet()

	// A parse error here is expected and ignored: the whole point is that argv
	// did not parse. Whatever the flagset did manage to bind is still better
	// than nothing.
	_ = fs.Parse(args)

	for _, b := range bound {
		if *b.value {
			*b.global = true
		}
	}
}

// presentationBinding ties one recovered flag to the global it turns on.
type presentationBinding struct {
	value  *bool
	global *bool
}

// newPresentationFlagSet builds the recovery flagset. Separated from the
// recovery itself so the drift test can inspect the real flagset rather than a
// hand-maintained copy of its flag names.
func newPresentationFlagSet() (*pflag.FlagSet, []presentationBinding) {
	fs := pflag.NewFlagSet("presentation", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.SetOutput(io.Discard)
	// Usage must not print: this runs while an error is already being reported.
	fs.Usage = func() {}

	return fs, []presentationBinding{
		{fs.BoolP("json", "j", false, ""), &globalJSON},
		{fs.Bool("silent", false, ""), &globalSilent},
		{fs.Bool("soft-fail", false, ""), &globalSoftFail},
	}
}

// argsForPresentationRecovery returns the process arguments to re-scan.
func argsForPresentationRecovery() []string {
	if len(os.Args) < 2 {
		return nil
	}
	return os.Args[1:]
}
