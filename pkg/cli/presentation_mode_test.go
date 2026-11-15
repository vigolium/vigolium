package cli

import (
	"errors"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetPresentationFlags(t *testing.T) {
	t.Helper()
	swapGlobal(t, &globalJSON, false)
	swapGlobal(t, &globalSilent, false)
	swapGlobal(t, &globalSoftFail, false)
	swapGlobal(t, &globalCIOutput, false)
}

// Flag ORDER used to decide whether a failed command answered in JSON at all:
// cobra binds globalJSON during parsing, so when parsing is what failed the
// flag was never bound and the error path emitted nothing.
//
//	vigolium traffic --json --definitely-invalid  -> one JSON usage_error
//	vigolium traffic --definitely-invalid --json  -> empty stdout
func TestPresentationModeRecoveredFromArgvAfterAParseFailure(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"json after the bad flag", []string{"traffic", "--definitely-invalid", "--json"}, true},
		{"json before the bad flag", []string{"traffic", "--json", "--definitely-invalid"}, true},
		{"long assignment form", []string{"traffic", "--definitely-invalid", "--json=true"}, true},
		{"shorthand", []string{"traffic", "--definitely-invalid", "-j"}, true},
		{"global before the command", []string{"--json", "traffic", "--definitely-invalid"}, true},
		{"alias", []string{"tf", "--definitely-invalid", "--json"}, true},
		{"not requested", []string{"traffic", "--definitely-invalid"}, false},
		// An explicit false must stay false; the old argv scan compared whole
		// arguments and would have missed this either way.
		{"explicit false", []string{"traffic", "--definitely-invalid", "--json=false"}, false},
		// After the terminator the token is a positional argument, not a flag.
		{"after the -- terminator", []string{"traffic", "--", "--json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPresentationFlags(t)
			resolvePresentationMode(tc.args)
			if globalJSON != tc.want {
				t.Errorf("globalJSON = %v, want %v for %v", globalJSON, tc.want, tc.args)
			}
		})
	}
}

func TestPresentationModeRecoversSoftFailAndSilent(t *testing.T) {
	resetPresentationFlags(t)
	resolvePresentationMode([]string{"traffic", "--definitely-invalid", "--soft-fail", "--silent"})

	if !globalSoftFail {
		t.Error("--soft-fail must be recovered; otherwise a parse failure exits non-zero for a caller that opted out")
	}
	if !globalSilent {
		t.Error("--silent must be recovered")
	}
}

func TestPresentationModeDoesNotUnsetAnAlreadyResolvedMode(t *testing.T) {
	resetPresentationFlags(t)
	globalJSON = true
	// A successful parse already resolved the mode; the recovery must not
	// second-guess it from argv.
	resolvePresentationMode([]string{"traffic"})
	if !globalJSON {
		t.Error("an already-resolved presentation mode must be left alone")
	}
}

// The three utilities that report a match used to call os.Exit(ExitFuzzMatch)
// straight from their handler, skipping every deferred close and jumping over
// Execute — so --soft-fail, documented as forcing a successful exit everywhere,
// silently did not apply to the exit code most likely to be gated in CI.
func TestMatchOutcomeIsATypedErrorNotADirectExit(t *testing.T) {
	err := asMatchErrorf("--fail-on-match: %d secret(s) matched", 2)

	if got := classifyExitCode(err); got != ExitFuzzMatch {
		t.Errorf("exit code = %d, want %d", got, ExitFuzzMatch)
	}
	var match matchError
	if !errors.As(err, &match) {
		t.Error("a match outcome must be recognizable by type, not by message text")
	}
	// A match is a completed result, so it must not be confused with the
	// severity gate or with an execution failure.
	if classifyExitCode(err) == ExitFailOnGate || classifyExitCode(err) == ExitError {
		t.Error("a match is neither a gate trip nor a failure")
	}
}

func TestGateAndMatchRemainDistinct(t *testing.T) {
	gate := gateError{err: errors.New("high severity finding")}
	match := asMatchErrorf("matched")

	if classifyExitCode(gate) == classifyExitCode(match) {
		t.Error("a severity gate (4) and a fuzz match (3) are different outcomes and must not collapse")
	}
}

// A flag bound before the parse error must not stop the rest from being
// recovered. The early return on machineOutputMode() did exactly that: cobra
// set globalJSON while parsing `--json`, so by the time recovery ran the mode
// "was already resolved" and --soft-fail was dropped.
func TestPresentationModeRecoversTheRestAfterAnEarlyBinding(t *testing.T) {
	resetPresentationFlags(t)
	globalJSON = true // as cobra would have left it
	resolvePresentationMode([]string{"traffic", "--json", "--definitely-invalid", "--soft-fail"})

	if !globalJSON {
		t.Error("an already-resolved presentation mode must be left alone")
	}
	if !globalSoftFail {
		t.Error("--soft-fail must still be recovered when another flag parsed first")
	}
}

// --ci-output-format was removed: typing it is a usage error naming -j and
// --format jsonl, reported in the caller's own mode.
func TestCIOutputFormatIsRemoved(t *testing.T) {
	swapGlobal(t, &globalCIOutput, true)
	err := rejectCIOutputFlag()
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, err.Error(), "-j")
	assert.Contains(t, err.Error(), "--format jsonl")
	assert.False(t, globalCIOutput, "the refusal is not itself a machine-output run")
	assert.True(t, rootCmd.PersistentFlags().Lookup("ci-output-format").Hidden)

	globalCIOutput = false
	assert.NoError(t, rejectCIOutputFlag())
}

// The drift test: every recovered flag must carry its root counterpart's type,
// because pflag decides whether a flag consumes the next argument from the type.
func TestPresentationFlagsMatchRootTypes(t *testing.T) {
	root := rootCmd
	fs, _ := newPresentationFlagSet()
	checked := 0
	fs.VisitAll(func(recovered *pflag.Flag) {
		checked++
		actual := root.PersistentFlags().Lookup(recovered.Name)
		if actual == nil {
			actual = root.Flags().Lookup(recovered.Name)
		}
		if actual == nil {
			t.Errorf("recovery declares --%s, which the root command does not", recovered.Name)
			return
		}
		if actual.Value.Type() != recovered.Value.Type() {
			t.Errorf("--%s is %s on the root command and %s in recovery; pflag parses the two differently",
				recovered.Name, actual.Value.Type(), recovered.Value.Type())
		}
		if actual.Shorthand != recovered.Shorthand {
			t.Errorf("--%s shorthand is %q on the root command and %q in recovery",
				recovered.Name, actual.Shorthand, recovered.Shorthand)
		}
	})
	if checked != 3 {
		t.Fatalf("compared %d flags, want 3 — the recovery set changed without this test", checked)
	}
}
