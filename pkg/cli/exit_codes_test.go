package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestClassifyExitCodeSeparatesGateFromError(t *testing.T) {
	// The change this table exists for: a scan that ran cleanly and found a
	// high-severity finding is the OPPOSITE outcome from one that failed to
	// start, and both used to exit 1.
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitSuccess},
		{"plain error", errors.New("boom"), ExitError},
		{"usage error", asUsageError(errors.New("bad combo")), ExitUsageError},
		{"fail-on gate", gateError{err: errors.New("--fail-on high")}, ExitFailOnGate},
	}
	for _, tc := range cases {
		if got := classifyExitCode(tc.err); got != tc.want {
			t.Errorf("%s: exit = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestClassifyExitCodeSeesThroughWrapping(t *testing.T) {
	// Errors are wrapped on their way up through the run path; a gate that stops
	// being recognised after one %w is a gate that silently exits 1.
	wrapped := fmt.Errorf("scan failed: %w", gateError{err: errors.New("gate")})
	if got := classifyExitCode(wrapped); got != ExitFailOnGate {
		t.Errorf("wrapped gate: exit = %d, want %d", got, ExitFailOnGate)
	}
	wrappedUsage := fmt.Errorf("context: %w", asUsageError(errors.New("bad flag")))
	if got := classifyExitCode(wrappedUsage); got != ExitUsageError {
		t.Errorf("wrapped usage: exit = %d, want %d", got, ExitUsageError)
	}
}

func TestAsUsageErrorPassesNilThrough(t *testing.T) {
	// So a call site can wrap its return value directly.
	if err := asUsageError(nil); err != nil {
		t.Errorf("asUsageError(nil) = %v, want nil", err)
	}
}

func TestUsageErrorPreservesMessage(t *testing.T) {
	err := asUsageError(errors.New("--all-hosts is required"))
	if err.Error() != "--all-hosts is required" {
		t.Errorf("message rewritten: %q", err.Error())
	}
}

// Every flag-parse error leaves flagErrorFunc as a usage error (exit 2).
func TestFlagParseErrorsAreUsageErrors(t *testing.T) {
	root := &cobra.Command{Use: "vigolium"}
	c := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(c)
	var db string
	var n int
	c.Flags().StringVar(&db, "db", "", "")
	c.Flags().IntVar(&n, "limit", 0, "")
	for _, argv := range [][]string{
		{"--bogus"}, {"-Z"}, {"--db"}, {"--limit", "abc"}, {"---x"},
	} {
		err := c.ParseFlags(argv)
		require.Error(t, err, argv)
		if got := classifyExitCode(flagErrorFunc(c, err)); got != ExitUsageError {
			t.Errorf("%v: %v exits %d, want %d", argv, err, got, ExitUsageError)
		}
	}
	require.True(t, isRequiredFlagError(errors.New(`required flag(s) "db" not set`)))
	require.False(t, isRequiredFlagError(errors.New("connection refused")))
}

// TestExitCodeTable pins the whole exit-code contract (docs/coding-agent.md,
// "Process contract") in one place: the code classifyExitCode picks, the
// error.code classifyErrorCode reports for it, and the process status with and
// without --soft-fail.
func TestExitCodeTable(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantExit int
		wantCode apicontract.ErrorCode
	}{
		{"plain error", errors.New("boom"), ExitError, apicontract.CodeFailed},
		{"usage error", usageErrorf("--a and --b are mutually exclusive"), ExitUsageError, apicontract.CodeUsageError},
		{"usage error from clicommon", clicommon.UsageErrorf("usage: config set <key> <value>"), ExitUsageError, apicontract.CodeUsageError},
		{"confirmation required", fmt.Errorf("delete: %w", errConfirmationRequired), ExitUsageError, apicontract.CodeUsageError},
		{"coded error", codedErrorf(apicontract.CodeNoTargetsInScope, "all 3 targets rejected by scope"), ExitError, apicontract.CodeNoTargetsInScope},
		{"fuzz match", asMatchErrorf("matched 2 responses"), ExitFuzzMatch, apicontract.CodeFailed},
		{"fail-on gate", gateError{err: errors.New("--fail-on high")}, ExitFailOnGate, apicontract.CodeGateTripped},
		{"incomplete timed_out", incompleteErrorf(apicontract.CodeTimedOut, "agent hit --max-duration"), ExitIncomplete, apicontract.CodeTimedOut},
		{"incomplete budget", incompleteErrorf(apicontract.CodeBudgetExhausted, "request budget spent"), ExitIncomplete, apicontract.CodeBudgetExhausted},
		{"incomplete partial", incompleteErrorf(apicontract.CodePartial, "2 of 5 phases failed"), ExitIncomplete, apicontract.CodePartial},
		{"incomplete with non-incomplete code", incompleteErrorf(apicontract.CodeFailed, "x"), ExitIncomplete, apicontract.CodePartial},
		{"wrapped incomplete", fmt.Errorf("agent run: %w", incompleteErrorf(apicontract.CodeTimedOut, "deadline")), ExitIncomplete, apicontract.CodeTimedOut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exit := classifyExitCode(tc.err)
			if exit != tc.wantExit {
				t.Fatalf("exit = %d, want %d", exit, tc.wantExit)
			}
			if code := classifyErrorCode(tc.err, exit); code != tc.wantCode {
				t.Errorf("error.code = %q, want %q", code, tc.wantCode)
			}
			if !tc.wantCode.Valid() {
				t.Errorf("%q is not in the apicontract closed set", tc.wantCode)
			}
			if got := processExitCode(exit, false); got != tc.wantExit {
				t.Errorf("process exit without --soft-fail = %d, want %d", got, tc.wantExit)
			}
			if got := processExitCode(exit, true); got != ExitSuccess {
				t.Errorf("process exit with --soft-fail = %d, want 0", got)
			}
		})
	}
}

// The pkg/cli names are aliases, not copies: an error built in a subpackage
// through clicommon must classify exactly like one built here.
func TestExitCodesMatchAPIContract(t *testing.T) {
	for got, want := range map[int]int{
		ExitSuccess:    apicontract.ExitSuccess,
		ExitError:      apicontract.ExitError,
		ExitUsageError: apicontract.ExitUsageError,
		ExitFuzzMatch:  apicontract.ExitFuzzMatch,
		ExitFailOnGate: apicontract.ExitFailOnGate,
		ExitIncomplete: apicontract.ExitIncomplete,
	} {
		if got != want {
			t.Errorf("exit code %d drifted from apicontract %d", got, want)
		}
	}
	if ExitIncomplete != 5 {
		t.Errorf("ExitIncomplete = %d, want 5", ExitIncomplete)
	}
	if AgentSchemaVersion != apicontract.SchemaVersion {
		t.Errorf("AgentSchemaVersion %d != apicontract.SchemaVersion %d", AgentSchemaVersion, apicontract.SchemaVersion)
	}
}

// Bad invocations are usage errors (exit 2), not failures of the work.
func TestBadInvocationsAreUsageErrors(t *testing.T) {
	opts := &types.Options{OnlyPhase: "bogusphase"}
	onlyErr := runner.ApplyNativePhaseSelection(opts, nil)
	both := runner.ApplyNativePhaseSelection(&types.Options{OnlyPhase: "discovery", SkipPhases: []string{"spidering"}}, nil)
	_, _, rangeErr := parseDateRangeFlags("2026-02-01", "2026-01-01", "--from", "--to")
	_, formatErr := source.NewFileSource(source.FileSourceConfig{FilePath: "x.txt", Format: "bogus", FormatExplicit: true})
	for name, err := range map[string]error{
		"unknown --only phase":  onlyErr,
		"--only with --skip":    both,
		"inverted --from/--to":  rangeErr,
		"unknown input format":  formatErr,
		"fuzz with no payloads": fmt.Errorf("wrapped: %w", fuzz.ErrNoPayloads),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if got := classifyExitCode(err); got != ExitUsageError {
			t.Errorf("%s: exit %d, want 2 (%v)", name, got, err)
		}
	}
}
