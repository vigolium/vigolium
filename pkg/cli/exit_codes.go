package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Process exit codes. The table itself lives in pkg/apicontract, shared with
// the REST API's error vocabulary; these names keep pkg/cli's call sites short.
//
// `1` used to mean both "the scan crashed" and "the scan worked and found a
// high-severity finding" — opposite outcomes that a CI job or an agent has to
// react to differently, and could not tell apart. Splitting them is the whole
// change; the rest of the table is written down so a consumer can rely on it.
//
//	0  success
//	1  error
//	2  usage error (bad flag, bad combination)
//	3  fuzz --fail-on-match matched
//	4  --fail-on <severity> gate tripped
//	5  incomplete: the work ran but did not finish (timed_out, budget_exhausted,
//	   partial). A scan with --fail-on-partial (implied by --fail-on) exits 5
//	   when its coverage was partial.
//
// When several apply the first wins: error (1) > gate (4) > incomplete (5).
//
// --soft-fail still forces 0 everywhere, unchanged: a caller that has opted out
// of exit-code gating opted out of all of it.
const (
	ExitSuccess    = apicontract.ExitSuccess
	ExitError      = apicontract.ExitError
	ExitUsageError = apicontract.ExitUsageError
	ExitFuzzMatch  = apicontract.ExitFuzzMatch
	ExitFailOnGate = apicontract.ExitFailOnGate
	ExitIncomplete = apicontract.ExitIncomplete
)

// usageError marks an error as a misuse of the command line — an unknown flag
// value, a rejected combination, a missing required flag — rather than a
// failure of the work. Cobra's own flag-parse errors are classified separately
// (see classifyExitCode), because they never pass through here.
//
// The type lives in clicommon so subpackages (configcmd) can return it without
// importing pkg/cli; these aliases keep the existing call sites unchanged.
type usageError = clicommon.UsageError

// asUsageError wraps err so Execute exits 2. Returns nil for a nil error, so it
// can wrap a call site's return value directly.
func asUsageError(err error) error { return clicommon.AsUsageError(err) }

// usageErrorf builds a usage error (exit 2) from a format string, for the common
// case of rejecting a bad flag value at its own call site.
func usageErrorf(format string, args ...any) error {
	return clicommon.UsageError{Err: fmt.Errorf(format, args...)}
}

// incompleteError marks work that ran but did not finish (exit 5). Like
// gateError it is a completed result: return it only after the output was
// written. See clicommon.IncompleteError.
type incompleteError = clicommon.IncompleteError

// incompleteErrorf builds an exit-5 result carrying one of the incomplete codes
// (timed_out, budget_exhausted, partial).
func incompleteErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	return clicommon.IncompleteErrorf(code, format, args...)
}

// gateError marks the --fail-on severity gate. It is not a failure: the scan ran
// to completion and its output was written before this is returned. A consumer
// distinguishing "found something" from "broke" reads exit 4 vs exit 1.
type gateError struct{ err error }

func (g gateError) Error() string { return g.err.Error() }
func (g gateError) Unwrap() error { return g.err }

// matchError marks a --fail-on-match / --fail-on-crack hit. Like gateError it is
// a completed result, not a failure: the work ran, its output was written, and
// the caller asked to learn about a match through the exit status.
//
// It exists because the three utilities that report a match used to call
// os.Exit(ExitFuzzMatch) directly from their handler. os.Exit runs no deferred
// functions, so that skipped the database close, the temporary-file cleanup, and
// the log flush; it also jumped over Execute entirely, so --soft-fail — which is
// documented as forcing a successful exit everywhere — silently did not apply to
// the one exit code an operator is most likely to want suppressed in CI.
type matchError struct{ err error }

func (m matchError) Error() string { return m.err.Error() }
func (m matchError) Unwrap() error { return m.err }

// asMatchError builds the typed outcome for a --fail-on-match hit.
func asMatchErrorf(format string, args ...any) error {
	return matchError{err: fmt.Errorf(format, args...)}
}

// recordExportFailure folds a failed export into a command's named return, so a
// requested artifact that was never written cannot be reported as success.
//
// It used to be invisible. Every per-format failure printed to stderr and
// stopped there, so a scan whose -o directory was unwritable exited 0, emitted
// `scan.finished status=completed` on the --events stream, and left zero bytes
// behind — three independent success signals for a run that produced no output.
// A driver reading the machine interface could not tell that apart from a clean
// scan with no findings.
//
// A failure already in flight wins, because the export most likely failed
// BECAUSE the scan did and the cause is the more useful thing to report. That
// deliberately includes the --fail-on gate and --fail-on-match, which are
// completed results whose premise is that the output was written first: both are
// layered on by the CALLER (withFailOnGate in runScanCmd, outside the defers
// that run this), so an export failure recorded here is already the `prior` that
// withFailOnGate yields to. The precedence lives there, in one place; do not
// re-derive it here.
//
// Exit code and machine code come from the coded error, which classifyExitCode
// maps to ExitError and classifyErrorCode reports as apicontract.CodeExportFailed — or as
// the renderer's own artifact code when the failure carries one (a PDF render
// is pdf_failed).
//
// The exporters print nothing themselves — the root handler renders whatever
// error a command returns, so printing there too said the same thing twice. That
// leaves exactly one case where a failure would otherwise vanish: when an
// earlier error wins and this one is dropped. It is printed here, and only here.
func recordExportFailure(err *error, exportErr error) {
	if exportErr == nil {
		return
	}
	if *err != nil {
		fmt.Fprintf(os.Stderr, "%s the run also failed to write its output: %v\n",
			terminal.ErrorPrefix(), exportErr)
		return
	}
	code := apicontract.CodeExportFailed
	var specific interface{ Code() apicontract.ErrorCode }
	if errors.As(exportErr, &specific) && isExportFailureCode(specific.Code()) {
		code = specific.Code()
	}
	*err = clicommon.NewCodedError(code, exportErr)
}

// isExportFailureCode reports whether code names a requested artifact that was
// not written: export_failed, or a renderer's more specific pdf_failed.
func isExportFailureCode(code apicontract.ErrorCode) bool {
	return code == apicontract.CodeExportFailed || code == apicontract.CodePDFFailed
}

// writeRequestedFile publishes an artifact the caller asked for with -o, and
// codes a failure as apicontract.CodeExportFailed.
//
// The code is the point, and it is why this is one function rather than the
// two-line pair it replaces at each site. The work ran and its result exists; it
// just did not reach the file that was asked for, and the caller's correct
// response is to retry the WRITE rather than the read. Left to inference, a
// missing parent directory wraps os.ErrNotExist and classifies as
// source_missing — which tells a driver the database it just read successfully
// is not there. docs/coding-agent.md promises export_failed for any -o that
// cannot be written, and a promise that general cannot be kept by remembering to
// wrap at each call site.
func writeRequestedFile(dest string, data []byte) error {
	if err := atomicfile.WriteBytes(dest, data); err != nil {
		return codedErrorf(apicontract.CodeExportFailed, "write %s: %w", dest, err)
	}
	return nil
}

// isExportFailure reports whether err is a failure to write a requested output
// rather than a failure of the work that produced it.
//
// The distinction matters to the defers that materialize the remaining formats.
// They skip on a failed scan, because a success-looking file of stale or partial
// project data is worse than no file — but an unwritable html path says nothing
// about the findings, and cancelling the jsonl export over it loses the one
// format that would still have landed. Each --format is attempted
// independently; this is what keeps that true once one of them starts failing
// the command.
func isExportFailure(err error) bool {
	var coded codedError
	return errors.As(err, &coded) && isExportFailureCode(coded.Code())
}

// classifyExitCode maps a command's error to its exit code.
func classifyExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var gate gateError
	if errors.As(err, &gate) {
		return ExitFailOnGate
	}
	var match matchError
	if errors.As(err, &match) {
		return ExitFuzzMatch
	}
	var incomplete incompleteError
	if errors.As(err, &incomplete) {
		return ExitIncomplete
	}
	var usage usageError
	if errors.As(err, &usage) {
		return ExitUsageError
	}
	var cli clicommon.CLIError
	if errors.As(err, &cli) {
		// A refused send is a usage error with its own code: nothing was sent
		// and the fix is a flag (--ignore-scope) or the scope.
		if cli.IsUsage() || cli.ErrorCode() == apicontract.CodeOutOfScope {
			return ExitUsageError
		}
		return ExitError
	}
	// A refused non-interactive confirmation is a misuse of the command line,
	// not a failure of the work: nothing ran, nothing changed, and the fix is to
	// add --force. Exit 2 puts it in the same bucket as a missing required flag,
	// which is what it is.
	if errors.Is(err, errConfirmationRequired) {
		return ExitUsageError
	}
	// --module-id ext-<id> naming no loaded extension: the runner can only tell
	// once the extension engine has loaded, but it is still a mistyped flag value
	// and fails before any phase sends traffic.
	if errors.Is(err, runner.ErrUnknownExtensionModule) {
		return ExitUsageError
	}
	// A rejected --only/--skip (an unknown phase, both flags at once).
	if errors.Is(err, runner.ErrPhaseSelection) || errors.Is(err, runner.ErrEmptyModuleSelection) {
		return ExitUsageError
	}
	// -I naming no input format; a fuzz run with no payload source.
	if errors.Is(err, source.ErrUnknownFormat) || errors.Is(err, fuzz.ErrNoPayloads) {
		return ExitUsageError
	}
	return ExitError
}
