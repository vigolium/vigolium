package clicommon

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// The error types the CLI's exit-code classifier recognises. They live here,
// not in pkg/cli, so every command package (configcmd and any future split-out
// group) can return a usage error or a coded error without importing pkg/cli,
// which would be a cycle. pkg/cli keeps short unexported aliases so its own call
// sites read the same as before.

// UsageError marks an error as a misuse of the command line (an unknown flag
// value, a rejected combination, a missing required flag) rather than a failure
// of the work. It exits 2 with error.code "usage_error". Cobra's own flag-parse
// errors are classified separately, because they never pass through here.
type UsageError struct{ Err error }

func (u UsageError) Error() string { return u.Err.Error() }
func (u UsageError) Unwrap() error { return u.Err }

// AsUsageError wraps err so the command exits 2. It returns nil for a nil
// error, so a call site can wrap its return value directly.
func AsUsageError(err error) error {
	if err == nil {
		return nil
	}
	return UsageError{Err: err}
}

// UsageErrorf builds a usage error (exit 2) from a format string, for the
// common case of rejecting a bad flag value at its own call site.
func UsageErrorf(format string, args ...any) error {
	return UsageError{Err: fmt.Errorf(format, args...)}
}

// CodedError carries a stable error code alongside its message, for conditions
// the classifier cannot infer from an exit code or a wrapped sentinel. It exits
// 1 unless the code is one of the incomplete codes (see IncompleteError).
//
// The alternative was matching on message text: a code a consumer branches on
// must not depend on how the sentence around it is worded.
type CodedError struct {
	code apicontract.ErrorCode
	err  error
}

func (c CodedError) Error() string               { return c.err.Error() }
func (c CodedError) Unwrap() error               { return c.err }
func (c CodedError) Code() apicontract.ErrorCode { return c.code }

// NewCodedError wraps err with the given stable code.
func NewCodedError(code apicontract.ErrorCode, err error) error {
	return CodedError{code: code, err: err}
}

// CodedErrorf builds an error that reports the given stable code.
func CodedErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	return CodedError{code: code, err: fmt.Errorf(format, args...)}
}

// IncompleteError marks work that ran but did not finish: a time budget fired
// (timed_out), a request or token budget ran out (budget_exhausted), or some of
// the work failed while the rest completed (partial). It exits 5.
//
// Like the --fail-on gate it is a completed result, not a failure: the caller
// writes its output first and returns this afterwards, so the result document
// is already on stdout and no error document is appended. --soft-fail forces 0.
type IncompleteError struct {
	code apicontract.ErrorCode
	err  error
}

func (i IncompleteError) Error() string               { return i.err.Error() }
func (i IncompleteError) Unwrap() error               { return i.err }
func (i IncompleteError) Code() apicontract.ErrorCode { return i.code }

// IncompleteErrorf builds an incomplete-result error. code should satisfy
// code.IsIncomplete(); any other code falls back to "partial" so the exit
// status and the reported code cannot disagree.
func IncompleteErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	if !code.IsIncomplete() {
		code = apicontract.CodePartial
	}
	return IncompleteError{code: code, err: fmt.Errorf(format, args...)}
}

// CLIError is a command-line error that carries its remedies as fields rather
// than as decoration baked into the message. Error() is the human text: the
// fact, then the hint and the suggestion on their own lines. The -j error
// envelope copies the fields into error{hint, did_you_mean, usage_argv} and
// keeps error.message to the fact alone, so a program never has to scrape a
// suggestion out of prose.
//
// Code defaults to usage_error, which exits 2; any other code exits 1 and is
// reported as that code.
type CLIError struct {
	Err  error
	Code apicontract.ErrorCode
	// Hint is one sentence naming the next step.
	Hint string
	// DidYouMean is the nearest valid spelling of what was typed (a flag with
	// its dashes, a command path, an enum value).
	DidYouMean string
	// UsageArgv is the argv that prints the failing command's flags.
	UsageArgv []string
}

func (e CLIError) Unwrap() error { return e.Err }

// ErrorCode reports the error's stable code (usage_error when unset).
func (e CLIError) ErrorCode() apicontract.ErrorCode {
	if e.Code == "" {
		return apicontract.CodeUsageError
	}
	return e.Code
}

// IsUsage reports whether the error is a misuse of the command line (exit 2).
func (e CLIError) IsUsage() bool { return e.ErrorCode() == apicontract.CodeUsageError }

// Fact is the message without the remedies: what the -j envelope's
// error.message carries.
func (e CLIError) Fact() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Error renders the fact followed by the remedies, for a human reading stderr.
func (e CLIError) Error() string {
	return e.Fact() + e.Decoration()
}

// Decoration is the human-only suffix Error() appends to the fact.
func (e CLIError) Decoration() string {
	var b strings.Builder
	if e.DidYouMean != "" {
		b.WriteString("\n\n  " + terminal.InfoSymbol() + " Did you mean " + terminal.BoldCyan(e.DidYouMean) + "?")
	}
	if e.Hint != "" {
		if e.DidYouMean == "" {
			b.WriteString("\n")
		}
		b.WriteString("\n  " + terminal.InfoSymbol() + " " + e.Hint)
	}
	return b.String()
}

// UsageArgvFor is the argv that prints a command's flags as the `schema
// flags` document: ["vigolium", <path...>, "--usage", "-j"]. path is the
// command path without the root name ("" for the root).
func UsageArgvFor(path string) []string {
	argv := []string{"vigolium"}
	argv = append(argv, strings.Fields(path)...)
	return append(argv, "--usage", "-j")
}
