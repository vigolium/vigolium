package cli

import (
	"errors"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// A failed -j command used to print `✖ Error: …` to stderr and nothing at all to
// stdout. For a machine consumer that is two failures for the price of one: the
// read failed, and then the JSON parse failed for an unrelated reason, leaving
// the actual cause to be scraped out of human prose. A parseable error object is
// still an error — the exit code carries that — but it is one the caller can act
// on instead of guess at.
//
// The shape deliberately mirrors agentEnvelope's spine (schema_version, command,
// generated_at) so one parser reads both, with `error` present only on failure.
type agentErrorEnvelope struct {
	SchemaVersion int        `json:"schema_version"`
	Command       string     `json:"command"`
	OK            bool       `json:"ok"`
	Error         agentError `json:"error"`
	DBPath        string     `json:"db_path,omitempty"`
	// SoftFail states that --soft-fail suppressed the exit code. Without it a
	// consumer reading exit_code: 2 alongside a process that exited 0 has no way
	// to tell which number is the truth. Both are: exit_code is what the command
	// concluded, the process status is what the caller asked to be told.
	SoftFail bool `json:"soft_fail,omitempty"`
	// AgenticScanUUID names the agent run this invocation started, when the
	// failure came after one did, so it can be found again (`agent session`,
	// `log`).
	AgenticScanUUID string `json:"agentic_scan_uuid,omitempty"`
	GeneratedAt     string `json:"generated_at"`
	GeneratedAtMS   int64  `json:"generated_at_ms"`
}

type agentError struct {
	// Code is the stable, machine-branchable classification. Message is for a
	// human reading the log; never branch on it.
	Code     apicontract.ErrorCode `json:"code"`
	Message  string                `json:"message"`
	ExitCode int                   `json:"exit_code"`
	// Hint, DidYouMean and UsageArgv are copied from a clicommon.CLIError in
	// the chain; Message then holds the bare fact without them.
	Hint       string   `json:"hint,omitempty"`
	DidYouMean string   `json:"did_you_mean,omitempty"`
	UsageArgv  []string `json:"usage_argv,omitempty"`
}

// newAgentErrorBody builds the error object for err at exitCode. A CLIError in
// the chain contributes its remedies as fields, and its human decoration is
// removed from the message so message is the fact alone.
func newAgentErrorBody(err error, exitCode int) agentError {
	body := agentError{
		Code:     classifyErrorCode(err, exitCode),
		Message:  errorMessage(err),
		ExitCode: exitCode,
	}
	var cli clicommon.CLIError
	if errors.As(err, &cli) {
		if decor := cli.Decoration(); decor != "" {
			body.Message = strings.Replace(body.Message, decor, "", 1)
		}
		body.Hint = cli.Hint
		body.DidYouMean = cli.DidYouMean
		body.UsageArgv = cli.UsageArgv
	}
	return body
}

// errCodeIngestIncomplete is the one remaining alias, for ingest.go; new code
// names apicontract.Code* directly.
const errCodeIngestIncomplete = apicontract.CodeIngestIncomplete

// codedError carries a stable error code alongside its message, for conditions
// the classifier cannot infer from an exit code or a wrapped sentinel. The type
// lives in clicommon (see CodedError there) so subpackages can raise it too.
type codedError = clicommon.CodedError

// codedErrorf builds an error that reports the given stable code.
func codedErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	return clicommon.CodedErrorf(code, format, args...)
}

// classifyErrorCode maps an error to its stable code. The source cases are
// matched on message content because the database layer wraps driver errors as
// plain text; a miss degrades to apicontract.CodeFailed, never to a wrong success.
func classifyErrorCode(err error, exitCode int) apicontract.ErrorCode {
	switch exitCode {
	case ExitUsageError:
		// A usage error built around a coded error names its own condition and
		// keeps that code (an extension named with --ext that failed to load:
		// exit 2, extension_load_failed). Any other code is outranked by the
		// usage status, which is the contract there.
		var usage usageError
		if errors.As(err, &usage) {
			var coded codedError
			if errors.As(usage.Err, &coded) {
				return coded.Code()
			}
		}
		// A structured error with a code of its own that exits 2 (out_of_scope).
		var cli clicommon.CLIError
		if errors.As(err, &cli) && !cli.IsUsage() {
			return cli.ErrorCode()
		}
		return apicontract.CodeUsageError
	case ExitFailOnGate:
		return apicontract.CodeGateTripped
	case ExitIncomplete:
		// The incomplete error names which budget or failure stopped the work;
		// classifyExitCode only chose 5 because one is in the chain.
		var incomplete incompleteError
		if errors.As(err, &incomplete) {
			return incomplete.Code()
		}
		return apicontract.CodePartial
	}
	// A structured CLI error names its own condition.
	var cli clicommon.CLIError
	if errors.As(err, &cli) && !cli.IsUsage() {
		return cli.ErrorCode()
	}
	// An explicitly coded error outranks every inference below: the call site
	// knew exactly which condition this was.
	var coded codedError
	if errors.As(err, &coded) {
		return coded.Code()
	}
	// The shared opener's refusals are typed for the same reason, and are matched
	// by identity rather than by the "no such table" text below — it never reaches
	// the query layer, because the open is what was refused.
	var incompatible *clicommon.SourceIncompatibleError
	if errors.As(err, &incompatible) {
		return apicontract.CodeSourceIncompatible
	}
	// The database layer codes its own conditions (database_locked from an
	// exhausted busy retry, schema_too_new, schema_outdated) by implementing
	// Code(); pkg/database cannot return a clicommon type.
	var dbCoded interface{ Code() apicontract.ErrorCode }
	if errors.As(err, &dbCoded) {
		return dbCoded.Code()
	}
	// A fuzz run whose baseline got no answer sent no payload: the target
	// was not reachable.
	if errors.Is(err, fuzz.ErrBaselineUnreachable) {
		return apicontract.CodeNoTargetsReachable
	}
	// The AI provider refused the connection or did not resolve before any
	// call to it succeeded. The agent layer passes provider errors on as
	// text, so the marker is matched on the message too.
	if errors.Is(err, stream.ErrProviderUnreachable) ||
		strings.Contains(strings.ToLower(err.Error()), stream.ErrProviderUnreachable.Error()) {
		return apicontract.CodeProviderUnreachable
	}
	// The --read-only evidence open wraps the bare sentinel with its own remedy.
	if errors.Is(err, database.ErrSchemaOutdated) {
		return apicontract.CodeSchemaOutdated
	}
	// exitCode already came from classifyExitCode, which owns the usageError
	// classification — re-deriving it here would be a second copy of that rule.
	//
	// The missing-source case uses the stdlib sentinel rather than a substring:
	// every path that produces it wraps with %w (openSQLiteReadOnly wraps
	// os.Stat, statelessSourceError and clicommon.GetDB wrap onward), and
	// "no such file or directory" is an OS strerror string that is neither
	// locale- nor platform-stable.
	if errors.Is(err, os.ErrNotExist) {
		return apicontract.CodeSourceMissing
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "failed to connect to database"),
		strings.Contains(msg, "not a database"),
		strings.Contains(msg, "readonly database"):
		return apicontract.CodeSourceUnreadable
	// A missing table is matched on message text for the same reason the cases
	// above are, but with a firmer guarantee: unlike an OS strerror string, "no
	// such table" is SQLite's OWN error text, fixed in its source and identical
	// on every platform and locale.
	//
	// Postgres is matched on its SQLSTATE (42P01 = undefined_table), which
	// pgdriver renders into the error string. Deliberately NOT on the prose:
	// Postgres message text is translated per `lc_messages`, so matching
	// "relation … does not exist" would be exactly the locale-unstable string the
	// paragraph above rejects — a closed code set with a branch that silently
	// stops firing on a non-English server.
	case strings.Contains(msg, "no such table"),
		strings.Contains(msg, "42p01"):
		return apicontract.CodeSourceIncompatible
	}
	return apicontract.CodeFailed
}

// emitJSONError writes the structured error to stdout when the caller asked for
// JSON. It is a no-op otherwise, so the human path is byte-for-byte unchanged.
func emitJSONError(err error, exitCode int, cmd *cobra.Command) {
	if !globalJSON || err == nil {
		return
	}
	// One document per invocation. A gate trip, a --fail-on-match hit, or a
	// failure partway through a write all arrive here with a complete result
	// already on stdout; appending a second top-level object to it produces a
	// stream no single json.Unmarshal can read. The exit code reports the
	// outcome in those cases.
	//
	// The exception is --watch, where stdout is already NDJSON (jsonStreamFramed):
	// one more line is the frame, not a violation of it, and a stream that ends
	// because the read broke should say why on the stream. Encode compactly so
	// the error occupies exactly one line like every tick before it.
	if jsonResultEmitted && !jsonStreamFramed {
		return
	}
	if jsonStreamFramed {
		prev := jsonStreamMode
		jsonStreamMode = true
		defer func() { jsonStreamMode = prev }()
	}
	env := outcomeErrorEnvelope(err, exitCode, cmd)
	// Straight to stdout, deliberately NOT through writeAgentJSON: -o/--output
	// redirects the RESULT document, and an error is not one. Routing it there
	// would write the failure into the file the caller expected results in, and
	// leave stdout carrying a receipt for it.
	_ = writeErrorFrame(env)
}
