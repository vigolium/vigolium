package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// A -j invocation prints exactly one document, and that document's `ok` must
// agree with the exit status. A command cannot decide `ok` itself: it writes
// its result and then returns whatever went wrong afterwards (a failed scan, a
// partial ingest, an export that could not be written), and only the root
// handler sees the final error and the exit code it maps to. So the result
// document is held in memory while the command runs and published once, from
// Execute, after the exit code is known:
//
//   - exit 0, 3 or 4 (success, a --fail-on-match hit, the --fail-on gate): the
//     document as the command wrote it, ok:true;
//   - any other exit: the same document with ok:false and an error object
//     {code, message, exit_code} beside it, so the work that did happen is not
//     thrown away to make room for the failure.
//
// The -o file and its receipt go through the same path: the file gets the
// finished document, and the receipt states the same ok/error.
//
// Streams (--watch) are written as they happen and are not held.

// jsonResultDeferred is armed by Execute. Outside it (unit tests that call a
// command's RunE directly) results are written immediately, as before.
var jsonResultDeferred bool

// heldJSONResult is a result document waiting for the exit code.
type heldJSONResult struct {
	// v is the value that was encoded: an *agentEnvelope, or a receipt map.
	v any
	// doc is v as encoded when the command wrote it; published as-is when the
	// outcome is ok.
	doc []byte
	// items are the envelope's rows before the output budget cut them, so a
	// re-encode with the error attached is measured from the full set.
	items any
	// budgeted re-applies --max-output-bytes on a re-encode.
	budgeted bool
	// dest is the -o file ("" = stdout).
	dest string
}

var heldResult *heldJSONResult

// exitIsOK reports whether an exit code is a completed result: success, a
// --fail-on-match hit (3) or the --fail-on gate (4). Everything else (1 error,
// 2 usage, 5 incomplete) is ok:false.
func exitIsOK(code int) bool {
	return code == ExitSuccess || code == ExitFuzzMatch || code == ExitFailOnGate
}

// holdJSONResult records a result document for Execute to publish. It latches
// jsonResultEmitted like a write would, so the one-document guards in the
// commands behave the same either way.
func holdJSONResult(r *heldJSONResult) {
	heldResult = r
	jsonResultEmitted = true
}

// finishJSONOutcome publishes the -j outcome of the invocation: the held result
// document with ok and error decided from the exit code, or, when the command
// produced no document, the error envelope. It returns the exit code and error
// the process should end with, which differ from the inputs only when writing
// the held -o file failed.
func finishJSONOutcome(err error, code int, cmd *cobra.Command) (int, error) {
	held := heldResult
	heldResult = nil
	jsonResultDeferred = false
	if held == nil || !globalJSON {
		emitJSONError(err, code, cmd)
		return code, err
	}
	if pubErr := publishHeldResult(held, err, code); pubErr != nil {
		// Nothing reached stdout: the -o file could not be written. That is the
		// outcome now, framed like any other failure.
		jsonResultEmitted = false
		fmt.Fprintf(os.Stderr, "%s %v\n", terminal.ErrorPrefix(), pubErr)
		err = pubErr
		code = classifyExitCode(err)
		emitJSONError(err, code, cmd)
		return code, err
	}
	return code, err
}

// publishHeldResult writes held to its destination, with the error attached
// when the exit code is not a completed result.
func publishHeldResult(held *heldJSONResult, err error, code int) error {
	doc := held.doc
	var body *agentError
	if !exitIsOK(code) {
		b := newAgentErrorBody(err, code)
		body = &b
		reencoded, encErr := attachOutcomeError(held, body)
		if encErr != nil {
			return encErr
		}
		doc = reencoded
	}
	if held.dest != "" {
		return writeJSONResultToFileNow(held.dest, doc, held.v, body)
	}
	return writeAgentJSONDoc(doc)
}

// errorMessage is err's text, "" for nil.
func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// attachOutcomeError sets ok:false and the error object on the held value and
// encodes it again. The output budget is re-applied from the full row set, so
// --max-output-bytes is measured with the error included.
func attachOutcomeError(held *heldJSONResult, body *agentError) ([]byte, error) {
	switch v := held.v.(type) {
	case *agentEnvelope:
		v.OK = false
		v.Error = body
		v.SoftFail = globalSoftFail
		if held.budgeted {
			v.Items = held.items
			delete(v.extra, outputBudgetKey)
			doc, err := applyOutputBudget(v, maxOutputBytes)
			if err != nil {
				return nil, err
			}
			if doc != nil {
				return doc, nil
			}
		}
		return encodeAgentJSON(v)
	case map[string]any:
		v["ok"] = false
		v["error"] = body
		if globalSoftFail {
			v["soft_fail"] = true
		}
		return encodeAgentJSON(v)
	}
	return held.doc, nil
}

// outcomeErrorEnvelope builds the error envelope for an invocation that wrote no
// result document.
func outcomeErrorEnvelope(err error, exitCode int, cmd *cobra.Command) agentErrorEnvelope {
	name := "vigolium"
	if cmd != nil {
		name = commandPathWithoutRoot(cmd)
	}
	now := time.Now()
	return agentErrorEnvelope{
		SchemaVersion: AgentSchemaVersion,
		Command:       name,
		OK:            false,
		Error:         newAgentErrorBody(err, exitCode),
		DBPath:        resolvedReadDBPath(),
		SoftFail:      globalSoftFail,
		GeneratedAt:   agentTimestamp(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
	}
}
