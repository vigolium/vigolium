package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// withDeferredJSON arms the held-result path the way Execute does, and
// restores every global the outcome path touches.
func withDeferredJSON(t *testing.T) *cobra.Command {
	t.Helper()
	withMachineDocumentState(t)
	prevDeferred, prevHeld, prevBudget := jsonResultDeferred, heldResult, maxOutputBytes
	t.Cleanup(func() { jsonResultDeferred, heldResult, maxOutputBytes = prevDeferred, prevHeld, prevBudget })
	globalJSON = true
	jsonResultDeferred = true
	heldResult = nil
	maxOutputBytes = 0
	root := &cobra.Command{Use: "vigolium"}
	cmd := &cobra.Command{Use: "traffic"}
	root.AddCommand(cmd)
	return cmd
}

// runAsExecute runs fn the way Execute runs a command under -j: the result
// document is held, then published with ok and error decided from fn's error.
func runAsExecute(cmd *cobra.Command, fn func() error) error {
	jsonResultDeferred = true
	err := fn()
	_, _ = finishJSONOutcome(err, classifyExitCode(err), cmd)
	return err
}

func outcomeDoc(t *testing.T, out string) map[string]any {
	t.Helper()
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1, "exactly one document on stdout: %q", out)
	return docs[0]
}

// TestJSONOutcomeOKMatchesExitCode: the held document's ok is decided from the
// exit code, and error is present exactly when ok is false.
func TestJSONOutcomeOKMatchesExitCode(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		code     int
		wantOK   bool
		wantCode apicontract.ErrorCode
	}{
		{"success", nil, ExitSuccess, true, ""},
		{"fuzz match", asMatchErrorf("matched"), ExitFuzzMatch, true, ""},
		{"gate", gateError{err: errors.New("gate")}, ExitFailOnGate, true, ""},
		{"failure after result", errors.New("scan failed"), ExitError, false, apicontract.CodeFailed},
		{"coded failure", codedErrorf(apicontract.CodeFindingNotFound, "no finding 9"), ExitError, false, apicontract.CodeFindingNotFound},
		{"usage", usageErrorf("bad"), ExitUsageError, false, apicontract.CodeUsageError},
		{"incomplete", incompleteErrorf(apicontract.CodePartial, "half"), ExitIncomplete, false, apicontract.CodePartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := withDeferredJSON(t)
			out := captureStdout(t, func() {
				require.NoError(t, writeAgentJSON(newAgentEnvelope("traffic", "", []map[string]any{{"uuid": "a"}}, 1, 0, 10)))
				code, _ := finishJSONOutcome(tc.err, tc.code, cmd)
				require.Equal(t, tc.code, code)
			})
			doc := outcomeDoc(t, out)
			require.Equal(t, tc.wantOK, doc["ok"])
			require.Len(t, doc["items"], 1, "the document keeps what the work produced")
			errObj, hasErr := doc["error"].(map[string]any)
			require.Equal(t, !tc.wantOK, hasErr, "error is present exactly when ok is false: %v", doc)
			if hasErr {
				require.Equal(t, string(tc.wantCode), errObj["code"])
				require.EqualValues(t, tc.code, errObj["exit_code"])
				require.NotEmpty(t, errObj["message"])
			}
		})
	}
}

// TestJSONOutcomeNoResultIsErrorEnvelope: with nothing held, a failure prints
// the error envelope, as before.
func TestJSONOutcomeNoResultIsErrorEnvelope(t *testing.T) {
	cmd := withDeferredJSON(t)
	out := captureStdout(t, func() { _, _ = finishJSONOutcome(errors.New("boom"), ExitError, cmd) })
	doc := outcomeDoc(t, out)
	require.Equal(t, false, doc["ok"])
	require.Equal(t, "traffic", doc["command"])
	require.NotNil(t, doc["error"])
}

// TestJSONOutcomeOutputFileCarriesOutcome: -o gets the finished document and
// the receipt states the same ok/error.
func TestJSONOutcomeOutputFileCarriesOutcome(t *testing.T) {
	cmd := withDeferredJSON(t)
	dest := filepath.Join(t.TempDir(), "result.json")
	jsonOutputPath = dest
	out := captureStdout(t, func() {
		require.NoError(t, writeAgentJSON(newAgentEnvelope("traffic", "", []map[string]any{{"uuid": "a"}}, 1, 0, 10)))
		require.Empty(t, mustReadFileOrEmpty(dest), "the -o file is written once the outcome is known")
		_, _ = finishJSONOutcome(errors.New("late failure"), ExitError, cmd)
	})
	receipt := outcomeDoc(t, out)
	require.Equal(t, false, receipt["ok"])
	require.NotNil(t, receipt["error"])

	var saved map[string]any
	require.NoError(t, json.Unmarshal(mustReadFileOrEmpty(dest), &saved))
	require.Equal(t, false, saved["ok"])
	require.NotNil(t, saved["error"])
}

// TestJSONOutcomeOutputFileFailureIsExportFailed: a held -o that cannot be
// written ends the invocation as export_failed with the error envelope.
func TestJSONOutcomeOutputFileFailureIsExportFailed(t *testing.T) {
	cmd := withDeferredJSON(t)
	jsonOutputPath = filepath.Join(t.TempDir(), "absent", "result.json")
	var code int
	out := captureStdout(t, func() {
		require.NoError(t, writeAgentJSON(newAgentEnvelope("traffic", "", []map[string]any{}, 0, 0, 10)))
		_ = captureStderr(t, func() { code, _ = finishJSONOutcome(nil, ExitSuccess, cmd) })
	})
	require.Equal(t, ExitError, code)
	doc := outcomeDoc(t, out)
	require.Equal(t, false, doc["ok"])
	require.Equal(t, string(apicontract.CodeExportFailed), doc["error"].(map[string]any)["code"])
}

// TestJSONOutcomeBudgetIncludesError: --max-output-bytes is measured with the
// error object attached.
func TestJSONOutcomeBudgetIncludesError(t *testing.T) {
	cmd := withDeferredJSON(t)
	rows := make([]map[string]any, 40)
	for i := range rows {
		rows[i] = map[string]any{"uuid": i, "pad": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
	}
	maxOutputBytes = 1500
	out := captureStdout(t, func() {
		require.NoError(t, writeAgentJSON(newAgentEnvelope("traffic", "", rows, 40, 0, 40)))
		_, _ = finishJSONOutcome(errors.New("failed after the page was built"), ExitError, cmd)
	})
	require.LessOrEqual(t, len(out), 1500, "the budget holds with the error attached")
	doc := outcomeDoc(t, out)
	require.Equal(t, false, doc["ok"])
	budget := doc[outputBudgetKey].(map[string]any)
	require.EqualValues(t, 40, budget["returned"].(float64)+budget["omitted"].(float64),
		"omitted is counted from the full row set, not the first cut")
}

func mustReadFileOrEmpty(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}
