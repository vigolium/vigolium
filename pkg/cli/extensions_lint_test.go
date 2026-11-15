package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

func writeTestFileAt(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func withExtLintState(t *testing.T) {
	t.Helper()
	withMachineDocumentState(t)
	prevStdin, prevKind, prevStrict := lintStdin, lintStdinKind, lintStrict
	t.Cleanup(func() { lintStdin, lintStdinKind, lintStrict = prevStdin, prevKind, prevStrict })
	lintStdin, lintStdinKind, lintStrict = false, "", false
}

const extLintCleanJS = `module.exports = {
  id: "clean",
  type: "passive",
  severity: "info",
  scanPerRequest: function(ctx) { return null; }
};
`

// Warnings only: a top-level effectful call.
const extLintWarnJS = `var warm = vigolium.http.get("http://127.0.0.1:1/");
module.exports = {
  id: "warn",
  type: "passive",
  severity: "info",
  scanPerRequest: function(ctx) { return null; }
};
`

// Errors: the declared scan type's handler is missing.
const extLintErrJS = `module.exports = {
  id: "err",
  type: "active",
  severity: "high",
  scanTypes: ["per_insertion_point"]
};
`

func runExtLint(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runExtensionsLint(extensionsLintCmd, args) })
	return out, err
}

func TestExtLint_ExitCodes(t *testing.T) {
	withExtLintState(t)

	_, err := runExtLint(t, writeLintFile(t, "clean.js", extLintCleanJS))
	require.NoError(t, err)

	_, err = runExtLint(t, writeLintFile(t, "warn.js", extLintWarnJS))
	require.NoError(t, err, "warnings alone exit 0")

	_, err = runExtLint(t, writeLintFile(t, "err.js", extLintErrJS))
	require.Error(t, err)
	require.Equal(t, ExitError, classifyExitCode(err))
	require.Equal(t, apicontract.CodeLintFailed, classifyErrorCode(err, classifyExitCode(err)))
	require.Contains(t, err.Error(), "1 error(s)")

	lintStrict = true
	_, err = runExtLint(t, writeLintFile(t, "warn.js", extLintWarnJS))
	require.Error(t, err, "--strict turns warnings into errors")
	require.Equal(t, apicontract.CodeLintFailed, classifyErrorCode(err, classifyExitCode(err)))
}

// TestExtLint_JSONDocument: -j is one document — files as items, a summary, ok
// false exactly when there are errors — with no human report on stdout.
func TestExtLint_JSONDocument(t *testing.T) {
	withExtLintState(t)
	globalJSON = true

	dir := t.TempDir()
	writeTestFileAt(t, dir, "clean.js", extLintCleanJS)
	writeTestFileAt(t, dir, "err.js", extLintErrJS)
	writeTestFileAt(t, dir, "typo.vgm.yaml", "id: t\ntype: passive\nmatcher:\n  - contains: x\n")

	var err error
	out := captureStdout(t, func() {
		err = runAsExecute(extensionsLintCmd, func() error { return runExtensionsLint(extensionsLintCmd, []string{dir}) })
	})
	require.Error(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1, out)
	doc := docs[0]
	require.Equal(t, "extensions lint", doc["command"])
	require.Equal(t, false, doc["ok"])
	require.Equal(t, "lint_failed", doc["error"].(map[string]any)["code"])

	summary := doc["summary"].(map[string]any)
	require.EqualValues(t, 3, summary["files"])
	require.GreaterOrEqual(t, summary["errors"].(float64), float64(2))

	items := doc["items"].([]any)
	require.Len(t, items, 3)
	rules := map[string]map[string]any{}
	for _, it := range items {
		f := it.(map[string]any)
		require.Contains(t, []any{"js", "ts", "yaml"}, f["kind"])
		require.NotNil(t, f["issues"], "issues is never null")
		for _, is := range f["issues"].([]any) {
			m := is.(map[string]any)
			for _, k := range []string{"severity", "line", "col", "message", "rule"} {
				require.Contains(t, m, k)
			}
			rules[m["rule"].(string)] = m
		}
	}
	require.Contains(t, rules, "missing-handler")
	require.Contains(t, rules, "yaml-unknown-key")
	require.EqualValues(t, 3, rules["yaml-unknown-key"]["line"])
	require.Contains(t, rules["yaml-unknown-key"]["message"], `did you mean "matchers"?`)
}

func TestExtLint_JSONCleanIsOK(t *testing.T) {
	withExtLintState(t)
	globalJSON = true
	out, err := runExtLint(t, writeLintFile(t, "warn.js", extLintWarnJS))
	require.NoError(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	require.Equal(t, true, docs[0]["ok"])
	require.EqualValues(t, 1, docs[0]["summary"].(map[string]any)["warnings"])
}

// TestExtLint_StdinSniffsYAML: --stdin without --stdin-kind lints a YAML
// extension as YAML (it used to always be parsed as JavaScript).
func TestExtLint_StdinSniffsYAML(t *testing.T) {
	withExtLintState(t)
	globalJSON = true
	lintStdin = true
	w := withPipedStdin(t)
	_, werr := w.WriteString("id: s\ntype: passive\nmatchers:\n  - contains: x\n")
	require.NoError(t, werr)
	require.NoError(t, w.Close())

	out, err := runExtLint(t)
	require.NoError(t, err, out)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	f := docs[0]["items"].([]any)[0].(map[string]any)
	require.Equal(t, "yaml", f["kind"])
	require.Equal(t, "<stdin>", f["path"])
}

func TestExtLint_StdinKindValidation(t *testing.T) {
	withExtLintState(t)
	lintStdinKind = "yaml"
	_, err := runExtLint(t, writeLintFile(t, "clean.js", extLintCleanJS))
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))

	lintStdin, lintStdinKind = true, "python"
	_, err = runExtLint(t)
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
}

func TestSniffExtensionKind(t *testing.T) {
	require.Equal(t, "yaml", sniffExtensionKind("# c\nid: x\ntype: passive\n"))
	require.Equal(t, "js", sniffExtensionKind(extLintCleanJS))
	require.Equal(t, "js", sniffExtensionKind("var type = 1;"))
}

// TestExtensionLoadExitError: the runner's explicit-extension failure is exit 2
// with error.code extension_load_failed.
func TestExtensionLoadExitError(t *testing.T) {
	loadErr := &runner.ExtensionLoadError{Failures: []jsext.LoadFailure{{
		Path: "bad.js", Stage: jsext.LoadStageMetadata, Err: errors.New("boom"), Explicit: true,
	}}}
	err := codedScanError(fmt.Errorf("scan: %w", loadErr))
	require.Contains(t, err.Error(), "bad.js (metadata): boom")
	require.Equal(t, ExitUsageError, classifyExitCode(err))
	require.Equal(t, apicontract.CodeExtensionLoadFailed, classifyErrorCode(err, classifyExitCode(err)))
}

// TestApplyScanCompletion_ExtensionsFailed: scan.finished carries the
// extensions the runner recorded as failed on the scan row.
func TestApplyScanCompletion_ExtensionsFailed(t *testing.T) {
	ev := &scanevents.Event{Type: scanevents.TypeScanFinished, Status: scanevents.StatusCompleted}
	applyScanCompletion(ev, &database.Scan{ExtensionsFailed: []string{"/x/bad.js"}})
	require.Equal(t, []string{"/x/bad.js"}, ev.ExtensionsFailed)

	ev = &scanevents.Event{Type: scanevents.TypeScanFinished}
	applyScanCompletion(ev, &database.Scan{})
	require.Nil(t, ev.ExtensionsFailed)
}
