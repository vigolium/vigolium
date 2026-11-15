package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

func writeLintFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func withSessionLintState(t *testing.T) {
	t.Helper()
	withMachineDocumentState(t)
	prev := sessionLintStdin
	t.Cleanup(func() { sessionLintStdin = prev })
	sessionLintStdin = false
}

const lintSingleSession = `name: admin
role: primary
login:
  url: https://example.com/login
  method: POST
  type: bearer
  token_path: .token
`

const lintTypo = `sessions:
  - name: admin
    role: primary
    login:
      url: https://example.com/login
      method: POST
      extarct:
        - source: cookie
`

func TestSessionLint_SingleSessionClean(t *testing.T) {
	withSessionLintState(t)
	f := writeLintFile(t, "admin.yaml", lintSingleSession)
	var err error
	out := captureStdout(t, func() { err = runSessionLint(sessionLintCmd, []string{f}) })
	require.NoError(t, err)
	require.Contains(t, out, "all clean")
}

func TestSessionLint_TypoIsCodedErrorWithLine(t *testing.T) {
	withSessionLintState(t)
	f := writeLintFile(t, "typo.yaml", lintTypo)
	var err error
	out := captureStdout(t, func() { err = runSessionLint(sessionLintCmd, []string{f}) })
	require.Error(t, err)
	// The old sentinel was errors.New(""): an exit 1 with nothing to say.
	require.NotEmpty(t, strings.TrimSpace(err.Error()))
	require.Equal(t, apicontract.CodeLintFailed, classifyErrorCode(err, classifyExitCode(err)))
	require.Contains(t, out, "line 7:7")
	require.Contains(t, out, `unknown field "extarct"`)
}

func TestSessionLint_MultipleFilesJSON(t *testing.T) {
	withSessionLintState(t)
	globalJSON = true
	clean := writeLintFile(t, "admin.yaml", lintSingleSession)
	typo := writeLintFile(t, "typo.yaml", lintTypo)
	broken := writeLintFile(t, "broken.json", "{\"sessions\": [\n  {\"name\": }\n]}")

	var err error
	out := captureStdout(t, func() {
		err = runAsExecute(sessionLintCmd, func() error { return runSessionLint(sessionLintCmd, []string{clean, typo, broken}) })
	})
	require.Error(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	doc := docs[0]
	require.Equal(t, "auth lint", doc["command"])
	require.Equal(t, "read", doc["kind"])
	require.Equal(t, false, doc["ok"])
	require.Equal(t, "lint_failed", doc["error"].(map[string]any)["code"])
	require.EqualValues(t, 3, doc["files"])
	require.EqualValues(t, 0, doc["warnings"])

	items := doc["items"].([]any)
	require.EqualValues(t, len(items), doc["total"])
	require.EqualValues(t, len(items), doc["errors"])
	var sawTypo, sawBroken bool
	for _, it := range items {
		m := it.(map[string]any)
		require.Contains(t, m, "file")
		require.Contains(t, m, "severity")
		require.Contains(t, m, "message")
		require.NotEqual(t, clean, m["file"], "a clean file contributes no items")
		if m["field"] == "sessions[0].login.extarct" {
			sawTypo = true
			require.Equal(t, typo, m["file"])
			require.EqualValues(t, 7, m["line"])
			require.EqualValues(t, 7, m["column"])
		}
		if m["file"] == broken {
			sawBroken = true
			require.EqualValues(t, 2, m["line"])
			require.Contains(t, m["message"], "failed to parse")
		}
	}
	require.True(t, sawTypo && sawBroken, "items: %v", items)
}

func TestSessionLint_JSONClean(t *testing.T) {
	withSessionLintState(t)
	globalJSON = true
	f := writeLintFile(t, "admin.yaml", lintSingleSession)
	var err error
	out := captureStdout(t, func() { err = runSessionLint(sessionLintCmd, []string{f}) })
	require.NoError(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	require.Equal(t, true, docs[0]["ok"])
	require.Equal(t, []any{}, docs[0]["items"])
	require.EqualValues(t, 0, docs[0]["errors"])
}

func TestSessionLint_NoInputIsUsageError(t *testing.T) {
	withSessionLintState(t)
	err := runSessionLint(sessionLintCmd, nil)
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
}
