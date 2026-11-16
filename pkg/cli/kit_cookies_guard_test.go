package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/browsercookie"
)

const kitCookiesTestSecret = "LIVE-SESSION-VALUE-0123456789"

// stubKitCookiesRead makes the command read res instead of this machine's
// browser profiles and keychain, and returns the queries it was given.
func stubKitCookiesRead(t *testing.T, res browsercookie.Result) *[]browsercookie.Query {
	t.Helper()
	var seen []browsercookie.Query
	prev := kitCookiesRead
	kitCookiesRead = func(_ context.Context, q browsercookie.Query) (browsercookie.Result, error) {
		seen = append(seen, q)
		return res, nil
	}
	t.Cleanup(func() { kitCookiesRead = prev })
	return &seen
}

func kitCookiesOneCookie() browsercookie.Result {
	return browsercookie.Result{
		Cookies: []browsercookie.Cookie{{Name: "sid", Value: kitCookiesTestSecret, Domain: "app.acme.test", Path: "/", Browser: "chrome", Profile: "Default"}},
		Origins: []browsercookie.Origin{{Origin: "https://app.acme.test",
			LocalStorage:   []browsercookie.StorageItem{{Name: "token", Value: kitCookiesTestSecret}},
			SessionStorage: []browsercookie.StorageItem{{Name: "nonce", Value: kitCookiesTestSecret}}}},
		Stores: []browsercookie.StoreResult{{Store: browsercookie.StoreInfo{Browser: "chrome", Profile: "Default"}, Count: 1}},
	}
}

func kitCookiesDeniedKeyring() browsercookie.Result {
	return browsercookie.Result{
		Stores: []browsercookie.StoreResult{{Store: browsercookie.StoreInfo{Browser: "chrome", Profile: "Default"},
			Problem: browsercookie.ProblemKeyringDenied, Detail: "keyring password retrieval failed"}},
	}
}

// Under -j redaction (a coding agent) every cookie and storage value is masked
// and the envelope says redacted:true; --reveal is the deliberate way out.
func TestKitCookiesJSONMasksValuesUnderRedaction(t *testing.T) {
	resetKitCookiesFlags(t)
	stubKitCookiesRead(t, kitCookiesOneCookie())
	swapGlobal(t, &jsonRedactOn, true)
	t.Cleanup(func() { viewsRedacted.Store(false) })

	doc := emitCaptured(t, func() error { return runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	raw := mustJSON(t, doc)
	assert.NotContains(t, raw, kitCookiesTestSecret, "no value reaches the document")
	assert.Equal(t, true, doc["redacted"])
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, browsercookie.Redact(kitCookiesTestSecret), items[0].(map[string]any)["value"])

	resetKitCookiesFlags(t)
	kitCookiesReveal = true
	viewsRedacted.Store(false)
	doc = emitCaptured(t, func() error { return runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	assert.Contains(t, mustJSON(t, doc), kitCookiesTestSecret, "--reveal shows the values")
	assert.Equal(t, false, doc["redacted"])
}

// Storage values alone are masked through the shared marker too: a report
// with no cookie but a localStorage value still says redacted:true.
func TestKitCookiesStorageOnlyMaskingMarksRedacted(t *testing.T) {
	viewsRedacted.Store(false)
	t.Cleanup(func() { viewsRedacted.Store(false) })
	report := kitCookiesReport{kitCookiesExtras: kitCookiesExtras{Origins: []browsercookie.Origin{{Origin: "https://app.acme.test",
		LocalStorage: []browsercookie.StorageItem{{Name: "token", Value: kitCookiesTestSecret}}}}}}

	got := redactKitCookiesReport(false, report)
	assert.Equal(t, kitCookiesTestSecret, got.Origins[0].LocalStorage[0].Value)
	assert.False(t, viewsRedacted.Load(), "redaction off marks nothing")

	got = redactKitCookiesReport(true, report)
	assert.Equal(t, browsercookie.Redact(kitCookiesTestSecret), got.Origins[0].LocalStorage[0].Value)
	assert.Equal(t, kitCookiesTestSecret, report.Origins[0].LocalStorage[0].Value, "the input is not modified")
	assert.True(t, viewsRedacted.Load())
}

// Outside an agent (redaction off) -j carries the values and says so.
func TestKitCookiesJSONCarriesValuesWithoutRedaction(t *testing.T) {
	resetKitCookiesFlags(t)
	stubKitCookiesRead(t, kitCookiesOneCookie())
	swapGlobal(t, &jsonRedactOn, false)
	viewsRedacted.Store(false)
	doc := emitCaptured(t, func() error { return runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	assert.Contains(t, mustJSON(t, doc), kitCookiesTestSecret)
	assert.Equal(t, false, doc["redacted"])
}

// --stdout is refused under a coding agent unless --reveal or
// VIGOLIUM_REDACT=0 says the caller means it; the read never runs.
func TestKitCookiesStdoutRefusedUnderACodingAgent(t *testing.T) {
	resetKitCookiesFlags(t)
	seen := stubKitCookiesRead(t, kitCookiesOneCookie())
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("VIGOLIUM_REDACT", "")
	swapGlobal(t, &redactRequested, false)
	swapGlobal(t, &jsonRedactOn, false)
	t.Cleanup(func() { viewsRedacted.Store(false) })
	// The guard reads the mode the root pre-run resolved.
	require.NoError(t, applyRedactionMode())
	require.True(t, redactRequested, "a coding agent requests redaction without -j")
	kitCookiesFormat, kitCookiesStdout = "header", true

	err := runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"})
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, err.Error(), "-o <file>")
	assert.Empty(t, *seen, "nothing was read")

	for name, setup := range map[string]func(){
		"--reveal":          func() { kitCookiesReveal = true },
		"VIGOLIUM_REDACT=0": func() { t.Setenv("VIGOLIUM_REDACT", "0") },
		"--no-redact":       func() { swapGlobal(t, &globalNoRedact, true) },
	} {
		t.Run(name, func(t *testing.T) {
			resetKitCookiesFlags(t)
			kitCookiesFormat, kitCookiesStdout = "header", true
			setup()
			require.NoError(t, applyRedactionMode())
			var runErr error
			out := captureStdout(t, func() {
				captureStderr(t, func() { runErr = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
			})
			require.NoError(t, runErr)
			assert.Contains(t, out, "sid="+kitCookiesTestSecret)
		})
	}
}

// A failed read (the keyring refused the key) never writes the export: a good
// state.json survives, the error is keyring_denied, and the listing does not
// claim "no cookies matched".
func TestKitCookiesDeniedKeyringKeepsTheExistingExport(t *testing.T) {
	resetKitCookiesFlags(t)
	stubKitCookiesRead(t, kitCookiesDeniedKeyring())
	out := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(out, []byte(`{"cookies":["good"]}`), 0o600))
	kitCookiesFormat, kitCookiesOutput = "playwright", out

	var err error
	stderr := captureStderr(t, func() { err = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	require.Error(t, err)
	assert.Equal(t, apicontract.CodeKeyringDenied, classifyErrorCode(err, classifyExitCode(err)))
	assert.NotContains(t, stderr, "no cookies matched", "a denied keyring is not an empty profile")
	got, rerr := os.ReadFile(out)
	require.NoError(t, rerr)
	assert.Equal(t, `{"cookies":["good"]}`, string(got), "the saved session is untouched")

	// A clone is not built from a failed read either.
	resetKitCookiesFlags(t)
	clone := filepath.Join(t.TempDir(), "clone")
	kitCookiesCloneDir = clone
	captureStderr(t, func() { err = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	assert.Equal(t, apicontract.CodeKeyringDenied, classifyErrorCode(err, classifyExitCode(err)))
	_, statErr := os.Stat(clone)
	assert.True(t, os.IsNotExist(statErr))
}

// An empty read never replaces an existing -o file: it is kept, the document
// says output_kept, and the run exits 3. A new path is still written.
func TestKitCookiesEmptyReadKeepsTheExistingExport(t *testing.T) {
	resetKitCookiesFlags(t)
	stubKitCookiesRead(t, browsercookie.Result{Stores: []browsercookie.StoreResult{{Store: browsercookie.StoreInfo{Browser: "chrome"}}}})
	out := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(out, []byte("saved"), 0o600))
	kitCookiesFormat, kitCookiesOutput = "playwright", out

	withMachineDocumentState(t)
	globalJSON = true
	var err error
	stdout := captureStdout(t, func() { err = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	require.Error(t, err)
	assert.Equal(t, ExitFuzzMatch, classifyExitCode(err))
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1)
	assert.Equal(t, out, docs[0]["output_kept"])
	assert.Nil(t, docs[0]["output"])
	got, _ := os.ReadFile(out)
	assert.Equal(t, "saved", string(got))

	resetKitCookiesFlags(t)
	fresh := filepath.Join(t.TempDir(), "new.json")
	kitCookiesFormat, kitCookiesOutput = "playwright", fresh
	captureStderr(t, func() { err = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	require.NoError(t, err)
	_, statErr := os.Stat(fresh)
	assert.NoError(t, statErr, "a new path is written as before")
}

// --no-prompt reaches the read.
func TestKitCookiesNoPromptReachesTheRead(t *testing.T) {
	resetKitCookiesFlags(t)
	seen := stubKitCookiesRead(t, kitCookiesOneCookie())
	kitCookiesNoPrompt = true
	captureStdout(t, func() {
		captureStderr(t, func() { _ = runKitCookies(newKitCookiesTestCmd(), []string{"app.acme.test"}) })
	})
	require.Len(t, *seen, 1)
	assert.True(t, (*seen)[0].NoPrompt)
}

// VIGOLIUM_COOKIES_ACK is read through the shared truthy parser: 1, true, yes
// and on acknowledge; 0, false or a typo is not consent.
func TestKitCookiesAckEnvUsesSharedTruthyParser(t *testing.T) {
	swapGlobal(t, &kitCookiesAck, false)
	for raw, want := range map[string]bool{
		"1": true, "true": true, "TRUE": true, " 1 ": true, "yes": true, "on": true,
		"": false, "0": false, "false": false, "no": false, "2": false, "ture": false,
	} {
		t.Setenv("VIGOLIUM_COOKIES_ACK", raw)
		assert.Equal(t, want, kitCookiesAcknowledged(), "%q", raw)
	}
}

// Every hint that mentions the macOS prompt recommends a one-time "Allow" and
// never tells the operator to "choose Always Allow".
func TestKitCookiesHintsNeverRecommendAlwaysAllow(t *testing.T) {
	for _, text := range []string{kitCookiesDoctorCmd.Long, kitCookiesCmd.Long} {
		assert.NotContains(t, strings.ToLower(text), `choose "always allow"`)
	}
	assert.Contains(t, kitCookiesDoctorCmd.Long, `Choose "Allow"`)
}
