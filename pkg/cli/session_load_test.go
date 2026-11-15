package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// withSessionLoadState isolates the auth load globals, the database and the
// machine-output latch for one test.
func withSessionLoadState(t *testing.T) {
	t.Helper()
	withMachineDocumentState(t)
	prevHost, prevNoVal, prevSrc := sessionLoadHost, sessionLoadNoValidate, sessionLoadSource
	prevAgent, prevName, prevForce := sessionLoadAgentFormat, sessionLoadName, sessionLoadForce
	prevTimeout, prevProxy := sessionLoadTimeout, globalProxy
	t.Cleanup(func() {
		sessionLoadHost, sessionLoadNoValidate, sessionLoadSource = prevHost, prevNoVal, prevSrc
		sessionLoadAgentFormat, sessionLoadName, sessionLoadForce = prevAgent, prevName, prevForce
		sessionLoadTimeout, globalProxy = prevTimeout, prevProxy
		clicommon.ResetDBCache()
	})
	clicommon.ResetDBCache()
	sessionLoadHost, sessionLoadNoValidate, sessionLoadSource = "", false, "cli"
	sessionLoadAgentFormat, sessionLoadName, sessionLoadForce = false, "", false
	sessionLoadTimeout, globalProxy = sessionLoadDefaultTimeout, ""
	t.Setenv("HOME", t.TempDir())
	// Keep the environment proxy out of the login transport.
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "VIGOLIUM_PROXY"} {
		t.Setenv(k, "")
	}
	globalDB = filepath.Join(t.TempDir(), "auth.sqlite")
}

// loginApp: POST /login succeeds (cookie + "Welcome") only with pw=right; any
// other password re-renders the form with "invalid".
func loginApp(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "pw=right") {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
			_, _ = fmt.Fprint(w, "Welcome")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "anon", Value: "1", Path: "/"})
		_, _ = fmt.Fprint(w, `<form><input type="password" name="pw"></form> invalid`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeSessionFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sessions.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func storedSessionNames(t *testing.T) []string {
	t.Helper()
	clicommon.ResetDBCache()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = globalDB
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	rows, err := database.NewRepository(db).GetAuthenticationHostnamesByProject(context.Background(), database.DefaultProjectUUID)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return nil
	}
	require.NoError(t, err)
	var names []string
	for _, r := range rows {
		names = append(names, r.SessionName)
	}
	return names
}

func twoSessionFile(loginURL string) string {
	return fmt.Sprintf(`sessions:
  - name: good
    role: primary
    login:
      url: %[1]s/login
      method: POST
      body: pw=right
      extract:
        - source: cookie
      expect:
        body_contains: Welcome
  - name: bad
    role: compare
    login:
      url: %[1]s/login
      method: POST
      body: pw=wrong
      extract:
        - source: cookie
      expect:
        body_contains: Welcome
`, loginURL)
}

// A wrong password caught by expect.body_contains: exit 1 with login_failed,
// and the failed session is not saved.
func TestSessionLoad_FailedLoginNotPersisted(t *testing.T) {
	withSessionLoadState(t)
	srv := loginApp(t, nil)
	file := writeSessionFile(t, twoSessionFile(srv.URL))

	var err error
	out := captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.Error(t, err)
	require.Equal(t, ExitError, classifyExitCode(err))
	require.Equal(t, apicontract.CodeLoginFailed, classifyErrorCode(err, ExitError))
	require.Contains(t, err.Error(), "bad (expect_body_missing)")
	require.Contains(t, out, "expect_body_missing")
	require.Equal(t, []string{"good"}, storedSessionNames(t))
}

func TestSessionLoad_ForcePersistsFailed(t *testing.T) {
	withSessionLoadState(t)
	sessionLoadForce = true
	srv := loginApp(t, nil)
	file := writeSessionFile(t, twoSessionFile(srv.URL))

	var err error
	_ = captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.Error(t, err, "--force saves, but the failed login still exits 1")
	require.ElementsMatch(t, []string{"good", "bad"}, storedSessionNames(t))
}

// No expect block, form came back: unverified warning, saved, exit 0.
func TestSessionLoad_UnverifiedIsWarning(t *testing.T) {
	withSessionLoadState(t)
	srv := loginApp(t, nil)
	file := writeSessionFile(t, fmt.Sprintf(`name: maybe
login:
  url: %s/login
  method: POST
  body: pw=wrong
  extract:
    - source: cookie
`, srv.URL))

	var err error
	out := captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.NoError(t, err)
	require.Contains(t, out, "unverified")
	require.Equal(t, []string{"maybe"}, storedSessionNames(t))
}

// Multi-step flows are checked step by step (the old probe sent the empty
// parent URL).
func TestSessionLoad_MultiStep(t *testing.T) {
	withSessionLoadState(t)
	var step1, step2 atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		step1.Add(1)
		_, _ = fmt.Fprint(w, `{"tmp":"xyz"}`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		step2.Add(1)
		body, _ := io.ReadAll(r.Body)
		require.Contains(t, string(body), "xyz")
		_, _ = fmt.Fprint(w, `{"token":"T"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	file := writeSessionFile(t, fmt.Sprintf(`sessions:
  - name: ms
    role: primary
    login:
      steps:
        - url: %[1]s/a
          method: POST
          body: '{}'
          extract:
            - source: json
              path: $.tmp
              apply_as: "var:tmp"
        - url: %[1]s/b
          method: POST
          body: '{"t":"{tmp}"}'
          expect:
            status: [200]
          extract:
            - source: json
              path: $.token
              apply_as: "Authorization: Bearer {value}"
`, srv.URL))

	var err error
	_ = captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.NoError(t, err)
	require.EqualValues(t, 1, step1.Load())
	require.EqualValues(t, 1, step2.Load())
	require.Equal(t, []string{"ms"}, storedSessionNames(t))
}

// --proxy is honoured: the proxy sees the login request.
func TestSessionLoad_HonoursProxy(t *testing.T) {
	withSessionLoadState(t)
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		require.Equal(t, "login.example.test", r.URL.Hostname(), "a proxied request carries the absolute target URL")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
		_, _ = fmt.Fprint(w, "Welcome")
	}))
	defer proxy.Close()
	globalProxy = proxy.URL
	file := writeSessionFile(t, `name: viaproxy
login:
  url: http://login.example.test/login
  method: POST
  body: pw=right
  extract:
    - source: cookie
  expect:
    body_contains: Welcome
`)

	var err error
	_ = captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.NoError(t, err)
	require.EqualValues(t, 1, proxied.Load())
}

// -j: one document, the mutation spine, one LoginResult per session, the
// persisted/failed names, and on failure ok:false with error.code.
func TestSessionLoad_JSONDocument(t *testing.T) {
	withSessionLoadState(t)
	globalJSON = true
	srv := loginApp(t, nil)
	file := writeSessionFile(t, twoSessionFile(srv.URL))

	var err error
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			err = runAsExecute(sessionLoadCmd, func() error { return runSessionLoad(sessionLoadCmd, []string{file}) })
		})
	})
	require.Error(t, err)
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, "human output must stay off stdout under -j")
	doc := docs[0]
	require.Equal(t, "auth load", doc["command"])
	require.Equal(t, "mutation", doc["kind"])
	require.Equal(t, false, doc["ok"])
	require.Equal(t, true, doc["changed"])
	require.Equal(t, []any{"good"}, doc["persisted"])
	require.Equal(t, []any{"bad"}, doc["failed"])
	errObj := doc["error"].(map[string]any)
	require.Equal(t, "login_failed", errObj["code"])
	items := doc["items"].([]any)
	require.Len(t, items, 2)
	good, bad := items[0].(map[string]any), items[1].(map[string]any)
	require.Equal(t, "good", good["session"])
	require.Equal(t, true, good["ok"])
	require.Equal(t, true, good["verified"])
	require.Equal(t, []any{"Cookie"}, good["extracted_headers"])
	require.Equal(t, false, bad["ok"])
	require.Equal(t, "expect_body_missing", bad["reason"])
	require.EqualValues(t, 200, bad["status"])
	require.Contains(t, stderr, "Validating login flows")
}

func TestSessionLoad_JSONSuccess(t *testing.T) {
	withSessionLoadState(t)
	globalJSON = true
	sessionLoadHost = "static.example"
	file := writeSessionFile(t, "name: static\nheaders:\n  Authorization: Bearer x\n")

	var err error
	out := captureStdout(t, func() { err = runSessionLoad(sessionLoadCmd, []string{file}) })
	require.NoError(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	require.Equal(t, true, docs[0]["ok"])
	require.Nil(t, docs[0]["error"])
	require.Equal(t, []any{}, docs[0]["failed"])
	items := docs[0]["items"].([]any)
	require.Equal(t, "static_headers", items[0].(map[string]any)["reason"])
}
