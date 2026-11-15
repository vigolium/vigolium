package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

func withSessionCheckState(t *testing.T) {
	t.Helper()
	withSessionLoadState(t)
	prevURL, prevMethod, prevSess, prevTimeout := sessionCheckURL, sessionCheckMethod, sessionCheckSession, sessionCheckTimeout
	t.Cleanup(func() {
		sessionCheckURL, sessionCheckMethod, sessionCheckSession, sessionCheckTimeout = prevURL, prevMethod, prevSess, prevTimeout
	})
	sessionCheckURL, sessionCheckMethod, sessionCheckSession = "", "", ""
	sessionCheckTimeout = sessionLoadDefaultTimeout
}

// checkApp is a small app with a cookie login:
//
//	POST /login     pw=right sets sid=ok; anything else re-renders the form
//	GET  /account   the account page with sid=ok, else 302 to /login?next=
//	GET  /wall      always the login form (credentials never get past it)
//	GET  /api/data  JSON with "Authorization: Bearer good", else 401
//	GET  /about     the same public page for everyone
//	GET  /me        {"email":...} with sid=ok, {"guest":true} otherwise (200 both)
func checkApp(t *testing.T) *httptest.Server {
	t.Helper()
	const form = `<html><form method="post" action="/login"><input name="u"><input type="password" name="pw"></form></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := false
		if c, err := r.Cookie("sid"); err == nil && c.Value == "ok" {
			authed = true
		}
		switch r.URL.Path {
		case "/login":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "pw=right") {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
				_, _ = fmt.Fprint(w, "Welcome back")
				return
			}
			_, _ = fmt.Fprint(w, form+" invalid password")
		case "/account":
			if !authed {
				http.Redirect(w, r, "/login?next=/account", http.StatusFound)
				return
			}
			_, _ = fmt.Fprint(w, `<html><h1>Your account</h1><p>alice@example.com</p><a href="/logout">Log out</a></html>`)
		case "/wall":
			_, _ = fmt.Fprint(w, form)
		case "/api/data":
			if r.Header.Get("Authorization") != "Bearer good" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"data":[1,2,3]}`)
		case "/about":
			_, _ = fmt.Fprint(w, `<html><h1>About</h1><p>We make widgets.</p></html>`)
		case "/me":
			w.Header().Set("Content-Type", "application/json")
			if authed {
				_, _ = fmt.Fprint(w, `{"email":"alice@example.com"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"guest":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cookieLoginSession(base, pw string, extra string) string {
	return fmt.Sprintf(`name: alice
login:
  url: %s/login
  method: POST
  body: u=alice&pw=%s
  type: cookie
  expect:
    body_contains: Welcome
%s`, base, pw, extra)
}

func runCheck(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runSessionCheck(sessionCheckCmd, args) })
	return out, err
}

func TestSessionCheck_Verdicts(t *testing.T) {
	srv := checkApp(t)
	tests := []struct {
		name    string
		file    string
		url     string
		verdict authentication.Verdict
		code    apicontract.ErrorCode
	}{
		{"302 to login without the session", cookieLoginSession(srv.URL, "right", ""), "/account", authentication.VerdictAuthenticated, ""},
		{"login wall", cookieLoginSession(srv.URL, "right", ""), "/wall", authentication.VerdictLoginWall, apicontract.CodeNotAuthenticated},
		{"public page", cookieLoginSession(srv.URL, "right", ""), "/about", authentication.VerdictIndistinguishable, apicontract.CodeNotAuthenticated},
		{"401 for a bad token", "name: api\nheaders:\n  Authorization: Bearer stale\n", "/api/data", authentication.VerdictUnauthorized, apicontract.CodeNotAuthenticated},
		{"401 anonymous, 200 with a good token", "name: api\nheaders:\n  Authorization: Bearer good\n", "/api/data", authentication.VerdictAuthenticated, ""},
		{"failed login", cookieLoginSession(srv.URL, "wrong", ""), "/account", authentication.VerdictError, apicontract.CodeLoginFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withSessionCheckState(t)
			sessionCheckURL = srv.URL + tt.url
			out, err := runCheck(t, writeSessionFile(t, tt.file))
			require.Contains(t, out, string(tt.verdict))
			if tt.code == "" {
				require.NoError(t, err, out)
				return
			}
			require.Error(t, err)
			require.Equal(t, ExitError, classifyExitCode(err))
			require.Equal(t, tt.code, classifyErrorCode(err, ExitError))
		})
	}
}

// The session's own check block: check.url (a path, resolved against the
// login origin) and a logged_in rule that tells the 200/200 /me apart.
func TestSessionCheck_ConfiguredCheckJSON(t *testing.T) {
	withSessionCheckState(t)
	globalJSON = true
	srv := checkApp(t)
	file := writeSessionFile(t, cookieLoginSession(srv.URL, "right", `check:
  url: /me
  logged_in:
    status: [200]
    body_contains: '"email"'
    header_regex: '(?i)^content-type: application/json'
`))

	var err error
	var stdout string
	_ = captureStderr(t, func() {
		stdout = captureStdout(t, func() { err = runSessionCheck(sessionCheckCmd, []string{file}) })
	})
	require.NoError(t, err)
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, "human output must stay off stdout under -j")
	doc := docs[0]
	require.Equal(t, "auth check", doc["command"])
	require.Equal(t, "read", doc["kind"])
	require.Equal(t, true, doc["ok"])
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	it := items[0].(map[string]any)
	require.Equal(t, "alice", it["session"])
	require.Equal(t, srv.URL+"/me", it["url"])
	require.Equal(t, "GET", it["method"])
	require.Equal(t, "authenticated", it["verdict"])
	require.Equal(t, true, it["authenticated"])
	require.EqualValues(t, 200, it["auth_response"].(map[string]any)["status"])
	require.EqualValues(t, 200, it["anon_response"].(map[string]any)["status"])
	require.Equal(t, true, it["login"].(map[string]any)["ok"])
	var names []string
	for _, s := range it["signals"].([]any) {
		names = append(names, s.(map[string]any)["name"].(string))
	}
	require.Contains(t, names, authentication.SignalConfiguredLoggedIn)
}

func TestSessionCheck_JSONFailureCarriesCode(t *testing.T) {
	withSessionCheckState(t)
	globalJSON = true
	srv := checkApp(t)
	sessionCheckURL = srv.URL + "/wall"
	file := writeSessionFile(t, cookieLoginSession(srv.URL, "right", ""))

	var err error
	var stdout string
	_ = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			err = runAsExecute(sessionCheckCmd, func() error { return runSessionCheck(sessionCheckCmd, []string{file}) })
		})
	})
	require.Error(t, err)
	doc := decodeStdoutDocuments(t, stdout)[0]
	require.Equal(t, false, doc["ok"])
	require.Equal(t, "not_authenticated", doc["error"].(map[string]any)["code"])
	it := doc["items"].([]any)[0].(map[string]any)
	require.Equal(t, "login_wall", it["verdict"])
	require.Equal(t, false, it["authenticated"])
}

// A bare name that is not a file is looked up among the project's stored
// sessions.
func TestSessionCheck_StoredSession(t *testing.T) {
	withSessionCheckState(t)
	srv := checkApp(t)
	u, _ := url.Parse(srv.URL)

	db, err := getDBFor(clicommon.IntentWrite)
	require.NoError(t, err)
	rows := database.SessionsToAuthenticationHostnames([]*authentication.Session{{
		Name: "apikey", Role: authentication.RolePrimary,
		Headers: map[string]string{"Authorization": "Bearer good"},
	}}, database.DefaultProjectUUID, u.Host)
	require.NoError(t, database.NewRepository(db).SaveAuthenticationHostnames(context.Background(), rows))
	clicommon.ResetDBCache()

	sessionCheckURL = srv.URL + "/api/data"
	out, err := runCheck(t, "apikey")
	require.NoError(t, err, out)
	require.Contains(t, out, "authenticated")

	clicommon.ResetDBCache() // the first run closed the cached handle on exit
	_, err = runCheck(t, "nobody")
	require.Error(t, err)
	require.Equal(t, apicontract.CodeNotFound, classifyErrorCode(err, ExitError))
}

func TestSessionCheck_NoURLIsUsageError(t *testing.T) {
	withSessionCheckState(t)
	srv := checkApp(t)
	_, err := runCheck(t, writeSessionFile(t, cookieLoginSession(srv.URL, "right", "")))
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
	require.Contains(t, err.Error(), "--url is required")
}

func TestSessionCheck_InvalidCheckBlock(t *testing.T) {
	withSessionCheckState(t)
	srv := checkApp(t)
	_, err := runCheck(t, writeSessionFile(t, cookieLoginSession(srv.URL, "right", "check:\n  url: /me\n  logged_in:\n    body_regex: '('\n")))
	require.Error(t, err)
	require.Equal(t, apicontract.CodeConfigInvalid, classifyErrorCode(err, ExitError))
}
