package idor_guid

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerInsertionPoint_DetectsSequentialIDOR drives the real scan method
// against a backend that serves a valid (200, distinct-content) object for any
// numeric id — including the original id's neighbors. The module predicts
// id+/-1, fetches them, and reports because the neighbor returns a 200 whose
// body differs from the baseline.
func TestScanPerInsertionPoint_DetectsSequentialIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Each id yields a valid object whose content embeds the id, so neighbor
		// responses are 200 and differ from the baseline body. Padding keeps the
		// body comfortably over the module's 100-byte floor.
		_, _ = fmt.Fprintf(w, "{\"id\":%q,\"owner\":%q,\"secret\":%q,\"pad\":%q}",
			id, "user-"+id, "token-"+id, strings.Repeat("x", 120))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Baseline carries the original object; the module compares neighbors to it.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		"{\"id\":\"100\",\"owner\":\"user-100\",\"secret\":\"token-100\",\"pad\":\""+strings.Repeat("x", 120)+"\"}",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an IDOR finding when neighbor ids return valid distinct objects")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that enforces
// authorization (404 for any id but the owner's) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "100" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		_, _ = w.Write([]byte("{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":\"" + strings.Repeat("x", 120) + "\"}"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		"{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":\""+strings.Repeat("x", 120)+"\"}",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "404 for neighbor ids means authorization is enforced — no finding")
}

// keycloakLoginBody is a trimmed Keycloak Sign-In form — the page the predicted
// header value returned in the reported false positive. It contains login-form
// markers (password input, login-actions/authenticate action) and a per-request
// session token so two fetches always "differ".
func keycloakLoginBody(sessionCode string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><body>
<form id="kc-form-login" action="/realms/master/login-actions/authenticate?session_code=%s&execution=fc587d0a" method="post">
  <input id="username" name="username" value="" type="text" autocomplete="username"/>
  <input id="password" name="password" value="" type="password" autocomplete="current-password"/>
  <button name="login" id="kc-login" type="submit">Sign In</button>
</form>
<div>%s</div>
</body></html>`, sessionCode, strings.Repeat("x", 120))
}

// rawRequestWithHeader builds an HttpRequestResponse for rawURL carrying the
// given extra header line (e.g. "Upgrade-Insecure-Requests: 1"), so a test can
// target a header insertion point that modtest.Request does not synthesize.
func rawRequestWithHeader(t *testing.T, rawURL, headerLine string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n\r\n", target, u.Host, headerLine)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestScanPerInsertionPoint_SkipsNonIDHeader is the regression for the reported
// false positive: the scanner treated the numeric value of the standard request
// header Upgrade-Insecure-Requests as an object reference and fuzzed neighbor
// "0". A standard request header is never an object reference, so the module
// must skip it without sending a single probe.
func TestScanPerInsertionPoint_SkipsNonIDHeader(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte(keycloakLoginBody("sess-" + strconv.FormatInt(atomic.LoadInt64(&hits), 10))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := rawRequestWithHeader(t, srv.URL+"/realms/master/protocol/openid-connect/auth", "Upgrade-Insecure-Requests: 1")
	ip := modtest.InsertionPoint(t, rr, "Upgrade-Insecure-Requests")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a standard request header is not an IDOR candidate")
	assert.Zero(t, atomic.LoadInt64(&hits), "the module must not probe a non-ID header at all")
}

// TestScanPerInsertionPoint_AuthChallengePageNotIDOR ensures the confirmation
// content gate rejects a neighbor id that returns a login / SSO page. The
// owner's id (100) serves a real JSON object; any other id serves the Keycloak
// Sign-In form. Without the gate this looks like a textbook predictable-id IDOR
// (200, body > 100, differs from baseline, and the same-id refetch is stable so
// the determinism gate passes) — but the "leaked object" is just the login page.
func TestScanPerInsertionPoint_AuthChallengePageNotIDOR(t *testing.T) {
	t.Parallel()
	var sess int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "100" {
			_, _ = fmt.Fprintf(w, "{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":%q}", strings.Repeat("x", 120))
			return
		}
		// Neighbor ids redirect (unauthenticated) to the login shell, with a fresh
		// session token per request so the body always differs.
		n := atomic.AddInt64(&sess, 1)
		_, _ = w.Write([]byte(keycloakLoginBody("sess-" + strconv.FormatInt(n, 10))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		"{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":\""+strings.Repeat("x", 120)+"\"}",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a neighbor id that returns a login/SSO page is not a leaked object")
}

// noiseBody renders a body (comfortably over the module's 100-byte floor) whose
// only variable part is a 20-digit counter token, so two such bodies are always
// 200/distinct — the shape of a tracking endpoint that returns different content
// on every request regardless of the id.
func noiseBody(n int64) string {
	return fmt.Sprintf("{\"data\":\"%020d\",\"pad\":%q}", n, strings.Repeat("x", 120))
}

// TestScanPerInsertionPoint_NonDeterministicEndpoint is the regression for the
// sequential-id false positive: the backend returns different content on every
// request regardless of the id, so a predicted id+/-1 "returns a valid different
// resource" exactly like a real predictable-reference IDOR. The determinism gate
// re-issues the ORIGINAL id, sees the same-id response vary just as much, and
// suppresses the finding.
func TestScanPerInsertionPoint_NonDeterministicEndpoint(t *testing.T) {
	t.Parallel()
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore id entirely: every request gets fresh, distinct content.
		n := atomic.AddInt64(&counter, 1)
		_, _ = w.Write([]byte(noiseBody(n)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		noiseBody(0),
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic endpoint (same id → different content) must not be reported as predictable-id IDOR")
}
