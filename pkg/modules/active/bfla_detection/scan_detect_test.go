package bfla_detection

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// withHeader returns a copy of rr whose request carries the given header. BFLA
// credential-stripping tests only run against a request that actually presents
// credentials, so the authenticated baseline must carry an Authorization or
// Cookie header.
func withHeader(t *testing.T, rr *httpmsg.HttpRequestResponse, name, value string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), name, value)
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(rr.Service(), raw)
	return httpmsg.NewHttpRequestResponse(req, rr.Response())
}

// redirectShell is the 200-OK soft login-redirect page a fronting gateway returns
// for every unauthenticated GET. It reflects the requested path into the first
// bytes (mirroring the real bsr.netflix.net response), which makes the byte-head
// wildcard guard miss it — each path produces a slightly different head.
func redirectShell(path string) string {
	return `<!DOCTYPE html>
<html>
  <head>
    <title>Redirecting...</title>
    <noscript>
      <meta http-equiv="refresh" content="0; url=/login?original_uri=` + url.PathEscape(path) + `" />
    </noscript>
  </head>
  <body>Redirecting to login...</body>
</html>`
}

// adminBody is the privileged page content. It is large enough that the full
// unauthenticated response (status line + headers + body) stays within 50% of
// the baseline body length, satisfying the module's isBodyLengthSimilar check.
var adminBody = "<html><body>Admin console: " + strings.Repeat("user record ", 80) + "</body></html>"

// TestScanPerRequest_DetectsBFLA drives the real scan method against an admin
// endpoint that serves the same privileged content whether or not the request
// carries Authorization/Cookie headers (broken function-level authorization).
// A distinct shell is returned for the wildcard probe so the finding isn't
// rejected as a wildcard match.
func TestScanPerRequest_DetectsBFLA(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Privileged content served regardless of auth headers.
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed an authenticated 2xx baseline for the admin path. The request must
	// carry a credential (here a session Cookie) or the auth-strip test is a no-op.
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a BFLA finding when the admin page is reachable without auth")
}

// TestScanPerRequest_NoFalsePositive ensures an admin endpoint that enforces
// authorization (401 once the Authorization/Cookie headers are stripped) yields
// no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Enforce auth: without credentials, deny.
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The baseline request is authenticated (carries a Cookie); stripping it must
	// trip the server's 401 and yield no finding.
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an admin page that requires auth must not yield a BFLA finding")
}

// TestScanPerRequest_LoginPageOnUnauthNoFalsePositive reproduces the loose-length
// false positive: stripping auth returns a 200 LOGIN page of similar LENGTH but
// entirely different CONTENT than the admin page. The old "body length within
// 50%" check flagged it; the content-similarity gate must reject it because the
// privileged content was not actually served unauthenticated.
func TestScanPerRequest_LoginPageOnUnauthNoFalsePositive(t *testing.T) {
	t.Parallel()
	loginBody := "<html><body>Please sign in to continue. " + strings.Repeat("username password forgot ", 35) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Only GET is enabled, so method-switching probes (POST/PUT/DELETE) get a
		// 405 and don't fire — isolating the auth-strip content check.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Auth stripped → a 200 login page: similar size, totally different content.
		_, _ = w.Write([]byte(loginBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed the authenticated admin page as the baseline (carries a Cookie so the
	// auth-strip test actually runs and is then rejected on content dissimilarity).
	rr := withHeader(t, modtest.Response(modtest.Request(t, srv.URL+"/admin/users"), "text/html", adminBody),
		"Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 login page of similar length but different content must not be flagged as BFLA")
}

// TestScanPerRequest_CatchAllGatewayNoFalsePositive reproduces the bsr.netflix.net
// false positive: a fronting gateway accepts POST/PUT/DELETE for EVERY path with a
// uniform empty 200 (Content-Length: 0) and answers every unauthenticated GET with
// the same soft login-redirect shell. The old method-switching path flagged the
// empty 200 as a BFLA bypass because the byte-head wildcard guard does not match an
// empty body; the same-method baseline confirmation must reject it because "/",
// "/includes/", and the admin path all return the identical response.
func TestScanPerRequest_CatchAllGatewayNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-GET methods are accepted for every path with an empty 200.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Every GET — admin path, sibling, root, or the random wildcard probe —
		// returns the same login-bounce shell.
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(redirectShell(r.URL.Path)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The authenticated admin GET (carries a Cookie) also lands on the login
	// bounce, as in the report; the same-method baseline must drop it.
	adminPath := "/includes/admin-user-details-kp5deaqq"
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+adminPath),
		"text/html",
		redirectShell(adminPath),
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all gateway returning the same response for every path/method must not be flagged as BFLA")
}

// TestScanPerRequest_PublicPageNoCredentialsNoFalsePositive reproduces the
// lp.stryker.com false positive: an unauthenticated GET to a "/debug/" landing
// page returns 200, and "removing" the (absent) Authorization/Cookie headers
// trivially returns the same 200 because the request was never authenticated.
// The endpoint is simply public — there is no authorization to break — so a
// request that carried no credentials must not be tested for an auth-strip bypass.
func TestScanPerRequest_PublicPageNoCredentialsNoFalsePositive(t *testing.T) {
	t.Parallel()
	// A dynamic landing page: same template, content varies slightly per request
	// (as the report's 13985 vs 14389 body lengths show).
	landing := "<html><body>Stryker landing page " + strings.Repeat("product highlight ", 90) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Only GET is served; method-switching probes get a 405 and don't fire,
		// isolating the auth-strip path that produced the report.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(landing))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// No Authorization, no Cookie — exactly the request from the report.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/debug/"), "text/html", landing)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a public page reached without credentials must not be flagged as a BFLA auth bypass")
}

// TestScanPerRequest_RandomizedContentNoFalsePositive guards the multi-sample
// reproduction check: the baseline request is authenticated (carries a Cookie),
// and the first auth-stripped probe happens to return privileged-looking content,
// but the endpoint flaps — subsequent requests return a different (login) page.
// A real bypass returns the privileged content every time; this coincidental
// single-sample match must be rejected.
func TestScanPerRequest_RandomizedContentNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/users"
	loginBody := "<html><body>Please sign in to continue. " + strings.Repeat("username password forgot ", 35) + "</body></html>"

	var mu sync.Mutex
	adminGETs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != adminPath {
			// Wildcard probe and other paths get a neutral shell.
			_, _ = w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		// First admin GET looks privileged; every later one flaps to a login page.
		mu.Lock()
		adminGETs++
		first := adminGETs == 1
		mu.Unlock()
		if first {
			_, _ = w.Write([]byte(adminBody))
			return
		}
		_, _ = w.Write([]byte(loginBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withHeader(t, modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html", adminBody),
		"Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a single coincidental privileged-content match that does not reproduce must not be flagged as BFLA")
}

// TestScanPerRequest_StaticImageAssetNoFalsePositive reproduces the
// media-assets.stryker.com false positive: an Akamai/Scene7 image route whose
// path matches the admin heuristic only by substring ("/system" inside the
// "System Image" filename segment) serves a 200 WebP image to everyone. Stripping
// or switching auth returns the same image, so the old code flagged it. The
// content-type gate must drop the whole request before any sub-test runs.
func TestScanPerRequest_StaticImageAssetNoFalsePositive(t *testing.T) {
	t.Parallel()
	// A binary WebP payload, mirroring the report's RIFF....WEBP body.
	webp := "RIFF\x00\x00\x00\x00WEBPVP8 " + strings.Repeat("\x00\x01\x02\x03\xff\xfe", 64)
	const imgPath = "/is/image/stryker/System Image"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The image path answers 200 for every method (CDN cache hit); all other
		// paths — the wildcard probe and the method baseline — 404. Without the
		// content-type gate this shape makes the method-switching test fire.
		if r.URL.Path != imgPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "image/webp")
		_, _ = w.Write([]byte(webp))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/is/image/stryker/System%20Image"), "image/webp", webp)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static image asset must never be flagged as a BFLA privileged endpoint")
}

// TestScanPerRequest_EmptyPrivilegedBaselineNoFalsePositive reproduces the
// stryker-agile.atlassian.net /secure/ConfigureReport.jspa false positive: a JSP
// action endpoint (matched as "admin" via the "/config" substring in
// "/configurereport") answers an unauthenticated request with an empty 200
// (Content-Length: 0) for both GET and POST, while a random nonexistent path
// 404s — so the same-method baseline guard does not match and the empty 200 was
// flagged as a BFLA method-switch bypass. An empty privileged baseline carries no
// content to reproduce, so the whole request must be skipped.
func TestScanPerRequest_EmptyPrivilegedBaselineNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/secure/ConfigureReport.jspa"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath {
			// Random wildcard / method-baseline probes hit the app's 404 with a body,
			// so the same-method baseline differs from the admin path's empty 200.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// The action handler swallows GET and POST alike with an empty 200.
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Exactly the report: an unauthenticated GET to the .jspa path, empty body.
	rr := modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html;charset=utf-8", "")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint whose privileged baseline is an empty 200 must not be flagged as BFLA")
}

// TestScanPerRequest_MethodSwitchEmptyBodyNoFalsePositive guards the
// method-switching empty-body case: the admin GET baseline carries real content,
// but switching to POST returns an empty 2xx (a gateway/handler swallowing the
// request). An empty switched-method response is not evidence the privileged
// function executed and must not be flagged.
func TestScanPerRequest_MethodSwitchEmptyBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/config"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		if r.Method != http.MethodGet {
			// Non-GET methods are accepted with an empty 200 — no content executed.
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// No credentials (as in the report), so only the method-switching test runs.
	rr := modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html", adminBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a method switch returning an empty 2xx must not be flagged as BFLA")
}

// TestScanPerRequest_BinaryBodyMislabeledNoFalsePositive guards the binary-body
// sniff fallback: a binary asset mislabeled with a text Content-Type (a CDN bug)
// must still be skipped, since the content-type allow-list alone would let it
// through.
func TestScanPerRequest_BinaryBodyMislabeledNoFalsePositive(t *testing.T) {
	t.Parallel()
	binary := "\x00\x01\x02\x03\x00\xff\xfe\x00" + strings.Repeat("\x00\x10\x20\x7f", 200)
	const p = "/system/blob"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != p {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Mislabeled as HTML, but the body is binary.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(binary))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+p), "text/html", binary)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a binary body mislabeled as text must be skipped via the body sniff")
}
