package path_normalization

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// expressStaticHandler models an express.static / `send` style static handler
// mounted at /static that is vulnerable to the matrix-parameter + encoded-slash
// bypass. The ";/" prefix keeps the router pointed at the static mount while the
// resolver decodes %2f and traverses above the root; a plain traversal (no ";")
// is blocked by the boundary check, so it never leaks. The decoy/random
// filenames simply 404.
func expressStaticHandler() http.HandlerFunc {
	const passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	const pkgJSON = `{"name":"acme-internal-newsroom","version":"2.4.1","dependencies":{"express":"^4.18.2","consul":"^0.40.0"}}`
	return func(w http.ResponseWriter, r *http.Request) {
		uri := strings.ToLower(r.RequestURI)
		bypassed := strings.Contains(uri, ";/") && strings.Contains(uri, "..%2f")
		switch {
		case bypassed && strings.Contains(uri, "etc/passwd"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(passwd))
		case bypassed && strings.Contains(uri, "package.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(pkgJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Cannot GET the requested path"))
		}
	}
}

func staticAssetRequest(t *testing.T, baseURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	// A captured static-asset request (the crawler's view of /static/js/app.js),
	// carrying a JS baseline so the content-type gate fires and the leaked file
	// markers are clearly absent from the baseline.
	return modtest.Response(
		modtest.Request(t, baseURL+"/static/js/app.js"),
		"application/javascript",
		"console.log('newsroom app bundle');",
	)
}

// TestStaticTraversal_DetectsExpressStaticPasswd is the core positive: the
// matrix-parameter + encoded-slash shell reads /etc/passwd off the static root
// and is reported Critical/Certain (3 content markers).
func TestStaticTraversal_DetectsExpressStaticPasswd(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(expressStaticHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a static-root traversal finding for the express.static semicolon bypass")
	assert.Equal(t, ModuleID, res[0].ModuleID)
	assert.Equal(t, severity.Critical, res[0].Info.Severity, "a multi-marker file read should be Critical")
	assert.Equal(t, severity.Certain, res[0].Info.Confidence)
	assert.Contains(t, res[0].Matched, ";/", "the reported payload should carry the matrix-parameter bypass")
	assert.Contains(t, res[0].Response, "root:", "the finding should carry the leaked file content as evidence")
}

// TestStaticTraversal_DetectsAppRootPackageJSON confirms the Node app-root
// target (package.json one level above the static dir) is read and reported.
func TestStaticTraversal_DetectsAppRootPackageJSON(t *testing.T) {
	t.Parallel()
	// Same handler but without /etc/passwd reachable: only package.json leaks.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri := strings.ToLower(r.RequestURI)
		if strings.Contains(uri, ";/") && strings.Contains(uri, "..%2f") && strings.Contains(uri, "package.json") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"acme-internal","version":"2.4.1","dependencies":{"express":"^4.18.2"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Cannot GET the requested path"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when package.json leaks via the static-root bypass")
	assert.Contains(t, res[0].Response, `"dependencies"`)
}

// TestStaticTraversal_DetectsDirectoryListing confirms the listing oracle: a
// trailing-slash traversal that surfaces an autoindex is flagged even without a
// known filename.
func TestStaticTraversal_DetectsDirectoryListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		low := strings.ToLower(r.RequestURI)
		if strings.Contains(low, ";/") && strings.Contains(low, "..%2f") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Index of /</title></head><body><h1>Index of /</h1>` +
				`<pre><a href="../">Parent Directory</a>` + "\n" +
				`<a href="app.js">app.js</a>` + "\n" + `<a href="package.json">package.json</a></pre></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the bypass surfaces a directory listing")
	assert.Contains(t, strings.ToLower(res[0].Response), "index of /")
}

// TestStaticTraversal_NoFalsePositiveOnWildcardShell ensures an SPA/catch-all
// host that returns the same 200 shell for every path is not flagged: the
// wildcard probe matches every traversal response.
func TestStaticTraversal_NoFalsePositiveOnWildcardShell(t *testing.T) {
	t.Parallel()
	shell := "<html><head><title>App</title></head><body><div id=app>" +
		strings.Repeat("spa-shell-content ", 40) + "</div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SPA wildcard host must not yield a static-root traversal finding")
}

// TestStaticTraversal_NoFalsePositiveOnNormalStatic ensures a host that serves
// assets but blocks every traversal shape (the boundary check holds) is not
// flagged.
func TestStaticTraversal_NoFalsePositiveOnNormalStatic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		low := strings.ToLower(r.RequestURI)
		if strings.Contains(low, "..") || strings.Contains(low, ";") || strings.Contains(low, "%2f") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("console.log('app bundle');"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that blocks traversal must not be flagged")
}

// TestStaticTraversal_NoFalsePositiveOnCatchAllDecoy is the decoy-negative
// regression guard: a pathological host that returns passwd-looking content for
// ANY matrix-bypass path (including a bogus filename) must be suppressed,
// because the decoy probe surfaces the same markers.
func TestStaticTraversal_NoFalsePositiveOnCatchAllDecoy(t *testing.T) {
	t.Parallel()
	const passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		low := strings.ToLower(r.RequestURI)
		if strings.Contains(low, ";/") && strings.Contains(low, "..%2f") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(passwd)) // returned regardless of the requested filename
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := staticAssetRequest(t, srv.URL)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all that returns the file for any filename must be caught by the decoy negative")
}
