package php_path_info_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsPathInfo simulates a cgi.fix_pathinfo=1 server that
// happily serves PATH_INFO requests with 200 and app content, while returning a
// distinct 404 for the random fingerprint path.
func TestScanPerRequest_DetectsPathInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PATH_INFO test paths are rooted at index.php or a non-existent script.
		if strings.Contains(r.URL.Path, "index.php") || strings.Contains(r.URL.Path, "script.php") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome to the application home page rendered via PATH_INFO routing</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("short 404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when PATH_INFO requests return 200 app content")
}

// TestScanPerRequest_NoFalsePositive ensures a server that rejects PATH_INFO
// requests with 404 yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server rejecting PATH_INFO must not yield findings")
}

// TestScanPerRequest_NoFalsePositive_CatchAll reproduces the off-by-slash-style
// false positive for PATH_INFO: the host serves one generic 200 shell for ANY
// path containing ".php" (a blanket rewrite / catch-all router) while returning
// a DISTINCT 404 for the random fingerprint path (which has no ".php"). The
// existing 404-fingerprint check passes (candidate differs from the 404), but
// the response does not actually depend on the script — every `*.php` URL is
// identical. The catch-all control gate must drop it.
func TestScanPerRequest_NoFalsePositive_CatchAll(t *testing.T) {
	t.Parallel()
	const shell = "<html><body>SPA application shell — served for every script-shaped path</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".php") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>distinct not found page</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blanket 200 for any *.php path (catch-all) must not be reported as PATH_INFO misconfig")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
