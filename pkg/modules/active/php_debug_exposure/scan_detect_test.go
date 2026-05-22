package php_debug_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// phpInfoBody is a synthetic phpinfo() page carrying the markers the module
// looks for at the probed debug paths.
const phpInfoBody = `<html><body>
<h1>PHP Version 8.2.1</h1>
<p>phpinfo()</p>
<table><tr><td>Configuration File (php.ini) Path</td><td>/etc/php</td></tr></table>
</body></html>`

// TestScanPerRequest_DetectsPhpInfo serves a phpinfo() page at /info.php while
// returning a distinct 404 for the random fingerprint path, so the module's
// per-host probing fires a finding.
func TestScanPerRequest_DetectsPhpInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info.php" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(phpInfoBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found marker page distinct content here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /info.php returns a phpinfo page")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
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
	assert.Empty(t, res, "a host with no exposed PHP debug endpoints must not yield findings")
}

// TestCanProcess validates the host-liveness gate: a request without a
// response must not be processed.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr), "request without a response should not be processed")
	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, New().CanProcess(withResp), "request with a response should be processed")
}
