package php_source_disclosure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// phpSourceBody is raw PHP source served as plaintext (no surrounding HTML),
// matching the markers while avoiding the anti-markers.
const phpSourceBody = "<?php\n$config = array();\n$db = 'localhost';\necho 'hello';\n"

// TestScanPerRequest_DetectsSourceDisclosure serves raw PHP source at
// /index.php while returning a distinct 404 for the fingerprint path.
func TestScanPerRequest_DetectsSourceDisclosure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(phpSourceBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found page contents go here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when PHP source is served as plaintext")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// (and renders normal HTML for index.php) yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Page Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that never leaks PHP source must not yield findings")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
