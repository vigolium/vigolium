package express_directory_listing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsDirectoryListing serves serve-index style autoindex
// markup for the probed static directories, which the module should flag.
func TestScanPerRequest_DetectsDirectoryListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404-fingerprint path returns a benign body distinct from listings.
		if r.URL.Path == "/vigolium-nonexistent-path-404-check" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Every probed directory returns an Apache-style autoindex listing.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Index of /uploads</title></head>` +
			`<body><h1>Index of /uploads</h1><table><tr><td><a href="secret.txt">secret.txt</a></td></tr></table></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The custom CanProcess needs a baseline response attached.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a directory-listing finding when autoindex markers are served")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns plain 404s for
// the probed directories yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "plain 404 responses must not yield a directory-listing finding")
}

// TestCanProcess covers the custom CanProcess guard: a response is required.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no response attached should be rejected")

	withResp := modtest.Response(rr, "text/html", "<html></html>")
	assert.True(t, m.CanProcess(withResp))
}
