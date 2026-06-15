package common_directory_listing

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

// TestScanPerRequest_DetectsApacheListing drives the real scan method against a
// host that serves a classic Apache "Index of" directory listing for /uploads/.
// The 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsApacheListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/uploads") {
			_, _ = w.Write([]byte("<html><head><title>Index of /uploads</title></head>" +
				"<body><h1>Index of /uploads</h1><pre><a href=\"a.txt\">a.txt</a></pre></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>not found, padded to differ from listing body length</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a directory-listing finding when an Apache Index of page is served")
}

// TestScanPerRequest_CatchAllListingNoFinding reproduces the catch-all false
// positive: a host that renders an "Index of" page for EVERY path (including a
// random nonexistent directory) is a templated soft-404 / SPA shell, not real
// autoindex, and must not yield a finding.
func TestScanPerRequest_CatchAllListingNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Keep the 404-fingerprint body benign so the per-probe hash gate does not
		// short-circuit; every other path (incl. the random catch-all dir) "lists".
		if r.URL.Path == "/vigolium-nonexistent-path-404-check" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("plain not found body"))
			return
		}
		_, _ = w.Write([]byte("<html><head><title>Index of /</title></head>" +
			"<body><h1>Index of /</h1><pre><a href=\"x\">x</a></pre></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 'lists' every random directory is a catch-all, not an exposure")
}

// TestScanPerRequest_NoFalsePositive ensures a host serving ordinary HTML
// (no listing markers) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>Welcome</title></head><body>regular page content</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "ordinary HTML without listing markers must not yield a finding")
}
