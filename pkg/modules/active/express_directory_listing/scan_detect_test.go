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

// listingBody is an Apache-style autoindex page used by the tests.
const listingBody = `<html><head><title>Index of /uploads</title></head>` +
	`<body><h1>Index of /uploads</h1><table><tr><td><a href="secret.txt">secret.txt</a></td></tr></table></body></html>`

// knownDir reports whether p is one of the static directories the module probes.
func knownDir(p string) bool {
	switch p {
	case "/public/", "/uploads/", "/static/", "/assets/", "/files/", "/media/", "/images/", "/dist/":
		return true
	}
	return false
}

// TestScanPerRequest_DetectsDirectoryListing serves serve-index style autoindex
// markup for the probed static directories — but 404s any other path (including
// a nonexistent directory) like a real autoindex server, so the catch-all guard
// does not fire.
func TestScanPerRequest_DetectsDirectoryListing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if knownDir(r.URL.Path) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(listingBody))
			return
		}
		// Everything else (404-fingerprint path, the random catch-all dir probe,
		// nonexistent directories) returns a plain 404.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The custom CanProcess needs a baseline response attached.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a directory-listing finding when autoindex markers are served")
}

// TestScanPerRequest_CatchAllListingNoFinding reproduces the catch-all false
// positive: a host that renders a listing-shaped body for EVERY path (including
// a random nonexistent directory) must not yield any finding.
func TestScanPerRequest_CatchAllListingNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404-fingerprint path stays benign so the per-probe hash check doesn't
		// short-circuit; every other path (incl. the random catch-all dir) "lists".
		if r.URL.Path == "/vigolium-nonexistent-path-404-check" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(listingBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 'lists' every random directory is a catch-all, not an exposure")
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

// gatsbyMediaBody reproduces the Roche "Media" false positive: a rendered Gatsby
// content page that has an <h1>, a <table>, and <a href=> links — but is a real
// page (generator/react-helmet/OpenGraph markers), not a directory listing.
const gatsbyMediaBody = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<meta name="theme-color" content="#fff"><meta name="generator" content="Gatsby 5.13.3">` +
	`<meta data-react-helmet="true" name="title" content="Acme | Media">` +
	`<meta data-react-helmet="true" property="og:title" content="Acme | Media">` +
	`<title data-react-helmet="true">Acme | Media</title></head>` +
	`<body><div id="___gatsby"><h1>Media</h1>` +
	`<table><tr><td><a href="/media/stories">Stories</a></td></tr></table></div></body></html>`

// TestScanPerRequest_AppContentPageNoFinding ensures a rendered SPA/CMS content
// page served at a probed directory (h1 + table + links, but framework markers)
// is not flagged as a directory listing.
func TestScanPerRequest_AppContentPageNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if knownDir(r.URL.Path) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(gatsbyMediaBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a rendered content page (Gatsby/React/OpenGraph markers) is not a directory listing")
}

// TestIsDirectoryListing exercises the body classifier directly across the real
// autoindex signatures it must catch and the content-page shapes it must reject.
func TestIsDirectoryListing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "apache autoindex title+h1",
			body: listingBody,
			want: true,
		},
		{
			name: "serve-index listing directory title",
			body: `<html><head><title>listing directory /uploads</title></head>` +
				`<body><h1>listing directory /uploads</h1><ul><li><a href="a.txt">a.txt</a></li></ul></body></html>`,
			want: true,
		},
		{
			name: "nginx pre block with parent link",
			body: `<html><head><title>Index of /files/</title></head><body>` +
				`<h1>Index of /files/</h1><hr><pre><a href="../">../</a>` +
				`<a href="dump.sql">dump.sql</a></pre></body></html>`,
			want: true,
		},
		{
			name: "custom middleware table with parent link, no Index of",
			body: `<html><body><table><tr><td><a href="../">Parent</a></td></tr>` +
				`<tr><td><a href="backup.zip">backup.zip</a></td></tr></table></body></html>`,
			want: true,
		},
		{
			name: "gatsby content page with h1+table+links",
			body: gatsbyMediaBody,
			want: false,
		},
		{
			name: "plain content page: h1+table+link, no listing markers",
			body: `<html><head><title>Pricing</title></head><body><h1>Our Plans</h1>` +
				`<table><tr><td><a href="/signup">Sign up</a></td></tr></table></body></html>`,
			want: false,
		},
		{
			name: "content page titled Index of X with real content h1",
			body: `<html><head><title>Index of Publications</title></head><body>` +
				`<h1>Our Publications</h1><ul><li><a href="/pub/1">One</a></li></ul></body></html>`,
			want: false,
		},
		{
			name: "pre code block with a link but no parent dir",
			body: `<html><body><pre><a href="/docs">see the docs</a></pre></body></html>`,
			want: false,
		},
		{
			name: "content page whose prose mentions directory and listing",
			body: `<html><body><article><a href="/blog">Our product directory listing guide</a></article></body></html>`,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isDirectoryListing(tc.body))
		})
	}
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
