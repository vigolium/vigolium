package metaframework_probe

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

// metaframeworkHandler exposes a SvelteKit version file at /_app/version.json
// (200 + a body containing "version") and 404s everything else.
func metaframeworkHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_app/version.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"1700000000000"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerHost_DetectsSvelteKitVersion drives the real scan method against a
// host exposing the SvelteKit version endpoint and asserts a finding.
func TestScanPerHost_DetectsSvelteKitVersion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(metaframeworkHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the SvelteKit version file is exposed")
	assert.True(t, strings.Contains(res[0].Info.Name, "SvelteKit"), "finding should name the SvelteKit framework")
}

// TestScanPerHost_NoFalsePositive ensures a host that 404s every probe yields
// no finding.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host exposing no metaframework endpoints must not yield a finding")
}

// spaShell is the catch-all index.html that a single-page-app reverse proxy
// returns with 200 text/html for EVERY path. Note "device-width" — the
// substring "dev" inside it is what previously produced a bogus "/__remix/dev"
// finding.
const spaShell = `<!DOCTYPE html><html lang="en"><head><link rel="stylesheet" href="/public/umi.css">` +
	`<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<title>app</title><script>window.routerBase = "/";</script></head><body><div id="root"></div></body></html>`

// TestScanPerHost_SPACatchAllNoFalsePositive reproduces the reported false
// positive: a host that serves the same 200 text/html shell for every path
// (including /__remix/dev and a random nonexistent path) must yield no finding.
func TestScanPerHost_SPACatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(spaShell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", spaShell)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SPA catch-all that 200s every path must not produce a metaframework finding")
}

// TestScanPerHost_DetectsSvelteKitData drives a host exposing the SvelteKit
// __data.json endpoint with a real devalue payload and asserts a finding, while
// every other path returns the SPA shell — proving the wildcard gate does not
// suppress a genuine JSON artifact.
func TestScanPerHost_DetectsSvelteKitData(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__data.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"type":"data","nodes":[{"type":"data","data":[]}]}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(spaShell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", spaShell)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the SvelteKit data endpoint is exposed")
	assert.True(t, strings.Contains(res[0].Info.Name, "SvelteKit"), "finding should name the SvelteKit framework")
}

// TestScanPerHost_RemixDevNotMatchedByDeviceWidth guards the specific substring
// regression: a host that serves the SPA shell for /__remix/dev (but 404s the
// wildcard probe, so the wildcard gate is inactive) must still be rejected by
// the content-type / marker gate rather than matching "dev" in "device-width".
func TestScanPerHost_RemixDevNotMatchedByDeviceWidth(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__remix/dev" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(spaShell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", spaShell)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML shell at /__remix/dev must not match on the 'dev' in 'device-width'")
}

// TestContentGates exercises the content-type / marker helpers directly.
func TestContentGates(t *testing.T) {
	t.Parallel()
	assert.True(t, isHTMLShell("text/html; charset=utf-8", ""))
	assert.True(t, isHTMLShell("", "<!DOCTYPE html><html></html>"))
	assert.False(t, isHTMLShell("application/json", `{"version":"1"}`))

	assert.True(t, isJSON("application/json", `{"version":"1"}`))
	assert.True(t, isJSON("", `{"type":"data"}`))
	assert.False(t, isJSON("text/html", `{"version":"1"}`), "html content-type must not be treated as JSON")

	assert.True(t, isDirListing("<html><head><title>Index of /_astro/</title></head></html>"))
	assert.False(t, isDirListing(spaShell))
}

// TestCanProcess covers the custom CanProcess gate: a request needs a response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no baseline response means not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}
