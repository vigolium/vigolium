package cache_deception

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

// authedBody is the (large enough) authenticated content the cache deception
// attack tries to get cached. It must exceed the module's 200-byte floor.
var authedBody = "<html><body>" + strings.Repeat("private account data ", 30) + "</body></html>"

// TestScanPerRequest_DetectsCacheDeception drives the real scan method against a
// backend that (a) serves authenticated content for the requested path, (b)
// serves a distinct small shell for nonexistent wildcard probes, and (c) caches
// the authenticated body — advertised via X-Cache: HIT — when a static
// extension like ".css" is appended to the path. That is the classic web cache
// deception condition.
func TestScanPerRequest_DetectsCacheDeception(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "-vigolium-wp/"):
			// Wildcard probe: distinct, small 404 shell so it never matches the
			// authenticated baseline.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		case strings.Contains(r.URL.Path, ".css"):
			// Cache-deception sink: the static-extension URL is served from the
			// cache with the full authenticated body.
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte(authedBody))
		default:
			// Authenticated baseline content.
			_, _ = w.Write([]byte(authedBody))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a cache-deception finding when the authenticated body is cached on a .css path")
}

// TestScanPerRequest_NoFalsePositive ensures a backend that never advertises a
// cache hit (no X-Cache/Age/CF-Cache-Status) yields no finding, even though the
// confused path returns the same body.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "-vigolium-wp/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		default:
			// Same body for every path, but never any cache-hit header.
			_, _ = w.Write([]byte(authedBody))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without a cache-hit indicator there is no cache-deception finding")
}
