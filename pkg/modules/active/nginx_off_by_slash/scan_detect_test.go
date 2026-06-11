package nginx_off_by_slash

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const obsSecret = "<html><body>SECRET ALIASED DIRECTORY LISTING: db.conf app.py settings.py</body></html>"

// TestScanPerRequest_DetectsStableOffBySlash fires when an alias-traversal path
// resolves to a SPECIFIC resource outside the alias dir: the escaped path
// returns a stable, distinct 200 while the in-alias equivalent, a random-suffix
// traversal, and the wildcard probe all 404. The response genuinely depends on
// the traversed path — the hallmark of a real off-by-slash.
func TestScanPerRequest_DetectsStableOffBySlash(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the specific escaped path (segment "images" → first suffix
		// "static", i.e. /images../static, mapping to the parent /static dir)
		// resolves; everything else — /images/static, /images../<random>, the
		// wildcard probe — 404s.
		if r.URL.Path == "/images../static" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(obsSecret))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/images/list"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a stable distinct 200 on an alias-traversal path must be reported")
}

// TestScanPerRequest_NoFalsePositive_BinaryImageCDN guards the path_normalization
// FP class for this module: an extensionless image-CDN URL (Scene7/Akamai shape)
// passes the URL-extension filter, and its alias-traversal path returns a stable
// 200 image/webp. Binary/static-asset content is the static handler simply
// serving a file (and its bytes are not stable on re-optimizing CDNs), so it must
// be excluded by the response Content-Type gate — no finding. Without that gate
// this exact shape (stable distinct 200, in-alias + random + wildcard all 404)
// would be reported.
func TestScanPerRequest_NoFalsePositive_BinaryImageCDN(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/images../static" {
			w.Header().Set("Content-Type", "image/webp")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("RIFF" + strings.Repeat("x", 200) + "WEBP"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/images/render"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a binary image/webp alias-traversal response must not be flagged")
}

// TestScanPerRequest_NoFalsePositive_GenericPrefixResponse reproduces the
// reported false positive: a prefixed auth middleware / API gateway returns one
// generic body (`{"message":"User not logged in"}`) for the ENTIRE /api path
// space, so /api../content "succeeds" only because /api/content — and indeed
// /api/anything — returns the identical shell. The ".." escaped nothing. The
// wildcard probe (a path outside /api) 404s and cannot catch this; only the
// differential gate against the in-alias equivalent does.
func TestScanPerRequest_NoFalsePositive_GenericPrefixResponse(t *testing.T) {
	t.Parallel()
	const authWall = `{"code":10001,"message":"User not logged in","data":{},"nowTime":"2026-06-05 02:52:22"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generic 200 for any path under /api (mirrors a prefix-scoped auth
		// middleware); anything else — including the wildcard probe — 404s.
		if strings.HasPrefix(r.URL.Path, "/api") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(authWall))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/api/content"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a prefix-wide generic response identical to the in-alias path must not be reported")
}

// TestScanPerRequest_NoFalsePositive_SuffixInvariantCatchAll covers a catch-all
// that serves the same 200 for any suffix under the escaped prefix while the
// in-alias path 404s: /seg../<anything> all return one shell, so the body does
// not depend on the suffix and no real file is being read.
func TestScanPerRequest_NoFalsePositive_SuffixInvariantCatchAll(t *testing.T) {
	t.Parallel()
	const shell = "<html><body>application landing shell — same for every escaped path</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any traversal suffix resolves to one shell (suffix-invariant); the
		// in-alias equivalent and the wildcard probe 404.
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a suffix-invariant catch-all under the escaped prefix must not be reported")
}

// TestScanPerRequest_NoFalsePositive_TransientOffBySlash reproduces a one-shot
// 200: only the very first alias-traversal request succeeds, then 404s. The
// multi-round stability gate must drop it.
func TestScanPerRequest_NoFalsePositive_TransientOffBySlash(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			mu.Lock()
			first := !served
			served = true
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(obsSecret))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-shot transient 200 that does not reproduce must not be reported")
}
