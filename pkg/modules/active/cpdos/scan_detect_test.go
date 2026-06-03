package cpdos

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

// cachingServer returns an httptest server that simulates a shared cache keyed by
// path + the vigolium_cb buster (the request headers are intentionally unkeyed,
// which is what makes CPDoS possible). origin computes the un-cached response for
// a miss; the result is then stored and replayed (advertised via X-Cache) on the
// next request with the same buster.
func cachingServer(origin func(r *http.Request) (int, string)) *httptest.Server {
	var mu sync.Mutex
	cache := map[string]struct {
		status int
		body   string
	}{}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path + "?" + r.URL.Query().Get("vigolium_cb")

		mu.Lock()
		entry, hit := cache[key]
		mu.Unlock()

		if hit {
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(entry.status)
			_, _ = w.Write([]byte(entry.body))
			return
		}

		status, body := origin(r)
		mu.Lock()
		cache[key] = struct {
			status int
			body   string
		}{status, body}
		mu.Unlock()

		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestScanPerRequest_DetectsHMO drives the real scan method against a cache that
// stores the origin's 405 when a method-override header is present, then replays
// that error to a subsequent clean request on the same buster — the HMO CPDoS
// condition.
func TestScanPerRequest_DetectsHMO(t *testing.T) {
	t.Parallel()
	srv := cachingServer(func(r *http.Request) (int, string) {
		if r.Header.Get("X-HTTP-Method-Override") != "" ||
			r.Header.Get("X-HTTP-Method") != "" ||
			r.Header.Get("X-Method-Override") != "" {
			return http.StatusMethodNotAllowed, "method not allowed"
		}
		return http.StatusOK, "baseline content for the cached resource"
	})
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an HMO CPDoS finding when a method-override error is cached and replayed")
	assert.Contains(t, res[0].ExtractedResults, "variant=HMO")
}

// TestScanPerRequest_DetectsHHO covers the oversized-header variant: the origin
// rejects a large request header with 400, which the cache stores and replays.
func TestScanPerRequest_DetectsHHO(t *testing.T) {
	t.Parallel()
	srv := cachingServer(func(r *http.Request) (int, string) {
		for _, vals := range r.Header {
			for _, v := range vals {
				if len(v) >= 8000 {
					return http.StatusBadRequest, "bad request"
				}
			}
		}
		return http.StatusOK, "baseline content for the cached resource"
	})
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an HHO CPDoS finding when an oversized-header error is cached and replayed")
	assert.Contains(t, res[0].ExtractedResults, "variant=HHO")
}

// TestScanPerRequest_NoFalsePositive ensures that a backend which errors on the
// override header but never caches (no X-Cache HIT / Age) yields no finding —
// the pre-flight cacheability gate must fail closed.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Errors on override but is never served from cache (no hit indicators).
		if r.Header.Get("X-HTTP-Method-Override") != "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("method not allowed"))
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("ok ", 50)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without a cache HIT the pre-flight must reject the endpoint and report nothing")
}

// TestScanPerRequest_NoFinding_WhenPayloadHarmless covers a cacheable endpoint
// that ignores the override / oversized headers and always returns 200. The
// with-payload step must observe no error status, so no finding is produced.
func TestScanPerRequest_NoFinding_WhenPayloadHarmless(t *testing.T) {
	t.Parallel()
	srv := cachingServer(func(_ *http.Request) (int, string) {
		return http.StatusOK, "baseline content for the cached resource"
	})
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a harmless payload that never triggers an error must not be reported")
}

// TestScanPerRequest_NoFinding_WhenErrorNotCached covers the critical false
// positive: a per-request edge/WAF block that returns an error for the payload
// but never caches it. The clean replay then returns the normal baseline (not the
// error), so the cache-confirm step fails and nothing is reported.
func TestScanPerRequest_NoFinding_WhenErrorNotCached(t *testing.T) {
	t.Parallel()

	hasOversizedHeader := func(r *http.Request) bool {
		for _, vals := range r.Header {
			for _, v := range vals {
				if len(v) >= 8000 {
					return true
				}
			}
		}
		return false
	}

	var mu sync.Mutex
	cache := map[string]string{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per-request block: the payload always errors but is never cached.
		if r.Header.Get("X-HTTP-Method-Override") != "" || hasOversizedHeader(r) {
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("blocked"))
			return
		}

		key := r.URL.Path + "?" + r.URL.Query().Get("vigolium_cb")
		mu.Lock()
		body, hit := cache[key]
		if !hit {
			body = "baseline content for the cached resource"
			cache[key] = body
		}
		mu.Unlock()

		if hit {
			w.Header().Set("X-Cache", "HIT")
		} else {
			w.Header().Set("X-Cache", "MISS")
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a per-request block that is never cached must not be reported as CPDoS")
}
