package web_cache_poisoning

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsCachePoisoning drives the real scan method against a
// backend that reflects the unkeyed X-Forwarded-Host header into the body — the
// classic web-cache-poisoning sink. The module injects its poison marker and
// should observe it reflected.
func TestScanPerRequest_DetectsCachePoisoning(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect any of the unkeyed headers the module probes back into the body.
		xfh := r.Header.Get("X-Forwarded-Host")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = fmt.Fprintf(w, "<html><body><link href=\"https://%s/style.css\"></body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a cache-poisoning finding when X-Forwarded-Host is reflected")
}

// TestScanPerRequest_NoFalsePositive ensures a backend that ignores the injected
// headers (no reflection in body or Location) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>static page, no header reflection</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a backend that ignores the unkeyed headers must not yield a finding")
}

// TestScanPerRequest_UncacheableReflectionNoFinding covers the false-positive
// class reported in the field: the injected header value is reflected, but the
// carrying response is not shared-cacheable. Reflection alone is not poisoning.
func TestScanPerRequest_UncacheableReflectionNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect X-Forwarded-Host but mark the response uncacheable — exactly the
		// shape of a dynamic, per-user page that a shared cache will not store.
		xfh := r.Header.Get("X-Forwarded-Host")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintf(w, "<html><body><link href=\"https://%s/style.css\"></body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reflected header in an uncacheable response must not be flagged")
}

// TestGenuinelyCacheable exercises the cacheability gate directly, including the
// exact Atlassian login-redirect false positive: a 302 whose Location echoes
// X-Forwarded-Host into a continue URL, behind a CDN reporting X-Cache: Miss,
// with Vary: Accept and no Cache-Control. That response is not cacheable and
// must not be reported.
func TestGenuinelyCacheable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    int
		headers   map[string]string
		injected  string
		wantCache bool
	}{
		{
			name:      "atlassian login redirect false positive",
			status:    302,
			headers:   map[string]string{"X-Cache": "Miss from cloudfront", "Vary": "Accept"},
			injected:  "X-Forwarded-Host",
			wantCache: false,
		},
		{
			name:      "directive-less 200 is not cacheable",
			status:    200,
			headers:   map[string]string{},
			injected:  "X-Forwarded-Host",
			wantCache: false,
		},
		{
			name:      "explicit public max-age 200 is cacheable",
			status:    200,
			headers:   map[string]string{"Cache-Control": "public, max-age=60"},
			injected:  "X-Forwarded-Host",
			wantCache: true,
		},
		{
			name:      "served-from-cache HIT is cacheable",
			status:    200,
			headers:   map[string]string{"X-Cache": "HIT from cloudfront", "Cache-Control": "max-age=30"},
			injected:  "X-Forwarded-Host",
			wantCache: true,
		},
		{
			name:      "set-cookie disqualifies despite public directive",
			status:    200,
			headers:   map[string]string{"Cache-Control": "public, max-age=60", "Set-Cookie": "s=1"},
			injected:  "X-Forwarded-Host",
			wantCache: false,
		},
		{
			name:      "vary on injected header is not poisonable",
			status:    200,
			headers:   map[string]string{"Cache-Control": "public, max-age=60", "Vary": "X-Forwarded-Host"},
			injected:  "X-Forwarded-Host",
			wantCache: false,
		},
		{
			name:      "redirect with explicit cache directive is cacheable",
			status:    301,
			headers:   map[string]string{"Cache-Control": "public, max-age=300"},
			injected:  "X-Forwarded-Host",
			wantCache: true,
		},
		{
			name:      "max-age=0 is not a storable directive",
			status:    200,
			headers:   map[string]string{"Cache-Control": "max-age=0"},
			injected:  "X-Forwarded-Host",
			wantCache: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			get := func(name string) string { return tc.headers[name] }
			got, _ := genuinelyCacheable(get, tc.status, tc.injected)
			assert.Equal(t, tc.wantCache, got)
		})
	}
}
