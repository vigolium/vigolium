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
