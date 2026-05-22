package laravel_sensitive_files

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

// laravelHandler serves a telltale Laravel artisan script for /artisan and a
// distinct 404 body for everything else (including the module's random 404
// fingerprint probe), so the response for the real probe diverges from the
// fingerprinted not-found page.
func laravelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/artisan" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("#!/usr/bin/env php\n<?php\n// artisan\nuse Illuminate\\Foundation\\Application;\n$app = new Application();\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerRequest_DetectsArtisan drives the real scan method against a host
// that exposes the Laravel artisan script (wrong document root) and asserts the
// module reports a finding.
func TestScanPerRequest_DetectsArtisan(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(laravelHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>home</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /artisan is web-reachable")
	assert.True(t, strings.Contains(res[0].Info.Name, "Artisan"), "finding should name the artisan probe")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns 404 for every
// probed Laravel path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>home</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed Laravel files must not yield a finding")
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
