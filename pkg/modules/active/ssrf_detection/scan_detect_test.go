package ssrf_detection

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// internalIndicators are substrings present in the module's SSRF payloads when
// it points the target at an internal/metadata/file endpoint.
var internalIndicators = []string{"127.0.0.1", "localhost", "169.254", "file://", "metadata"}

func looksInternal(v string) bool {
	for _, ind := range internalIndicators {
		if strings.Contains(v, ind) {
			return true
		}
	}
	return false
}

// TestScanPerInsertionPoint_DetectsSSRFMarker drives the real scan method against
// a server that returns SSRF marker content (a passwd-like HTML page) only when
// the injected URL points somewhere internal. The clean baseline lacks those
// markers, so the module should flag the difference.
func TestScanPerInsertionPoint_DetectsSSRFMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if looksInternal(r.URL.Query().Get("url")) {
			_, _ = io.WriteString(w, "<html><body>root:x:0:0:root:/root:/bin/bash localhost</body></html>")
			return
		}
		_, _ = io.WriteString(w, "fetched remote resource ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Attach the captured baseline the executor would supply: a clean fetch of
	// the original (external) URL, which carries none of the SSRF markers.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an SSRF finding when internal markers appear in the probe response only")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that returns the
// same body regardless of the injected URL yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	const staticBody = "<html><body>static unchanging page</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, staticBody)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Baseline equals what every probe will return, so no marker is ever "new"
	// — even though the static body happens to contain an `<html` token.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/html", staticBody,
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "identical responses must not yield an SSRF finding")
}

// TestScanPerInsertionPoint_AmbientMarker reproduces the reported false positive:
// a non-deterministic endpoint whose live response ALWAYS carries a weak marker
// (`<html`) plus a rotating token, while the captured baseline happened to miss
// it. The stale-baseline marker check trips, but the reproducibility+control
// gate fetches the original value fresh, finds the same marker there, and so
// reports nothing.
func TestScanPerInsertionPoint_AmbientMarker(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Every response — for ANY url, including the original benign one — carries
		// an `<html` marker and a rotating token.
		c := atomic.AddInt64(&n, 1)
		_, _ = fmt.Fprintf(w, "<html><body>edge challenge token=%020d</body></html>", c)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Stale captured baseline that lacks the `<html` marker the live page now carries.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "loading edge protection please wait",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a marker the live page always carries (present in a fresh control too) must not be reported as SSRF")
}
