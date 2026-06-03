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
	"github.com/vigolium/vigolium/pkg/types/severity"
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

// TestScanPerInsertionPoint_RateLimitedNotSSRF reproduces the reported false
// positive: a scan hammered the host into rate limiting, so every probe gets a
// 429 whose HTML error page carries the broad `<html` marker. The captured
// baseline (a redirect-style page) lacked it, so the marker looked "new" and the
// localhost payload was reported as IPv6-loopback SSRF. A WAF/rate-limit page is
// not the target proxying our URL, so it must yield no finding.
func TestScanPerInsertionPoint_RateLimitedNotSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "<html><body>429 Too Many Requests</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Clean captured baseline from before the rate limiting kicked in; it lacks
	// the `<html` marker the 429 error page carries.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 429 rate-limit page must not be reported as SSRF")
}

// TestScanPerInsertionPoint_ErrorPageNotSSRF reproduces the exact reported false
// positive: injecting `http://127.0.0.1` into a `redirect_url` made a Cloudflare
// Access gate answer 400 "Invalid redirect URL" with an HTML error page. Its
// generic `<html` was absent from the 302 redirect baseline, so it looked "new"
// and was reported as loopback SSRF — even though a 400 means the input was
// REJECTED, the opposite of the server fetching it. A generic HTML marker on a
// non-2xx response must yield no finding.
func TestScanPerInsertionPoint_ErrorPageNotSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("redirect_url")
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			// Any absolute URL is rejected with a generic HTML error page, just like
			// a Cloudflare Access "Invalid redirect URL" gate.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<!doctype html><html><head><title>Error · Cloudflare Access</title></head><body>Invalid redirect URL</body></html>")
			return
		}
		// A relative path is accepted and answered with a 302 to the app.
		w.Header().Set("Location", "https://app.example.com/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Captured baseline: the original `/` value's 302 redirect carries no `<html`.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?redirect_url=/"),
		"text/html", "",
	)
	ip := modtest.InsertionPoint(t, rr, "redirect_url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 400 'Invalid redirect URL' error page must not be reported as SSRF")
}

// TestScanPerInsertionPoint_SoftErrorSiblingNotSSRF covers the soft-200 variant
// the status gate alone cannot catch: an app that answers EVERY absolute URL
// with the same generic HTML "invalid URL" page, but with a 200. The localhost
// payload trips `<html` and passes the 2xx gate, yet a benign non-internal
// sibling (192.0.2.1) yields the identical page — proving the app emits this HTML
// for any absolute URL rather than because it reached localhost.
func TestScanPerInsertionPoint_SoftErrorSiblingNotSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			// Soft-200: any absolute URL gets the same generic HTML rejection page.
			_, _ = io.WriteString(w, "<html><body>Invalid URL supplied</body></html>")
			return
		}
		_, _ = io.WriteString(w, "fetched remote resource ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Baseline from the original (relative) value lacks the `<html` marker.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic HTML page returned for every absolute URL (sibling included) must not be reported as SSRF")
}

// TestScanPerInsertionPoint_MetadataMarkerInHTMLIsSuspect reproduces the reported
// false positive: the DigitalOcean payload's "hostname" marker matched
// `window.location.hostname` inside a Ping SSO error page's <script> on a 400
// "Invalid redirect_uri" response. "hostname" is a common-word field token, the
// response is a non-2xx HTML error page (the URL was rejected, not fetched), and
// no distinctive metadata marker corroborates it — so it must surface only as a
// Suspect lead for manual review, never as a firm High SSRF.
func TestScanPerInsertionPoint_MetadataMarkerInHTMLIsSuspect(t *testing.T) {
	const ssoError = `<!DOCTYPE html><html><head><title>Error</title></head><body>` +
		`<script>if (!(window.location.hostname === "sso.example.com")) { /* cdn metrics */ }</script>` +
		`400 - Invalid redirect_uri</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("redirect_uri")
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			// Any absolute URL is rejected with the same SSO error page (carrying
			// window.location.hostname), exactly like the reported Ping gate.
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, ssoError)
			return
		}
		// A relative redirect target is accepted and answered with a clean 302.
		w.Header().Set("Location", "https://app.example.com/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Captured baseline: the original relative value's 302 carries no "hostname".
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?redirect_uri=/dashboard"),
		"text/html", "",
	)
	ip := modtest.InsertionPoint(t, rr, "redirect_uri")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "the weak metadata marker should still surface, but only as a suspect lead")
	assert.Equal(t, severity.Suspect, res[0].Info.Severity, "a common-word marker in a non-2xx HTML page must be Suspect, not High")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}

// TestScanPerInsertionPoint_GenuineMetadataIsHigh confirms the grading still
// reports a real SSRF at full severity: a genuinely proxied DigitalOcean metadata
// endpoint answers 200 with a plain-text body carrying the distinctive
// `droplet_id` field — a self-evidencing marker on a non-HTML 2xx response — so it
// stays High/Firm.
func TestScanPerInsertionPoint_GenuineMetadataIsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "169.254.169.254/metadata/v1") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "droplet_id: 12345678\nhostname: web-prod-01\nregion: nyc3\n")
			return
		}
		_, _ = io.WriteString(w, "fetched remote resource ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, severity.High, res[0].Info.Severity, "a distinctive metadata marker on a 2xx plain-text body is a firm SSRF")
	assert.Equal(t, severity.Firm, res[0].Info.Confidence)
	assert.Contains(t, res[0].Info.Description, "droplet_id")
}

// TestScanPerInsertionPoint_LoneWeakMarkerIsSuspect covers the corroboration rule:
// a 200 plain-text body that contains only a common-word field token ("hostname")
// with no distinctive marker beside it could occur by chance, so it is reported as
// Suspect rather than a firm finding.
func TestScanPerInsertionPoint_LoneWeakMarkerIsSuspect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "169.254.169.254/metadata/v1") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "hostname: somewhere\n")
			return
		}
		_, _ = io.WriteString(w, "fetched remote resource ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, severity.Suspect, res[0].Info.Severity, "a lone common-word marker is a suspect lead, not a firm SSRF")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}

// TestScanPerInsertionPoint_StrongMarkerInHTMLIsSuspect covers the content-type
// rule independently of marker strength: even the distinctive `droplet_id` token,
// when found inside an HTML document on a 200, is page markup rather than a proxied
// plain-text/JSON metadata body, so it is downgraded to Suspect.
func TestScanPerInsertionPoint_StrongMarkerInHTMLIsSuspect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "169.254.169.254/metadata/v1") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>droplet_id field name documented here</body></html>")
			return
		}
		_, _ = io.WriteString(w, "fetched remote resource ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?url=https://images.example.com/logo.png"),
		"text/plain", "fetched remote resource ok",
	)
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, severity.Suspect, res[0].Info.Severity, "a metadata marker inside an HTML body must be Suspect, not High")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}
