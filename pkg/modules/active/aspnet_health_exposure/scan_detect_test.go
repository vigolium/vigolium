package aspnet_health_exposure

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

// TestScanPerRequest_DetectsHealthEndpoint serves an ASP.NET health check JSON at
// /health. The module fingerprints a random 404 then probes the fixed health paths
// and should flag /health (200 + status/entries markers).
func TestScanPerRequest_DetectsHealthEndpoint(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Healthy","entries":{"db":{"status":"Healthy"}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a health-exposure finding when /health returns a health document")
}

// TestScanPerRequest_NoFalsePositive ensures a host with no health endpoints (all
// probes 404) produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed health endpoints must not yield a finding")
}

// TestScanPerRequest_GenericStatusJSONNoFalsePositive guards the marker
// tightening: a generic JSON API at /health that merely contains a "status"
// key (but no Healthy/Unhealthy/Degraded health-state value) must not be
// reported. The old marker set listed bare "status"/"entries", which matched
// any JSON status endpoint.
func TestScanPerRequest_GenericStatusJSONNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"running","entries":42,"uptime":12345}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic JSON status endpoint without a health-state value must not be reported")
}

// TestScanPerRequest_NoFP_SlugReflectingRoute reproduces the slug-reflection FP
// class (the easylens /topic/filament case): a content route under /topic/ echoes
// the requested slug into the page, so /topic/healthchecks-ui returns 200 with the
// word "healthchecks-ui" reflected — self-matching the "healthchecks-ui" marker
// even though no Health Checks UI dashboard exists. The SlugReflectionFP control
// (a canary sibling that reflects too) must suppress it.
func TestScanPerRequest_NoFP_SlugReflectingRoute(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-health-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
			return
		}
		// Every /topic/<slug> reflects the slug into an SEO content page.
		if slug, ok := strings.CutPrefix(r.URL.Path, "/topic/"); ok && slug != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>` + slug +
				` — Community</title><link rel="canonical" href="/topic/` + slug +
				`"/></head><body><h1>Posts about ` + slug + `</h1></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Observe a page under /topic/ so CandidateBasePaths walks /topic and the
	// module probes /topic/healthchecks-ui (marker == reflected slug).
	rr := modtest.Response(modtest.Request(t, srv.URL+"/topic/dotnet"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a slug-reflecting content route must not yield a health-exposure finding")
}

// TestScanPerRequest_NoFP_RootLevelReflectingShell reproduces the
// branding.roche.com/healthchecks-ui false positive: a brand/CMS single-page app
// (Frontify-style) whose router renders one 200 shell for EVERY unknown route and
// reflects the requested path into it as a {"view":"<slug>"} router-context blob,
// while the site root 302-redirects to login. /healthchecks-ui returns the shell
// with "healthchecks-ui" echoed, self-matching the slug marker with no dashboard
// behind it. The random-path 404 fingerprint cannot see this (each path's body
// differs by the reflected slug), so the catch-all-shell + root-level slug-reflection
// guards must suppress it.
func TestScanPerRequest_NoFP_RootLevelReflectingShell(t *testing.T) {
	t.Parallel()
	shell := func(seg string) string {
		return `<!DOCTYPE html><html class="mod modLayout"><head><title>Brand</title>` +
			`<meta name="viewport" content="width=device-width"></head><body>` +
			strings.Repeat(`<div class="mod skel"></div>`, 60) +
			`<script>window.__ctx={"route_initial":true,"view":"` + seg + `","user":[]};</script>` +
			`</body></html>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "vigolium-health-404-"):
			// A genuine 404 with a distinct small body so the fingerprint does not
			// pre-suppress — the FP must reach (and be caught by) the shell guards.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
		case p == "/":
			http.Redirect(w, r, "https://login.example.com/", http.StatusFound)
		default:
			seg := strings.Trim(p, "/")
			if i := strings.LastIndex(seg, "/"); i >= 0 {
				seg = seg[i+1:]
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell(seg)))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a path-reflecting SPA/CMS shell must not yield a health-exposure finding")
}

// TestScanPerRequest_NoFP_RootSlugReflectionGuard isolates the root-level
// slug-reflection control: the catch-all-shell samples are deliberately unavailable
// (the site root 302-redirects and a random web-root directory 404s), so ONLY
// SlugReflectionFP's web-root canary probe can disprove the reflected
// "healthchecks-ui" slug. The app echoes an arbitrary requested slug into a 200 page
// via a bare (no-leading-slash) attribute — surviving StripReflectedProbePath, which
// only removes the full "/healthchecks-ui" path — so the marker matches and the guard
// must fire.
func TestScanPerRequest_NoFP_RootSlugReflectionGuard(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "vigolium-health-404-"),
			strings.Contains(p, "vigolium-catchall-dir-"):
			w.WriteHeader(http.StatusNotFound) // defeat RandomDirCatchAll (non-2xx)
			_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
		case p == "/":
			http.Redirect(w, r, "https://login.example.com/", http.StatusFound) // defeat RootPageCatchAll
		default:
			seg := strings.Trim(p, "/")
			if i := strings.LastIndex(seg, "/"); i >= 0 {
				seg = seg[i+1:]
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div data-view="` + seg + `"></div></body></html>`))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a root-level reflected slug must be suppressed by the web-root canary control")
}

// TestScanPerRequest_HealthChecksUIDashboardDetected is the positive counterpart:
// a genuine AspNetCore.HealthChecks.UI dashboard carrying the library identifier,
// served ONLY at /healthchecks-ui, must still be reported. The site root serves a
// distinct homepage and random paths 404, so neither the catch-all-shell guard nor
// the slug-reflection control engages and the finding stands.
func TestScanPerRequest_HealthChecksUIDashboardDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthchecks-ui":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Health Checks UI</title></head>` +
				`<body><div id="app"></div><script>var ui = new AspNetCore.HealthChecks.UI({endpoint:"/hc"});` +
				`window.uiSettings={"pollingInterval":10};</script></body></html>`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Welcome</h1><p>corporate homepage</p></body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body><h1>Welcome</h1></body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a genuine Health Checks UI dashboard must still be reported")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
