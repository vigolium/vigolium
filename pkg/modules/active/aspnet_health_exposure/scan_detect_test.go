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

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
