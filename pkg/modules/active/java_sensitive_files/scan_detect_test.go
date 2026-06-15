package java_sensitive_files

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsWebXML drives the real scan method against a host
// that exposes /WEB-INF/web.xml. The module fingerprints a 404 first, then
// probes the sensitive paths; the deployment descriptor markers must surface a
// finding (now reported at the capped Medium / Tentative level).
func TestScanPerRequest_DetectsWebXML(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/WEB-INF/web.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?>` +
				`<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">` +
				`<servlet><servlet-name>dispatcher</servlet-name></servlet>` +
				`<filter><filter-name>auth</filter-name></filter></web-app>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a sensitive-file finding when /WEB-INF/web.xml is exposed")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "java sensitive file")
	assert.Equal(t, severity.Medium, res[0].Info.Severity, "sensitive-file findings are capped at Medium")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence, "sensitive-file findings are Tentative")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s every probe must not yield a sensitive-file finding")
}

// TestScanPerRequest_AppShellNoFalsePositive reproduces the Salesforce false
// positive: a framework app routes /WEB-INF/web.xml (and a divergent 404 probe)
// to a 200 application shell whose JavaScript merely contains the bare word
// "servlet". The shell carries no structural <web-app marker, so the strengthened
// AND-of-groups confirmation must reject it.
func TestScanPerRequest_AppShellNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		// Per-path body so the no-extension 404 fingerprint diverges from the
		// /WEB-INF/web.xml candidate (mirrors the embedded session/refURL the real
		// Salesforce shell varies per request), forcing the marker check to run.
		_, _ = w.Write([]byte(
			"window.sfdcPage = new GenericSfdcPage(); UserContext.initialize();" +
				" var servletPath='/aura'; var filterChain=[]; path=" + r.URL.Path))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an app shell containing only the word 'servlet' must not be flagged as web.xml")
}

// TestScanPerRequest_ExtensionCatchAllNoFalsePositive covers the multi-round
// decoy guard directly: the host serves a full, marker-satisfying web.xml body
// for EVERY *.xml path (an extension-scoped catch-all) but a divergent 404 for
// other paths. The candidate passes the structural markers and the soft-404
// fingerprint, so only the same-extension sibling probe can disprove it.
func TestScanPerRequest_ExtensionCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	const webXML = `<?xml version="1.0"?><web-app version="3.0">` +
		`<servlet><servlet-name>dispatcher</servlet-name></servlet></web-app>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".xml") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(webXML))
			return
		}
		// No-extension paths (incl. the 404 fingerprint) get a divergent body so
		// the candidate clears the fingerprint and reaches the decoy check.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nothing here, just a plain not-found page for "+r.URL.Path))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that serves the same web.xml body for every *.xml path is a catch-all, not an exposure")
}
