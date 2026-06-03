package reverse_proxy_path_confusion

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

const tomcatFingerprint = "<title>Tomcat Web Application Manager</title> list applications"

// shellMarker reports whether a raw request-target uses one of the confusion
// shells this module sends.
func shellMarker(requestURI string) bool {
	return strings.Contains(requestURI, "..;") ||
		strings.Contains(requestURI, "%23") ||
		strings.Contains(requestURI, "%2e%2e") ||
		strings.Contains(requestURI, "%2f")
}

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "proxy")
}

// TestScanPerRequest_Confusion simulates a reverse proxy that blocks
// /manager/html directly (403) but whose backend serves it when reached via a
// path-confusion shell. The full multi-round gate must confirm it.
func TestScanPerRequest_Confusion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ru := r.RequestURI
		switch {
		case ru == "/manager/html":
			// Proxy blocks the direct request.
			w.WriteHeader(http.StatusForbidden)
		case strings.Contains(ru, "manager/html") && shellMarker(ru):
			// Backend normalized the confusion shell back to /manager/html.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(tomcatFingerprint))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "path-confusion reach of a blocked backend endpoint must be detected")
	assert.Equal(t, "path", res[0].FuzzingParameter)
	assert.Equal(t, severity.High, res[0].Info.Severity)
	assert.Contains(t, strings.Join(res[0].ExtractedResults, " "), "manager/html")
}

// TestScanPerRequest_OpenlyReachable ensures that when the endpoint is reachable
// DIRECTLY (no proxy block), there is no confusion bug and nothing is reported.
func TestScanPerRequest_OpenlyReachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything containing manager/html returns the fingerprint, INCLUDING
		// the direct request — so it is not gated behind the proxy.
		if strings.Contains(r.RequestURI, "manager/html") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(tomcatFingerprint))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an openly reachable endpoint is not a proxy-confusion finding")
}

// TestScanPerRequest_CatchAllShell ensures the decoy-target negative rejects a
// server that returns the fingerprint for ANY path using the shell prefix (a
// catch-all), which would otherwise be a false positive.
func TestScanPerRequest_CatchAllShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ru := r.RequestURI
		switch {
		case ru == "/manager/html":
			w.WriteHeader(http.StatusForbidden)
		case shellMarker(ru):
			// Catch-all: every confusion-shell path returns the fingerprint,
			// even the decoy target — so the fingerprint is NOT evidence of
			// reaching the real endpoint.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(tomcatFingerprint))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all shell prefix must be rejected by the decoy-target negative")
}

// TestScanPerRequest_NoEndpoints ensures a host exposing none of the curated
// endpoints produces no finding.
func TestScanPerRequest_NoEndpoints(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no curated endpoint present → no finding")
}
