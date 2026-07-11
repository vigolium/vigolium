package spring_h2_console_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_DetectsH2Console drives the real scan method against a host
// that exposes the H2 database web console at /h2-console. The module
// fingerprints a random 404 path first, then probes the fixed H2 paths; the
// "H2 Console"/"JDBC URL"/org.h2 markers on a 200 response trigger a finding.
func TestScanPerRequest_DetectsH2Console(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/h2-console" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>H2 Console</title></head><body>JDBC URL: jdbc:h2:mem:test Driver Class: org.h2.Driver</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an H2 console candidate when /h2-console serves the console page")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding(), "a connection page alone does not prove database or code execution")
}

// TestScanPerRequest_DetectsContextPathConsole verifies the context-path walk:
// the H2 console is mounted under server.servlet.context-path at /api/h2-console
// (NOT at the web root), and the observed request is to /api/users. The module
// must derive the /api base from the observed path and find the console there.
func TestScanPerRequest_DetectsContextPathConsole(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/h2-console" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>H2 Console</title></head><body>JDBC URL: jdbc:h2:mem:test Driver Class: org.h2.Driver</body></html>`))
			return
		}
		// Root /h2-console and every sibling 404 — only the context-path mount serves it.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for an H2 console mounted under the /api context path")
	assert.Contains(t, res[0].URL, "/api/h2-console", "the finding URL must point at the context-path mount")
}

func TestScanPerRequest_AuthenticatedConsoleIsNotCalledPublic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/h2-console" && r.Header.Get("Authorization") == "Bearer operator" {
			_, _ = w.Write([]byte(`<title>H2 Console</title> JDBC URL org.h2.Driver`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/")
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "Authorization", "Bearer operator")
	require.NoError(t, err)
	rr = httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), raw), modtest.Response(rr, "text/html", "ok").Response())

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a console visible only with the captured credential is not public exposure")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every H2 probe
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
	assert.Empty(t, res, "a host that 404s all H2 paths must not yield a finding")
}

// TestScanPerRequest_WeakMarkerNoFalsePositive ensures a page that merely
// mentions "H2 Console" (e.g. documentation) but lacks the JDBC URL / org.h2
// connection-form tokens is no longer reported.
func TestScanPerRequest_WeakMarkerNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/h2-console" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>See the H2 Console documentation page</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page that only mentions H2 Console without the JDBC connection form must not yield a finding")
}

// TestCanProcess covers the module gate: it requires a non-nil response baseline.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil), "nil ctx must not be processed")

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "a request without a response baseline must not be processed")

	withResp := httpmsg.NewHttpRequestResponse(rr.Request(), httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\n")))
	assert.True(t, m.CanProcess(withResp), "a request with a response baseline must be processed")
}
