package spring_debug_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsWhitelabelError drives the real scan method against
// a host that serves the Spring Boot Whitelabel Error Page at /error. The module
// fingerprints a random 404 path first, then probes the fixed debug paths; the
// "Whitelabel Error Page" markers on a 200 response trigger a finding.
func TestScanPerRequest_DetectsWhitelabelError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Whitelabel Error Page</h1><p>There was an unexpected error (type=Internal Server Error, status=500).</p></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Spring debug finding when /error serves the Whitelabel Error Page")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns a benign body
// for every debug probe yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ordinary application page with no spring markers"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no spring debug markers must not yield a finding")
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
