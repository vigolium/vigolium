package django_debug_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsDebugPage drives the real scan method against a host
// running with DEBUG=True: its 404 handler renders the Django technical debug
// page exposing URL patterns and version info.
func TestScanPerRequest_DetectsDebugPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>Page not found (404)</h1>" +
			"<p>Request Method: GET</p><p>Request URL: http://x/foo</p>" +
			"<p>Using the URLconf defined in mysite.urls, Django tried these URL patterns</p>" +
			"<p>Django Version: 4.2.1</p></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Django debug finding when the technical 404 page is served")
}

// TestScanPerRequest_NoFalsePositive ensures a plain 404 (DEBUG=False) yields
// no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>Not Found</h1></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-debug 404 page must not yield a finding")
}
