package django_debug_toolbar_exposure

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

// TestScanPerRequest_DetectsDebugToolbar drives the real scan method against a
// host whose /__debug__/ endpoint serves the django-debug-toolbar markup. The
// random 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsDebugToolbar(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__debug__") {
			_, _ = w.Write([]byte("<html><body><div id=\"djDebug\" class=\"djdt-hidden\">" +
				"<h1>Django Debug Toolbar</h1><div class=\"djdt-panelContent panel\">SQL</div>" +
				"</div></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 not found distinct baseline body padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a debug-toolbar finding when /__debug__/ serves the toolbar markup")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for the
// toolbar paths yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without the debug toolbar must not yield a finding")
}
