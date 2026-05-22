package drupal_misconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsExposedChangelog drives the real scan method against
// a host that serves /CHANGELOG.txt, leaking the exact Drupal core version. The
// random 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsExposedChangelog(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/CHANGELOG.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Drupal 7.92, 2022-06-01\n----------------------\n" +
				"Changes since 7.91:\n- Bug fixes and improvements.\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>The requested page could not be found, distinct 404 body.</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Drupal misconfig finding when CHANGELOG.txt is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for every
// Drupal-specific path yields no finding.
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
	assert.Empty(t, res, "a non-Drupal host must not yield a finding")
}
