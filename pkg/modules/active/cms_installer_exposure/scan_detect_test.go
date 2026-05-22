package cms_installer_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsWordPressInstaller drives the real scan method
// against a host whose /wp-admin/install.php serves the WordPress setup wizard.
// The random 404 fingerprint path returns a distinct not-found page so the
// installer body is not mistaken for the 404 baseline.
func TestScanPerRequest_DetectsWordPressInstaller(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/install.php" {
			_, _ = w.Write([]byte("<html><head><title>WordPress &rsaquo; Installation</title></head>" +
				"<body class=\"wp-install\"><form id=\"setup\"><select name=\"language\">" +
				"<option>en</option></select><a href=\"setup-config.php\">install.php</a></form></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>nothing to see here, distinct 404 body padding padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a CMS installer finding when the WordPress installer is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns 404 for every
// installer path yields no finding.
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
	assert.Empty(t, res, "a host with no installer endpoints must not yield a finding")
}
