package wp_misconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsExposedConfig drives the real scan method against a
// host that serves wp-config.php as plaintext. The module fingerprints a 404
// first, then probes fixed WordPress paths and matches markers on a 200.
func TestScanPerRequest_DetectsExposedConfig(t *testing.T) {
	t.Parallel()
	wpConfig := "<?php\n" +
		"define('DB_NAME', 'wordpress');\n" +
		"define('DB_USER', 'wp_admin');\n" +
		"define('DB_PASSWORD', 's3cret');\n" +
		"define('AUTH_KEY', 'put-your-unique-phrase-here');\n" +
		"define('LOGGED_IN_SALT', 'another-unique-phrase');\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-config.php" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(wpConfig))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when wp-config.php is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every WordPress
// probe path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "404 responses must not yield a WordPress misconfiguration finding")
}
