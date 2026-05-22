package symfony_misconfig

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
// host that leaks /config/packages/doctrine.yaml. The module fingerprints a 404
// first, then probes fixed Symfony paths and matches markers on a 200. The
// telltale doctrine config body satisfies the markers while differing from the
// short 404 body.
func TestScanPerRequest_DetectsExposedConfig(t *testing.T) {
	t.Parallel()
	doctrineYAML := "doctrine:\n  dbal:\n    url: '%env(resolve:DATABASE_URL)%'\n    driver: 'pdo_mysql'\n    server_version: '8.0'\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/packages/doctrine.yaml" {
			w.Header().Set("Content-Type", "text/yaml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(doctrineYAML))
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
	require.NotEmpty(t, res, "expected a finding when a Symfony config file is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every Symfony
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
	assert.Empty(t, res, "404 responses must not yield a Symfony misconfiguration finding")
}

// TestCanProcess gates on the presence of a captured response (live host).
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Response(modtest.Request(t, "http://example.com/"), "text/html", "ok")
	assert.True(t, New().CanProcess(rr), "a request with a response should be processable")

	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(bare), "a request without a response should not be processable")
}
