package tomcat_manager_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsManager drives the real scan method against a host
// that serves an open Tomcat Web Application Manager. The module fingerprints a
// 404 first, then probes fixed Tomcat paths and matches markers on a 200.
func TestScanPerRequest_DetectsManager(t *testing.T) {
	t.Parallel()
	managerHTML := "<html><head><title>/manager</title></head><body>" +
		"<h1>Tomcat Web Application Manager</h1>" +
		"<p>Deploy directory or WAR file located on server</p>" +
		"<form><input value=\"Deploy\"><input value=\"Undeploy\"></form>" +
		"</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manager/html" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(managerHTML))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the Tomcat manager is exposed")
}

// TestScanPerRequest_DetectsAuthChallenge covers the 401 + WWW-Authenticate
// detection path: a manager that requires Basic auth still reveals Tomcat.
func TestScanPerRequest_DetectsAuthChallenge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manager/html" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a Tomcat auth challenge is returned")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
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
	assert.Empty(t, res, "404 responses must not yield a Tomcat exposure finding")
}
