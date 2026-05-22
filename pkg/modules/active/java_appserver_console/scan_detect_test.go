package java_appserver_console

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

// TestScanPerRequest_DetectsWildFlyConsole drives the real scan method against a
// host that serves the WildFly/JBoss HAL management console at /console. The
// module first fingerprints a random 404 path, then probes /console; a 200 with
// the WildFly markers (and none of the anti-markers) must yield a finding.
func TestScanPerRequest_DetectsWildFlyConsole(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>HAL Management Console</title></head>" +
				"<body>Welcome to the WildFly Management Console powered by JBoss. " +
				"This is the application server administration interface.</body></html>"))
			return
		}
		// Distinct, short 404 for everything else (including the fingerprint probe).
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an app-server console finding when /console exposes WildFly markers")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "console")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// (including the console paths) yields no finding.
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
	assert.Empty(t, res, "a host that 404s every probe must not yield a console finding")
}
