package wp_xmlrpc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const methodsResponse = `<?xml version="1.0"?>
<methodResponse>
  <params><param><value><array><data>
    <value><string>system.multicall</string></value>
    <value><string>system.listMethods</string></value>
    <value><string>pingback.ping</string></value>
    <value><string>wp.getUsersBlogs</string></value>
  </data></array></value></param></params>
</methodResponse>`

// TestScanPerRequest_DetectsXMLRPC drives the real scan method against a host
// whose /xmlrpc.php answers system.listMethods, advertising the dangerous
// system.multicall and pingback.ping methods. The module emits the base
// "enabled" finding plus the multicall and pingback findings.
func TestScanPerRequest_DetectsXMLRPC(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xmlrpc.php" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(methodsResponse))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected findings when xmlrpc.php lists methods")
	assert.GreaterOrEqual(t, len(res), 3, "expected base + multicall + pingback findings")
}

// TestScanPerRequest_NoFalsePositive ensures a host without an XML-RPC endpoint
// (404) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a missing xmlrpc.php must not yield an XML-RPC finding")
}
