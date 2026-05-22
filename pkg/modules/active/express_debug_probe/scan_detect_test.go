package express_debug_probe

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsStackTrace drives the real scan method against an
// Express app running with verbose errors: the default handler dumps a Node.js
// stack trace including node_modules/ frames and an absolute file path. Echoing
// the request path keeps each probe body distinct from the 404 fingerprint.
func TestScanPerRequest_DetectsStackTrace(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Error: cannot handle " + r.URL.Path + "\n" +
			"    at Layer.handle (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)\n" +
			"    at /usr/src/app/server.js:42:13\n"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/items/42")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an Express debug finding when a Node.js stack trace leaks")
}

// TestScanPerRequest_NoFalsePositive ensures an app returning a clean,
// non-verbose error (no stack frames or paths) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"error":"Not Found","message":"Cannot GET"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/items/42")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a clean framework error shape must not yield a debug finding")
}
