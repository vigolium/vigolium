package fastapi_docs_exposure

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

// TestScanPerRequest_DetectsSwaggerUI serves a Swagger UI page at /docs (with
// telltale markers and a body that differs from the 404 fingerprint) so the
// module reports an exposed-docs finding.
func TestScanPerRequest_DetectsSwaggerUI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/docs":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><div id=\"swagger-ui\"></div>" +
				"<script>const ui = SwaggerUIBundle({url: '/openapi.json'})</script>" +
				strings.Repeat(" ", 400) + "</body></html>"))
		default:
			// Distinct, short 404 body so the fingerprint diverges from /docs.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("nope"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an exposed-docs finding when Swagger UI is served at /docs")
}

// TestScanPerRequest_NoFalsePositive returns 404 for every docs path, so nothing
// should be flagged.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "404 docs paths must not yield a finding")
}
