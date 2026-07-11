package fastapi_docs_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
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
	require.Len(t, res, 1, "one docs surface should produce one observation")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding())
}

// TestScanPerRequest_DetectsContextPathDocs verifies the context-path walk: a
// FastAPI sub-app serves its docs at /api/docs (NOT the web root) and the
// observed request is to /api/items. The module must derive the /api base and
// find the docs there.
func TestScanPerRequest_DetectsContextPathDocs(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/docs" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><div id=\"swagger-ui\"></div>" +
				"<script>const ui = SwaggerUIBundle({url: '/api/openapi.json'})</script>" +
				strings.Repeat(" ", 400) + "</body></html>"))
			return
		}
		// Root /docs and every sibling 404 — only the context-path mount serves it.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/items"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for FastAPI docs mounted under the /api context path")
	assert.Contains(t, res[0].URL, "/api/docs", "the finding URL must point at the context-path mount")
}

func TestScanPerRequest_AuthenticatedDocsAreNotCalledPublic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs" && r.Header.Get("Cookie") == "session=developer" {
			_, _ = w.Write([]byte(`<div id="swagger-ui"></div><script>SwaggerUIBundle({})</script>`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "app")
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "Cookie", "session=developer")
	require.NoError(t, err)
	rr = httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), raw), rr.Response())

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "docs visible only with the captured session are not public exposure")
}

// TestScanPerRequest_NoFP_GenericJSONShell reproduces the generic-JSON-catch-all
// FP class: a host that 200s every path with a JSON body carrying the generic
// keys "info" and "paths" but NO "openapi"/"swagger" version key. The old
// single-OR matcher fired on the bare "info"/"paths" tokens; the anchor-group
// requirement must suppress it.
func TestScanPerRequest_NoFP_GenericJSONShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Generic API envelope: has "info" and "paths" but no version key.
		_, _ = w.Write([]byte(`{"info":"service up","paths":["/a","/b"],"status":"ok"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic JSON body with only info/paths (no openapi key) must not yield a finding")
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
