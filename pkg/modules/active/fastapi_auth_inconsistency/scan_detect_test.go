package fastapi_auth_inconsistency

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const unprotectedSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.0"},
  "paths": {
    "/api/users": {
      "get": {"operationId": "list_users", "summary": "List users"}
    }
  }
}`

const protectedSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.0"},
  "security": [{"OAuth2": []}],
  "paths": {
    "/api/users": {
      "get": {"operationId": "list_users", "summary": "List users"}
    }
  }
}`

// TestScanPerRequest_DetectsUnprotectedOps serves an OpenAPI spec with an /api
// operation that has no security defined at any level, which the module flags.
func TestScanPerRequest_DetectsUnprotectedOps(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(unprotectedSpec))
			return
		}
		// The verification call to /api/users should succeed unauthenticated.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for an /api operation with no security")
}

// TestScanPerRequest_NoFalsePositive serves a spec where global security covers
// the operation, so nothing should be flagged.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(protectedSpec))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a globally-secured spec must not yield a finding")
}

// TestScanPerRequest_NoOpenAPI ensures a host without an openapi.json yields nothing.
func TestScanPerRequest_NoOpenAPI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
