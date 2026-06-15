package fastapi_auth_inconsistency

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const templatedSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.0"},
  "paths": {
    "/api/users/{user_id}": {
      "get": {"operationId": "get_user", "summary": "Get user"}
    }
  }
}`

// hasVerifiedLine reports whether any extracted result is a runtime "Verified:"
// confirmation (as opposed to a spec-only "unprotected operation" entry).
func hasVerifiedLine(extracted []string) bool {
	for _, e := range extracted {
		if strings.HasPrefix(e, "Verified:") {
			return true
		}
	}
	return false
}

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
	assert.Equal(t, severity.Firm, res[0].Info.Confidence, "a runtime-reachable op confirms the finding as Firm")
	assert.True(t, hasVerifiedLine(res[0].ExtractedResults), "a reachable op must add a Verified line")
}

// TestScanPerRequest_RuntimeProtectedIsTentative covers the new confidence gate:
// the spec declares an op as unprotected, but at runtime it returns 401 (auth is
// enforced via undeclared middleware). The schema inconsistency is still surfaced,
// but as Tentative with no "Verified:" line — not a Firm proven bypass.
func TestScanPerRequest_RuntimeProtectedIsTentative(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(unprotectedSpec))
			return
		}
		w.WriteHeader(http.StatusUnauthorized) // runtime enforces auth
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the schema inconsistency is still surfaced")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence, "unconfirmed at runtime must be Tentative, not Firm")
	assert.False(t, hasVerifiedLine(res[0].ExtractedResults), "a 401 op must not produce a Verified line")
}

// TestScanPerRequest_TemplatedPathNotVerified ensures a templated path
// (/api/users/{user_id}) is never "verified" by a literal call — the placeholder
// would just 404/422 and say nothing about auth — so the finding stays Tentative.
func TestScanPerRequest_TemplatedPathNotVerified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(templatedSpec))
			return
		}
		// Even though a literal "/api/users/{user_id}" call would 200 here, the
		// templated path must be skipped rather than reported as verified.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the spec inconsistency is still surfaced for a templated op")
	assert.False(t, hasVerifiedLine(res[0].ExtractedResults), "a templated path must not be literally verified")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}

// TestScanPerRequest_422CountsAsReached confirms a FastAPI 422 (request validation
// runs only after auth is cleared) is treated as proof the endpoint is reachable
// unauthenticated, yielding a Firm, verified finding.
func TestScanPerRequest_422CountsAsReached(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(unprotectedSpec))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity) // 422: reached, validation failed
		_, _ = w.Write([]byte(`{"detail":[]}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, severity.Firm, res[0].Info.Confidence, "a 422 proves the endpoint was reached unauthenticated")
	assert.True(t, hasVerifiedLine(res[0].ExtractedResults))
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
