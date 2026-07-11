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
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
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

const templatedSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.0"},
  "paths": {
    "/api/users/{user_id}": {
      "get": {"operationId": "get_user", "summary": "Get user"}
    }
  }
}`

func scanTestServer(t *testing.T, handler http.HandlerFunc) []*output.ResultEvent {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	return results
}

func TestUnprotectedSchemaOperationIsObservation(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(unprotectedSpec))
			return
		}
		_, _ = w.Write([]byte(`[{"id":1,"email":"public@example.test"}]`))
	})
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
}

func Test422NeverConfirmsAuthenticationBypass(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(unprotectedSpec))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":[]}`))
	})
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.NotContains(t, strings.Join(results[0].ExtractedResults, "\n"), "Confirmed")
}

func TestTemplatedUnprotectedOperationRemainsObservation(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(templatedSpec))
			return
		}
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestDeclaredProtectedOperationReturningAnonymousDataIsFinding(t *testing.T) {
	t.Parallel()
	var anonymousCalls int
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(protectedSpec))
			return
		}
		if r.URL.Path == "/api/users" {
			anonymousCalls++
			assert.Empty(t, r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[{"id":7,"email":"alice@example.test"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	require.Len(t, results, 1)
	assert.GreaterOrEqual(t, anonymousCalls, 2)
	assert.Equal(t, output.RecordKindFinding, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, results[0].EvidenceGrade)
}

func TestDeclaredProtectedOperationReturningEmptyJSONIsNotFinding(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(protectedSpec))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	assert.Empty(t, results, "an empty success body is not substantive protected data")
}

func TestDeclaredProtectedOperationEnforcedAtRuntime(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(protectedSpec))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"not authenticated"}`))
	})
	assert.Empty(t, results)
}

func TestRoutinePublicHealthOperationIsSkipped(t *testing.T) {
	t.Parallel()
	spec := strings.ReplaceAll(unprotectedSpec, "/api/users", "/api/health")
	results := scanTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(spec))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	assert.Empty(t, results)
}

func TestNoOpenAPI(t *testing.T) {
	t.Parallel()
	results := scanTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	assert.Empty(t, results)
}
