package unauth_service_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func run(t *testing.T, srv *httptest.Server) *output.ResultEvent {
	t.Helper()
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)
	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	if len(res) == 0 {
		return nil
	}
	require.Len(t, res, 1)
	return res[0]
}

func TestDetectsDockerEngine(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Platform":{"Name":"Docker Engine"},"ApiVersion":"1.41","KernelVersion":"5.15.0","GoVersion":"go1.18"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := run(t, srv)
	require.NotNil(t, got, "expected a Docker Engine observation")
	assert.Equal(t, output.RecordKindObservation, got.RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, got.EvidenceGrade)
	assert.Contains(t, got.ExtractedResults[0], "Docker Engine API")
	assert.NotContains(t, got.Info.Description, "equivalent to root")
}

func TestDetectsKubelet(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pods" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"nginx"}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := run(t, srv)
	require.NotNil(t, got, "expected a Kubelet finding")
	assert.Equal(t, output.RecordKindFinding, got.RecordKind)
	assert.Equal(t, output.EvidenceGradeImpact, got.EvidenceGrade)
	assert.Contains(t, got.ExtractedResults[0], "Kubelet API")
	assert.NotContains(t, got.Info.Description, "command execution")
}

func TestDetectsElasticsearch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"es01","cluster_name":"prod","version":{"number":"7.10.0"},"tagline":"You Know, for Search"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := run(t, srv)
	require.NotNil(t, got, "expected an Elasticsearch observation")
	assert.Equal(t, output.RecordKindObservation, got.RecordKind)
	assert.Contains(t, got.ExtractedResults[0], "Elasticsearch")
}

func TestElasticsearchDocumentReadIsFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_search" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"took":1,"_shards":{"total":1,"successful":1,"failed":0},"hits":{"hits":[{"_index":"customers","_id":"1","_source":{"email":"alice@example.test"}}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := run(t, srv)
	require.NotNil(t, got)
	assert.Equal(t, output.RecordKindFinding, got.RecordKind)
	assert.Equal(t, output.EvidenceGradeImpact, got.EvidenceGrade)
	assert.Contains(t, got.Info.Description, "stored document content")
}

func TestRegistryCatalogNamesRemainCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/_catalog" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			_, _ = w.Write([]byte(`{"repositories":["public/app"]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := run(t, srv)
	require.NotNil(t, got)
	assert.Equal(t, output.RecordKindCandidate, got.RecordKind)
	assert.NotEqual(t, output.EvidenceGradeImpact, got.EvidenceGrade)
	assert.Contains(t, got.Info.Description, "Public registries may intentionally")
}

func TestStatusCodeWithoutNativeStructureIsIgnored(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","message":"service available"}`))
	}))
	defer srv.Close()

	assert.Nil(t, run(t, srv), "a reproduced 200 alone must not identify an infrastructure service")
}

// TestNoFalsePositiveHTMLCatchAll reproduces the universal catch-all / echo FP
// class: a host that answers EVERY path with a 200 text/html body (here only a
// reflecting tail fragment, as a gzip + bogus Content-Length:0 transport quirk
// would leave) that happens to contain the Docker Registry probe's weak
// "repositories" marker. Status 200 + the bare word would forge a Docker Registry
// finding (and reproduce across both rounds, since the catch-all is stable); the
// content-type discipline (every fingerprinted service answers with JSON, never
// an HTML document) rejects it.
func TestNoFalsePositiveHTMLCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Truncated tail: no <!doctype/<html>, carries the weak "repositories"
		// token the Docker Registry v2 probe accepts, reflecting the path too.
		_, _ = w.Write([]byte("</nav><main>route " + r.URL.Path +
			" — browse our repositories and docs</main></body>"))
	}))
	defer srv.Close()

	got := run(t, srv)
	assert.Empty(t, got, "an HTML catch-all echoing 'repositories' must not be flagged as a Docker Registry")
}

// A normal web host (HTML for everything, and 401 on API-ish paths) must not match
// any service signature.
func TestNoFalsePositiveWebHost(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			// Some apps expose a /version — but without the Docker/K8s JSON shape.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"app":"myapp","version":"2.3.1"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="app">Welcome</div></body></html>`))
	}))
	defer srv.Close()

	got := run(t, srv)
	assert.Empty(t, got, "a plain web host must not be flagged as an infra service")
}
