package unauth_service_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func run(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)
	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	if len(res) == 0 {
		return nil
	}
	require.Len(t, res, 1)
	return res[0].ExtractedResults
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
	require.NotEmpty(t, got, "expected a Docker Engine finding")
	assert.Contains(t, got[0], "Docker Engine API")
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
	require.NotEmpty(t, got, "expected a Kubelet finding")
	assert.Contains(t, got[0], "Kubelet API")
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
	require.NotEmpty(t, got, "expected an Elasticsearch finding")
	assert.Contains(t, got[0], "Elasticsearch")
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
