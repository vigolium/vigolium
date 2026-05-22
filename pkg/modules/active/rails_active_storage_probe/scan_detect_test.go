package rails_active_storage_probe

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsDirectUpload simulates a Rails app whose Active
// Storage direct-upload endpoint advertises POST via an Allow header on OPTIONS,
// with a distinct body from the random 404 path.
func TestScanPerRequest_DetectsDirectUpload(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/active_storage/direct_uploads" {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("active storage direct upload endpoint present and reachable here"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the direct-upload endpoint advertises POST")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without Active Storage endpoints must not yield findings")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
