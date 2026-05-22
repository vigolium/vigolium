package wp_user_enum

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

// TestScanPerRequest_DetectsRESTUsers drives the real scan method against a host
// whose unauthenticated /wp-json/wp/v2/users endpoint returns a JSON array of
// users, leaking their slugs. The module enumerates those usernames.
//
// The author-archive method is not exercised here: the HTTP requester follows
// redirects by default, so the module never observes the raw 30x the author
// archive emits; the REST API method is the deterministic in-band signal.
func TestScanPerRequest_DetectsRESTUsers(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/wp-json/wp/v2/users") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1,"name":"Site Admin","slug":"admin"},{"id":2,"name":"Editor","slug":"editor"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the REST users endpoint leaks slugs")
	assert.Contains(t, res[0].ExtractedResults, "admin")
}

// TestScanPerRequest_NoFalsePositive ensures a host that exposes neither author
// archives nor the REST users endpoint yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// REST users locked down (403), author archives just 404.
		if strings.HasPrefix(r.URL.Path, "/wp-json") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a locked-down host must not yield a user enumeration finding")
}
