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
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_DetectsRESTUsers drives the real scan method against a host
// whose unauthenticated /wp-json/wp/v2/users endpoint returns a JSON array of
// users, leaking their slugs. The module enumerates those usernames. The
// author-archive redirect vector is exercised separately in
// TestScanPerRequest_DetectsAuthorArchive.
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
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.False(t, res[0].IsFinding(), "public REST authors are not necessarily private login identities")
}

// TestScanPerRequest_DetectsAuthorArchive drives the author-archive vector: a
// host that redirects /?author=N to /author/<distinct-username>/ leaks real
// usernames. The baseline control id 404s, so the genuine per-id slugs survive.
func TestScanPerRequest_DetectsAuthorArchive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		names := map[string]string{"1": "siteadmin", "2": "editor-jane"}
		if name, ok := names[r.URL.Query().Get("author")]; ok {
			w.Header().Set("Location", "/author/"+name+"/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /?author=N leaks distinct usernames")
	assert.Contains(t, res[0].ExtractedResults, "siteadmin")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.False(t, res[0].IsFinding())
}

// TestScanPerRequest_NoFP_AuthorIDEcho reproduces the AEM-style self-redirect FP
// (the diagnostics.acme.com class): a non-WordPress host canonicalises
// /?author=N to /author/N.html, echoing the requested id back with an extension.
// Each probe yields a distinct value (N.html), defeating the uniformity guard,
// yet none is a leaked username — the id-echo guard must drop them all.
func TestScanPerRequest_NoFP_AuthorIDEcho(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("author"); id != "" {
			w.Header().Set("Location", "/author/"+id+".html/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a /?author=N -> /author/N.html self-canonicalisation must not be reported as user enumeration")
}

// TestScanPerRequest_NoFP_UniformCatchAll covers a host that redirects every
// /?author=N (including the out-of-range control) to one catch-all author slug.
// The baseline match (and the uniformity guard behind it) must suppress it.
func TestScanPerRequest_NoFP_UniformCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/author/blog/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a single catch-all author slug echoed for every /?author=N must not be reported as enumeration")
}

// TestScanPerRequest_NoFP_UniformDistinctBaseline exercises the uniformity guard
// directly: the control id 404s (so the baseline filter does not fire), but all
// real ids collapse to one identical slug — a catch-all, not enumeration.
func TestScanPerRequest_NoFP_UniformDistinctBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("author") {
		case "1", "2", "3", "4", "5":
			w.Header().Set("Location", "/author/sameuser/")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "all author ids collapsing to one slug must trip the uniformity guard")
}

// TestScanPerRequest_NoFP_ReservedSlug covers a redirect to WordPress' own route
// (/author/login/), which is not a username.
func TestScanPerRequest_NoFP_ReservedSlug(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("author") == "1" {
			w.Header().Set("Location", "/author/login/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a redirect to a reserved /author/<route> must not be reported as a username")
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
