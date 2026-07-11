package drupal_user_enum

import (
	"fmt"
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

// TestScanPerRequest_DetectsUserEnum drives the real scan method against a host
// that redirects /user/N profile lookups to /users/<username>, leaking real
// usernames (the classic Drupal canonical-URL enumeration vector).
func TestScanPerRequest_DetectsUserEnum(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /user/1 -> /users/admin, /user/2 -> /users/editor, etc.
		if strings.HasPrefix(r.URL.Path, "/user/") {
			uid := strings.TrimPrefix(r.URL.Path, "/user/")
			names := map[string]string{"1": "admin", "2": "editor", "3": "author"}
			if name, ok := names[uid]; ok {
				w.Header().Set("Location", fmt.Sprintf("/users/%s", name))
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a user-enumeration finding when /user/N redirects to /users/<name>")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.False(t, res[0].IsFinding(), "public profile names are not necessarily login identities")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s the profile paths
// (and exposes no JSON:API) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without exposed user profiles must not yield a finding")
}

// TestScanPerRequest_NoFP_SSOErrorPage reproduces the motivating false positive:
// a CDN/SSO-fronted host that answers every /user/N with a generic 200 page
// whose <title> is "404 Not Found". The page is not Drupal, so the title vector
// must not mine it for a "username".
func TestScanPerRequest_NoFP_SSOErrorPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body>nginx</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-Drupal 200 error/SSO page must not be reported as user enumeration")
}

// TestScanPerRequest_NoFP_DrupalAccessDenied covers the common Drupal case where
// anonymous /user/N returns a 200 "Access denied | Site" page. It is Drupal, but
// the title is an auth/status title, not a username — the denylist must reject it.
func TestScanPerRequest_NoFP_DrupalAccessDenied(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Generator", "Drupal 10 (https://www.drupal.org)")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Access denied | My Site</title></head><body>drupal-settings-json</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Drupal access-denied title must not be reported as a username")
}

// TestScanPerRequest_NoFP_UniformTitle covers a Drupal host that returns the same
// (non-error) title for every /user/N — including the baseline control UID. The
// baseline match plus the uniformity guard must suppress it.
func TestScanPerRequest_NoFP_UniformTitle(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Generator", "Drupal 10")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Welcome | My Site</title></head><body>drupal-settings-json</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a single page echoed for every /user/N must not be reported as enumeration")
}

// TestScanPerRequest_NoFP_ReservedRouteRedirect covers a redirect to Drupal's own
// auth route (/users/login), which must not be captured as a username.
func TestScanPerRequest_NoFP_ReservedRouteRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/1" {
			w.Header().Set("Location", "/users/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a redirect to a reserved /users/<route> must not be reported as a username")
}

// TestScanPerRequest_NoFP_AEMExtensionCanonicalisation reproduces the motivating
// false positive: an AEM-fronted host (diagnostics.acme.com) that canonicalises
// extensionless paths by 302-redirecting /user/N -> /user/N.html. The redirect
// regex captures "N.html" for each probe — distinct per UID, so the uniformity
// guard never trips and the baseline differs from every real probe — yet each is
// just the requested id echoed back with a file extension, not a leaked username.
func TestScanPerRequest_NoFP_AEMExtensionCanonicalisation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AEM dispatcher canonicalises /user/N to /user/N.html (and selectors),
		// the same resource echoed back — not a profile for a named user.
		if strings.HasPrefix(r.URL.Path, "/user/") && !strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Location", r.URL.Path+".html")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an AEM /user/N -> /user/N.html self-canonicalisation must not be reported as user enumeration")
}

// TestScanPerRequest_DetectsTitleVector confirms the title vector still fires when
// the host is recognisably Drupal and leaks distinct usernames per UID.
func TestScanPerRequest_DetectsTitleVector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/user/") {
			uid := strings.TrimPrefix(r.URL.Path, "/user/")
			names := map[string]string{"1": "alice", "2": "bob"}
			if name, ok := names[uid]; ok {
				w.Header().Set("X-Generator", "Drupal 10")
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><head><title>" + name + " | My Site</title></head><body>drupal-settings-json</body></html>"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a Drupal host leaks distinct usernames in the profile title")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
}

func TestParseDrupalJSONAPIUsersRequiresStructuredResources(t *testing.T) {
	t.Parallel()
	count, labels, ok := parseDrupalJSONAPIUsers(`{"data":[{"type":"user--user","id":"u1","attributes":{"display_name":"Alice"}}]}`)
	assert.True(t, ok)
	assert.Equal(t, 1, count)
	assert.Equal(t, []string{"Alice"}, labels)

	_, _, ok = parseDrupalJSONAPIUsers(`{"message":"type user--user"}`)
	assert.False(t, ok, "a generic string mention is not a JSON:API user collection")
}
