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
