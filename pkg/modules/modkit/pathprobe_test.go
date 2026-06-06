package modkit_test

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

func TestMatchAllGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		require   [][]string
		wantOK    bool
		wantFirst string
	}{
		{
			name:      "all groups hit returns matches",
			body:      `{"propertySources":[],"activeProfiles":["prod"]}`,
			require:   [][]string{{`"propertySources"`}, {`"activeProfiles"`, `"name"`}},
			wantOK:    true,
			wantFirst: `"propertySources"`,
		},
		{
			name:    "anchor group missing rejects",
			body:    `{"name":"x","status":"UP"}`,
			require: [][]string{{`"propertySources"`}, {`"name"`}},
			wantOK:  false,
		},
		{
			name:    "corroborator group missing rejects",
			body:    `{"propertySources":[]}`,
			require: [][]string{{`"propertySources"`}, {`"activeProfiles"`}},
			wantOK:  false,
		},
		{
			name:    "weak single substring no longer enough",
			body:    `[{"key":"status","value":"Status"},{"key":"scope","value":"Scope"}]`,
			require: [][]string{{`"status":"UP"`, `"status":"DOWN"`}},
			wantOK:  false,
		},
		{
			name:    "empty requireAll never fires",
			body:    `anything`,
			require: nil,
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matched, ok := modkit.MatchAllGroups(tc.body, tc.require)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.NotEmpty(t, matched)
				assert.Equal(t, tc.wantFirst, matched[0])
				assert.Len(t, matched, len(tc.require))
			} else {
				assert.Nil(t, matched)
			}
		})
	}
}

// TestSiblingPathCatchAll_SubDirCatchAll verifies that a sub-directory catch-all
// (every child of /admin/ returns the same body) is detected.
func TestSiblingPathCatchAll_SubDirCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"registration":{"managementUrl":"x"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")
	match := func(b string) bool { return strings.Contains(b, `"registration"`) }

	assert.True(t, modkit.SiblingPathCatchAll(rr, client, "/admin/instances", match),
		"a sub-directory catch-all under /admin/ must be detected")
}

// TestSiblingPathCatchAll_RealEndpoint verifies a genuine endpoint (only its own
// path returns the marker; siblings 404) is NOT flagged as a catch-all.
func TestSiblingPathCatchAll_RealEndpoint(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/instances" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"registration":{"managementUrl":"x"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")
	match := func(b string) bool { return strings.Contains(b, `"registration"`) }

	assert.False(t, modkit.SiblingPathCatchAll(rr, client, "/admin/instances", match),
		"a real endpoint whose siblings 404 must not be flagged as a catch-all")
}

// TestSiblingPathCatchAll_RootPathSkipped verifies single-segment paths are a
// no-op (left to the caller's root 404 fingerprint), issuing no sibling request.
func TestSiblingPathCatchAll_RootPathSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"registration":{}}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")
	match := func(b string) bool { return strings.Contains(b, `"registration"`) }

	assert.False(t, modkit.SiblingPathCatchAll(rr, client, "/admin", match),
		"a root-level probe path must be skipped (no sibling request)")
}

// TestMatchAndConfirmSibling exercises the combined match + catch-all guard the
// marker-based exposure modules call: a genuine endpoint confirms (siblings 404),
// a non-matching body is rejected outright, and a sub-directory catch-all is
// suppressed even when the body matches.
func TestMatchAndConfirmSibling(t *testing.T) {
	t.Parallel()
	markers := [][]string{{`"registration"`}, {`"managementUrl"`}}

	t.Run("genuine endpoint confirms", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin/instances" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"registration":{"managementUrl":"x"}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		body := `{"registration":{"managementUrl":"x"}}`

		matched, ok := modkit.MatchAndConfirmSibling(rr, client, "/admin/instances", body, markers)
		require.True(t, ok, "a real endpoint whose siblings 404 must confirm")
		assert.Equal(t, []string{`"registration"`, `"managementUrl"`}, matched)
	})

	t.Run("non-matching body rejected", func(t *testing.T) {
		t.Parallel()
		client := modtest.Requester(t)
		rr := modtest.Request(t, "http://example.invalid/")

		matched, ok := modkit.MatchAndConfirmSibling(rr, client, "/admin/instances", `{"name":"x"}`, markers)
		assert.False(t, ok, "a body missing a marker group must not confirm")
		assert.Nil(t, matched)
	})

	t.Run("sub-directory catch-all suppressed", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/admin/") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"registration":{"managementUrl":"x"}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		body := `{"registration":{"managementUrl":"x"}}`

		matched, ok := modkit.MatchAndConfirmSibling(rr, client, "/admin/instances", body, markers)
		assert.False(t, ok, "a sub-directory catch-all that serves the markers for every child must be suppressed")
		assert.Nil(t, matched)
	})
}
