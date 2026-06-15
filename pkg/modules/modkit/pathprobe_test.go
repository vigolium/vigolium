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

func TestCandidateBasePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "multi-segment yields root plus ancestors plus self",
			path: "/api/v1/users",
			want: []string{"", "/api", "/api/v1", "/api/v1/users"},
		},
		{
			name: "single-segment context root included via self",
			path: "/myapp",
			want: []string{"", "/myapp"},
		},
		{
			name: "trailing slash directory",
			path: "/myapp/",
			want: []string{"", "/myapp"},
		},
		{
			name: "root only",
			path: "/",
			want: []string{""},
		},
		{
			name: "empty path is root only",
			path: "",
			want: []string{""},
		},
		{
			name: "a file is not a mount point",
			path: "/index.html",
			want: []string{""},
		},
		{
			name: "dotfile self is not a base but root still probed",
			path: "/.env",
			want: []string{""},
		},
		{
			name: "static-asset ancestors and self are skipped",
			path: "/assets/js/app.js",
			want: []string{""},
		},
		{
			name: "static segment mid-path is skipped but real prefix kept",
			path: "/app/static/logo.png",
			want: []string{"", "/app"},
		},
		{
			name: "query string is stripped",
			path: "/api/v1?id=1",
			want: []string{"", "/api", "/api/v1"},
		},
		{
			name: "depth is capped",
			path: "/a/b/c/d/e/f/g",
			want: []string{"", "/a", "/a/b", "/a/b/c", "/a/b/c/d"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := modkit.CandidateBasePaths(tc.path)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, len(got), modkit.MaxBasePathDepth)
			// Root must always be present and first so adopting the helper never
			// drops a module's pre-existing root coverage.
			require.NotEmpty(t, got)
			assert.Equal(t, "", got[0])
		})
	}
}

func TestCandidateBasePathsIncludingStatic(t *testing.T) {
	t.Parallel()

	// The static-inclusive variant keeps /assets, /static, etc. — the directories
	// CandidateBasePaths drops — because that is where exposed files turn up.
	assert.Equal(t,
		[]string{"", "/assets", "/assets/js"},
		modkit.CandidateBasePathsIncludingStatic("/assets/js/app.js"),
		"file discovery must walk into static-asset directories")

	assert.Equal(t,
		[]string{"", "/app", "/app/static"},
		modkit.CandidateBasePathsIncludingStatic("/app/static/logo.png"),
		"a /static segment must be retained as a base, not skipped")

	// Root is still always present and first.
	got := modkit.CandidateBasePathsIncludingStatic("/")
	assert.Equal(t, []string{""}, got)

	// Contrast: the default variant drops those same static prefixes.
	assert.Equal(t, []string{""}, modkit.CandidateBasePaths("/assets/js/app.js"))
}

func TestBasePathClaimKey(t *testing.T) {
	t.Parallel()

	// Distinct (host, base) pairs must never collide, including pairs that would
	// collide under naive string concatenation.
	a := modkit.BasePathClaimKey("host.com", "/api")
	b := modkit.BasePathClaimKey("host.com/api", "")
	assert.NotEqual(t, a, b, "NUL separator must prevent host/base boundary collisions")

	// Same pair is stable.
	assert.Equal(t, a, modkit.BasePathClaimKey("host.com", "/api"))
	// Different host or different base both change the key.
	assert.NotEqual(t, a, modkit.BasePathClaimKey("other.com", "/api"))
	assert.NotEqual(t, a, modkit.BasePathClaimKey("host.com", "/api/v1"))
}

// TestResemblesObservedPage covers the catch-all-shell guard: a probe body
// textually equal to the originally-observed page is a catch-all hit (drop),
// while a genuinely different exposed file is not. Nil/empty baselines fail open.
func TestResemblesObservedPage(t *testing.T) {
	t.Parallel()

	const shell = `<!DOCTYPE html><html><head><title>Portal</title></head><body>` +
		`<nav><a href="/login">Sign in</a><a href="/search">Search</a></nav>` +
		`<main>Welcome to the invoice portal. Please sign in to continue.</main></body></html>`

	// A captured baseline response equal to the shell → probe returning the shell
	// is the catch-all case and must be reported as resembling the observed page.
	rr := modtest.Response(modtest.Request(t, "http://example.com/"), "text/html", shell)
	assert.True(t, modkit.ResemblesObservedPage(rr, shell),
		"a probe body equal to the observed page is a catch-all shell")

	// A genuinely different exposed file (PHP source) is not the shell.
	assert.False(t, modkit.ResemblesObservedPage(rr, "<?php $databases['default'] = ['password' => 'secret'];"),
		"an exposed config/source file must not resemble the homepage shell")

	// Fail-open: no baseline response, or an empty observed body, returns false so
	// a module without a captured baseline never has a finding suppressed.
	assert.False(t, modkit.ResemblesObservedPage(modtest.Request(t, "http://example.com/"), shell),
		"no baseline response must fail open (false)")
	assert.False(t, modkit.ResemblesObservedPage(nil, shell), "nil ctx must fail open (false)")
}

func TestStripReflectedProbePath(t *testing.T) {
	t.Parallel()

	// The exact Grab false positive: the requested path is reflected into a
	// <form action>, so a generic "admin" marker matches our own request. After the
	// strip the reflected segment is gone and "admin" no longer appears.
	body := `<form action="/tai-khoan/dang-nhap/admin" method="post"><input type="password"></form>`
	stripped := modkit.StripReflectedProbePath(body, "/tai-khoan/dang-nhap/admin")
	assert.NotContains(t, stripped, "admin", "the reflected probe path must be removed")

	// The query-stripped prefix is also removed (a reflected action drops the query).
	got := modkit.StripReflectedProbePath(`see <a href="/_profiler/">here</a>`, "/_profiler/?panel=request")
	assert.NotContains(t, got, "_profiler", "the query-stripped path prefix must also be removed")

	// Endpoint content that doesn't echo the path is left intact: a real Spring
	// DevTools response mentioning "spring"/"restart" outside the path survives.
	real := `{"status":"restarted the spring context"}`
	assert.Equal(t, real, modkit.StripReflectedProbePath(real, "/.~~spring-boot!~/restart"),
		"content that does not contain the probe path is unchanged")

	// Fail-open on empty inputs.
	assert.Equal(t, "x", modkit.StripReflectedProbePath("x", ""))
	assert.Equal(t, "", modkit.StripReflectedProbePath("", "/admin"))
}

// TestDecoyFileBaseline_ExtensionScopedCatchAll verifies the decoy keeps the
// candidate's parent dir AND extension and surfaces a catch-all: a handler that
// serves the same body for every /orders/*.log returns that body for the decoy,
// so the caller can drop /orders/run.log as a false positive.
func TestDecoyFileBaseline_ExtensionScopedCatchAll(t *testing.T) {
	t.Parallel()
	const catchAll = "2026-06-12 12:00:00 service started\n2026-06-12 12:00:01 ready\n"
	var gotDecoyPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every *.log under /orders/ returns the same log-looking body.
		if strings.HasPrefix(r.URL.Path, "/orders/") && strings.HasSuffix(r.URL.Path, ".log") {
			if r.URL.Path != "/orders/run.log" {
				gotDecoyPath = r.URL.Path
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(catchAll))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	status, body, ok := modkit.DecoyFileBaseline(nil, rr, client, "/orders/run.log")
	require.True(t, ok, "decoy fetch must succeed")
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, modkit.BodiesSimilar(body, catchAll), "decoy body must match the catch-all body the candidate also returns")
	assert.True(t, strings.HasPrefix(gotDecoyPath, "/orders/"), "decoy must stay in the candidate's parent dir, got %q", gotDecoyPath)
	assert.True(t, strings.HasSuffix(gotDecoyPath, ".log"), "decoy must keep the .log extension, got %q", gotDecoyPath)
	assert.NotEqual(t, "/orders/run.log", gotDecoyPath, "decoy must be a different file than the candidate")
}

// TestDecoyFileBaseline_RealFile verifies that when only the candidate exists and
// its siblings 404, the decoy returns a non-200 — so the caller keeps the finding.
func TestDecoyFileBaseline_RealFile(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orders/.git/config" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	status, _, ok := modkit.DecoyFileBaseline(nil, rr, client, "/orders/.git/config")
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, status, "a genuine file whose siblings 404 must yield a non-200 decoy")
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

	assert.True(t, modkit.SiblingPathCatchAll(nil, rr, client, "/admin/instances", match),
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

	assert.False(t, modkit.SiblingPathCatchAll(nil, rr, client, "/admin/instances", match),
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

	assert.False(t, modkit.SiblingPathCatchAll(nil, rr, client, "/admin", match),
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
