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

	// slug-reflection: the anchor is only the probe's own last path segment echoed
	// into a content route (/topic/<slug> -> "<slug> …"). A random sibling
	// reflects a DIFFERENT slug, so the sibling catch-all check can't see it — the
	// PathSegmentReflected control must. This is the /topic/filament FP: the anchor
	// "filament" equals the segment, and /topic/<canary> reflects the canary too.
	t.Run("slug-reflecting content route suppressed", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slug, ok := strings.CutPrefix(r.URL.Path, "/topic/"); ok && slug != "" {
				w.WriteHeader(http.StatusOK)
				// Reflect the requested slug — the anchor word for the real probe,
				// the canary word for the control probe.
				_, _ = w.Write([]byte("<h1>Explore " + slug + " Lenses</h1>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		// Anchor "filament" is a substring of the /topic/filament segment, so the
		// reflection control fires; the sibling catch-all check alone would miss it.
		reflMarkers := [][]string{{"filament"}}
		body := "<h1>Explore filament Lenses</h1>"

		matched, ok := modkit.MatchAndConfirmSibling(rr, client, "/topic/filament", body, reflMarkers)
		assert.False(t, ok, "a slug-reflecting content route whose anchor is the reflected path segment must be suppressed")
		assert.Nil(t, matched)
	})

	// A real endpoint whose anchor happens to equal its path segment (siblings 404,
	// no slug reflection) must still confirm — the control probe 404s, so the
	// reflection guard is a no-op and the finding stands.
	t.Run("real endpoint with segment-equal anchor confirms", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/graphql" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"graphql":{"__schema":{}}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		// Anchor "graphql" is a substring of the /api/graphql segment, so the
		// control probe runs — but /api/<canary> 404s (not reflected), so confirm.
		gqlMarkers := [][]string{{"graphql"}, {"__schema"}}
		body := `{"graphql":{"__schema":{}}}`

		matched, ok := modkit.MatchAndConfirmSibling(rr, client, "/api/graphql", body, gqlMarkers)
		require.True(t, ok, "a real endpoint whose siblings 404 must confirm even when its anchor equals its path segment")
		assert.Equal(t, []string{"graphql", "__schema"}, matched)
	})
}

// TestPathSegmentReflected exercises the slug-reflection control directly: it
// returns true only when a sibling carrying a distinctive canary slug is echoed
// into a 200 body, and is a no-op (false) for root-level paths.
func TestPathSegmentReflected(t *testing.T) {
	t.Parallel()

	t.Run("reflecting content route", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slug, ok := strings.CutPrefix(r.URL.Path, "/topic/"); ok && slug != "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<h1>" + slug + " Lenses</h1>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		assert.True(t, modkit.PathSegmentReflected(rr, client, "/topic/filament"),
			"a route echoing an arbitrary slug into a 200 body must be detected as reflecting")
	})

	t.Run("non-reflecting endpoint (siblings 404)", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/topic/filament" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<h1>real</h1>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		assert.False(t, modkit.PathSegmentReflected(rr, client, "/topic/filament"),
			"an endpoint whose random siblings 404 is not a reflecting route")
	})

	t.Run("root-level path is a no-op", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Even a root catch-all that echoes the path must not count: root probes
			// are covered by the caller's root soft-404 fingerprint.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<h1>" + r.URL.Path + "</h1>"))
		}))
		defer srv.Close()

		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		assert.False(t, modkit.PathSegmentReflected(rr, client, "/redoc"),
			"a root-level probe path must be a no-op (no control probe, never dropped)")
	})
}

// TestSlugReflectionFP exercises the flat-marker convenience guard: it drops a
// finding only when EVERY matched marker is the reflected path segment AND the
// route echoes an arbitrary canary slug; any structural (non-segment) marker or a
// non-reflecting route keeps the finding.
func TestSlugReflectionFP(t *testing.T) {
	t.Parallel()
	reflecting := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slug, ok := strings.CutPrefix(r.URL.Path, "/topic/"); ok && slug != "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<h1>Posts about " + slug + "</h1>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	}

	t.Run("all matched markers are the reflected segment -> drop", func(t *testing.T) {
		t.Parallel()
		srv := reflecting()
		defer srv.Close()
		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		assert.True(t, modkit.SlugReflectionFP(rr, client, "/topic/healthchecks-ui", []string{"healthchecks-ui"}),
			"a match resting only on the reflected path slug must be dropped")
	})

	t.Run("a structural marker also matched -> keep", func(t *testing.T) {
		t.Parallel()
		srv := reflecting()
		defer srv.Close()
		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		// "AspNetCore.HealthChecks.UI" is not a substring of the "healthchecks-ui"
		// segment, so the finding has independent support and no control probe runs.
		assert.False(t, modkit.SlugReflectionFP(rr, client, "/topic/healthchecks-ui",
			[]string{"healthchecks-ui", "AspNetCore.HealthChecks.UI"}),
			"a finding backed by a non-segment structural marker must be kept")
	})

	t.Run("reflected segment but route does not reflect (siblings 404) -> keep", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/topic/healthchecks-ui" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("real dashboard"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/")
		assert.False(t, modkit.SlugReflectionFP(rr, client, "/topic/healthchecks-ui", []string{"healthchecks-ui"}),
			"a real endpoint whose siblings 404 must be kept even when the marker equals the segment")
	})

	t.Run("empty markers -> keep (no probe)", func(t *testing.T) {
		t.Parallel()
		client := modtest.Requester(t)
		rr := modtest.Request(t, "http://example.invalid/")
		assert.False(t, modkit.SlugReflectionFP(rr, client, "/topic/x", nil))
	})
}
