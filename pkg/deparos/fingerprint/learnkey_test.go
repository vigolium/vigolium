package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathRecorder is a 404 server that records every requested wire path.
func pathRecorder(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<html><body>nope</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

// MISS-3: a directory key learns from children of the directory with the key's
// extension on the wire — /api/<rand>.php — never /<rand>api/.
func TestLearnAndCacheProbesChildrenWithExtension(t *testing.T) {
	srv, paths := pathRecorder(t, nil)
	l := NewLearner(srv.Client(), nil)
	l.SetDelay(0)
	c := NewCache(l)
	base, err := url.Parse(srv.URL + "/api/")
	require.NoError(t, err)

	key := CacheKey{Host: base.Host, Path: "/api/", Extension: ".php"}
	_, err = c.LearnAndCache(context.Background(), key, base)
	require.NoError(t, err)

	got := paths()
	require.Len(t, got, 4)
	for _, p := range got {
		assert.True(t, strings.HasPrefix(p, "/api/"), "probe %q must be a child of /api/", p)
		assert.True(t, strings.HasSuffix(p, ".php"), "probe %q must carry .php on the wire", p)
		assert.NotContains(t, strings.TrimPrefix(p, "/api/"), "/", "probe %q must be a direct child", p)
	}
}

// The "" key covers directory-form hits too: three file-form children plus one
// "rand/" probe, and no extra probes when both forms answer the same.
func TestLearnKeyEmptyExtensionAddsDirectoryForm(t *testing.T) {
	srv, paths := pathRecorder(t, nil)
	l := NewLearner(srv.Client(), nil)
	l.SetDelay(0)
	base, err := url.Parse(srv.URL + "/api/")
	require.NoError(t, err)

	sigs, err := l.LearnKey(context.Background(), CacheKey{Host: base.Host, Path: "/api/"}, base)
	require.NoError(t, err)
	assert.Len(t, sigs, 1)

	got := paths()
	require.Len(t, got, 4)
	dirForm := 0
	for _, p := range got {
		require.True(t, strings.HasPrefix(p, "/api/"), "probe %q must be a child of /api/", p)
		if strings.HasSuffix(p, "/") {
			dirForm++
		}
	}
	assert.Equal(t, 1, dirForm, "exactly one directory-form probe: %v", got)
}

// When the directory form answers differently (a 301 to the slash form, say),
// a second signature is learned for the same key so directory hits are judged
// against their own soft-404 shape.
func TestLearnKeyLearnsSeparateDirectorySignature(t *testing.T) {
	srv, paths := pathRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"forbidden"}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<html><body>nope</body></html>")
	})
	l := NewLearner(srv.Client(), nil)
	l.SetDelay(0)
	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)

	sigs, err := l.LearnKey(context.Background(), CacheKey{Host: base.Host, Path: "/"}, base)
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	assert.Len(t, paths(), 6)
}

// PreWarm puts each root extension on the wire and learns only "" for the
// other common directories: ~48 requests instead of ~160.
func TestPreWarmRequestBudget(t *testing.T) {
	srv, paths := pathRecorder(t, nil)
	l := NewLearner(srv.Client(), nil)
	l.SetDelay(0)
	c := NewCache(l)
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)

	c.PreWarm(context.Background(), base, 4)

	got := paths()
	assert.LessOrEqual(t, len(got), 48, "pre-warm request count")
	sawExt := map[string]bool{}
	for _, p := range got {
		for _, ext := range []string{".php", ".jsp", ".json"} {
			if strings.HasSuffix(p, ext) && strings.Count(p, "/") == 1 {
				sawExt[ext] = true
			}
		}
	}
	assert.Len(t, sawExt, 3, "root extension keys must send their extension: %v", got)
	_, ok := c.Get(CacheKey{Host: base.Host, Path: "/api/", Extension: ""})
	assert.True(t, ok, "/api/ baseline learned")
	_, ok = c.Get(CacheKey{Host: base.Host, Path: "/api/", Extension: ".php"})
	assert.False(t, ok, "non-root dirs learn only the \"\" key")
}
