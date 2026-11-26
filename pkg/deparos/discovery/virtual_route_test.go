package discovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// wordpressLikeServer answers like a WordPress site's rewrite rules: feed/,
// rss/ and the canonical-redirecting sample-page/ work under ANY parent path,
// while real directories exist at one place only.
func wordpressLikeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/realdir/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>real directory index</html>"))
		case p == "/wp-includes/":
			w.WriteHeader(http.StatusForbidden)
		case p == "/wp-includes/js/":
			w.WriteHeader(http.StatusForbidden)
		case p == "/members/":
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasSuffix(p, "/secure/"):
			// Forbidden under any parent, yet a concrete file inside may be
			// served: never a reason to stop exploring.
			w.WriteHeader(http.StatusForbidden)
		case p == "/sample-page/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>sample page</html>"))
		case strings.HasSuffix(p, "/sample-page/"):
			http.Redirect(w, r, "/sample-page/", http.StatusMovedPermanently)
		case strings.HasSuffix(p, "/feed/atom/"):
			w.Header().Set("Content-Type", "application/atom+xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<feed>" + p + "</feed>"))
		case strings.HasSuffix(p, "/atom/"):
			http.Redirect(w, r, strings.TrimSuffix(p, "atom/")+"feed/atom/", http.StatusMovedPermanently)
		case strings.HasSuffix(p, "/feed/"):
			w.Header().Set("Content-Type", "application/rss+xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<rss>" + p + "</rss>"))
		case strings.HasSuffix(p, "/rss/"):
			http.Redirect(w, r, strings.TrimSuffix(p, "rss/")+"feed/", http.StatusMovedPermanently)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
		}
	}))
}

// A directory the application answers the same way under any parent (a rewrite
// rule such as WordPress's /<anything>/feed/, including chains like
// /<anything>/feed/atom/ whose last segment alone does not vary that way) is a
// virtual route, not a directory: brute-forcing inside it and recursing again
// multiplied a
// 1-minute discovery into 30 minutes and 170k requests. Directories that only
// exist where they were found — including 401/403 ones, whose contents may
// still be served — keep being explored.
func TestOnDirectoryDiscovered_SkipsPathIndependentVirtualRoutes(t *testing.T) {
	server := wordpressLikeServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Filenames.UseObservedNames = true
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	engine.AddObservedName("index")
	engine.AddObservedName("config")

	recursed := func(dir string) bool {
		before := engine.taskQueue.Size()
		require.NoError(t, engine.OnDirectoryDiscovered(server.URL+dir, 0))
		return engine.taskQueue.Size() > before
	}

	for _, dir := range []string{"/feed/", "/comments/feed/", "/comments/rss/", "/comments/sample-page/", "/feed/atom/", "/2026/feed/atom/"} {
		require.False(t, recursed(dir), "%s answers the same under any parent; it must not be recursed into", dir)
	}
	for _, dir := range []string{"/realdir/", "/wp-includes/", "/wp-includes/js/", "/members/", "/secure/", "/sample-page/"} {
		require.True(t, recursed(dir), "%s must still be recursed into", dir)
	}
}
