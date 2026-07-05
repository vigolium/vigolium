package dedup

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskSet_BasicOperations(t *testing.T) {
	tmpDir := t.TempDir()

	ds, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "test",
		Cleanup:   true,
	})
	require.NoError(t, err)
	defer func() { _ = ds.Close() }()

	// First time: should not be seen
	assert.False(t, ds.IsSeen("key1"))
	assert.Equal(t, int64(1), ds.Size())
	assert.Equal(t, uint64(0), ds.Hits())

	// Second time: should be seen
	assert.True(t, ds.IsSeen("key1"))
	assert.Equal(t, int64(1), ds.Size())
	assert.Equal(t, uint64(1), ds.Hits())

	// New key
	assert.False(t, ds.IsSeen("key2"))
	assert.Equal(t, int64(2), ds.Size())

	// Contains check (read-only)
	assert.True(t, ds.Contains("key1"))
	assert.True(t, ds.Contains("key2"))
	assert.False(t, ds.Contains("key3"))

	// Contains should not add key
	assert.Equal(t, int64(2), ds.Size())
}

func TestDiskSet_Cleanup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cleanup")

	ds, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "cleanup",
		Cleanup:   true,
	})
	require.NoError(t, err)

	ds.IsSeen("key1")
	_ = ds.Close()

	// Directory should be removed
	_, err = os.Stat(dbPath)
	assert.True(t, os.IsNotExist(err))
}

func TestDiskSet_NoCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nocleanup")

	ds, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "nocleanup",
		Cleanup:   false,
	})
	require.NoError(t, err)

	ds.IsSeen("key1")
	_ = ds.Close()

	// Directory should exist
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)
}

func TestDiskSet_Persistence(t *testing.T) {
	tmpDir := t.TempDir()

	// First session
	ds1, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "persist",
		Cleanup:   false,
	})
	require.NoError(t, err)

	ds1.IsSeen("key1")
	ds1.IsSeen("key2")
	_ = ds1.Close()

	// Second session - data should persist
	ds2, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "persist",
		Cleanup:   true,
	})
	require.NoError(t, err)
	defer func() { _ = ds2.Close() }()

	// Keys should be found
	assert.True(t, ds2.Contains("key1"))
	assert.True(t, ds2.Contains("key2"))
	assert.False(t, ds2.Contains("key3"))
}

func TestDiskSet_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()

	ds, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "concurrent",
		Cleanup:   true,
	})
	require.NoError(t, err)
	defer func() { _ = ds.Close() }()

	const numGoroutines = 100
	const keysPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < keysPerGoroutine; j++ {
				key := "key" + string(rune('A'+id%26)) + string(rune('0'+j%10))
				ds.IsSeen(key)
			}
		}(i)
	}

	wg.Wait()

	// Should have some entries (exact count depends on key collisions)
	assert.Greater(t, ds.Size(), int64(0))
}

func TestDiskSet_MultipleNamespaces(t *testing.T) {
	tmpDir := t.TempDir()

	ds1, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "ns1",
		Cleanup:   true,
	})
	require.NoError(t, err)
	defer func() { _ = ds1.Close() }()

	ds2, err := NewDiskSet(&Config{
		BasePath:  tmpDir,
		Namespace: "ns2",
		Cleanup:   true,
	})
	require.NoError(t, err)
	defer func() { _ = ds2.Close() }()

	// Same key in different namespaces should be independent
	ds1.IsSeen("shared-key")
	assert.True(t, ds1.IsSeen("shared-key"))
	assert.False(t, ds2.IsSeen("shared-key")) // Not seen in ns2
	assert.True(t, ds2.IsSeen("shared-key"))  // Now seen in ns2
}

func TestHashRequest(t *testing.T) {
	// Hash of empty string (FNV-1a 64-bit in hex)
	emptyBodyHash := "cbf29ce484222325"

	tests := []struct {
		method string
		url    string
		body   string
		want   string
	}{
		{"GET", "http://example.com/path", "", "GET|http://example.com/path|" + emptyBodyHash},
		{"POST", "https://example.com/api", "", "POST|https://example.com/api|" + emptyBodyHash},
		{"POST", "https://example.com/api", "name=test", "POST|https://example.com/api|" + hashFNV64aHex("name=test")},
	}

	for _, tt := range tests {
		got := HashRequest(tt.method, tt.url, tt.body)
		assert.Equal(t, tt.want, got)
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Default port removal
		{"http://example.com:80/path", "http://example.com/path"},
		{"https://example.com:443/path", "https://example.com/path"},

		// Non-default ports preserved
		{"http://example.com:8080/path", "http://example.com:8080/path"},
		{"https://example.com:8443/path", "https://example.com:8443/path"},

		// Case normalization
		{"HTTP://EXAMPLE.COM/Path", "http://example.com/Path"},
		{"HTTPS://Example.Com/PATH", "https://example.com/PATH"},

		// Path preservation
		{"http://example.com/path/", "http://example.com/path/"},
		{"http://example.com/path", "http://example.com/path"},

		// Query params with values (sorted by key) - non-static files
		{"http://example.com/path?a=1&b=2", "http://example.com/path?a=1&b=2"},
		{"http://example.com/path?b=2&a=1", "http://example.com/path?a=1&b=2"},
		{"http://example.com/path?id=123", "http://example.com/path?id=123"},

		// Different param values = different normalized URLs
		{"http://example.com/api?id=1", "http://example.com/api?id=1"},
		{"http://example.com/api?id=2", "http://example.com/api?id=2"},

		// Invalid URL (no scheme) - path still gets normalized
		{"not-a-valid-url", "/not-a-valid-url"},

		// Path normalization - double slashes
		{"http://example.com//api//v1", "http://example.com/api/v1"},

		// Path normalization - dot segments
		{"http://example.com/./api/./v1", "http://example.com/api/v1"},
		{"http://example.com/api/../v1", "http://example.com/v1"},

		// Repeating segment collapse
		{"https://example.com/admin/services/admin/services/", "https://example.com/admin/services/"},
		{"http://example.com/a/b/a/b/", "http://example.com/a/b/"},
		{"http://example.com/api/v1/api/v1/api/v1/", "http://example.com/api/v1/"},

		// No repeating collapse for short paths
		{"http://example.com/a/b/", "http://example.com/a/b/"},

		// No collapse for incomplete repetitions
		{"http://example.com/a/b/a/b/c/", "http://example.com/a/b/a/b/c/"},

		// Query params with repeating path
		{"http://example.com/a/b/a/b/?key=val", "http://example.com/a/b/?key=val"},

		// Multiple params sorted by key
		{"https://example.com/api?id=1&name=foo", "https://example.com/api?id=1&name=foo"},
		{"https://example.com/api?name=foo&id=1", "https://example.com/api?id=1&name=foo"},

		// Different param sets should normalize differently
		{"https://example.com/api?id=1", "https://example.com/api?id=1"},
		{"https://example.com/api?id=1&name=foo", "https://example.com/api?id=1&name=foo"},

		// Empty query string
		{"https://example.com/api?", "https://example.com/api"},

		// Fragment stripped
		{"https://example.com/api?id=1#section", "https://example.com/api?id=1"},

		// Static files - query params stripped entirely
		{"http://example.com/app.js?v=1.2.3", "http://example.com/app.js"},
		{"http://example.com/style.css?hash=abc123", "http://example.com/style.css"},
		{"http://example.com/image.png?size=100", "http://example.com/image.png"},
		{"http://example.com/font.woff2?v=1", "http://example.com/font.woff2"},
		{"http://example.com/video.mp4?token=xyz", "http://example.com/video.mp4"},
		{"http://example.com/bundle.js.map?v=1", "http://example.com/bundle.js.map"},
		{"http://example.com/module.mjs?cache=bust", "http://example.com/module.mjs"},
		{"http://example.com/deep/path/to/script.js?v=2", "http://example.com/deep/path/to/script.js"},

		// Static files without query params (unchanged)
		{"http://example.com/app.js", "http://example.com/app.js"},
		{"http://example.com/style.css", "http://example.com/style.css"},

		// Path-normalization bypass (percent-ENCODED markers): the wire form is
		// kept verbatim so a fuzz wordlist under a "/%23/../FUZZ" template does NOT
		// collapse every distinct word to one key, and a bypass stays distinct from
		// its resolved target. A decoded "#" is a fragment delimiter, so the
		// discovery pipeline emits the escaped "%23" form (see extractPathFromURL).
		{"https://example.com/%23/../metrics", "https://example.com/%23/../metrics"},
		{"https://example.com/%23/../admin.js", "https://example.com/%23/../admin.js"},
		{"https://example.com/%23/../metrics/", "https://example.com/%23/../metrics/"},
		{"https://example.com/%2e%2e/metrics", "https://example.com/%2e%2e/metrics"},
		{"https://example.com/..%2fmetrics", "https://example.com/..%2fmetrics"},
		// A genuine (decoded, unencoded) fragment is still stripped — "#frag" is not
		// part of the request and must dedupe with the fragment-less URL.
		{"https://example.com/page#frag", "https://example.com/page"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeURL(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNormalizeURL_BypassPathsStayDistinct is a regression test for a FUZZ template
// using a path-normalization bypass ("/%23/../FUZZ"). Before the fix, NormalizeURL
// parsed the decoded URL — where "#" is a fragment delimiter — so every word
// collapsed to the root key and only the first fuzz word was ever probed; and even
// the escaped form was path.Clean-collapsed onto its resolved target. This asserts
// each word now hashes distinctly and a bypass is distinct from its clean target.
func TestNormalizeURL_BypassPathsStayDistinct(t *testing.T) {
	key := func(u string) string { return HashRequest("GET", u, "") }

	// Each fuzz word must produce a UNIQUE request key (no collapse to root).
	words := []string{"metrics", "admin.js", "actuator", "health", "robots.txt"}
	seen := make(map[string]string, len(words))
	for _, w := range words {
		u := "https://h.com/%23/../" + w
		k := key(u)
		if prev, dup := seen[k]; dup {
			t.Fatalf("bypass fuzz words %q and %q collapsed to the same dedup key %q", prev, u, k)
		}
		seen[k] = u
	}

	// A bypass request is distinct from its resolved target (the origin may gate
	// them differently — the whole reason for sending it).
	if key("https://h.com/%23/../metrics") == key("https://h.com/metrics") {
		t.Fatal("bypass /%23/../metrics must not dedupe against the clean /metrics")
	}
	// Other encodings of the same technique are also preserved.
	if key("https://h.com/%2e%2e/metrics") == key("https://h.com/metrics") {
		t.Fatal("encoded-dot bypass must stay distinct from the clean target")
	}

	// Regression guard: an ordinary (unencoded) relative path is still canonicalized
	// so genuine duplicates keep deduping.
	if key("https://h.com/api/../v1") != key("https://h.com/v1") {
		t.Fatal("plain relative /api/../v1 must still normalize to /v1")
	}
}

func TestIsStaticFile(t *testing.T) {
	tests := []struct {
		path   string
		static bool
	}{
		// Scripts
		{"/app.js", true},
		{"/module.mjs", true},
		{"/common.cjs", true},
		// Stylesheets
		{"/style.css", true},
		// Images
		{"/image.png", true},
		{"/photo.jpg", true},
		{"/icon.svg", true},
		{"/favicon.ico", true},
		// Fonts
		{"/font.woff2", true},
		{"/font.ttf", true},
		// Video
		{"/video.mp4", true},
		// Audio
		{"/audio.mp3", true},
		// Maps
		{"/bundle.js.map", true},
		// Non-static
		{"/api/users", false},
		{"/index.html", false},
		{"/data.json", false},
		{"/script.php", false},
		{"/page.aspx", false},
		// Deep paths
		{"/deep/path/to/bundle.js", true},
		{"/assets/fonts/roboto.woff2", true},
		// Case insensitive
		{"/APP.JS", true},
		{"/Style.CSS", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.static, isStaticFile(tt.path))
		})
	}
}

func TestNormalizeQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string][]string
		expected string
	}{
		{"empty", map[string][]string{}, ""},
		{"single param", map[string][]string{"id": {"1"}}, "id=1"},
		{"multiple params sorted", map[string][]string{"b": {"2"}, "a": {"1"}}, "a=1&b=2"},
		{"multiple values same key", map[string][]string{"tags": {"c", "a", "b"}}, "tags=a&tags=b&tags=c"},
		{"mixed", map[string][]string{"id": {"1"}, "tags": {"b", "a"}}, "id=1&tags=a&tags=b"},
		{"empty value", map[string][]string{"key": {""}}, "key="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeQueryParams(tt.params)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCollapseRepeatingSegments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Should collapse
		{"2x repeat", "/a/b/a/b/", "/a/b/"},
		{"3x repeat", "/admin/services/public/admin/services/public/admin/services/public/", "/admin/services/public/"},
		{"2-segment 3x", "/api/v1/api/v1/api/v1/", "/api/v1/"},
		{"no trailing slash", "/a/b/a/b", "/a/b"},
		{"4-segment 2x", "/one/two/three/four/one/two/three/four/", "/one/two/three/four/"},

		// Should NOT collapse
		{"no repeat", "/a/b/c/d/", "/a/b/c/d/"},
		{"single segment repeat", "/v1/v1/", "/v1/v1/"},
		{"incomplete repeat", "/a/b/a/b/c/", "/a/b/a/b/c/"},
		{"short path", "/a/b/", "/a/b/"},
		{"3 segments no repeat", "/a/b/c/", "/a/b/c/"},

		// Edge cases
		{"empty", "", ""},
		{"root", "/", "/"},
		{"single segment", "/api/", "/api/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collapseRepeatingSegments(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"simple path", "/api/v1", "/api/v1"},
		{"trailing slash", "/api/v1/", "/api/v1/"},
		{"double slash", "//api//v1", "/api/v1"},
		{"dot segments", "/./api/./v1", "/api/v1"},
		{"parent segments", "/api/../v1", "/v1"},
		{"complex", "//api/./test/../v1//", "/api/v1/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func BenchmarkDiskSet_IsSeen_Hit(b *testing.B) {
	tmpDir := b.TempDir()

	ds, _ := NewDiskSet(&Config{
		BasePath: tmpDir,
		Cleanup:  true,
	})
	defer func() { _ = ds.Close() }()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		ds.IsSeen("preload-" + string(rune(i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ds.IsSeen("preload-" + string(rune(i%1000)))
	}
}

func BenchmarkDiskSet_IsSeen_Miss(b *testing.B) {
	tmpDir := b.TempDir()

	ds, _ := NewDiskSet(&Config{
		BasePath: tmpDir,
		Cleanup:  true,
	})
	defer func() { _ = ds.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ds.IsSeen("unique-" + string(rune(i)))
	}
}
