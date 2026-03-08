package payload

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMergePathWithBase verifies path overlap merging at task execution time.
// NOTE: MergePathWithBase now returns FULL merged paths (not relative paths).
func TestMergePathWithBase(t *testing.T) {
	tests := []struct {
		name       string
		storedPath string
		currentDir string
		expected   string
	}{
		// Child paths: storedPath is under currentDir → return full storedPath
		{
			name:       "path under current dir",
			storedPath: "/admin/list/",
			currentDir: "/admin/",
			expected:   "/admin/list/", // Full path, not relative
		},
		{
			name:       "exact match",
			storedPath: "/admin/",
			currentDir: "/admin/",
			expected:   "",
		},
		{
			name:       "stored under root",
			storedPath: "/admin/sub/",
			currentDir: "/",
			expected:   "/admin/sub/", // Full path
		},
		{
			name:       "deep nested under current",
			storedPath: "/admin/api/v1/users/",
			currentDir: "/admin/api/",
			expected:   "/admin/api/v1/users/", // Full path
		},
		{
			name:       "partial overlap at root",
			storedPath: "/admin/",
			currentDir: "/",
			expected:   "/admin/", // Full path
		},
		{
			name:       "no leading slash stored",
			storedPath: "admin/list/",
			currentDir: "/admin/",
			expected:   "/admin/list/", // Full path
		},
		{
			name:       "no leading slash current",
			storedPath: "/admin/list/",
			currentDir: "admin/",
			expected:   "/admin/list/", // Full path
		},
		{
			name:       "no trailing slash current",
			storedPath: "/admin/list/",
			currentDir: "/admin",
			expected:   "/admin/list/", // Full path
		},

		// Suffix-prefix overlap - merge into full path
		{
			name:       "suffix-prefix overlap v1/admin",
			storedPath: "/v1/admin/user/list",
			currentDir: "/api/v1/admin/",
			expected:   "/api/v1/admin/user/list", // Suffix "v1/admin" matches prefix, merge
		},
		{
			name:       "suffix-prefix overlap api",
			storedPath: "/api/data/",
			currentDir: "/admin/api/",
			expected:   "/admin/api/data/", // Suffix "api" matches prefix, merge
		},
		{
			name:       "suffix-prefix overlap a/b/c",
			storedPath: "/a/b/c/d/e",
			currentDir: "/x/a/b/c/",
			expected:   "/x/a/b/c/d/e", // Suffix "a/b/c" matches prefix, merge
		},
		{
			name:       "suffix-prefix overlap admin/api",
			storedPath: "/admin/api/",
			currentDir: "/x/admin/api/",
			expected:   "/x/admin/api/", // Full overlap, return currentDir
		},

		// Edge cases: empty/root
		{
			name:       "empty storedPath",
			storedPath: "",
			currentDir: "/api/v1/",
			expected:   "",
		},
		{
			name:       "root storedPath",
			storedPath: "/",
			currentDir: "/api/v1/",
			expected:   "",
		},
		{
			name:       "empty currentDir",
			storedPath: "/api/v1/users/",
			currentDir: "",
			expected:   "/api/v1/users/", // Full path
		},
		{
			name:       "root currentDir",
			storedPath: "/api/v1/users/",
			currentDir: "/",
			expected:   "/api/v1/users/", // Full path
		},
		{
			name:       "both empty",
			storedPath: "",
			currentDir: "",
			expected:   "",
		},
		{
			name:       "both root",
			storedPath: "/",
			currentDir: "/",
			expected:   "",
		},

		// Parent relationship - must skip to prevent path duplication
		{
			name:       "storedPath is parent of currentDir",
			storedPath: "/admin/",
			currentDir: "/admin/config/",
			expected:   "",
		},
		{
			name:       "storedPath is parent multi-level",
			storedPath: "/site/hc/",
			currentDir: "/site/hc/static/js/",
			expected:   "",
		},
		{
			name:       "bug scenario from logs",
			storedPath: "/site/hc/",
			currentDir: "/site/hc/static/",
			expected:   "",
		},
		{
			name:       "parent without trailing slash",
			storedPath: "/admin",
			currentDir: "/admin/config/",
			expected:   "",
		},

		// Paths with common prefix - return storedPath as-is (same site structure)
		{
			name:       "common prefix api versions",
			storedPath: "/api/v2/",
			currentDir: "/api/v1/",
			expected:   "/api/v2/", // Share "api", return as-is
		},
		{
			name:       "common prefix - bug scenario Mod_Rewrite_Shop",
			storedPath: "/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/",
			currentDir: "/Mod_Rewrite_Shop/Details/web-camera-a4tech/",
			expected:   "/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/", // Share 2 segments, return as-is
		},
		{
			name:       "common prefix - nested sibling with subpath",
			storedPath: "/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/",
			currentDir: "/Mod_Rewrite_Shop/Details/color-printer/",
			expected:   "/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/", // Share 2 segments, return as-is
		},
		{
			name:       "common prefix different product dirs",
			storedPath: "/products/phones/",
			currentDir: "/products/tablets/",
			expected:   "/products/phones/", // Share "products", return as-is
		},

		// Unrelated paths - append to currentDir
		{
			name:       "no overlap different dirs",
			storedPath: "/api/v1/",
			currentDir: "/other/",
			expected:   "/other/api/v1/", // Appended to currentDir
		},
		{
			name:       "no overlap completely different",
			storedPath: "/users/list/",
			currentDir: "/admin/config/",
			expected:   "/admin/config/users/list/", // Appended to currentDir
		},

		// Double slash normalization
		{
			name:       "double slash in storedPath child of currentDir",
			storedPath: "//api//v1//users/",
			currentDir: "/api/",
			expected:   "/api/v1/users/", // Full path, normalized
		},
		{
			name:       "double slash in storedPath unrelated",
			storedPath: "//double//slash//path/",
			currentDir: "/other/",
			expected:   "/other/double/slash/path/", // Appended to currentDir
		},
		{
			name:       "double slash in currentDir",
			storedPath: "/admin/list/",
			currentDir: "//admin//",
			expected:   "/admin/list/", // Full path
		},

		// Absolute URL handling - extract path only
		{
			name:       "absolute URL as storedPath - unrelated",
			storedPath: "https://capital.com/risk-disclosure-policy",
			currentDir: "/admin/",
			expected:   "/admin/risk-disclosure-policy", // Appended to currentDir
		},
		{
			name:       "absolute URL with path matching currentDir",
			storedPath: "https://example.com/admin/config/",
			currentDir: "/admin/",
			expected:   "/admin/config/", // Full path (child)
		},
		{
			name:       "absolute URL root only",
			storedPath: "https://example.com/",
			currentDir: "/admin/",
			expected:   "", // Root path skipped
		},
		{
			name:       "absolute URL no path",
			storedPath: "https://example.com",
			currentDir: "/admin/",
			expected:   "", // No path, skipped
		},
		{
			name:       "embedded URL in path (malformed data)",
			storedPath: "/L0/https://capital.com/risk-disclosure-policy",
			currentDir: "/admin/",
			expected:   "/admin/risk-disclosure-policy", // Appended
		},
		{
			name:       "protocol-relative URL",
			storedPath: "//cdn.example.com/assets/app.js",
			currentDir: "/admin/",
			expected:   "/admin/assets/app.js", // Appended (path extracted)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergePathWithBase(tt.storedPath, tt.currentDir)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractPathFromAbsoluteURL tests the URL sanitization function.
func TestExtractPathFromAbsoluteURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Regular paths - unchanged
		{"regular path", "/api/v1/users", "/api/v1/users"},
		{"root path", "/", "/"},
		{"empty path", "", ""},
		{"relative path", "api/users", "api/users"},

		// Absolute URLs - extract path
		{"https URL", "https://example.com/api/v1", "/api/v1"},
		{"http URL", "http://example.com/path", "/path"},
		{"https URL with query", "https://api.example.com/search?q=test", "/search?q=test"},
		{"https URL root only", "https://example.com/", "/"},
		{"https URL no path", "https://example.com", "/"},
		{"ws URL", "ws://example.com/socket", "/socket"},
		{"wss URL", "wss://example.com/secure", "/secure"},
		{"ftp URL", "ftp://files.example.com/file.zip", "/file.zip"},

		// Embedded URLs in path (malformed data from previous bugs)
		{"embedded https URL", "/L0/https://capital.com/risk", "/risk"},
		{"embedded http URL", "/prefix/http://example.com/api/v1", "/api/v1"},
		{"double embedded URL", "/L0/https://a.com/L1/https://b.com/final", "/final"},

		// Protocol-relative URLs
		{"protocol-relative", "//cdn.example.com/script.js", "/script.js"},
		{"protocol-relative no path", "//example.com", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathFromAbsoluteURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// BenchmarkMergePathWithBase measures path merging performance.
func BenchmarkMergePathWithBase(b *testing.B) {
	testCases := []struct {
		stored  string
		current string
	}{
		{"/admin/list/", "/admin/"},
		{"/api/v1/", "/other/"},
		{"/admin/", "/admin/"},
		{"/admin/sub/", "/"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc := testCases[i%len(testCases)]
		MergePathWithBase(tc.stored, tc.current)
	}
}

func TestCountCommonPrefixSegments(t *testing.T) {
	tests := []struct {
		name       string
		storedPath string
		currentDir string
		expected   int
	}{
		{"share 2 segments", "/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/", "/Mod_Rewrite_Shop/Details/color-printer/", 2},
		{"share 1 segment", "/api/v1/", "/api/v2/", 1},
		{"share all segments", "/api/v1/", "/api/v1/users/", 2},
		{"no common prefix", "/admin/", "/users/", 0},
		{"completely different", "/a/", "/b/", 0},
		{"empty paths", "", "/api/", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countCommonPrefixSegments(tt.storedPath, tt.currentDir)
			assert.Equal(t, tt.expected, result)
		})
	}
}
