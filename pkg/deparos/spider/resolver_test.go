package spider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLResolver_Resolve(t *testing.T) {
	resolver := NewURLResolver()

	tests := []struct {
		name        string
		base        string
		relative    string
		expected    string
		expectError bool
	}{
		{
			name:     "absolute URL",
			base:     "https://example.com/api",
			relative: "https://other.com/path",
			expected: "https://other.com/path",
		},
		{
			name:     "protocol-relative URL",
			base:     "https://example.com/api",
			relative: "//other.com/path",
			expected: "https://other.com/path",
		},
		{
			name:     "absolute path",
			base:     "https://example.com/api/v1",
			relative: "/admin",
			expected: "https://example.com/admin",
		},
		{
			name:     "relative path - sibling",
			base:     "https://example.com/api/v1/users",
			relative: "posts",
			expected: "https://example.com/api/v1/posts",
		},
		{
			name:     "relative path - parent",
			base:     "https://example.com/api/v1/users",
			relative: "../admin",
			expected: "https://example.com/api/admin",
		},
		{
			name:     "relative path - current dir",
			base:     "https://example.com/api/v1/",
			relative: "./users",
			expected: "https://example.com/api/v1/users",
		},
		{
			name:     "query string only - preserved",
			base:     "https://example.com/api/users",
			relative: "?page=2",
			expected: "https://example.com/api/users?page=2",
		},
		{
			name:     "fragment only",
			base:     "https://example.com/api/users",
			relative: "#section",
			expected: "https://example.com/api/users", // Fragment omitted
		},
		{
			name:        "empty relative URL",
			base:        "https://example.com/api",
			relative:    "",
			expectError: true,
		},
		{
			name:     "whitespace trimming",
			base:     "https://example.com/api",
			relative: "  /admin  ",
			expected: "https://example.com/admin",
		},
		{
			name:     "normalize double slashes",
			base:     "https://example.com",
			relative: "/api//v1///users",
			expected: "https://example.com/api/v1/users",
		},
		{
			name:     "preserve trailing slash",
			base:     "https://example.com",
			relative: "/api/v1/",
			expected: "https://example.com/api/v1/",
		},
		{
			name:        "javascript: protocol (invalid)",
			base:        "https://example.com",
			relative:    "javascript:alert(1)",
			expected:    "javascript:///", // url.Parse normalizes javascript: URLs oddly, but that's OK - scope checker will filter
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, err := url.Parse(tt.base)
			require.NoError(t, err)

			resolved, err := resolver.Resolve(base, tt.relative)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, resolved.String())
		})
	}
}

func TestURLResolver_Normalize(t *testing.T) {
	resolver := NewURLResolver()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase scheme and host",
			input:    "HTTPS://EXAMPLE.COM/Path",
			expected: "https://example.com/Path",
		},
		{
			name:     "normalize path",
			input:    "https://example.com//api//v1/",
			expected: "https://example.com/api/v1/",
		},
		{
			name:     "preserve query parameters",
			input:    "https://example.com/api?z=1&a=2&m=3",
			expected: "https://example.com/api?z=1&a=2&m=3",
		},
		{
			name:     "strip fragment",
			input:    "https://example.com/api#section",
			expected: "https://example.com/api",
		},
		{
			name:     "preserve trailing slash",
			input:    "https://example.com/api/",
			expected: "https://example.com/api/",
		},
		{
			name:     "add leading slash to empty path",
			input:    "https://example.com",
			expected: "https://example.com/",
		},
		{
			name:     "resolve . and ..",
			input:    "https://example.com/api/./v1/../v2",
			expected: "https://example.com/api/v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)
			require.NoError(t, err)

			normalized := resolver.Normalize(u)
			assert.Equal(t, tt.expected, normalized)
		})
	}
}

func TestURLResolver_NormalizePath(t *testing.T) {
	resolver := NewURLResolver()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty path",
			input:    "",
			expected: "/",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "/",
		},
		{
			name:     "simple path",
			input:    "/api/users",
			expected: "/api/users",
		},
		{
			name:     "double slashes",
			input:    "//api//users",
			expected: "/api/users",
		},
		{
			name:     "trailing slash preserved",
			input:    "/api/users/",
			expected: "/api/users/",
		},
		{
			name:     "current directory",
			input:    "/api/./users",
			expected: "/api/users",
		},
		{
			name:     "parent directory",
			input:    "/api/v1/../users",
			expected: "/api/users",
		},
		{
			name:     "multiple parent directories",
			input:    "/api/v1/v2/../../users",
			expected: "/api/users",
		},
		{
			name:     "parent beyond root",
			input:    "/../api",
			expected: "/api",
		},
		{
			name:     "no leading slash",
			input:    "api/users",
			expected: "/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := resolver.normalizePath(tt.input)
			assert.Equal(t, tt.expected, normalized)
		})
	}
}

func TestURLResolver_NilHandling(t *testing.T) {
	resolver := NewURLResolver()

	t.Run("nil base URL", func(t *testing.T) {
		_, err := resolver.Resolve(nil, "/path")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "base URL is nil")
	})

	t.Run("nil URL in normalize", func(t *testing.T) {
		result := resolver.Normalize(nil)
		assert.Equal(t, "", result)
	})
}

func TestURLResolver_SanitizesGarbageChars(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		{"backslash escaped path", `\/trading\/`, "/trading/"},
		{"double backslash", `\\trading\\`, "/trading"},
		{"url encoded backslash", "%5C/path%5C/", "/path/"},
		{"url encoded backslash lowercase", "%5c/path%5c/", "/path/"},
		{"url encoded quote", "%22/api%22", "/api"},
		{"mixed garbage backslash quote", `\"\/path\/file\"`, "/path/file"},
		{"double encoded backslash", "%255C/path/", "/path/"},
		{"normal path unchanged", "/api/users", "/api/users"},
		{"path with query - preserved", "/api?q=test", "/api"},
		{"trailing slash preserved", "/trading/", "/trading/"},
		{"tab character removed", "/path\tname", "/pathname"},
		{"newline removed", "/path\nname", "/pathname"},
		{"single quote removed", "/path'name", "/pathname"},
		{"double quote removed", `/path"name`, "/pathname"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"dir backslash escaped", `\/trading\/dir/`, "/trading/dir/"},
		{"dir url encoded backslash", "%5C/path%5C/dir/", "/path/dir/"},
		{"dir normal unchanged", "/api/users/", "/api/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestURLResolver_SanitizesAbsoluteURLs(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		// Backslash in path component is cleaned
		{"absolute URL with encoded backslash in path", "https://api.example.com/%5C/path/", "/path/"},
		{"absolute URL with backslash in path", "https://api.example.com/\\/trading\\/", "/trading/"},
		{"absolute URL normal", "https://api.example.com/api/users", "/api/users"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"absolute URL dir with backslash", "https://api.example.com/\\/trading\\/dir/", "/trading/dir/"},
		{"absolute URL dir normal", "https://api.example.com/api/users/", "/api/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestURLResolver_EmptyAfterSanitization(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	// Path that becomes empty after removing all garbage
	_, err := resolver.Resolve(base, `\"\"`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty URL after sanitization")
}

func TestURLResolver_JavaScriptEscapes(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		// Unicode escapes \uXXXX
		{"unicode slash", `/api\u002Fdata`, "/api/data"},
		{"unicode quote decoded then removed", `/api\u0022test`, "/apitest"},
		{"unicode backslash decoded then removed", `/api\u005Ctest`, "/apitest"},
		{"unicode single quote decoded then removed", `/api\u0027test`, "/apitest"},
		{"multiple unicode escapes", `/\u0061pi/\u0075sers`, "/api/users"}, // \u0061=a, \u0075=u

		// Hex escapes \xXX
		{"hex slash", `/api\x2Fdata`, "/api/data"},
		{"hex quote decoded then removed", `/api\x22test`, "/apitest"},
		{"hex backslash decoded then removed", `/api\x5Ctest`, "/apitest"},
		{"hex single quote decoded then removed", `/api\x27test`, "/apitest"},
		{"multiple hex escapes", `/\x61pi/\x75sers`, "/api/users"}, // \x61=a, \x75=u

		// Mixed escapes
		{"mixed unicode and hex", `/api\u002F\x64ata`, "/api/data"}, // \u002F=/, \x64=d
		{"mixed with normal chars", `/api/\u0076\x31/users`, "/api/v1/users"},

		// Edge cases - backslash is removed as garbage char after JS escape processing
		{"incomplete unicode escape", `/api\u00`, "/apiu00"},  // Not enough digits, backslash removed
		{"incomplete hex escape", `/api\x2`, "/apix2"},        // Not enough digits, backslash removed
		{"invalid unicode escape", `/api\uZZZZ`, "/apiuZZZZ"}, // Invalid hex, backslash removed
		{"invalid hex escape", `/api\xZZ`, "/apixZZ"},         // Invalid hex, backslash removed
		{"no escapes", "/api/users", "/api/users"},            // No change
		{"uppercase unicode", `/api\u002fdata`, "/api/data"},  // Lowercase hex digits work too
		{"uppercase hex", `/api\x2fdata`, "/api/data"},        // Lowercase hex digits work too

		// Directory paths (ending with /) - trailing slash must be preserved
		{"dir unicode slash", `/api\u002Fdata/`, "/api/data/"},
		{"dir hex slash", `/api\x2Fdata/`, "/api/data/"},
		{"dir multiple escapes", `/api/\u0076\x31/users/`, "/api/v1/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestURLResolver_TripleEncoding(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		// Triple-encoded backslash: %25255C -> %255C -> %5C -> \ -> removed
		{"triple encoded backslash", "%25255C/path/", "/path/"},
		// Triple-encoded quote: %252522 -> %2522 -> %22 -> " -> removed
		{"triple encoded quote", "%252522/api%252522", "/api"},
		// Triple-encoded slash: %25252F -> %252F -> %2F -> /
		{"triple encoded slash", "/api%25252Fusers", "/api/users"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"dir triple encoded backslash", "%25255C/path/dir/", "/path/dir/"},
		{"dir triple encoded slash", "/api%25252Fusers/", "/api/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestURLResolver_BacktickRemoval(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		{"backtick in path", "/api`test`/users", "/apitest/users"},
		{"backtick at start", "`/api/users", "/api/users"},
		{"backtick at end", "/api/users`", "/api/users"},
		{"url encoded backtick", "/api%60test/users", "/apitest/users"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"dir backtick in path", "/api`test`/users/", "/apitest/users/"},
		{"dir url encoded backtick", "/api%60test/users/", "/apitest/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestDecodeJSEscapes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Unicode escapes
		{"unicode basic", `\u0041`, "A"},
		{"unicode lowercase", `\u0061`, "a"},
		{"unicode slash", `\u002F`, "/"},
		{"unicode quote", `\u0022`, `"`},
		{"multiple unicode", `\u0048\u0065\u006C\u006C\u006F`, "Hello"},

		// Hex escapes
		{"hex basic", `\x41`, "A"},
		{"hex lowercase", `\x61`, "a"},
		{"hex slash", `\x2F`, "/"},
		{"hex quote", `\x22`, `"`},
		{"multiple hex", `\x48\x65\x6C\x6C\x6F`, "Hello"},

		// Mixed
		{"mixed escapes", `\u0048\x65llo`, "Hello"},
		{"with normal text", `api/\u0076\x31/users`, "api/v1/users"},

		// Edge cases
		{"no escapes", "normal string", "normal string"},
		{"empty string", "", ""},
		{"backslash only", `\`, `\`},
		{"incomplete unicode", `\u00`, `\u00`},
		{"incomplete hex", `\x0`, `\x0`},
		{"invalid unicode", `\uGGGG`, `\uGGGG`},
		{"invalid hex", `\xGG`, `\xGG`},
		{"backslash at end", `test\`, `test\`},
		{"backslash u without digits", `\u`, `\u`},
		{"backslash x without digits", `\x`, `\x`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeJSEscapes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestURLResolver_UnbalancedBrackets(t *testing.T) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/")

	tests := []struct {
		name     string
		input    string
		wantPath string
	}{
		// Standalone unbalanced brackets as segments - should be removed
		{"standalone ]", "/v2/]/v2/welcome", "/v2/v2/welcome"},
		{"standalone [", "/v2/[/sans-serif/35em", "/v2/sans-serif/35em"},
		{"standalone }", "/api/}/test", "/api/test"},
		{"standalone {", "/api/{/test", "/api/test"},
		{"standalone >", "/api/>/test", "/api/test"},
		{"standalone <", "/api/</test", "/api/test"},

		// Trailing unbalanced brackets - should be trimmed
		{"trailing ]", "/v2/plain]/type", "/v2/plain/type"},
		{"trailing }", "/api/test}/endpoint", "/api/test/endpoint"},
		{"trailing >", "/api/test>/endpoint", "/api/test/endpoint"},

		// Leading unbalanced brackets - should be trimmed
		{"leading [", "/api/[invalid/test", "/api/invalid/test"},
		{"leading {", "/api/{incomplete/test", "/api/incomplete/test"},
		{"leading <", "/api/<broken/test", "/api/broken/test"},

		// Multiple unbalanced brackets
		{"multiple ] segments", "/v2/]/type/]", "/v2/type"},
		{"mixed [ and ]", "/api/[/test/]/data", "/api/test/data"},

		// Real cases from logs
		{"real case 1", "/v2/]/v2/welcome", "/v2/v2/welcome"},
		{"real case 2", "/v2/plain]/type/]", "/v2/plain/type"},
		{"real case 3", "/v2/[/sans-serif/35em", "/v2/sans-serif/35em"},

		// Balanced brackets - should be preserved (valid templates)
		{"balanced []", "/api/[id]/test", "/api/[id]/test"},
		{"balanced {}", "/api/{param}/test", "/api/{param}/test"},
		{"balanced <>", "/api/<id>/test", "/api/<id>/test"},
		{"balanced [[]]", "/api/[[id]]/test", "/api/[[id]]/test"},

		// Edge cases
		{"brackets with alphanumeric", "/v2/plain]/required/web", "/v2/plain/required/web"},

		// URL-encoded brackets
		{"encoded ]", "/api/%5D/test", "/api/test"},
		{"encoded [", "/api/%5B/test", "/api/test"},
		{"encoded trailing ]", "/api/test%5D/foo", "/api/test/foo"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"dir with standalone ]", "/v2/]/v2/welcome/", "/v2/v2/welcome/"},
		{"dir with trailing ]", "/v2/plain]/type/", "/v2/plain/type/"},
		{"dir with standalone [", "/api/[/test/", "/api/test/"},
		{"dir balanced preserved", "/api/[id]/test/", "/api/[id]/test/"},
		{"dir multiple unbalanced", "/v2/]/type/]/", "/v2/type/"},

		// Relative paths with .. and . - must be preserved for resolution
		{".. with unbalanced ]", "../]/api/test", "/api/test"},
		{".. preserved", "../admin", "/admin"},
		{". preserved", "./users", "/users"},
		{"multiple .. preserved", "../../config", "/config"},
		{".. in middle with ]", "/api/../]/test", "/test"},
		{"mixed .. and brackets", "../api/]/test", "/api/test"},
		{". and ] combined", "./api/]/test", "/api/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolver.Resolve(base, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, resolved.Path)
		})
	}
}

func TestSanitizePathSegments(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Basic cases
		{"/api/users", "/api/users"},
		{"/", "/"},
		{"", ""},

		// Unbalanced brackets removed
		{"/v2/]/v2/welcome", "/v2/v2/welcome"},
		{"/v2/plain]/type", "/v2/plain/type"},
		{"/api/[/test", "/api/test"},
		{"/api/test>", "/api/test"},

		// Balanced brackets preserved
		{"/api/[id]/test", "/api/[id]/test"},
		{"/api/{param}", "/api/{param}"},

		// Multiple unbalanced
		{"/]/[/}/", ""},
		{"/v2/]/]/test", "/v2/test"},

		// Segments with only brackets
		{"/api/]/test", "/api/test"},
		{"/]/api", "/api"},

		// Directory paths (ending with /) - trailing slash must be preserved
		{"/api/users/", "/api/users/"},
		{"/v2/]/v2/welcome/", "/v2/v2/welcome/"},
		{"/v2/plain]/type/", "/v2/plain/type/"},
		{"/api/[id]/test/", "/api/[id]/test/"},

		// Relative paths with .. and . - must be preserved for resolution
		{"../admin", "../admin"},
		{"./users", "./users"},
		{"../../config", "../../config"},
		{"../api/test", "../api/test"},
		{"./api/test", "./api/test"},
		{"../]/api", "../api"},
		{"./]/test", "./test"},
		{"/api/../test", "/api/../test"},
		{"/api/./test", "/api/./test"},
		{"../api/]/test", "../api/test"},
		{"./api/]/test", "./api/test"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizePathSegments(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestURLResolver_QueryParamsPreserved(t *testing.T) {
	resolver := NewURLResolver()

	tests := []struct {
		name          string
		base          string
		relative      string
		expectedPath  string
		expectedQuery string
	}{
		{
			name:          "absolute URL with query params",
			base:          "https://example.com/",
			relative:      "https://api.example.com/users?id=123&name=test",
			expectedPath:  "/users",
			expectedQuery: "id=123&name=test",
		},
		{
			name:          "relative path with query",
			base:          "https://example.com/api/",
			relative:      "users?page=2&limit=10",
			expectedPath:  "/api/users",
			expectedQuery: "page=2&limit=10",
		},
		{
			name:          "absolute path with query",
			base:          "https://example.com/old/",
			relative:      "/new/endpoint?filter=active",
			expectedPath:  "/new/endpoint",
			expectedQuery: "filter=active",
		},
		{
			name:          "query only",
			base:          "https://example.com/api/users",
			relative:      "?sort=desc",
			expectedPath:  "/api/users",
			expectedQuery: "sort=desc",
		},
		{
			name:          "empty query",
			base:          "https://example.com/",
			relative:      "/api/users",
			expectedPath:  "/api/users",
			expectedQuery: "",
		},
		{
			name:          "query with special chars",
			base:          "https://example.com/",
			relative:      "/search?q=hello+world&type=all",
			expectedPath:  "/search",
			expectedQuery: "q=hello+world&type=all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, err := url.Parse(tt.base)
			require.NoError(t, err)

			resolved, err := resolver.Resolve(base, tt.relative)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPath, resolved.Path, "path mismatch")
			assert.Equal(t, tt.expectedQuery, resolved.RawQuery, "query mismatch")
		})
	}
}

func TestURLResolver_NormalizePreservesQuery(t *testing.T) {
	resolver := NewURLResolver()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single query param",
			input:    "https://example.com/api?id=123",
			expected: "https://example.com/api?id=123",
		},
		{
			name:     "multiple query params",
			input:    "https://example.com/api?id=1&name=foo&type=bar",
			expected: "https://example.com/api?id=1&name=foo&type=bar",
		},
		{
			name:     "query params with path normalization",
			input:    "https://example.com//api//v1?id=123",
			expected: "https://example.com/api/v1?id=123",
		},
		{
			name:     "no query params",
			input:    "https://example.com/api",
			expected: "https://example.com/api",
		},
		{
			name:     "fragment stripped but query preserved",
			input:    "https://example.com/api?id=123#section",
			expected: "https://example.com/api?id=123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)
			require.NoError(t, err)

			normalized := resolver.Normalize(u)
			assert.Equal(t, tt.expected, normalized)
		})
	}
}

func BenchmarkURLResolver_Resolve(b *testing.B) {
	resolver := NewURLResolver()
	base, _ := url.Parse("https://example.com/api/v1/users")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.Resolve(base, "../admin")
	}
}

func BenchmarkURLResolver_Normalize(b *testing.B) {
	resolver := NewURLResolver()
	u, _ := url.Parse("https://example.com/api/v1/users?z=1&a=2#section")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolver.Normalize(u)
	}
}
