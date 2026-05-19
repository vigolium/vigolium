package fingerprint

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomPaths(t *testing.T) {
	baseURL, err := url.Parse("https://example.com/api/users.json")
	require.NoError(t, err)

	paths, err := GenerateRandomPaths(baseURL)
	require.NoError(t, err)
	assert.Len(t, paths, 4, "Should generate exactly 4 paths")

	// All paths should be different
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			assert.NotEqual(t, paths[i], paths[j], "Path %d and %d should differ", i, j)
		}
	}

	// All paths should preserve the parent directory /api/
	for i, p := range paths {
		assert.True(t, strings.HasPrefix(p, "/api/"), "Path %d should preserve parent directory /api/: %s", i, p)
	}

	// Path 0: Prefix - /api/{random}users.json
	assert.Contains(t, paths[0], "users.json", "Path 0 (prefix) should contain users.json")

	// Path 1: Suffix - /api/users{random}.json
	assert.Contains(t, paths[1], ".json", "Path 1 (suffix) should preserve extension")

	// Path 2: Extension - /api/users.json.{random}
	assert.Contains(t, paths[2], "/api/users.json.", "Path 2 (extension) should add fake extension")

	// Path 3: Middle - /api/us{random}ers.json
	assert.Contains(t, paths[3], ".json", "Path 3 (middle) should preserve extension")
}

func TestGenerateRandomPaths_PathLengths(t *testing.T) {
	baseURL, err := url.Parse("https://example.com/test")
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		paths, err := GenerateRandomPaths(baseURL)
		require.NoError(t, err)
		require.Len(t, paths, 4)

		// Path 0: Prefix (6 chars) - /{random}test
		baseName0 := strings.TrimPrefix(paths[0], "/")
		assert.GreaterOrEqual(t, len(baseName0), 10, "Prefix should add 6 chars (6hex + test=4)")

		// Path 1: Suffix (6 chars) - /test{random}
		baseName1 := strings.TrimPrefix(paths[1], "/")
		assert.GreaterOrEqual(t, len(baseName1), 10, "Suffix should add 6 chars (test=4 + 6hex)")

		// Path 2: Extension (4 chars) - /test.{random}
		assert.Contains(t, paths[2], ".", "Extension should add dot")
		extPart := strings.Split(paths[2], ".")[1]
		assert.Len(t, extPart, 4, "Extension should use 4-char hex")

		// Path 3: Middle (9 chars) - /te{random}st
		baseName3 := strings.TrimPrefix(paths[3], "/")
		assert.GreaterOrEqual(t, len(baseName3), 13, "Middle should add 9 chars (te=2 + 9hex + st=2)")
	}
}

func TestGenerateRandomPaths_NilURL(t *testing.T) {
	_, err := GenerateRandomPaths(nil)
	assert.Error(t, err, "Should error on nil URL")
	assert.Contains(t, err.Error(), "nil", "Error should mention nil")
}

func TestGenerateRandomPaths_EmptyPath(t *testing.T) {
	baseURL, err := url.Parse("https://example.com")
	require.NoError(t, err)

	paths, err := GenerateRandomPaths(baseURL)
	require.NoError(t, err)
	assert.Len(t, paths, 4)

	// All paths should start with /
	for i, p := range paths {
		assert.True(t, strings.HasPrefix(p, "/"), "Path %d should start with /: %s", i, p)
	}
}

func TestPrependToLastSegment(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		random      string
		shouldMatch string
		description string
	}{
		{
			name:        "file_with_extension",
			path:        "/api/users.json",
			random:      "abc123",
			shouldMatch: "/api/abc123users.json",
			description: "Should prepend to filename",
		},
		{
			name:        "file_without_extension",
			path:        "/site/default",
			random:      "xyz789",
			shouldMatch: "/site/xyz789default",
			description: "Should prepend to filename",
		},
		{
			name:        "root_path",
			path:        "/",
			random:      "xyz",
			shouldMatch: "/xyz",
			description: "Root should become /random",
		},
		{
			name:        "empty_path",
			path:        "",
			random:      "test",
			shouldMatch: "/test",
			description: "Empty should become /random",
		},
		{
			name:        "trailing_slash_directory",
			path:        "/api/users/",
			random:      "rand",
			shouldMatch: "/api/randusers/",
			description: "Directory: prepend to dir name, preserve trailing slash",
		},
		{
			name:        "deep_path",
			path:        "/a/b/c/d.txt",
			random:      "hex",
			shouldMatch: "/a/b/c/hexd.txt",
			description: "Should prepend to filename in deep path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := prependToLastSegment(tt.path, tt.random)
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestAppendToLastSegment(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		random      string
		shouldMatch string
		description string
	}{
		{
			name:        "file_with_extension",
			path:        "/api/users.json",
			random:      "abc123",
			shouldMatch: "/api/usersabc123.json",
			description: "Should append before extension",
		},
		{
			name:        "file_without_extension",
			path:        "/site/default",
			random:      "xyz789",
			shouldMatch: "/site/defaultxyz789",
			description: "Should append to end of filename",
		},
		{
			name:        "root_path",
			path:        "/",
			random:      "xyz",
			shouldMatch: "/xyz",
			description: "Root should become /random",
		},
		{
			name:        "empty_path",
			path:        "",
			random:      "test",
			shouldMatch: "/test",
			description: "Empty should become /random",
		},
		{
			name:        "trailing_slash_directory",
			path:        "/api/users/",
			random:      "rand",
			shouldMatch: "/api/usersrand/",
			description: "Directory: append to dir name, preserve trailing slash",
		},
		{
			name:        "deep_path",
			path:        "/a/b/c/d.txt",
			random:      "hex",
			shouldMatch: "/a/b/c/dhex.txt",
			description: "Should append to filename in deep path",
		},
		{
			name:        "multiple_extensions",
			path:        "/file.tar.gz",
			random:      "rnd",
			shouldMatch: "/file.tarrnd.gz",
			description: "Should append before last extension only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendToLastSegment(tt.path, tt.random)
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestAddFakeExtension(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		random      string
		shouldMatch string
		description string
	}{
		{
			name:        "file_with_extension",
			path:        "/api/users.json",
			random:      "abc123",
			shouldMatch: "/api/users.json.abc123",
			description: "Should add fake extension after existing",
		},
		{
			name:        "file_without_extension",
			path:        "/api/users",
			random:      "xyz",
			shouldMatch: "/api/users.xyz",
			description: "Should add as extension",
		},
		{
			name:        "root_path",
			path:        "/",
			random:      "xyz",
			shouldMatch: "/xyz",
			description: "Root should become /random",
		},
		{
			name:        "empty_path",
			path:        "",
			random:      "test",
			shouldMatch: "/test",
			description: "Empty should become /random",
		},
		{
			name:        "trailing_slash_directory",
			path:        "/api/users/",
			random:      "rand",
			shouldMatch: "/api/users.rand/",
			description: "Directory: add extension, preserve trailing slash",
		},
		{
			name:        "deep_path",
			path:        "/site/hc/static/site/default",
			random:      "fake",
			shouldMatch: "/site/hc/static/site/default.fake",
			description: "Should add extension preserving full path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addFakeExtension(tt.path, tt.random)
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestInsertIntoLastSegment(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		random      string
		shouldMatch string
		description string
	}{
		{
			name:        "file_with_extension",
			path:        "/api/users.json",
			random:      "xxx",
			shouldMatch: "/api/usxxxers.json",
			description: "Should insert into middle of filename",
		},
		{
			name:        "file_without_extension",
			path:        "/site/default",
			random:      "yyy",
			shouldMatch: "/site/defyyyault",
			description: "Should insert into middle",
		},
		{
			name:        "short_filename",
			path:        "/ab.txt",
			random:      "zzz",
			shouldMatch: "/azzzb.txt",
			description: "Short filename: insert in middle",
		},
		{
			name:        "single_char_filename",
			path:        "/a.txt",
			random:      "zzz",
			shouldMatch: "/azzz.txt",
			description: "Single char filename: append instead",
		},
		{
			name:        "root_path",
			path:        "/",
			random:      "xyz",
			shouldMatch: "/xyz",
			description: "Root should become /random",
		},
		{
			name:        "empty_path",
			path:        "",
			random:      "test",
			shouldMatch: "/test",
			description: "Empty should become /random",
		},
		{
			name:        "trailing_slash_directory",
			path:        "/api/users/",
			random:      "rand",
			shouldMatch: "/api/usranders/",
			description: "Directory: insert into dir name, preserve trailing slash",
		},
		{
			name:        "deep_path",
			path:        "/site/hc/static/site/default",
			random:      "xxx",
			shouldMatch: "/site/hc/static/site/defxxxault",
			description: "Should insert into last segment only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertIntoLastSegment(tt.path, tt.random)
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestGenerateRandomHex(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"prefix_suffix_length", 6},
		{"middle_length", 9},
		{"extension_length", 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hex, err := generateRandomHex(tt.length)
			require.NoError(t, err)
			assert.Len(t, hex, tt.length, "Generated hex should have exact length")

			// Should be valid hex (0-9, a-f)
			for i, c := range hex {
				isValid := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
				assert.True(t, isValid, "Char %d ('%c') should be valid hex", i, c)
			}
		})
	}
}

func TestGenerateRandomHex_Consistency(t *testing.T) {
	seen := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		hex, err := generateRandomHex(8)
		require.NoError(t, err)
		assert.False(t, seen[hex], "Generated duplicate hex: %s", hex)
		seen[hex] = true
	}

	assert.Len(t, seen, count, "Should generate %d unique hex strings", count)
}

func TestGenerateRandomHex_Zero(t *testing.T) {
	hex, err := generateRandomHex(0)
	require.NoError(t, err)
	assert.Empty(t, hex, "Zero length should return empty string")
}

func TestGenerateRandomPathWithVariation(t *testing.T) {
	basePath := "/api/users.json"

	t.Run("prefix_variation", func(t *testing.T) {
		path, err := GenerateRandomPathWithVariation(basePath, VariationPrefix, 6)
		require.NoError(t, err)
		assert.Contains(t, path, "/api/", "Should contain /api/")
		assert.Contains(t, path, "users.json", "Should contain users.json")
		assert.NotEqual(t, basePath, path, "Should be different from base")

		// Extract hex part - should be prepended to users
		filename := strings.TrimPrefix(path, "/api/")
		filename = strings.TrimSuffix(filename, ".json")
		assert.Len(t, filename, 11, "Filename should be 11 chars (6hex + users)")
	})

	t.Run("suffix_variation", func(t *testing.T) {
		path, err := GenerateRandomPathWithVariation(basePath, VariationSuffix, 9)
		require.NoError(t, err)
		assert.Contains(t, path, "/api/users", "Should contain /api/users")
		assert.Contains(t, path, ".json", "Should preserve .json extension")

		withoutExt := strings.TrimSuffix(path, ".json")
		originalWithoutExt := "/api/users"
		added := len(withoutExt) - len(originalWithoutExt)
		assert.Equal(t, 9, added, "Should add 9 chars before extension")
	})

	t.Run("extension_variation", func(t *testing.T) {
		path, err := GenerateRandomPathWithVariation(basePath, VariationExtension, 4)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(path, "/api/users.json."), "Should add fake extension")

		parts := strings.Split(path, ".")
		require.Len(t, parts, 3, "Should have 3 parts (users, json, random)")
		assert.Len(t, parts[2], 4, "Fake extension should be 4 chars")
	})

	t.Run("middle_variation", func(t *testing.T) {
		path, err := GenerateRandomPathWithVariation(basePath, VariationMiddle, 9)
		require.NoError(t, err)
		assert.Contains(t, path, "/api/us", "Should start with /api/us")
		assert.Contains(t, path, "ers.json", "Should end with ers.json")

		// Filename should be: us + 9hex + ers = 14 chars
		withoutExt := strings.TrimSuffix(path, ".json")
		filename := strings.TrimPrefix(withoutExt, "/api/")
		assert.Len(t, filename, 14, "Filename should be 14 chars (us + 9hex + ers)")
	})

	t.Run("unknown_variation", func(t *testing.T) {
		_, err := GenerateRandomPathWithVariation(basePath, PathVariation(99), 6)
		assert.Error(t, err, "Should error on unknown variation type")
	})
}

func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		pathVar     string
		expectedURL string
	}{
		{
			name:        "simple",
			baseURL:     "https://example.com/api",
			pathVar:     "/api/test/path",
			expectedURL: "https://example.com/api/test/path",
		},
		{
			name:        "with_port",
			baseURL:     "https://example.com:8080/api",
			pathVar:     "/api/users",
			expectedURL: "https://example.com:8080/api/users",
		},
		{
			name:        "query_string_preserved",
			baseURL:     "https://example.com/api?key=value",
			pathVar:     "/new/path",
			expectedURL: "https://example.com/new/path?key=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			fullURL := BuildFullURL(baseURL, tt.pathVar)

			parsedResult, err := url.Parse(fullURL)
			require.NoError(t, err)

			expectedParsed, err := url.Parse(tt.expectedURL)
			require.NoError(t, err)

			assert.Equal(t, expectedParsed.Host, parsedResult.Host, "Host should match")
			assert.Equal(t, expectedParsed.Path, parsedResult.Path, "Path should match")
		})
	}
}

func TestPathVariations_Uniqueness(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com/test.php")

	allPaths := make(map[string]bool)
	iterations := 20

	for i := 0; i < iterations; i++ {
		paths, err := GenerateRandomPaths(baseURL)
		require.NoError(t, err)

		assert.Len(t, paths, 4, "Iteration %d: should have 4 paths", i)

		for j := 0; j < len(paths); j++ {
			for k := j + 1; k < len(paths); k++ {
				assert.NotEqual(t, paths[j], paths[k], "Iteration %d: path %d and %d should differ", i, j, k)
			}
		}

		for _, p := range paths {
			allPaths[p] = true
		}
	}

	assert.GreaterOrEqual(t, len(allPaths), iterations*3, "Should generate mostly unique paths across iterations")
}

// Test that all strategies preserve parent directory structure
func TestPathStrategies_PreserveDirectory(t *testing.T) {
	baseURL, _ := url.Parse("https://target.com/site/hc/static/site/default")

	paths, err := GenerateRandomPaths(baseURL)
	require.NoError(t, err)

	expectedPrefix := "/site/hc/static/site/"

	for i, p := range paths {
		assert.True(t, strings.HasPrefix(p, expectedPrefix),
			"Path %d (%s) should preserve parent directory %s", i, p, expectedPrefix)
	}
}

// Regression test for path-specific catch-all scenario
func TestWildcardValidation_PathSpecificCatchAll(t *testing.T) {
	// This test validates that path generation stays within catch-all patterns
	// Bug scenario: /site/hc/static/site/* catch-all returns 302 for any path
	// Old behavior: test paths escape the pattern by inserting directory
	// New behavior: test paths stay within the same directory

	basePath := "/site/hc/static/site/default"

	baseURL, err := url.Parse("https://example.com" + basePath)
	require.NoError(t, err)

	paths, err := GenerateRandomPaths(baseURL)
	require.NoError(t, err)

	expectedPrefix := "/site/hc/static/site/"

	for i, p := range paths {
		assert.True(t, strings.HasPrefix(p, expectedPrefix),
			"Path %d (%s) should preserve parent directory %s", i, p, expectedPrefix)
	}
}

// Test directory paths (ending with /)
func TestPathStrategies_Directories(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com/api/users/")

	paths, err := GenerateRandomPaths(baseURL)
	require.NoError(t, err)

	// All paths should preserve parent directory /api/
	for i, p := range paths {
		assert.True(t, strings.HasPrefix(p, "/api/"), "Path %d should preserve /api/: %s", i, p)
		assert.True(t, strings.HasSuffix(p, "/"), "Path %d should preserve trailing slash: %s", i, p)
	}
}

// Benchmarks
func BenchmarkGenerateRandomPaths(b *testing.B) {
	baseURL, _ := url.Parse("https://example.com/api/users.json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateRandomPaths(baseURL)
	}
}

func BenchmarkGenerateRandomHex6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateRandomHex(6)
	}
}

func BenchmarkGenerateRandomHex9(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateRandomHex(9)
	}
}

func BenchmarkPrependToLastSegment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = prependToLastSegment("/api/v1/users.json", "abc123")
	}
}

func BenchmarkAppendToLastSegment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = appendToLastSegment("/api/v1/users.json", "abc123xyz")
	}
}

func BenchmarkAddFakeExtension(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = addFakeExtension("/api/v1/users.json", "abcd")
	}
}

func BenchmarkInsertIntoLastSegment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = insertIntoLastSegment("/api/v1/users.json", "abcdef123")
	}
}
