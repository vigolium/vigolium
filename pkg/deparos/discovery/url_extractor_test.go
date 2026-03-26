package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractFilename verifies URL filename/extension extraction.
//
func TestExtractFilename(t *testing.T) {
	tests := []struct {
		name         string
		urlPath      string
		expectedName string
		expectedExt  string
		description  string
	}{
		{
			name:         "simple file with extension",
			urlPath:      "/admin/login.php",
			expectedName: "login",
			expectedExt:  "php",
			description:  "Basic case: filename with extension",
		},
		{
			name:         "file without extension",
			urlPath:      "/api/users",
			expectedName: "users",
			expectedExt:  "",
			description:  "File with no extension",
		},
		{
			name:         "compound extension tar.gz",
			urlPath:      "/backup/archive.tar.gz",
			expectedName: "archive",
			expectedExt:  "tar.gz",
			description:  "Compound extension tar.gz should be recognized",
		},
		{
			name:         "root path",
			urlPath:      "/",
			expectedName: "",
			expectedExt:  "",
			description:  "Root path should be skipped",
		},
		{
			name:         "empty path",
			urlPath:      "",
			expectedName: "",
			expectedExt:  "",
			description:  "Empty path should be skipped",
		},
		{
			name:         "filename ending with dot",
			urlPath:      "/test/file.",
			expectedName: "file",
			expectedExt:  "",
			description:  "Filename ending with dot has empty extension",
		},
		{
			name:         "complex path",
			urlPath:      "/deep/nested/path/config.json",
			expectedName: "config",
			expectedExt:  "json",
			description:  "Deep nested path - only last component matters",
		},
		{
			name:         "path with query string ignored",
			urlPath:      "/api/search.jsp",
			expectedName: "search",
			expectedExt:  "jsp",
			description:  "Only path component, query would be stripped before this",
		},
		{
			name:         "file with no leading slash",
			urlPath:      "index.html",
			expectedName: "index",
			expectedExt:  "html",
			description:  "Path without leading slash",
		},
		{
			name:         "directory ending with slash",
			urlPath:      "/admin/",
			expectedName: "",
			expectedExt:  "",
			description:  "Directory path ending with slash - empty filename",
		},
		{
			name:         "multiple dots in path but not filename",
			urlPath:      "/v1.0/api.v2/users.xml",
			expectedName: "users",
			expectedExt:  "xml",
			description:  "Dots in directory names don't affect filename parsing",
		},
		{
			name:         "hidden file (dotfile)",
			urlPath:      "/config/.htaccess",
			expectedName: "",
			expectedExt:  "htaccess",
			description:  "Dotfile - name is empty, extension is full filename minus dot",
		},
		{
			name:         "common web extensions",
			urlPath:      "/page.aspx",
			expectedName: "page",
			expectedExt:  "aspx",
			description:  "ASPX extension",
		},
		{
			name:         "javascript compound extension min.js",
			urlPath:      "/assets/app.min.js",
			expectedName: "app",
			expectedExt:  "min.js",
			description:  "Compound extension min.js should be recognized",
		},
		{
			name:         "hash pattern in filename",
			urlPath:      "/js/app.b5ca88ec.js",
			expectedName: "app",
			expectedExt:  "js",
			description:  "Hash pattern stripped - extract name only",
		},
		{
			name:         "css with hash",
			urlPath:      "/css/surgeons.757b7acf.css",
			expectedName: "surgeons",
			expectedExt:  "css",
			description:  "CSS with hash stripped - extract name only",
		},
		{
			name:         "backup file extensions",
			urlPath:      "/config.bak",
			expectedName: "config",
			expectedExt:  "bak",
			description:  "Backup file extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ext := ExtractFilename(tt.urlPath)

			assert.Equal(t, tt.expectedName, name,
				"Name mismatch for %s: %s", tt.urlPath, tt.description)
			assert.Equal(t, tt.expectedExt, ext,
				"Extension mismatch for %s: %s", tt.urlPath, tt.description)
		})
	}
}

// TestExtractFilename_CompoundExtensions verifies compound extension handling.
func TestExtractFilename_CompoundExtensions(t *testing.T) {
	t.Run("compound extensions recognized", func(t *testing.T) {
		testCases := []struct {
			path         string
			expectedName string
			expectedExt  string
		}{
			{"/archive.tar.gz", "archive", "tar.gz"},
			{"/app.min.js", "app", "min.js"},
			{"/vendor.chunk.js", "vendor", "chunk.js"},
			{"/main.bundle.js", "main", "bundle.js"},
			{"/module.esm.js", "module", "esm.js"},
			{"/backup.tar.bz2", "backup", "tar.bz2"},
			{"/data.tar.xz", "data", "tar.xz"},
		}

		for _, tc := range testCases {
			name, ext := ExtractFilename(tc.path)
			assert.Equal(t, tc.expectedName, name, "Name mismatch for %s", tc.path)
			assert.Equal(t, tc.expectedExt, ext, "Ext mismatch for %s", tc.path)
		}
	})

	t.Run("hash patterns stripped correctly", func(t *testing.T) {
		testCases := []struct {
			path         string
			expectedName string
			expectedExt  string
		}{
			{"/app.b5ca88ec.js", "app", "js"},                     // 8 hex chars
			{"/style.757b7acf.css", "style", "css"},               // 8 hex chars
			{"/chunk-vendors.d5a27c78.js", "chunk-vendors", "js"}, // 8 hex chars
			{"/main.abcdef.js", "main", "js"},                     // 6 hex chars (minimum)
			{"/app.abcdef123456.css", "app", "css"},               // 12 hex chars (maximum)
		}

		for _, tc := range testCases {
			name, ext := ExtractFilename(tc.path)
			assert.Equal(t, tc.expectedName, name, "Name mismatch for %s", tc.path)
			assert.Equal(t, tc.expectedExt, ext, "Ext mismatch for %s", tc.path)
		}
	})

	t.Run("non-hash patterns preserved", func(t *testing.T) {
		testCases := []struct {
			path         string
			expectedName string
			expectedExt  string
		}{
			{"/file.backup.old", "file.backup", "old"},                 // "backup" is not hex
			{"/data.json.bak", "data.json", "bak"},                     // "json" is not hex
			{"/app.config.js", "app.config", "js"},                     // "config" is not hex
			{"/file.ab.js", "file.ab", "js"},                           // Too short (< 6 chars)
			{"/file.abcdef123456789.js", "file.abcdef123456789", "js"}, // Too long (> 12 chars)
		}

		for _, tc := range testCases {
			name, ext := ExtractFilename(tc.path)
			assert.Equal(t, tc.expectedName, name, "Name mismatch for %s", tc.path)
			assert.Equal(t, tc.expectedExt, ext, "Ext mismatch for %s", tc.path)
		}
	})
}

// TestExtractFilename_Parity verifies expected extraction behavior.
func TestExtractFilename_Parity(t *testing.T) {

	t.Run("burp extracts last segment only", func(t *testing.T) {
		name, ext := ExtractFilename("/a/b/c/d/file.txt")
		assert.Equal(t, "file", name)
		assert.Equal(t, "txt", ext)
	})

	t.Run("multiple dots handled as hash pattern", func(t *testing.T) {
		// With new behavior, multiple dots are treated as name.hash.ext pattern
		name, ext := ExtractFilename("/file.with.many.dots.php")
		// Returns name="file.with.many.dots", ext="php"
		assert.Equal(t, "file.with.many.dots", name)
		assert.Equal(t, "php", ext)
	})

	t.Run("burp handles no extension", func(t *testing.T) {
		name, ext := ExtractFilename("/noextension")
		assert.Equal(t, "noextension", name)
		assert.Empty(t, ext)
	})

	t.Run("burp skips root path", func(t *testing.T) {
		name, ext := ExtractFilename("/")
		assert.Empty(t, name)
		assert.Empty(t, ext)
	})

	t.Run("name used for both file and directory discovery", func(t *testing.T) {
		//   - Priority 0: new boh((byte)0, ..., new ezo(this.l), ...) - file mode
		//   - Priority 1: new boh((byte)1, ..., new ezo(this.l), ...) - dir mode
		// So "login" from "login.php" becomes both "login" (file) and "login/" (directory)

		testCases := []struct {
			path string
			name string
			ext  string
		}{
			{"/login.php", "login", "php"},   // name used as file AND directory
			{"/index.html", "index", "html"}, // name used as file AND directory
			{"/config", "config", ""},        // name used as file AND directory
			{"/api.jsp", "api", "jsp"},       // name used as file AND directory
		}

		for _, tc := range testCases {
			name, ext := ExtractFilename(tc.path)
			assert.Equal(t, tc.name, name, "Name mismatch for %s", tc.path)
			assert.Equal(t, tc.ext, ext, "Extension mismatch for %s", tc.path)
			// Note: name IS used for directory discovery (with "/" suffix)
			// This is handled by the task system, not the extractor
		}
	})
}

// BenchmarkExtractFilename measures extraction performance.
func BenchmarkExtractFilename(b *testing.B) {
	paths := []string{
		"/admin/login.php",
		"/api/users",
		"/deep/nested/path/file.json",
		"/archive.tar.gz",
		"/",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := paths[i%len(paths)]
		ExtractFilename(path)
	}
}

// TestExtractDirectoryBreadcrumbs verifies directory extraction from URL paths.
// When spider discovers a file, we extract all parent directories for recursive brute force.
func TestExtractDirectoryBreadcrumbs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "deep file path - spider discovery",
			input:    "/webmail/program/js/common.min.js",
			expected: []string{"/webmail/", "/webmail/program/", "/webmail/program/js/"},
		},
		{
			name:     "root path",
			input:    "/",
			expected: nil,
		},
		{
			name:     "file in root",
			input:    "/file.txt",
			expected: nil,
		},
		{
			name:     "single directory excludes itself",
			input:    "/admin/",
			expected: nil,
		},
		{
			name:     "file in single directory",
			input:    "/admin/index.php",
			expected: []string{"/admin/"},
		},
		{
			name:     "directory path excludes itself",
			input:    "/a/b/c/",
			expected: []string{"/a/", "/a/b/"},
		},
		{
			name:     "consecutive slashes normalized",
			input:    "//double//slashes//file.txt",
			expected: []string{"/double/", "/double/slashes/"},
		},
		{
			name:     "empty path",
			input:    "",
			expected: nil,
		},
		{
			name:     "API versioned path",
			input:    "/api/v1/users/123/profile.json",
			expected: []string{"/api/", "/api/v1/", "/api/v1/users/", "/api/v1/users/123/"},
		},
		{
			name:     "dotfile in directory",
			input:    "/config/.htaccess",
			expected: []string{"/config/"},
		},
		{
			name:     "two levels file",
			input:    "/admin/config.php",
			expected: []string{"/admin/"},
		},
		{
			name:     "three levels file",
			input:    "/admin/api/users.json",
			expected: []string{"/admin/", "/admin/api/"},
		},
		{
			name:     "path without leading slash",
			input:    "admin/test/file.txt",
			expected: []string{"/admin/", "/admin/test/"},
		},
		{
			name:     "deep nested directory",
			input:    "/a/b/c/d/e/",
			expected: []string{"/a/", "/a/b/", "/a/b/c/", "/a/b/c/d/"},
		},
		{
			name:     "two directories",
			input:    "/first/second/",
			expected: []string{"/first/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractDirectoryBreadcrumbs(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractDirectoryBreadcrumbs_ConsistencyWithFilename verifies both functions work together.
func TestExtractDirectoryBreadcrumbs_ConsistencyWithFilename(t *testing.T) {
	testCases := []struct {
		path                string
		expectedName        string
		expectedExt         string
		expectedBreadcrumbs []string
	}{
		{
			path:                "/admin/login.php",
			expectedName:        "login",
			expectedExt:         "php",
			expectedBreadcrumbs: []string{"/admin/"},
		},
		{
			path:                "/api/v1/users.json",
			expectedName:        "users",
			expectedExt:         "json",
			expectedBreadcrumbs: []string{"/api/", "/api/v1/"},
		},
		{
			path:                "/webmail/program/js/common.min.js",
			expectedName:        "common", // min.js is a compound extension
			expectedExt:         "min.js",
			expectedBreadcrumbs: []string{"/webmail/", "/webmail/program/", "/webmail/program/js/"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			name, ext := ExtractFilename(tc.path)
			breadcrumbs := ExtractDirectoryBreadcrumbs(tc.path)

			assert.Equal(t, tc.expectedName, name)
			assert.Equal(t, tc.expectedExt, ext)
			assert.Equal(t, tc.expectedBreadcrumbs, breadcrumbs)
		})
	}
}

// TestExtractDirectoryBreadcrumbs_SpiderScenarios tests real-world spider discovery scenarios.
func TestExtractDirectoryBreadcrumbs_SpiderScenarios(t *testing.T) {
	testCases := []struct {
		name         string
		spiderURL    string
		expectedDirs []string
	}{
		{
			name:         "Roundcube webmail JS file",
			spiderURL:    "/webmail/program/js/common.min.js",
			expectedDirs: []string{"/webmail/", "/webmail/program/", "/webmail/program/js/"},
		},
		{
			name:      "WordPress plugin file",
			spiderURL: "/wp-content/plugins/contact-form-7/includes/js/scripts.js",
			expectedDirs: []string{
				"/wp-content/",
				"/wp-content/plugins/",
				"/wp-content/plugins/contact-form-7/",
				"/wp-content/plugins/contact-form-7/includes/",
				"/wp-content/plugins/contact-form-7/includes/js/",
			},
		},
		{
			name:         "REST API endpoint",
			spiderURL:    "/api/v2/users/profile",
			expectedDirs: []string{"/api/", "/api/v2/", "/api/v2/users/"},
		},
		{
			name:         "Static asset",
			spiderURL:    "/static/css/main.css",
			expectedDirs: []string{"/static/", "/static/css/"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractDirectoryBreadcrumbs(tc.spiderURL)
			assert.Equal(t, tc.expectedDirs, result)
		})
	}
}

// BenchmarkExtractDirectoryBreadcrumbs measures breadcrumb extraction performance.
func BenchmarkExtractDirectoryBreadcrumbs(b *testing.B) {
	paths := []string{
		"/webmail/program/js/common.min.js",
		"/api/v1/users/123/profile.json",
		"/file.txt",
		"/",
		"/admin/",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := paths[i%len(paths)]
		ExtractDirectoryBreadcrumbs(path)
	}
}

// TestExtractPathForFuzzing verifies directory path extraction for fuzzing.
func TestExtractPathForFuzzing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "file in nested directory",
			input:    "/api/v1/users/123",
			expected: "/api/v1/users/",
		},
		{
			name:     "file with extension",
			input:    "/admin/config.php",
			expected: "/admin/",
		},
		{
			name:     "file in root",
			input:    "/file.txt",
			expected: "",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "",
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "directory as-is",
			input:    "/admin/",
			expected: "/admin/",
		},
		{
			name:     "nested directory",
			input:    "/api/v1/users/",
			expected: "/api/v1/users/",
		},
		{
			name:     "deep path",
			input:    "/a/b/c/d/e.txt",
			expected: "/a/b/c/d/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPathForFuzzing(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractPathSegments verifies path segment extraction for fuzzing.
func TestExtractPathSegments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "API path",
			input:    "/api/v1/users/123",
			expected: []string{"api", "v1", "users", "123"},
		},
		{
			name:     "file with extension",
			input:    "/admin/config.php",
			expected: []string{"admin", "config.php"},
		},
		{
			name:     "root path",
			input:    "/",
			expected: nil,
		},
		{
			name:     "empty path",
			input:    "",
			expected: nil,
		},
		{
			name:     "directory path",
			input:    "/admin/",
			expected: []string{"admin"},
		},
		{
			name:     "single segment",
			input:    "/users",
			expected: []string{"users"},
		},
		{
			name:     "multiple slashes",
			input:    "//double//slashes//",
			expected: []string{"double", "slashes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPathSegments(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// NOTE: TestMergePathWithBase and related tests moved to pkg/discovery/payload/path_merge_test.go
// MergePathWithBase is now in the payload package.

// TestExtractHostComponents verifies host component extraction for wordlist generation.
func TestExtractHostComponents(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected []string
	}{
		{
			name:     "subdomain with common TLD",
			host:     "brand.example.com",
			expected: []string{"brand", "example"},
		},
		{
			name:     "multiple subdomains with country TLD",
			host:     "api.v2.brand.example.co.uk",
			expected: []string{"api", "v2", "brand", "example"},
		},
		{
			name:     "localhost with port skipped",
			host:     "localhost:8080",
			expected: nil,
		},
		{
			name:     "localhost without port skipped",
			host:     "localhost",
			expected: nil,
		},
		{
			name:     "IPv4 address skipped",
			host:     "192.168.1.1",
			expected: nil,
		},
		{
			name:     "IPv4 with port skipped",
			host:     "192.168.1.1:8080",
			expected: nil,
		},
		{
			name:     "IPv6 address skipped",
			host:     "[::1]:8080",
			expected: nil,
		},
		{
			name:     "simple domain",
			host:     "example.com",
			expected: []string{"example"},
		},
		{
			name:     "www prefix",
			host:     "www.example.com",
			expected: []string{"www", "example"},
		},
		{
			name:     "subdomain with country code TLD",
			host:     "sub.domain.example.com.au",
			expected: []string{"sub", "domain", "example"},
		},
		{
			name:     "domain with port",
			host:     "example.com:8080",
			expected: []string{"example"},
		},
		{
			name:     "subdomain with port",
			host:     "api.example.com:443",
			expected: []string{"api", "example"},
		},
		{
			name:     "empty host",
			host:     "",
			expected: nil,
		},
		{
			name:     "io TLD filtered",
			host:     "myapp.example.io",
			expected: []string{"myapp", "example"},
		},
		{
			name:     "dev TLD filtered",
			host:     "api.myservice.dev",
			expected: []string{"api", "myservice"},
		},
		{
			name:     "multiple country codes",
			host:     "shop.brand.co.jp",
			expected: []string{"shop", "brand"},
		},
		{
			name:     "deep subdomain",
			host:     "a.b.c.d.example.org",
			expected: []string{"a", "b", "c", "d", "example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractHostComponents(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// BenchmarkExtractHostComponents measures host component extraction performance.
func BenchmarkExtractHostComponents(b *testing.B) {
	hosts := []string{
		"brand.example.com",
		"api.v2.brand.example.co.uk",
		"localhost:8080",
		"192.168.1.1",
		"example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := hosts[i%len(hosts)]
		ExtractHostComponents(host)
	}
}

// TestExtractRawFilename verifies raw filename extraction that preserves full filenames.
// Unlike ExtractFilename, this does NOT strip hash segments - used for observedFiles.
func TestExtractRawFilename(t *testing.T) {
	tests := []struct {
		name             string
		urlPath          string
		expectedFilename string
		expectedExt      string
	}{
		{
			name:             "simple file with extension",
			urlPath:          "/admin/login.php",
			expectedFilename: "login.php",
			expectedExt:      "php",
		},
		{
			name:             "file with hash - preserved",
			urlPath:          "/js/app.b5ca88ec.js",
			expectedFilename: "app.b5ca88ec.js",
			expectedExt:      "js",
		},
		{
			name:             "file with content hash - preserved",
			urlPath:          "/assets/main.abc123def.css",
			expectedFilename: "main.abc123def.css",
			expectedExt:      "css",
		},
		{
			name:             "compound extension",
			urlPath:          "/backup/archive.tar.gz",
			expectedFilename: "archive.tar.gz",
			expectedExt:      "gz",
		},
		{
			name:             "min.js file",
			urlPath:          "/dist/vendor.min.js",
			expectedFilename: "vendor.min.js",
			expectedExt:      "js",
		},
		{
			name:             "root path",
			urlPath:          "/",
			expectedFilename: "",
			expectedExt:      "",
		},
		{
			name:             "empty path",
			urlPath:          "",
			expectedFilename: "",
			expectedExt:      "",
		},
		{
			name:             "file without extension",
			urlPath:          "/Makefile",
			expectedFilename: "Makefile",
			expectedExt:      "",
		},
		{
			name:             "directory path",
			urlPath:          "/admin/",
			expectedFilename: "",
			expectedExt:      "",
		},
		{
			name:             "dotfile - treated as no extension",
			urlPath:          "/.htaccess",
			expectedFilename: ".htaccess",
			expectedExt:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename, ext := ExtractRawFilename(tt.urlPath)
			assert.Equal(t, tt.expectedFilename, filename, "filename mismatch")
			assert.Equal(t, tt.expectedExt, ext, "extension mismatch")
		})
	}
}

// TestExtractRawFilename_VsExtractFilename verifies the difference between the two functions.
func TestExtractRawFilename_VsExtractFilename(t *testing.T) {
	tests := []struct {
		name          string
		urlPath       string
		rawFilename   string
		rawExt        string
		extractedName string
		extractedExt  string
		description   string
	}{
		{
			name:          "hash is stripped by ExtractFilename but preserved by ExtractRawFilename",
			urlPath:       "/js/app.b5ca88ec.js",
			rawFilename:   "app.b5ca88ec.js",
			rawExt:        "js",
			extractedName: "app",
			extractedExt:  "js",
			description:   "ExtractFilename strips hash, ExtractRawFilename preserves full filename",
		},
		{
			name:          "both return same for simple files",
			urlPath:       "/admin.php",
			rawFilename:   "admin.php",
			rawExt:        "php",
			extractedName: "admin",
			extractedExt:  "php",
			description:   "Simple filenames - raw returns full filename with extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test ExtractRawFilename
			rawFilename, rawExt := ExtractRawFilename(tt.urlPath)
			assert.Equal(t, tt.rawFilename, rawFilename, "raw filename mismatch: %s", tt.description)
			assert.Equal(t, tt.rawExt, rawExt, "raw extension mismatch: %s", tt.description)

			// Test ExtractFilename for comparison
			extractedName, extractedExt := ExtractFilename(tt.urlPath)
			assert.Equal(t, tt.extractedName, extractedName, "extracted name mismatch: %s", tt.description)
			assert.Equal(t, tt.extractedExt, extractedExt, "extracted extension mismatch: %s", tt.description)
		})
	}
}
