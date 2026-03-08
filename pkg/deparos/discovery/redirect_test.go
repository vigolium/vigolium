package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectDetector_DetectRedirect(t *testing.T) {
	tests := []struct {
		name                 string
		originalURL          string
		statusCode           int
		locationHeader       string
		depth                uint16
		maxDepth             uint16
		expectedIsRedirect   bool
		expectedIsTrailing   bool
		expectedShouldQueue  bool
		expectedShouldMark   bool
		expectedResolvedPath string
	}{
		{
			name:                 "301 trailing slash redirect",
			originalURL:          "http://example.com/admin",
			statusCode:           301,
			locationHeader:       "/admin/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   true,
			expectedShouldQueue:  true,
			expectedShouldMark:   true,
			expectedResolvedPath: "/admin/",
		},
		{
			name:                 "302 trailing slash redirect",
			originalURL:          "http://example.com/api",
			statusCode:           302,
			locationHeader:       "/api/",
			depth:                5,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   true,
			expectedShouldQueue:  true,
			expectedShouldMark:   true,
			expectedResolvedPath: "/api/",
		},
		{
			name:                 "301 non-trailing slash redirect",
			originalURL:          "http://example.com/old",
			statusCode:           301,
			locationHeader:       "/new",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   false,
			expectedShouldQueue:  true,
			expectedShouldMark:   false,
			expectedResolvedPath: "/new",
		},
		{
			name:                 "303 redirect (not detected per Burp)",
			originalURL:          "http://example.com/admin",
			statusCode:           303,
			locationHeader:       "/admin/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   false,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
		{
			name:                 "307 redirect (not detected per Burp)",
			originalURL:          "http://example.com/admin",
			statusCode:           307,
			locationHeader:       "/admin/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   false,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
		{
			name:                 "308 redirect (not detected per Burp)",
			originalURL:          "http://example.com/admin",
			statusCode:           308,
			locationHeader:       "/admin/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   false,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
		{
			name:                 "301 with max depth reached",
			originalURL:          "http://example.com/deep",
			statusCode:           301,
			locationHeader:       "/deep/",
			depth:                16,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   true,
			expectedShouldQueue:  false, // Depth limit reached
			expectedShouldMark:   true,
			expectedResolvedPath: "/deep/",
		},
		{
			name:                 "301 with empty location header",
			originalURL:          "http://example.com/test",
			statusCode:           301,
			locationHeader:       "",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
		{
			name:                 "301 with absolute URL in location",
			originalURL:          "http://example.com/old",
			statusCode:           301,
			locationHeader:       "http://example.com/old/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   true,
			expectedShouldQueue:  true,
			expectedShouldMark:   true,
			expectedResolvedPath: "/old/",
		},
		{
			name:                 "301 with different path (not trailing slash)",
			originalURL:          "http://example.com/foo",
			statusCode:           301,
			locationHeader:       "/bar/",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   true,
			expectedIsTrailing:   false,
			expectedShouldQueue:  true,
			expectedShouldMark:   false,
			expectedResolvedPath: "/bar/",
		},
		{
			name:                 "200 OK (not a redirect)",
			originalURL:          "http://example.com/page",
			statusCode:           200,
			locationHeader:       "",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   false,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
		{
			name:                 "404 Not Found (not a redirect)",
			originalURL:          "http://example.com/missing",
			statusCode:           404,
			locationHeader:       "",
			depth:                0,
			maxDepth:             16,
			expectedIsRedirect:   false,
			expectedIsTrailing:   false,
			expectedShouldQueue:  false,
			expectedShouldMark:   false,
			expectedResolvedPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := NewRedirectDetector()

			// Create HTTP response
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.locationHeader != "" {
				resp.Header.Set("Location", tt.locationHeader)
			}

			// Detect redirect
			info, err := rd.DetectRedirect(resp, tt.originalURL, tt.depth, tt.maxDepth)
			require.NoError(t, err)

			// Verify results
			assert.Equal(t, tt.expectedIsRedirect, info.IsRedirect, "IsRedirect mismatch")
			assert.Equal(t, tt.expectedIsTrailing, info.IsTrailingSlash, "IsTrailingSlash mismatch")
			assert.Equal(t, tt.expectedShouldQueue, info.ShouldQueueRedirect, "ShouldQueueRedirect mismatch")
			assert.Equal(t, tt.expectedShouldMark, info.ShouldMarkDirectory, "ShouldMarkDirectory mismatch")

			if tt.expectedResolvedPath != "" {
				assert.Contains(t, info.ResolvedLocation, tt.expectedResolvedPath, "ResolvedLocation path mismatch")
			}
		})
	}
}

func TestRedirectDetector_TrailingSlashAlgorithm(t *testing.T) {
	// Test the exact algorithm from Burp ff6.java:171-175
	tests := []struct {
		name         string
		originalPath []byte
		redirectPath []byte
		expected     bool
	}{
		{
			name:         "exact trailing slash",
			originalPath: []byte("/admin"),
			redirectPath: []byte("/admin/"),
			expected:     true,
		},
		{
			name:         "same path no trailing slash",
			originalPath: []byte("/admin"),
			redirectPath: []byte("/admin"),
			expected:     false,
		},
		{
			name:         "different path with slash",
			originalPath: []byte("/admin"),
			redirectPath: []byte("/users/"),
			expected:     false,
		},
		{
			name:         "longer by more than one byte",
			originalPath: []byte("/admin"),
			redirectPath: []byte("/admin/x"),
			expected:     false,
		},
		{
			name:         "shorter path",
			originalPath: []byte("/admin/test"),
			redirectPath: []byte("/admin"),
			expected:     false,
		},
		{
			name:         "empty to slash",
			originalPath: []byte(""),
			redirectPath: []byte("/"),
			expected:     true,
		},
		{
			name:         "root to root with slash",
			originalPath: []byte("/test"),
			redirectPath: []byte("/test/"),
			expected:     true,
		},
		{
			name:         "case sensitive match",
			originalPath: []byte("/Admin"),
			redirectPath: []byte("/Admin/"),
			expected:     true,
		},
		{
			name:         "case mismatch",
			originalPath: []byte("/admin"),
			redirectPath: []byte("/Admin/"),
			expected:     false, // Byte-level comparison is case-sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := NewRedirectDetector()
			result := rd.IsTrailingSlashRedirect(tt.originalPath, tt.redirectPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedirectDetector_URLNormalization(t *testing.T) {
	// Test URL normalization matching at.java:264-363
	tests := []struct {
		name        string
		inputPath   string
		expected    string
		description string
	}{
		{
			name:        "backslash to forward slash",
			inputPath:   "\\admin\\test",
			expected:    "/admin/test",
			description: "Convert backslashes (at.java:97-99)",
		},
		{
			name:        "ensure leading slash",
			inputPath:   "admin/test",
			expected:    "/admin/test",
			description: "Add leading slash (at.java:287-289)",
		},
		{
			name:        "remove dot segments",
			inputPath:   "/admin/./test",
			expected:    "/admin/test",
			description: "Remove /./ (at.java:334-338)",
		},
		{
			name:        "collapse double slashes",
			inputPath:   "/admin//test",
			expected:    "/admin/test",
			description: "Collapse // to / (at.java:340-344)",
		},
		{
			name:        "remove trailing dot",
			inputPath:   "/admin/.",
			expected:    "/admin",
			description: "Remove trailing /. (at.java:346-348)",
		},
		{
			name:        "resolve parent directory",
			inputPath:   "/admin/test/../config",
			expected:    "/admin/config",
			description: "Resolve /../ (at.java:300-332)",
		},
		{
			name:        "complex normalization",
			inputPath:   "\\admin\\./test//..//config/.",
			expected:    "/admin/config",
			description: "Multiple normalizations",
		},
		{
			name:        "preserve query fragment removal",
			inputPath:   "/admin#section",
			expected:    "/admin",
			description: "Fragment removed before normalization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := NewRedirectDetector()

			// Test fragment removal first if present
			path := tt.inputPath
			if idx := len(path); idx > 0 && path[idx-1] == '#' {
				// This would be handled by parseAndNormalizeURL
				path = path[:idx-1]
			}

			result := rd.NormalizePath(path)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestRedirectDetector_Integration(t *testing.T) {
	// Integration test with real HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			// Typical Apache/Nginx directory redirect
			w.Header().Set("Location", "/admin/")
			w.WriteHeader(301)
		case "/api":
			// Another common pattern
			w.Header().Set("Location", "/api/")
			w.WriteHeader(302)
		case "/old":
			// Non-trailing slash redirect
			w.Header().Set("Location", "/new")
			w.WriteHeader(301)
		case "/external":
			// External redirect
			w.Header().Set("Location", "https://other.example.com/")
			w.WriteHeader(302)
		default:
			w.WriteHeader(404)
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	rd := NewRedirectDetector()

	testCases := []struct {
		path               string
		expectedIsTrailing bool
	}{
		{"/admin", true},
		{"/api", true},
		{"/old", false},
		{"/external", false},
	}

	// Create client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := client.Get(server.URL + tc.path)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			info, err := rd.DetectRedirect(resp, server.URL+tc.path, 0, 16)
			require.NoError(t, err)

			assert.True(t, info.IsRedirect, "Should detect redirect")
			assert.Equal(t, tc.expectedIsTrailing, info.IsTrailingSlash,
				"Trailing slash detection for %s", tc.path)
		})
	}
}

func TestRedirectDetector_DuplicatePrevention(t *testing.T) {
	rd := NewRedirectDetector()

	// Create response for /admin -> /admin/ redirect
	resp := &http.Response{
		StatusCode: 301,
		Header:     make(http.Header),
	}
	resp.Header.Set("Location", "/admin/")

	// First detection should queue
	info1, err := rd.DetectRedirect(resp, "http://example.com/admin", 0, 16)
	require.NoError(t, err)
	assert.True(t, info1.ShouldQueueRedirect, "First detection should queue")

	// Second detection of same redirect should not queue (duplicate)
	info2, err := rd.DetectRedirect(resp, "http://example.com/admin", 0, 16)
	require.NoError(t, err)
	assert.False(t, info2.ShouldQueueRedirect, "Duplicate should not queue")

	// Different redirect should queue
	resp.Header.Set("Location", "/users/")
	info3, err := rd.DetectRedirect(resp, "http://example.com/users", 0, 16)
	require.NoError(t, err)
	assert.True(t, info3.ShouldQueueRedirect, "Different redirect should queue")
}

func TestRedirectDetector_RelativeURLResolution(t *testing.T) {
	rd := NewRedirectDetector()

	tests := []struct {
		name         string
		originalURL  string
		location     string
		expectedPath string
	}{
		{
			name:         "relative path",
			originalURL:  "http://example.com/admin/config",
			location:     "../users",
			expectedPath: "/users",
		},
		{
			name:         "absolute path",
			originalURL:  "http://example.com/admin",
			location:     "/admin/",
			expectedPath: "/admin/",
		},
		{
			name:         "absolute URL",
			originalURL:  "http://example.com/old",
			location:     "http://example.com/new",
			expectedPath: "/new",
		},
		{
			name:         "protocol relative",
			originalURL:  "http://example.com/test",
			location:     "//example.com/test/",
			expectedPath: "/test/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 301,
				Header:     make(http.Header),
			}
			resp.Header.Set("Location", tt.location)

			info, err := rd.DetectRedirect(resp, tt.originalURL, 0, 16)
			require.NoError(t, err)
			assert.Contains(t, info.ResolvedLocation, tt.expectedPath)
		})
	}
}

func TestRedirectDetector_PathExtraction(t *testing.T) {
	tests := []struct {
		name              string
		originalURL       string
		locationHeader    string
		expectedDirPath   string
		expectedFilename  string
		expectedExtension string
		expectedSameHost  bool
	}{
		{
			name:              "file redirect same host",
			originalURL:       "http://example.com/old",
			locationHeader:    "/us/en/index.html",
			expectedDirPath:   "/us/en/",
			expectedFilename:  "index",
			expectedExtension: "html",
			expectedSameHost:  true,
		},
		{
			name:              "directory redirect same host",
			originalURL:       "http://example.com/content/",
			locationHeader:    "/api/v1/",
			expectedDirPath:   "/api/v1/",
			expectedFilename:  "",
			expectedExtension: "",
			expectedSameHost:  true,
		},
		{
			name:              "cross-origin redirect",
			originalURL:       "http://example.com/assets",
			locationHeader:    "https://cdn.example.net/static/main.js",
			expectedDirPath:   "/static/",
			expectedFilename:  "main",
			expectedExtension: "js",
			expectedSameHost:  false,
		},
		{
			name:              "file in root",
			originalURL:       "http://example.com/old",
			locationHeader:    "/robots.txt",
			expectedDirPath:   "",
			expectedFilename:  "robots",
			expectedExtension: "txt",
			expectedSameHost:  true,
		},
		{
			name:              "trailing slash redirect - no extraction",
			originalURL:       "http://example.com/admin",
			locationHeader:    "/admin/",
			expectedDirPath:   "",
			expectedFilename:  "",
			expectedExtension: "",
			expectedSameHost:  true,
		},
		{
			name:              "redirect to deep path",
			originalURL:       "http://example.com/content/dam/icons/",
			locationHeader:    "/us/en/products/item.json",
			expectedDirPath:   "/us/en/products/",
			expectedFilename:  "item",
			expectedExtension: "json",
			expectedSameHost:  true,
		},
		{
			name:              "redirect to directory only",
			originalURL:       "http://example.com/old",
			locationHeader:    "/new/path/",
			expectedDirPath:   "/new/path/",
			expectedFilename:  "",
			expectedExtension: "",
			expectedSameHost:  true,
		},
		{
			name:              "same host different port",
			originalURL:       "http://example.com:8080/test",
			locationHeader:    "http://example.com:8080/api/v1/data.json",
			expectedDirPath:   "/api/v1/",
			expectedFilename:  "data",
			expectedExtension: "json",
			expectedSameHost:  true,
		},
		{
			name:              "cross-origin different port",
			originalURL:       "http://example.com/test",
			locationHeader:    "http://example.com:8080/api/data.json",
			expectedDirPath:   "/api/",
			expectedFilename:  "data",
			expectedExtension: "json",
			expectedSameHost:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := NewRedirectDetector()
			resp := &http.Response{
				StatusCode: 301,
				Header:     make(http.Header),
			}
			resp.Header.Set("Location", tt.locationHeader)

			info, err := rd.DetectRedirect(resp, tt.originalURL, 0, 16)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedDirPath, info.ExtractedDirPath, "ExtractedDirPath mismatch")
			assert.Equal(t, tt.expectedFilename, info.ExtractedFilename, "ExtractedFilename mismatch")
			assert.Equal(t, tt.expectedExtension, info.ExtractedExtension, "ExtractedExtension mismatch")
			assert.Equal(t, tt.expectedSameHost, info.IsSameHost, "IsSameHost mismatch")
		})
	}
}
