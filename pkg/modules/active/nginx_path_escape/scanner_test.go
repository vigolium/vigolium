package nginx_path_escape

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mpoolDrain"),
	)
	defer time.Sleep(2 * time.Second)
}

// =============================================================================
// Test getParentPath Function
// =============================================================================

func TestGetParentPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard path",
			input:    "/api/v1/users",
			expected: "/api/v1/",
		},
		{
			name:     "path with trailing slash",
			input:    "/api/v1/users/",
			expected: "/api/v1/",
		},
		{
			name:     "file at root",
			input:    "/api",
			expected: "/",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "/",
		},
		{
			name:     "dot",
			input:    ".",
			expected: ".",
		},
		{
			name:     "dot slash",
			input:    "./",
			expected: "./",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "filename only",
			input:    "filename",
			expected: "./",
		},
		{
			name:     "deeply nested path",
			input:    "/a/b/c/d/e/f",
			expected: "/a/b/c/d/e/",
		},
		{
			name:     "deeply nested with trailing slash",
			input:    "/a/b/c/d/e/f/",
			expected: "/a/b/c/d/e/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getParentPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Test createLevelInsertionPoint Function
// =============================================================================

func TestCreateLevelInsertionPoint(t *testing.T) {
	tests := []struct {
		name           string
		rawRequest     string
		pathLevel      string
		expectError    bool
		errorContains  string
		expectedName   string
		expectedBase   string
		expectedInLine string // expected string in the first line of modified request
	}{
		{
			name:           "basic path",
			rawRequest:     "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:      "/api/file",
			expectError:    false,
			expectedName:   "file",
			expectedBase:   "file",
			expectedInLine: "GET /api/file HTTP/1.1",
		},
		{
			name:           "two segments - full path",
			rawRequest:     "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:      "/api/v1/users",
			expectError:    false,
			expectedName:   "users",
			expectedBase:   "users",
			expectedInLine: "GET /api/v1/users HTTP/1.1",
		},
		{
			name:           "two segments - parent level",
			rawRequest:     "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:      "/api/v1",
			expectError:    false,
			expectedName:   "v1",
			expectedBase:   "v1",
			expectedInLine: "GET /api/v1 HTTP/1.1",
		},
		{
			name:           "request with query string is stripped",
			rawRequest:     "GET /api/file?query=value HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:      "/api/file",
			expectError:    false,
			expectedName:   "file",
			expectedBase:   "file",
			expectedInLine: "GET /api/file HTTP/1.1",
		},
		{
			name:           "single segment at root",
			rawRequest:     "GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:      "/file",
			expectError:    false,
			expectedName:   "file",
			expectedBase:   "file",
			expectedInLine: "GET /file HTTP/1.1",
		},
		{
			name:         "POST request",
			rawRequest:   "POST /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/api/users",
			expectError:  false,
			expectedName: "users",
			expectedBase: "users",
		},
		{
			// Regression: a "/" level (derived from a double-slash path
			// like //explore) has no fuzzable segment. Must return an
			// error, not panic in NewEncodedInsertionPoint.
			name:          "root level returns error not panic",
			rawRequest:    "GET /explore HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/",
			expectError:   true,
			errorContains: "empty path segment",
		},
		{
			name:          "all-slashes level returns error not panic",
			rawRequest:    "GET /explore HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "//",
			expectError:   true,
			errorContains: "empty path segment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modReq, ip, err := createLevelInsertionPoint([]byte(tt.rawRequest), tt.pathLevel)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ip)
			require.NotNil(t, modReq)

			assert.Equal(t, tt.expectedName, ip.Name())
			assert.Equal(t, tt.expectedBase, ip.BaseValue())

			if tt.expectedInLine != "" {
				assert.Contains(t, string(modReq), tt.expectedInLine)
			}
		})
	}
}

func TestCreateLevelInsertionPoint_BuildRequest(t *testing.T) {
	rawRequest := []byte("GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n")

	modReq, ip, err := createLevelInsertionPoint(rawRequest, "/api/file")
	require.NoError(t, err)
	require.NotNil(t, ip)
	_ = modReq

	// Replace "file" segment with "file../"
	payload := []byte("file../")
	result := ip.BuildRequest(payload)
	assert.Contains(t, string(result), "GET /api/file../ HTTP/1.1")
}

func TestEmptyPayloadProducesParentPath(t *testing.T) {
	tests := []struct {
		name         string
		rawRequest   string
		pathLevel    string
		expectedPath string // expected path in request line after injecting ""
	}{
		{
			name:         "/api/v1/admin → /api/v1/",
			rawRequest:   "GET /api/v1/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/api/v1/admin",
			expectedPath: "GET /api/v1/ HTTP/1.1",
		},
		{
			name:         "/api/v1 → /api/",
			rawRequest:   "GET /api/v1/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/api/v1",
			expectedPath: "GET /api/ HTTP/1.1",
		},
		{
			name:         "/api → /",
			rawRequest:   "GET /api/v1/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/api",
			expectedPath: "GET / HTTP/1.1",
		},
		{
			name:         "trailing slash /api/v1/admin/ → /api/v1/",
			rawRequest:   "GET /api/v1/admin/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/api/v1/admin",
			expectedPath: "GET /api/v1/ HTTP/1.1",
		},
		{
			name:         "single segment /file → /",
			rawRequest:   "GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:    "/file",
			expectedPath: "GET / HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ip, err := createLevelInsertionPoint([]byte(tt.rawRequest), tt.pathLevel)
			require.NoError(t, err)

			result := ip.BuildRequest([]byte(""))
			assert.Contains(t, string(result), tt.expectedPath)
		})
	}
}

func TestCreateLevelInsertionPoint_NoEncoding(t *testing.T) {
	rawRequest := []byte("GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n")

	_, ip, err := createLevelInsertionPoint(rawRequest, "/api/file")
	require.NoError(t, err)

	// Payload with special chars must NOT be double-encoded
	payload := []byte("file%2e%2e/..;/test")
	result := ip.BuildRequest(payload)

	resultStr := string(result)
	assert.Contains(t, resultStr, "GET /api/file%2e%2e/..;/test HTTP/1.1")
	assert.NotContains(t, resultStr, "%252e")
}

func TestCreateLevelInsertionPoint_SegmentReplacement(t *testing.T) {
	rawRequest := []byte("GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Level: /api/v1 → segment = "v1"
	_, ip, err := createLevelInsertionPoint(rawRequest, "/api/v1")
	require.NoError(t, err)
	assert.Equal(t, "v1", ip.BaseValue())

	// Replace "v1" with "v1..;/"
	result := ip.BuildRequest([]byte("v1..;/"))
	assert.Contains(t, string(result), "GET /api/v1..;/ HTTP/1.1")
}

// =============================================================================
// Test createFullPathInsertionPoint Function
// =============================================================================

func TestCreateFullPathInsertionPoint(t *testing.T) {
	tests := []struct {
		name          string
		rawRequest    string
		expectError   bool
		errorContains string
	}{
		{
			name:        "basic GET request",
			rawRequest:  "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectError: false,
		},
		{
			name:        "request with query string",
			rawRequest:  "GET /api/file?query=value HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectError: false,
		},
		{
			name:          "no newline in request",
			rawRequest:    "GET /api/file HTTP/1.1",
			expectError:   true,
			errorContains: "no newline found",
		},
		{
			name:        "POST request",
			rawRequest:  "POST /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := createFullPathInsertionPoint([]byte(tt.rawRequest))

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ip)
			assert.Equal(t, "fullpath", ip.Name())
		})
	}
}

func TestCreateFullPathInsertionPoint_BuildRequest(t *testing.T) {
	rawRequest := []byte("GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n")

	ip, err := createFullPathInsertionPoint(rawRequest)
	require.NoError(t, err)
	require.NotNil(t, ip)

	payload := []byte("/test/../escape")
	result := ip.BuildRequest(payload)

	assert.Contains(t, string(result), "GET /test/../escape HTTP/1.1")
}

// =============================================================================
// Test splitPathIntoLevels Function
// =============================================================================

func TestSplitPathIntoLevels(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "root path",
			input:    "/",
			expected: nil,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single segment",
			input:    "/api",
			expected: []string{"/api"},
		},
		{
			name:     "two segments",
			input:    "/api/v1",
			expected: []string{"/api/v1", "/api"},
		},
		{
			name:     "three segments",
			input:    "/api/v1/users",
			expected: []string{"/api/v1/users", "/api/v1", "/api"},
		},
		{
			name:     "path with file extension",
			input:    "/static/js/app.js",
			expected: []string{"/static/js/app.js", "/static/js", "/static"},
		},
		{
			name:     "deep path",
			input:    "/a/b/c/d/e/f",
			expected: []string{"/a/b/c/d/e/f", "/a/b/c/d/e", "/a/b/c/d", "/a/b/c", "/a/b", "/a"},
		},
		{
			name:     "path with trailing slash",
			input:    "/api/v1/",
			expected: []string{"/api/v1", "/api"},
		},
		{
			name:     "example from plan - gw/file/download/vlc/mojetv.mp4",
			input:    "/gw/file/download/vlc/mojetv.mp4",
			expected: []string{"/gw/file/download/vlc/mojetv.mp4", "/gw/file/download/vlc", "/gw/file/download", "/gw/file", "/gw"},
		},
		{
			// Regression: a leading double slash must not emit a bare
			// "/" level (which previously panicked downstream).
			name:     "leading double slash",
			input:    "//explore",
			expected: []string{"//explore"},
		},
		{
			name:     "leading double slash with dotted host",
			input:    "//google.com",
			expected: []string{"//google.com"},
		},
		{
			name:     "interior double slash",
			input:    "/a//b",
			expected: []string{"/a//b", "/a/", "/a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitPathIntoLevels(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Test MaxPathLevels Limiting
// =============================================================================

func TestMaxPathLevelsLimiting(t *testing.T) {
	tests := []struct {
		name          string
		fullPath      string
		maxLevels     int
		expectedCount int
		expectedFirst string
	}{
		{
			name:          "no limit (maxLevels=0)",
			fullPath:      "/a/b/c/d/e",
			maxLevels:     0,
			expectedCount: 5,
			expectedFirst: "/a/b/c/d/e",
		},
		{
			name:          "within limit",
			fullPath:      "/a/b/c",
			maxLevels:     5,
			expectedCount: 3,
			expectedFirst: "/a/b/c",
		},
		{
			name:          "exceeds limit",
			fullPath:      "/a/b/c/d/e",
			maxLevels:     3,
			expectedCount: 3,
			expectedFirst: "/a/b/c/d/e",
		},
		{
			name:          "maxLevels 1",
			fullPath:      "/static/js/app/main.js",
			maxLevels:     1,
			expectedCount: 1,
			expectedFirst: "/static/js/app/main.js",
		},
		{
			name:          "maxLevels 2",
			fullPath:      "/api/v1/users/123",
			maxLevels:     2,
			expectedCount: 2,
			expectedFirst: "/api/v1/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			levels := splitPathIntoLevels(tt.fullPath)
			if tt.maxLevels > 0 && len(levels) > tt.maxLevels {
				levels = levels[:tt.maxLevels]
			}
			assert.Len(t, levels, tt.expectedCount)
			if len(levels) > 0 {
				assert.Equal(t, tt.expectedFirst, levels[0], "First level must be the full path")
			}
		})
	}
}

// =============================================================================
// Test Path Level Selection Integration
// =============================================================================

func TestPathLevelSelectionIntegration(t *testing.T) {
	tests := []struct {
		name           string
		fullPath       string
		maxLevels      int
		expectedLevels []string
	}{
		{
			name:           "typical API path with maxLevels 4",
			fullPath:       "/api/v1/users/123/profile",
			maxLevels:      4,
			expectedLevels: []string{"/api/v1/users/123/profile", "/api/v1/users/123", "/api/v1/users", "/api/v1"},
		},
		{
			name:           "static file path with maxLevels 3",
			fullPath:       "/static/js/app/bundle.min.js",
			maxLevels:      3,
			expectedLevels: []string{"/static/js/app/bundle.min.js", "/static/js/app", "/static/js"},
		},
		{
			name:           "short path with high maxLevels",
			fullPath:       "/api/users",
			maxLevels:      10,
			expectedLevels: []string{"/api/users", "/api"},
		},
		{
			name:           "plan example - vcr.opswat.com path",
			fullPath:       "/gw/file/download/vlc/mojetv.mp4",
			maxLevels:      5,
			expectedLevels: []string{"/gw/file/download/vlc/mojetv.mp4", "/gw/file/download/vlc", "/gw/file/download", "/gw/file", "/gw"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			levels := splitPathIntoLevels(tt.fullPath)
			if tt.maxLevels > 0 && len(levels) > tt.maxLevels {
				levels = levels[:tt.maxLevels]
			}
			assert.Equal(t, tt.expectedLevels, levels)

			// First level must always be the full path
			if len(levels) > 0 {
				assert.Equal(t, strings.TrimSuffix(tt.fullPath, "/"), levels[0], "First level must be the full path")
			}
		})
	}
}

// =============================================================================
// Test Raw HTTP Request Output (segment-based payloads)
// =============================================================================

func TestRawHTTPRequestOutput(t *testing.T) {
	tests := []struct {
		name          string
		baseRequest   string
		pathLevel     string
		payload       string
		expectedInReq string
		notExpectedIn string
	}{
		{
			name:          "path traversal basic",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file../",
			expectedInReq: "GET /api/file../ HTTP/1.1",
		},
		{
			name:          "encoded traversal",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%2e%2e/",
			expectedInReq: "GET /api/file%2e%2e/ HTTP/1.1",
			notExpectedIn: "%25",
		},
		{
			name:          "semicolon injection",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file..;/",
			expectedInReq: "GET /api/file..;/ HTTP/1.1",
		},
		{
			name:          "backslash injection",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file..\\../",
			expectedInReq: "GET /api/file..\\../ HTTP/1.1",
		},
		{
			name:          "null byte injection",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%00../",
			expectedInReq: "GET /api/file%00../ HTTP/1.1",
		},
		{
			name:          "unicode overlong",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%c0%ae%c0%ae/",
			expectedInReq: "GET /api/file%c0%ae%c0%ae/ HTTP/1.1",
		},
		{
			name:          "fragment bypass",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%23/../",
			expectedInReq: "GET /api/file%23/../ HTTP/1.1",
		},
		{
			name:          "double encoding",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%252e%252e/",
			expectedInReq: "GET /api/file%252e%252e/ HTTP/1.1",
		},
		{
			name:          "newline bypass",
			baseRequest:   "GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/file",
			payload:       "file%0a/../",
			expectedInReq: "GET /api/file%0a/../ HTTP/1.1",
		},
		{
			name:          "deeper path - segment replacement",
			baseRequest:   "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pathLevel:     "/api/v1",
			payload:       "v1../",
			expectedInReq: "GET /api/v1../ HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ip, err := createLevelInsertionPoint([]byte(tt.baseRequest), tt.pathLevel)
			require.NoError(t, err)

			result := ip.BuildRequest([]byte(tt.payload))
			resultStr := string(result)

			assert.Contains(t, resultStr, tt.expectedInReq,
				"Expected request line not found")

			if tt.notExpectedIn != "" {
				assert.NotContains(t, resultStr, tt.notExpectedIn,
					"Unexpected content found in request")
			}

			assert.Contains(t, resultStr, "Host: example.com")
		})
	}
}

// =============================================================================
// Test Full Path Insertion Point Raw Request
// =============================================================================

func TestFullPathInsertionPoint_NoEncoding(t *testing.T) {
	rawRequest := []byte("GET /api/file HTTP/1.1\r\nHost: example.com\r\n\r\n")

	ip, err := createFullPathInsertionPoint(rawRequest)
	require.NoError(t, err)

	payload := []byte("/path%2e%2e/..;/test")
	result := ip.BuildRequest(payload)

	resultStr := string(result)
	assert.Contains(t, resultStr, "GET /path%2e%2e/..;/test HTTP/1.1")
	assert.NotContains(t, resultStr, "%252e")
}

// =============================================================================
// Test Severity Constants
// =============================================================================

func TestSeverityConstants(t *testing.T) {
	assert.Equal(t, 3, SeverityLow)
	assert.Equal(t, 4, SeverityMedium)
	assert.Equal(t, 5, SeverityHigh)
}

// =============================================================================
// Test toUpperFirstAlpha Function
// =============================================================================

func TestToUpperFirstAlpha(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase path",
			input:    "/api/v1",
			expected: "/Api/v1",
		},
		{
			name:     "already uppercase first segment",
			input:    "/API/v1",
			expected: "/API/V1",
		},
		{
			name:     "single char",
			input:    "/a",
			expected: "/A",
		},
		{
			name:     "root only",
			input:    "/",
			expected: "/",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "numeric start",
			input:    "/123abc",
			expected: "/123Abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toUpperFirstAlpha(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Test mixCase Function
// =============================================================================

func TestMixCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase path",
			input:    "/api",
			expected: "/ApI",
		},
		{
			name:     "longer path",
			input:    "/admin/panel",
			expected: "/AdMiN/pAnEl",
		},
		{
			name:     "single char",
			input:    "/a",
			expected: "/A",
		},
		{
			name:     "root only",
			input:    "/",
			expected: "/",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mixCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
