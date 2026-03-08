package xss_scanner

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// PathInjectionGenerator handles path-based injection strategies for XSS testing.
// It provides two strategies:
// 1. Recursive: Test each path segment individually (using httpmsg.ParsePathParameters)
// 2. Cut: Progressively cut path segments from the end
type PathInjectionGenerator struct{}

// GenerateCutPathVariants creates modified HTTP requests with progressively cut paths.
// Each variant represents cutting the path to a specific level from the end.
//
// Example:
//
//	Input: GET /api/v1/users?id=123 HTTP/1.1
//	Output: [
//	  "GET /api/v1/PLACEHOLDER?id=123 HTTP/1.1",  // cut 1 segment
//	  "GET /api/PLACEHOLDER?id=123 HTTP/1.1",      // cut 2 segments
//	  "GET /PLACEHOLDER?id=123 HTTP/1.1",          // cut 3 segments
//	]
//
// For each variant, the scanner will:
// 1. Parse path parameters (PLACEHOLDER becomes a path parameter)
// 2. Create standard insertion point
// 3. Test with XSS payloads (PLACEHOLDER → payload)
//
// Parameters:
//   - request: Complete HTTP request bytes
//
// Returns:
//   - List of modified requests with cut paths
//   - Error if path manipulation fails
func (g *PathInjectionGenerator) GenerateCutPathVariants(request []byte) ([][]byte, error) {
	// 1. Parse path parameters to understand structure
	pathParams, err := httpmsg.ParsePathParameters(request)
	if err != nil || len(pathParams) < 2 {
		return nil, err // Need at least 2 segments for cutting
	}

	// 2. Get full path with query string
	fullPath, err := httpmsg.GetPath(request)
	if err != nil {
		return nil, err
	}

	// 3. Split path and query string
	pathOnly, query := splitPathAndQuery(fullPath)

	// 4. Extract path segments
	segments := extractPathSegments(pathOnly)
	if len(segments) < 2 {
		return nil, nil // Need at least 2 segments
	}

	// 5. Generate cut variants
	var variants [][]byte
	for cutLevel := 1; cutLevel <= len(segments); cutLevel++ {
		// Calculate how many segments to keep
		keepCount := len(segments) - cutLevel

		// Build new path with PLACEHOLDER
		var newPath string
		if keepCount > 0 {
			keptSegments := segments[:keepCount]
			newPath = "/" + strings.Join(keptSegments, "/") + "/PLACEHOLDER"
		} else {
			newPath = "/PLACEHOLDER"
		}

		// Restore query string if it exists
		if query != "" {
			newPath += "?" + query
		}

		// Create modified request with new path
		modifiedRequest, err := httpmsg.SetPath(request, newPath)
		if err != nil {
			continue
		}

		variants = append(variants, modifiedRequest)
	}

	return variants, nil
}

// splitPathAndQuery splits a full path into path and query string components.
//
// Example:
//
//	"/api/users?id=123" → path="/api/users", query="id=123"
//	"/api/users" → path="/api/users", query=""
//
// Parameters:
//   - fullPath: Full path including query string (e.g., "/api?id=1")
//
// Returns:
//   - path: Path without query string
//   - query: Query string without '?' prefix
func splitPathAndQuery(fullPath string) (path, query string) {
	if idx := strings.IndexByte(fullPath, '?'); idx != -1 {
		return fullPath[:idx], fullPath[idx+1:]
	}
	return fullPath, ""
}

// extractPathSegments extracts path segments from a path string.
//
// Example:
//
//	"/api/v1/users" → ["api", "v1", "users"]
//	"/api" → ["api"]
//	"/" → []
//
// Parameters:
//   - path: URL path (e.g., "/api/v1/users")
//
// Returns:
//   - List of path segments
func extractPathSegments(path string) []string {
	// Trim leading and trailing slashes
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}

	// Split by slash
	segments := strings.Split(trimmed, "/")

	// Filter out empty segments
	var filtered []string
	for _, segment := range segments {
		if segment != "" {
			filtered = append(filtered, segment)
		}
	}

	return filtered
}

// GenerateAppendPathVariant creates a modified HTTP request with a fake 404 path segment appended.
// This tests error page reflection behavior by appending a non-existent path.
//
// Example:
//
//	Input: GET / HTTP/1.1
//	Output: "GET /thisdoesnotexisted404 HTTP/1.1"
//
//	Input: GET /api/v1/users?id=123 HTTP/1.1
//	Output: "GET /api/v1/users/thisdoesnotexisted404?id=123 HTTP/1.1"
//
// The scanner will:
// 1. Parse path parameters (thisdoesnotexisted404 becomes a path parameter)
// 2. Create insertion point for the appended segment
// 3. Test with XSS payloads (thisdoesnotexisted404 → payload)
//
// Parameters:
//   - request: Complete HTTP request bytes
//
// Returns:
//   - Modified request with appended fake 404 path
//   - Error if path manipulation fails
func (g *PathInjectionGenerator) GenerateAppendPathVariant(request []byte) ([]byte, error) {
	// 1. Get full path with query string
	fullPath, err := httpmsg.GetPath(request)
	if err != nil {
		return nil, err
	}

	// 2. Split path and query string
	pathOnly, query := splitPathAndQuery(fullPath)

	// 3. Build new path with appended segment
	// Remove trailing slash if present
	pathOnly = strings.TrimSuffix(pathOnly, "/")

	// Append fake 404 segment
	newPath := pathOnly + "/thisdoesnotexisted404"

	// 4. Restore query string if it exists
	if query != "" {
		newPath += "?" + query
	}

	// 5. Create modified request with new path
	modifiedRequest, err := httpmsg.SetPath(request, newPath)
	if err != nil {
		return nil, err
	}

	return modifiedRequest, nil
}
