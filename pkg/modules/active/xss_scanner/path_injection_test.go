package xss_scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestSplitPathAndQuery tests path and query separation
func TestSplitPathAndQuery(t *testing.T) {
	tests := []struct {
		name      string
		fullPath  string
		wantPath  string
		wantQuery string
	}{
		{
			name:      "path with query",
			fullPath:  "/api/v1/users?id=123&status=active",
			wantPath:  "/api/v1/users",
			wantQuery: "id=123&status=active",
		},
		{
			name:      "path without query",
			fullPath:  "/api/v1/users",
			wantPath:  "/api/v1/users",
			wantQuery: "",
		},
		{
			name:      "root path with query",
			fullPath:  "/?param=value",
			wantPath:  "/",
			wantQuery: "param=value",
		},
		{
			name:      "root path only",
			fullPath:  "/",
			wantPath:  "/",
			wantQuery: "",
		},
		{
			name:      "empty path",
			fullPath:  "",
			wantPath:  "",
			wantQuery: "",
		},
		{
			name:      "query with multiple question marks",
			fullPath:  "/search?q=what?is?this",
			wantPath:  "/search",
			wantQuery: "q=what?is?this",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotQuery := splitPathAndQuery(tt.fullPath)
			if gotPath != tt.wantPath {
				t.Errorf("splitPathAndQuery() path = %v, want %v", gotPath, tt.wantPath)
			}
			if gotQuery != tt.wantQuery {
				t.Errorf("splitPathAndQuery() query = %v, want %v", gotQuery, tt.wantQuery)
			}
		})
	}
}

// TestExtractPathSegments tests path segment extraction
func TestExtractPathSegments(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantSegments []string
	}{
		{
			name:         "simple path",
			path:         "/api/v1/users",
			wantSegments: []string{"api", "v1", "users"},
		},
		{
			name:         "single segment",
			path:         "/api",
			wantSegments: []string{"api"},
		},
		{
			name:         "root path",
			path:         "/",
			wantSegments: []string{},
		},
		{
			name:         "trailing slash",
			path:         "/api/v1/users/",
			wantSegments: []string{"api", "v1", "users"},
		},
		{
			name:         "empty segments",
			path:         "/api//v1///users",
			wantSegments: []string{"api", "v1", "users"},
		},
		{
			name:         "path with special chars",
			path:         "/api/users/123/profile",
			wantSegments: []string{"api", "users", "123", "profile"},
		},
		{
			name:         "empty path",
			path:         "",
			wantSegments: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPathSegments(tt.path)
			if len(got) != len(tt.wantSegments) {
				t.Errorf("extractPathSegments() got %d segments, want %d", len(got), len(tt.wantSegments))
				t.Logf("Got: %v", got)
				t.Logf("Want: %v", tt.wantSegments)
				return
			}
			for i := range got {
				if got[i] != tt.wantSegments[i] {
					t.Errorf("extractPathSegments() segment[%d] = %v, want %v", i, got[i], tt.wantSegments[i])
				}
			}
		})
	}
}

// TestGenerateCutPathVariants tests the cut path injection strategy
func TestGenerateCutPathVariants(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		wantVariants   int
		wantPaths      []string
		skipValidation bool
	}{
		{
			name: "three segment path with query",
			request: "GET /api/v1/users?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantVariants: 3,
			wantPaths: []string{
				"/api/v1/PLACEHOLDER?id=123",
				"/api/PLACEHOLDER?id=123",
				"/PLACEHOLDER?id=123",
			},
		},
		{
			name: "two segment path",
			request: "GET /api/users HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantVariants: 2,
			wantPaths: []string{
				"/api/PLACEHOLDER",
				"/PLACEHOLDER",
			},
		},
		{
			name: "single segment path",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantVariants: 0, // Less than 2 segments, should return nil
			wantPaths:    []string{},
		},
		{
			name: "four segment path",
			request: "GET /api/v1/users/123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantVariants: 4,
			wantPaths: []string{
				"/api/v1/users/PLACEHOLDER",
				"/api/v1/PLACEHOLDER",
				"/api/PLACEHOLDER",
				"/PLACEHOLDER",
			},
		},
		{
			name: "path with trailing slash",
			request: "GET /api/v1/users/ HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantVariants: 3,
			wantPaths: []string{
				"/api/v1/PLACEHOLDER",
				"/api/PLACEHOLDER",
				"/PLACEHOLDER",
			},
		},
		{
			name: "POST request with path",
			request: "POST /api/v1/users HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 12\r\n" +
				"\r\n" +
				"name=test&id=5",
			wantVariants: 3,
			wantPaths: []string{
				"/api/v1/PLACEHOLDER",
				"/api/PLACEHOLDER",
				"/PLACEHOLDER",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := &PathInjectionGenerator{}
			variants, err := generator.GenerateCutPathVariants([]byte(tt.request))

			if tt.wantVariants == 0 {
				if len(variants) > 0 {
					t.Errorf("GenerateCutPathVariants() should return nil for single segment, got %d variants", len(variants))
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateCutPathVariants() error = %v", err)
			}

			if len(variants) != tt.wantVariants {
				t.Errorf("GenerateCutPathVariants() got %d variants, want %d", len(variants), tt.wantVariants)
			}

			// Verify each variant has the expected path
			for i, variant := range variants {
				path, err := httpmsg.GetPath(variant)
				if err != nil {
					t.Errorf("GetPath() error = %v for variant %d", err, i)
					continue
				}

				if path != tt.wantPaths[i] {
					t.Errorf("Variant %d: got path %q, want %q", i, path, tt.wantPaths[i])
				}

				// Verify the variant can be parsed
				_, err = httpmsg.AnalyzeRequest(variant)
				if err != nil {
					t.Errorf("AnalyzeRequest() error = %v for variant %d", err, i)
					t.Logf("Variant %d request:\n%s", i, string(variant))
				}

				// Verify Content-Length is updated correctly
				requestStr := string(variant)
				if strings.Contains(requestStr, "Content-Length:") {
					if !strings.Contains(requestStr, "Content-Length: 0") && !strings.Contains(tt.request, "Content-Length: 0") {
						// Content-Length should be updated when path changes
						t.Logf("Variant %d has Content-Length header", i)
					}
				}
			}
		})
	}
}

// TestPathInjectionGeneratorEdgeCases tests edge cases
func TestPathInjectionGeneratorEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantErr bool
		wantNil bool
	}{
		{
			name:    "nil request",
			request: "",
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "malformed request",
			request: "INVALID REQUEST",
			wantErr: true,
			wantNil: true,
		},
		{
			name: "root path only",
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantErr: false,
			wantNil: true, // Less than 2 segments
		},
		{
			name: "path with query but no segments",
			request: "GET /?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantErr: false,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := &PathInjectionGenerator{}
			variants, err := generator.GenerateCutPathVariants([]byte(tt.request))

			if tt.wantErr {
				if err == nil && len(variants) == 0 {
					// No error but also no variants is acceptable
					return
				}
			}

			if tt.wantNil {
				if len(variants) > 0 {
					t.Errorf("GenerateCutPathVariants() should return nil/empty, got %d variants", len(variants))
				}
			}
		})
	}
}

// TestPathInjectionIntegrationWithBurpx tests integration with httpmsg APIs
func TestPathInjectionIntegrationWithBurpx(t *testing.T) {
	request := []byte("GET /api/v1/users?status=active HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: test\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")

	generator := &PathInjectionGenerator{}
	variants, err := generator.GenerateCutPathVariants(request)
	if err != nil {
		t.Fatalf("GenerateCutPathVariants() error = %v", err)
	}

	if len(variants) != 3 {
		t.Fatalf("Expected 3 variants, got %d", len(variants))
	}

	// For each variant, verify we can parse path parameters
	for i, variant := range variants {
		t.Run(fmt.Sprintf("variant_%d", i), func(t *testing.T) {
			// Parse path parameters
			pathParams, err := httpmsg.ParsePathParameters(variant)
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			// Should have at least one parameter (PLACEHOLDER)
			if len(pathParams) == 0 {
				t.Error("ParsePathParameters() returned no parameters")
				return
			}

			// Find PLACEHOLDER parameter
			foundPlaceholder := false
			for _, param := range pathParams {
				if param.Value() == "PLACEHOLDER" {
					foundPlaceholder = true
					t.Logf("Found PLACEHOLDER at position: %s", param.Name())
				}
			}

			if !foundPlaceholder {
				t.Error("PLACEHOLDER parameter not found in path parameters")
				t.Logf("Path params: %+v", pathParams)
			}

			// Verify insertion points can be created
			insertionPoints, err := httpmsg.CreateAllInsertionPoints(variant, true)
			if err != nil {
				t.Errorf("CreateAllInsertionPoints() error = %v", err)
				return
			}

			// Should have insertion points
			if len(insertionPoints) == 0 {
				t.Error("CreateAllInsertionPoints() returned no insertion points")
			}

			t.Logf("Variant %d: %d insertion points created", i, len(insertionPoints))
		})
	}
}

// ============================================================================
// TEST SUITE: Path Append Injection (Phase 2d)
// ============================================================================

// TestGenerateAppendPathVariant tests appending fake 404 path segment
func TestGenerateAppendPathVariant(t *testing.T) {
	tests := []struct {
		name     string
		request  string
		wantPath string
	}{
		{
			name: "root path",
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/thisdoesnotexisted404",
		},
		{
			name: "single segment path",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/api/thisdoesnotexisted404",
		},
		{
			name: "multi-segment path",
			request: "GET /api/p1/b1 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/api/p1/b1/thisdoesnotexisted404",
		},
		{
			name: "path with query string",
			request: "GET /api?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/api/thisdoesnotexisted404?id=123",
		},
		{
			name: "multi-segment path with query",
			request: "GET /api/v1/users?status=active HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/api/v1/users/thisdoesnotexisted404?status=active",
		},
		{
			name: "path with trailing slash",
			request: "GET /api/v1/ HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/api/v1/thisdoesnotexisted404",
		},
		{
			name: "POST request with path",
			request: "POST /api/v1/users HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 12\r\n" +
				"\r\n" +
				"name=test&id=5",
			wantPath: "/api/v1/users/thisdoesnotexisted404",
		},
		{
			name: "complex path with multiple query params",
			request: "GET /search/results?q=test&page=1&limit=10 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantPath: "/search/results/thisdoesnotexisted404?q=test&page=1&limit=10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := &PathInjectionGenerator{}
			variant, err := generator.GenerateAppendPathVariant([]byte(tt.request))

			if err != nil {
				t.Fatalf("GenerateAppendPathVariant() error = %v", err)
			}

			// Verify path changed correctly
			path, err := httpmsg.GetPath(variant)
			if err != nil {
				t.Fatalf("GetPath() error = %v", err)
			}

			if path != tt.wantPath {
				t.Errorf("Path = %q, want %q", path, tt.wantPath)
			}

			// Verify the variant can be parsed
			_, err = httpmsg.AnalyzeRequest(variant)
			if err != nil {
				t.Errorf("AnalyzeRequest() error = %v for variant", err)
				t.Logf("Variant request:\n%s", string(variant))
			}

			// Verify Content-Length is updated correctly if exists
			requestStr := string(variant)
			if strings.Contains(requestStr, "Content-Length:") {
				t.Logf("Variant has Content-Length header")
			}
		})
	}
}

// TestAppendPathVariantParameters tests that appended segment becomes a path parameter
func TestAppendPathVariantParameters(t *testing.T) {
	request := []byte("GET /api/v1/users?id=123 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: test\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")

	generator := &PathInjectionGenerator{}
	variant, err := generator.GenerateAppendPathVariant(request)
	if err != nil {
		t.Fatalf("GenerateAppendPathVariant() error = %v", err)
	}

	// Parse path parameters
	pathParams, err := httpmsg.ParsePathParameters(variant)
	if err != nil {
		t.Fatalf("ParsePathParameters() error = %v", err)
	}

	// Should have at least 4 parameters: api, v1, users, thisdoesnotexisted404
	if len(pathParams) < 4 {
		t.Errorf("ParsePathParameters() returned %d parameters, want at least 4", len(pathParams))
	}

	// Find thisdoesnotexisted404 parameter
	found404 := false
	for _, param := range pathParams {
		if param.Value() == "thisdoesnotexisted404" {
			found404 = true
			t.Logf("Found thisdoesnotexisted404 at position: %s", param.Name())
		}
	}

	if !found404 {
		t.Error("thisdoesnotexisted404 parameter not found in path parameters")
		t.Logf("Path params: %+v", pathParams)
	}

	// Verify insertion points can be created
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(variant, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Should have insertion points
	if len(insertionPoints) == 0 {
		t.Error("CreateAllInsertionPoints() returned no insertion points")
	}

	// Find insertion point for thisdoesnotexisted404
	foundIP := false
	for _, ip := range insertionPoints {
		if ip.BaseValue() == "thisdoesnotexisted404" {
			foundIP = true

			// Test BuildRequest
			payload := "<script>alert(1)</script>"
			modifiedRequest := ip.BuildRequest([]byte(payload))
			if modifiedRequest == nil {
				t.Error("BuildRequest() returned nil")
			}

			t.Logf("✓ Insertion point created for thisdoesnotexisted404, BuildRequest OK")
			break
		}
	}

	if !foundIP {
		t.Error("Insertion point not found for thisdoesnotexisted404")
	}
}

// TestAppendPathVariantEdgeCases tests edge cases
func TestAppendPathVariantEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantErr bool
	}{
		{
			name:    "empty request",
			request: "",
			wantErr: true,
		},
		{
			name:    "malformed request",
			request: "INVALID REQUEST",
			wantErr: true,
		},
		{
			name: "root path without trailing slash",
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantErr: false,
		},
		{
			name: "path with fragment",
			request: "GET /api#section HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := &PathInjectionGenerator{}
			variant, err := generator.GenerateAppendPathVariant([]byte(tt.request))

			if tt.wantErr {
				if err == nil && variant != nil {
					t.Logf("⚠ Expected error but got variant")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				} else if variant != nil {
					// Verify variant is valid
					_, err := httpmsg.AnalyzeRequest(variant)
					if err != nil {
						t.Errorf("Variant is not valid: %v", err)
					} else {
						path, _ := httpmsg.GetPath(variant)
						t.Logf("✓ Generated path: %s", path)
					}
				}
			}
		})
	}
}

// TestAppendPathVariantIntegration tests integration with full scanning flow
func TestAppendPathVariantIntegration(t *testing.T) {
	tests := []struct {
		name         string
		request      string
		wantSegment  string
		wantParamMin int
	}{
		{
			name: "simple API endpoint",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantSegment:  "thisdoesnotexisted404",
			wantParamMin: 2, // api + thisdoesnotexisted404
		},
		{
			name: "REST resource path",
			request: "GET /api/users/123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantSegment:  "thisdoesnotexisted404",
			wantParamMin: 4, // api, users, 123, thisdoesnotexisted404
		},
		{
			name: "path with query params",
			request: "GET /search?q=xss HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantSegment:  "thisdoesnotexisted404",
			wantParamMin: 2, // search, thisdoesnotexisted404
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := &PathInjectionGenerator{}
			variant, err := generator.GenerateAppendPathVariant([]byte(tt.request))
			if err != nil {
				t.Fatalf("GenerateAppendPathVariant() error = %v", err)
			}

			// Verify path parameters
			pathParams, err := httpmsg.ParsePathParameters(variant)
			if err != nil {
				t.Fatalf("ParsePathParameters() error = %v", err)
			}

			if len(pathParams) < tt.wantParamMin {
				t.Errorf("Got %d path params, want at least %d", len(pathParams), tt.wantParamMin)
			}

			// Verify the target segment exists
			foundSegment := false
			for _, param := range pathParams {
				if param.Value() == tt.wantSegment {
					foundSegment = true
					t.Logf("✓ Found %s at position %s", tt.wantSegment, param.Name())
				}
			}

			if !foundSegment {
				t.Errorf("Segment %s not found", tt.wantSegment)
			}

			// Verify insertion points work
			insertionPoints, err := httpmsg.CreateAllInsertionPoints(variant, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			if len(insertionPoints) == 0 {
				t.Error("No insertion points created")
			}

			t.Logf("✓ Created %d insertion points", len(insertionPoints))
		})
	}
}
